// Package engine wires the UniDB-Go stages into one pipeline:
// parse -> security -> plan -> route -> execute (single source or federated).
package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/federation"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
	"github.com/Dheeran-git/UniDBGo/router"
	"github.com/Dheeran-git/UniDBGo/security"
)

// Trace records what each stage decided and how long it took.
type Trace struct {
	AST      *parser.QueryAST
	Decision security.Decision
	Plan     *planner.ExecutionPlan
	Routes   []router.Route

	ParseTime, SecurityTime, PlanTime, RouteTime, ExecTime time.Duration
}

// Engine executes queries against a set of named backends.
type Engine struct {
	// Sources maps the database names used in queries ("postgres", "mysql",
	// "mongodb") to connected handles.
	Sources map[string]*api.DB
	// Default receives queries with no database qualifier when no router is
	// set or the router is not confident.
	Default string
	// Security inspects every query; nil disables inspection.
	Security *security.SecurityEngine
	// Router predicts a backend for unqualified queries; nil sends them to Default.
	Router router.Router
}

// Query runs the full pipeline and returns the rows with a stage trace.
func (e *Engine) Query(ctx context.Context, query string, args ...any) (internal.Result, *Trace, error) {
	tr := &Trace{}

	t0 := time.Now()
	ast, d, perr := e.parse(query)
	tr.ParseTime = time.Since(t0)
	tr.AST = ast

	if e.Security != nil {
		t1 := time.Now()
		tr.Decision = e.Security.AnalyzeASTFor(query, ast, perr, d)
		tr.SecurityTime = time.Since(t1)
		if tr.Decision.Block {
			return nil, tr, fmt.Errorf("%w: %s", api.ErrBlockedQuery, tr.Decision.Reason)
		}
	}
	if perr != nil {
		if e.Security != nil && e.Security.AllowUnparseable {
			// Unparseable but explicitly allowed: pass through to the default source.
			db := e.source(e.Default)
			if db == nil {
				return nil, tr, fmt.Errorf("engine: no source registered for %q", e.Default)
			}
			res, err := db.Query(ctx, query, args...)
			return res, tr, err
		}
		return nil, tr, perr
	}

	t2 := time.Now()
	plan, err := planner.GeneratePlan(ast)
	tr.PlanTime = time.Since(t2)
	tr.Plan = plan
	if err != nil {
		return nil, tr, err
	}

	t3 := time.Now()
	if e.Router != nil {
		tr.Routes, _ = e.Router.Route(plan)
	}
	tr.RouteTime = time.Since(t3)

	t4 := time.Now()
	defer func() { tr.ExecTime = time.Since(t4) }()

	if len(plan.Steps) == 1 {
		step := plan.Steps[0]
		db := e.source(e.target(step.Database, tr.Routes))
		if db == nil {
			return nil, tr, fmt.Errorf("engine: no source registered for %q", e.target(step.Database, tr.Routes))
		}
		res, err := db.Query(ctx, step.Query, args...)
		return res, tr, err
	}

	if len(args) > 0 {
		return nil, tr, errors.New("engine: bind arguments are not supported in federated queries")
	}
	if parser.DialectSensitive(query) && parser.Normalize(query, parser.Postgres) != parser.Normalize(query, parser.MySQL) {
		// Backslashes in literals, double quotes and '#' mean different things
		// to PostgreSQL and MySQL, so a federated query must avoid them.
		return nil, tr, errors.New("engine: federated queries must not use backslashes in literals, double quotes or '#', whose meaning differs between dialects")
	}
	// Scans go through each handle, so its middleware sees them.
	conns := make(map[string]internal.Connection, len(e.Sources))
	for name, db := range e.Sources {
		conns[name] = db
	}
	res, err := federation.NewEngine(conns).Execute(ctx, plan)
	return res, tr, err
}

// parse reads query with the lexical rules of the database it targets. The
// target is found from a first, MySQL-rules parse; the query is re-read only
// when its text means something different under the target's rules.
func (e *Engine) parse(query string) (*parser.QueryAST, parser.Dialect, error) {
	ast, err := parser.Parse(query)
	target := e.Default
	if err == nil && len(ast.Tables) > 0 && ast.Tables[0].Database != "" {
		if _, ok := e.Sources[ast.Tables[0].Database]; ok {
			target = ast.Tables[0].Database
		}
	}
	d := parser.MySQL
	if db := e.source(target); db != nil {
		d = parser.DialectOf(db.Driver())
	}
	if d != parser.MySQL && parser.DialectSensitive(query) {
		ast, err = parser.ParseFor(query, d)
	}
	return ast, d, err
}

// target picks the source for a single-source plan: an explicit qualifier,
// else a confident router prediction, else the default.
func (e *Engine) target(qualifier string, routes []router.Route) string {
	if qualifier != "" && qualifier != "default" {
		return qualifier
	}
	if len(routes) == 1 && routes[0].Database != "default" {
		if _, ok := e.Sources[routes[0].Database]; ok {
			return routes[0].Database
		}
	}
	return e.Default
}

// Exec runs a write statement after security inspection.
func (e *Engine) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	ast, d, perr := e.parse(query)
	if e.Security != nil {
		if dec := e.Security.AnalyzeASTFor(query, ast, perr, d); dec.Block {
			return nil, fmt.Errorf("%w: %s", api.ErrBlockedQuery, dec.Reason)
		}
	}
	if perr != nil && (e.Security == nil || !e.Security.AllowUnparseable) {
		return nil, perr
	}
	target := e.Default
	if perr == nil && len(ast.Tables) > 0 && ast.Tables[0].Database != "" {
		plan, err := planner.GeneratePlan(ast)
		if err != nil {
			return nil, err
		}
		if len(plan.Steps) != 1 {
			return nil, errors.New("engine: writes must target a single source")
		}
		target, query = plan.Steps[0].Database, plan.Steps[0].Query
	}
	db := e.source(target)
	if db == nil {
		return nil, fmt.Errorf("engine: no source registered for %q", target)
	}
	return db.Exec(ctx, query, args...)
}

func (e *Engine) source(name string) *api.DB {
	return e.Sources[name]
}

// Close closes every source.
func (e *Engine) Close() error {
	var errs []error
	for _, db := range e.Sources {
		if err := db.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
