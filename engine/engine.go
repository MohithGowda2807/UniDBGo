// Package engine wires the UniDB-Go stages into one pipeline:
// parse -> security -> plan -> route -> execute (single source or federated).
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	if security.IsDocument(query) {
		return e.queryDocument(ctx, query, tr, args)
	}

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
		name := e.target(step.Database, tr.Routes)
		db := e.source(name)
		if db == nil {
			return nil, tr, fmt.Errorf("engine: no source registered for %q", name)
		}
		if dt := parser.DialectOf(db.Driver()); dt != d && parser.DialectSensitive(query) {
			// The router chose a backend that reads this text differently from
			// the rules used for the checks above (backslashes, double quotes,
			// '#'). Re-read and re-check it as that backend will.
			if step, err = e.recheck(query, dt, tr); err != nil {
				return nil, tr, err
			}
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
		return nil, tr, errors.New("engine: federated queries must not use text that PostgreSQL and MySQL read differently (backslashes in literals, double quotes, '#', '||', '--' without a space, nested comments)")
	}
	// Scans go through each handle, so its middleware sees them.
	conns := make(map[string]internal.Connection, len(e.Sources))
	for name, db := range e.Sources {
		conns[name] = db
	}
	res, err := federation.NewEngine(conns).Execute(ctx, plan)
	return res, tr, err
}

// recheck parses and inspects query again with the lexical rules of dialect d
// and returns the single plan step to execute.
func (e *Engine) recheck(query string, d parser.Dialect, tr *Trace) (planner.ExecutionStep, error) {
	ast, perr := parser.ParseFor(query, d)
	if e.Security != nil {
		tr.Decision = e.Security.AnalyzeASTFor(query, ast, perr, d)
		if tr.Decision.Block {
			return planner.ExecutionStep{}, fmt.Errorf("%w: %s", api.ErrBlockedQuery, tr.Decision.Reason)
		}
	}
	if perr != nil {
		return planner.ExecutionStep{}, perr
	}
	tr.AST = ast
	plan, err := planner.GeneratePlan(ast)
	if err != nil {
		return planner.ExecutionStep{}, err
	}
	if len(plan.Steps) != 1 {
		return planner.ExecutionStep{}, errors.New("engine: query plan changed under the target dialect")
	}
	tr.Plan = plan
	return plan.Steps[0], nil
}

// queryDocument runs a JSON command document (a MongoDB command). Documents
// are not SQL: they skip the SQL parser and invariants, are checked for
// server-side JavaScript instead, and may only run on a MongoDB source, chosen
// by the router when it is confident and otherwise by Default or, failing
// that, as the only MongoDB source registered.
func (e *Engine) queryDocument(ctx context.Context, doc string, tr *Trace, args []any) (internal.Result, *Trace, error) {
	if e.Security != nil {
		t1 := time.Now()
		tr.Decision = e.Security.AnalyzeDocument(doc)
		tr.SecurityTime = time.Since(t1)
		if tr.Decision.Block {
			return nil, tr, fmt.Errorf("%w: %s", api.ErrBlockedQuery, tr.Decision.Reason)
		}
	}
	isMongo := func(name string) bool {
		db := e.source(name)
		return db != nil && strings.HasPrefix(strings.ToLower(db.Driver()), "mongo")
	}
	name := ""
	if e.Router != nil {
		t3 := time.Now()
		plan := &planner.ExecutionPlan{Steps: []planner.ExecutionStep{{ID: 1, Type: "SCAN", Query: doc}}}
		tr.Routes, _ = e.Router.Route(plan)
		tr.RouteTime = time.Since(t3)
		if len(tr.Routes) == 1 && isMongo(tr.Routes[0].Database) {
			name = tr.Routes[0].Database
		}
	}
	if name == "" && isMongo(e.Default) {
		name = e.Default
	}
	if name == "" {
		for n := range e.Sources {
			if isMongo(n) {
				if name != "" {
					return nil, tr, errors.New("engine: several MongoDB sources; set Default or a router to choose one for command documents")
				}
				name = n
			}
		}
	}
	if name == "" {
		return nil, tr, errors.New("engine: command documents need a MongoDB source")
	}
	t4 := time.Now()
	defer func() { tr.ExecTime = time.Since(t4) }()
	res, err := e.source(name).Query(ctx, doc, args...)
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
	if perr == nil && qualified(ast) {
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

// qualified reports whether any table of ast names a database.
func qualified(ast *parser.QueryAST) bool {
	for _, t := range ast.Tables {
		if t.Database != "" {
			return true
		}
	}
	return false
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
