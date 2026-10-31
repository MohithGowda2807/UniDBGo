// Package security inspects the syntax tree of SQL statements and blocks
// those that violate structural invariants typical of injection attacks.
package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/parser"
	"vitess.io/vitess/go/vt/sqlparser"
)

// Category names the structural invariant a query violated.
type Category string

const (
	CatNone              Category = ""
	CatTautology         Category = "tautology"          // V1
	CatPiggyback         Category = "piggyback"          // V2
	CatUnionExfiltration Category = "union-exfiltration" // V3
	CatUnboundedScan     Category = "unbounded-scan"     // V3 (flag only)
	CatCommentTruncation Category = "comment-truncation" // V4
	CatTimingFunction    Category = "dangerous-function" // V5
	CatInference         Category = "inference"          // V5
	CatSystemCatalog     Category = "system-catalog"
	CatUnparseable       Category = "unparseable"
	CatAnomaly           Category = "anomaly"
)

type Decision struct {
	Block    bool
	Flag     bool
	Reason   string
	Category Category
}

// SecurityEngine inspects the syntax tree of every query before it reaches a
// driver. The zero value is ready to use with the default configuration.
type SecurityEngine struct {
	// RestrictedTables are tables whose contents must not be extracted through
	// UNION branches or read by unbounded scans. Defaults to DefaultRestrictedTables.
	RestrictedTables []string
	// AllowUnparseable lets queries the grammar cannot parse through with a
	// flag instead of blocking them (fail-open). The default is fail-closed.
	AllowUnparseable bool
	// MaxQueryLength flags unusually long queries. Defaults to 5000 bytes.
	MaxQueryLength int
	// Dialect gives the lexical rules Analyze uses (default MySQL). The engine
	// and the middleware pick the dialect of the target database themselves.
	Dialect parser.Dialect

	// Decisions depend only on the query text, its dialect and the fields
	// above, so they are cached like parsed trees. Call ResetCache after
	// changing the configuration of an engine already in use.
	mu    sync.RWMutex
	cache map[parser.Dialect]map[string]Decision
}

// maxCachedDecisions bounds the decision cache; it is cleared when full.
const maxCachedDecisions = 10000

// ResetCache discards cached decisions.
func (e *SecurityEngine) ResetCache() {
	e.mu.Lock()
	e.cache = nil
	e.mu.Unlock()
}

func (e *SecurityEngine) cached(d parser.Dialect, query string) (Decision, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	dec, ok := e.cache[d][query]
	return dec, ok
}

func (e *SecurityEngine) remember(d parser.Dialect, query string, dec Decision) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cache == nil {
		e.cache = map[parser.Dialect]map[string]Decision{}
	}
	m := e.cache[d]
	if m == nil || len(m) >= maxCachedDecisions {
		m = make(map[string]Decision)
		e.cache[d] = m
	}
	m[query] = dec
	return dec
}

var DefaultRestrictedTables = []string{"users", "passwords", "tokens", "credentials", "sessions"}

// systemSchemas hold catalog metadata an attacker enumerates before extraction.
var systemSchemas = map[string]bool{
	"information_schema": true, "performance_schema": true, "sys": true, "pg_catalog": true,
}

// mysqlSystemTables are the privilege tables of MySQL's "mysql" schema. The
// schema name alone is not used because "mysql" is also a natural name for a
// UniDB-Go backend ("mysql.orders").
var mysqlSystemTables = map[string]bool{
	"user": true, "db": true, "tables_priv": true, "columns_priv": true, "procs_priv": true,
	"proxies_priv": true, "global_grants": true, "role_edges": true, "default_roles": true,
	"password_history": true, "servers": true,
}

// dangerousFunctions enable timing side channels, locks, file-system or
// network access. Names are matched without their schema qualifier.
var dangerousFunctions = map[string]bool{
	"sleep": true, "benchmark": true, "get_lock": true, "load_file": true,
	"pg_sleep": true, "pg_sleep_for": true, "pg_sleep_until": true,
	"pg_read_file": true, "pg_read_binary_file": true, "pg_ls_dir": true, "pg_stat_file": true,
	"lo_import": true, "lo_export": true, "dblink": true, "dblink_exec": true,
	"receive_message": true, // dbms_pipe.receive_message
}

// systemInfoFunctions disclose server metadata. Compared against constants
// they are the hallmark of inference (blind) attacks, which test their value
// bit by bit.
var systemInfoFunctions = map[string]bool{
	"version": true, "database": true, "schema": true, "user": true,
	"current_user": true, "session_user": true, "system_user": true, "connection_id": true,
	"current_database": true, "current_schema": true, "inet_server_addr": true,
}

// NewSecurityEngine creates a SecurityEngine with the default configuration
// and the given restricted tables (DefaultRestrictedTables when empty).
func NewSecurityEngine(restricted ...string) *SecurityEngine {
	return &SecurityEngine{RestrictedTables: restricted}
}

func (e *SecurityEngine) restricted(name string) bool {
	list := e.RestrictedTables
	if len(list) == 0 {
		list = DefaultRestrictedTables
	}
	for _, t := range list {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}

func (e *SecurityEngine) dialect() parser.Dialect {
	if e.Dialect == "" {
		return parser.MySQL
	}
	return e.Dialect
}

func block(c Category, format string, args ...any) Decision {
	return Decision{Block: true, Category: c, Reason: fmt.Sprintf(format, args...)}
}

func flag(c Category, format string, args ...any) Decision {
	return Decision{Flag: true, Category: c, Reason: fmt.Sprintf(format, args...)}
}

// Analyze runs Algorithm 1 with the engine's dialect: lexical comment check,
// statement count, then a recursive walk of the syntax tree that enforces
// the structural invariants.
func (e *SecurityEngine) Analyze(query string) Decision {
	return e.AnalyzeFor(query, e.dialect())
}

// AnalyzeFor is Analyze with the lexical rules of dialect d.
func (e *SecurityEngine) AnalyzeFor(query string, d parser.Dialect) Decision {
	if dec, ok := e.cached(d, query); ok {
		return dec
	}
	ast, err := parser.ParseFor(query, d)
	return e.AnalyzeASTFor(query, ast, err, d)
}

// AnalyzeAST is Analyze for a query that the caller has already parsed, so
// that the pipeline parses each query only once.
func (e *SecurityEngine) AnalyzeAST(query string, ast *parser.QueryAST, parseErr error) Decision {
	d := e.dialect()
	if ast != nil && ast.Dialect != "" {
		d = ast.Dialect
	}
	return e.AnalyzeASTFor(query, ast, parseErr, d)
}

// AnalyzeASTFor is AnalyzeAST for a query read with the rules of dialect d.
func (e *SecurityEngine) AnalyzeASTFor(query string, ast *parser.QueryAST, parseErr error, d parser.Dialect) Decision {
	if dec, ok := e.cached(d, query); ok {
		return dec
	}
	return e.remember(d, query, e.analyze(query, ast, parseErr, d))
}

func (e *SecurityEngine) analyze(query string, ast *parser.QueryAST, parseErr error, d parser.Dialect) Decision {
	if dec := checkTrailingComment(query, d); dec.Block {
		return dec
	}

	if errors.Is(parseErr, parser.ErrMultiStatement) {
		stmts, err := parser.StatementsFor(query, d)
		n := len(stmts)
		if err != nil {
			n++ // the malformed trailing statement
		}
		return block(CatPiggyback, "Piggy-backed query: %d stacked statements", n)
	}
	if parseErr != nil || ast == nil || ast.Stmt == nil {
		if parseErr == nil || errors.Is(parseErr, parser.ErrInvalidQuery) || errors.Is(parseErr, parser.ErrUnsupportedQuery) {
			// The grammar accepted the text but the summary did not; inspect the raw tree.
			if stmts, err := parser.StatementsFor(query, d); err == nil && len(stmts) == 1 {
				return e.finish(query, e.inspect(stmts[0]))
			}
		}
		if e.AllowUnparseable {
			return flag(CatUnparseable, "Query could not be parsed: %v", parseErr)
		}
		return block(CatUnparseable, "Query rejected: %v", parseErr)
	}

	return e.finish(query, e.inspect(ast.Stmt))
}

func (e *SecurityEngine) finish(query string, d Decision) Decision {
	if d.Block || d.Flag {
		return d
	}
	maxLen := e.MaxQueryLength
	if maxLen == 0 {
		maxLen = 5000
	}
	if len(query) > maxLen {
		return flag(CatAnomaly, "Anomaly: query length %d exceeds %d bytes", len(query), maxLen)
	}
	return Decision{}
}

// errStop carries a decision out of sqlparser.Walk.
type errStop struct{ d Decision }

func (errStop) Error() string { return "stop" }

func (e *SecurityEngine) inspect(stmt sqlparser.Statement) Decision {
	var flagged Decision
	_, topUnion := stmt.(*sqlparser.Union)

	err := sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch n := node.(type) {
		case *sqlparser.OrExpr:
			for _, branch := range disjuncts(n) {
				if isTautology(branch) {
					return false, errStop{block(CatTautology,
						"Tautology: disjunct %q is always true", sqlparser.String(branch))}
				}
			}
		case *sqlparser.FuncExpr:
			if name := n.Name.Lowered(); dangerousFunctions[name] {
				return false, errStop{block(CatTimingFunction, "Dangerous function call: %s()", name)}
			}
		case *sqlparser.LockingFunc:
			if n.Type == sqlparser.GetLock {
				return false, errStop{block(CatTimingFunction, "Dangerous function call: get_lock()")}
			}
		case *sqlparser.Union:
			for _, branch := range unionBranches(n) {
				if d := e.checkUnionBranch(branch, topUnion && n == stmt); d.Block {
					return false, errStop{d}
				}
			}
		case *sqlparser.Subquery:
			for _, t := range allTables(n) {
				if isCatalog(t) {
					return false, errStop{block(CatSystemCatalog,
						"Sub-query probes system catalog %s", sqlparser.String(t))}
				}
			}
		case *sqlparser.ComparisonExpr, *sqlparser.BetweenExpr, *sqlparser.IsExpr:
			if d := e.inferenceProbe(n.(sqlparser.Expr)); d.Block {
				return false, errStop{d}
			}
		case *sqlparser.Select:
			for _, t := range tablesOf(n) {
				if isCatalog(t) && !flagged.Flag {
					flagged = flag(CatSystemCatalog, "Reads system catalog %s", sqlparser.String(t))
				}
				if e.restricted(t.Name.String()) && n.Where == nil && n.Limit == nil && !flagged.Flag {
					flagged = flag(CatUnboundedScan,
						"Data exfiltration risk: unbounded scan of restricted table %s", t.Name.String())
				}
			}
		}
		return true, nil
	}, stmt)

	var stop errStop
	if errors.As(err, &stop) {
		return stop.d
	}
	return flagged
}

// inferenceProbe blocks a comparison that tests hidden values against
// constants, as blind (inference) attacks do: server metadata such as
// LENGTH(DATABASE()) > 5 or SUBSTRING(@@version,1,1) = '8', or a scalar
// sub-query over a restricted table such as
// ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64.
// Comparing with a column of the outer query (owner = CURRENT_USER(),
// id IN (SELECT user_id FROM users ...)) is legitimate.
func (e *SecurityEngine) inferenceProbe(cmp sqlparser.Expr) Decision {
	probe, column := "", false
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch n := node.(type) {
		case *sqlparser.FuncExpr:
			if systemInfoFunctions[n.Name.Lowered()] && probe == "" {
				probe = n.Name.Lowered() + "()"
			}
		case *sqlparser.Variable:
			if probe == "" {
				probe = "@@" + n.Name.String()
			}
		case *sqlparser.ColName:
			column = true
		case *sqlparser.Subquery:
			for _, t := range allTables(n) {
				if e.restricted(t.Name.String()) && probe == "" {
					probe = "a sub-query over " + t.Name.String()
				}
			}
			return false, nil // its own columns are not outer columns
		}
		return true, nil
	}, cmp)
	if probe != "" && !column {
		return block(CatInference, "Inference probe: predicate tests %s against constants", probe)
	}
	return Decision{}
}

// checkUnionBranch blocks UNION branches that read restricted tables or
// system catalogs (anywhere in the branch, including sub-queries), that
// select server metadata, or, for a top-level UNION, that select only
// constants (column-count probing).
func (e *SecurityEngine) checkUnionBranch(sel *sqlparser.Select, topLevel bool) Decision {
	for _, t := range allTables(sel) {
		if isCatalog(t) || e.restricted(t.Name.String()) {
			return block(CatUnionExfiltration, "UNION extraction from %s", sqlparser.String(t))
		}
	}
	var meta string
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch n := node.(type) {
		case *sqlparser.FuncExpr:
			if systemInfoFunctions[n.Name.Lowered()] {
				meta = n.Name.Lowered() + "()"
				return false, errStop{}
			}
		case *sqlparser.Variable:
			meta = "@@" + n.Name.String()
			return false, errStop{}
		}
		return true, nil
	}, sel)
	if meta != "" {
		return block(CatUnionExfiltration, "UNION extraction of %s", meta)
	}
	if topLevel {
		real := 0
		for _, t := range tablesOf(sel) {
			if !strings.EqualFold(t.Name.String(), "dual") {
				real++
			}
		}
		if real == 0 {
			return block(CatUnionExfiltration, "UNION branch without a source table (column probing)")
		}
	}
	return Decision{}
}

// isCatalog reports whether t is a system catalog table.
func isCatalog(t sqlparser.TableName) bool {
	schema := strings.ToLower(t.Qualifier.String())
	name := strings.ToLower(t.Name.String())
	switch {
	case systemSchemas[schema]:
		return true
	case schema == "mysql":
		return mysqlSystemTables[name]
	case schema == "" && strings.HasPrefix(name, "pg_"):
		return true // pg_user, pg_shadow, pg_tables, ... resolve through pg_catalog
	}
	return false
}

// isTautology reports whether a disjunct is always true: either its static
// value is true, or it compares an expression with itself.
func isTautology(e sqlparser.Expr) bool {
	if v, ok := eval(e); ok {
		return v.truthy()
	}
	if c, ok := e.(*sqlparser.ComparisonExpr); ok {
		switch c.Operator {
		case sqlparser.EqualOp, sqlparser.NullSafeEqualOp, sqlparser.LessEqualOp,
			sqlparser.GreaterEqualOp, sqlparser.LikeOp:
			return sqlparser.String(c.Left) == sqlparser.String(c.Right)
		}
	}
	return false
}

// disjuncts flattens nested OR expressions (the parser drops parentheses).
func disjuncts(e sqlparser.Expr) []sqlparser.Expr {
	if n, ok := e.(*sqlparser.OrExpr); ok {
		return append(disjuncts(n.Left), disjuncts(n.Right)...)
	}
	return []sqlparser.Expr{e}
}

func unionBranches(s sqlparser.TableStatement) []*sqlparser.Select {
	switch n := s.(type) {
	case *sqlparser.Select:
		return []*sqlparser.Select{n}
	case *sqlparser.Union:
		return append(unionBranches(n.Left), unionBranches(n.Right)...)
	}
	return nil
}

// tablesOf lists the base tables in the FROM clause of a single SELECT.
func tablesOf(sel *sqlparser.Select) []sqlparser.TableName {
	var out []sqlparser.TableName
	var visit func(sqlparser.TableExpr)
	visit = func(te sqlparser.TableExpr) {
		switch t := te.(type) {
		case *sqlparser.AliasedTableExpr:
			if name, ok := t.Expr.(sqlparser.TableName); ok {
				out = append(out, name)
			}
		case *sqlparser.JoinTableExpr:
			visit(t.LeftExpr)
			visit(t.RightExpr)
		case *sqlparser.ParenTableExpr:
			for _, x := range t.Exprs {
				visit(x)
			}
		}
	}
	for _, te := range sel.From {
		visit(te)
	}
	return out
}

// allTables lists every base table referenced anywhere under node,
// including FROM clauses of nested sub-queries.
func allTables(node sqlparser.SQLNode) []sqlparser.TableName {
	var out []sqlparser.TableName
	_ = sqlparser.Walk(func(n sqlparser.SQLNode) (bool, error) {
		if at, ok := n.(*sqlparser.AliasedTableExpr); ok {
			if name, ok := at.Expr.(sqlparser.TableName); ok {
				out = append(out, name)
			}
		}
		return true, nil
	}, node)
	return out
}

// checkTrailingComment detects comments used to cut off the remainder of a
// query ("admin'-- "). It blocks when the comment ends the input and its
// text continues the statement as SQL: a boolean connective followed by a
// comparison (AND password = ...), ORDER BY / GROUP BY, LIMIT n, or UNION
// SELECT. Prose such as "-- don't remove" or "-- from 2024" is allowed.
func checkTrailingComment(query string, d parser.Dialect) Decision {
	if !strings.ContainsAny(query, "#-/") {
		return Decision{} // no comment opener at all
	}
	tkn := parser.NewTokenizer(parser.Normalize(query, d))
	var body string
	lastIsComment := false
	for {
		typ, val := tkn.Scan()
		if typ == 0 {
			break
		}
		if typ == sqlparser.LEX_ERROR {
			return Decision{}
		}
		lastIsComment = typ == sqlparser.COMMENT
		if lastIsComment {
			body = val
		}
	}
	if !lastIsComment {
		return Decision{}
	}
	if strings.HasPrefix(body, "/*") {
		if strings.HasSuffix(body, "*/") {
			return Decision{} // a closed block comment truncates nothing
		}
		body = body[2:]
	} else {
		body = strings.TrimLeft(body, "-#")
	}
	if what := sqlContinuation(body); what != "" {
		return block(CatCommentTruncation, "Trailing comment swallows SQL (%s): %q", what, strings.TrimSpace(body))
	}
	return Decision{}
}

// sqlContinuation reports which SQL construct, if any, the comment text
// would contribute to the statement had it not been commented out.
func sqlContinuation(body string) string {
	body = strings.TrimSpace(body)
	body = strings.TrimPrefix(body, "'") // the rest of a literal the payload closed
	body = strings.TrimPrefix(body, `"`)
	tkn := parser.NewTokenizer(body)
	var toks []string
	for len(toks) < 64 {
		typ, val := tkn.Scan()
		if typ == 0 || typ == sqlparser.LEX_ERROR {
			break
		}
		switch {
		case typ == sqlparser.STRING:
			toks = append(toks, "<STR>")
		case typ == sqlparser.INTEGRAL:
			toks = append(toks, "<NUM>")
		case typ == sqlparser.ID:
			toks = append(toks, "<ID>")
		case typ == sqlparser.LE, typ == sqlparser.GE, typ == sqlparser.NE, typ == sqlparser.NULL_SAFE_EQUAL:
			toks = append(toks, "=")
		case len(val) > 0:
			toks = append(toks, strings.ToUpper(val))
		case typ < 256:
			toks = append(toks, string(rune(typ)))
		}
	}
	comparison := map[string]bool{"=": true, "<": true, ">": true, "LIKE": true, "IN": true, "IS": true, "BETWEEN": true, "REGEXP": true}
	for i, t := range toks {
		switch t {
		case "AND", "OR", "XOR", "WHERE", "HAVING", "ON":
			for _, u := range toks[i+1 : min(len(toks), i+6)] {
				if comparison[u] {
					return t + " predicate"
				}
			}
		case "ORDER", "GROUP":
			if i+1 < len(toks) && toks[i+1] == "BY" {
				return t + " BY"
			}
		case "LIMIT":
			if i+1 < len(toks) && toks[i+1] == "<NUM>" {
				return "LIMIT"
			}
		case "UNION":
			for _, u := range toks[i+1 : min(len(toks), i+3)] {
				if u == "SELECT" {
					return "UNION SELECT"
				}
			}
		}
	}
	return ""
}

// SecurityMiddleware creates a unified API middleware that rejects blocked
// queries with api.ErrBlockedQuery. Flagged queries proceed. The lexical
// rules follow the driver of the handle the middleware is installed on.
func SecurityMiddleware(engine *SecurityEngine) api.Middleware {
	return func(next api.Handler) api.Handler {
		return func(ctx context.Context, query string, args ...any) (internal.Result, error) {
			d := engine.dialect()
			if drv, ok := internal.DriverFrom(ctx); ok {
				d = parser.DialectOf(drv)
			}
			decision := engine.AnalyzeFor(query, d)
			if decision.Block {
				return nil, fmt.Errorf("%w: %s", api.ErrBlockedQuery, decision.Reason)
			}
			return next(ctx, query, args...)
		}
	}
}
