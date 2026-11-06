package parser

import (
	"errors"
	"fmt"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

// vparser is the Vitess parser, configured for the MySQL 8.0 grammar.
// analysisServerVersion is the MySQL version the tokenizer assumes when it
// decides whether the body of a versioned comment /*!NNNNN ... */ is code.
// MySQL executes the body when NNNNN is at most its own version, so a parser
// pinned to an older version than the server skips code the server runs
// (/*!80046 OR 1=1 */ against MySQL 8.0.46). The highest representable
// version treats every versioned comment as code, whatever the server.
const analysisServerVersion = "9.99.99"

var vparser = func() *sqlparser.Parser {
	p, err := sqlparser.New(sqlparser.Options{MySQLServerVersion: analysisServerVersion})
	if err != nil {
		panic(err)
	}
	return p
}()

// Statements is StatementsFor with MySQL lexical rules.
func Statements(query string) ([]sqlparser.Statement, error) {
	return StatementsFor(query, MySQL)
}

// StatementsFor parses every statement contained in query, reading it with
// the lexical rules of d. Unlike Parse it does not stop at the first
// semicolon, so callers can detect stacked (piggy-backed) statements. If a
// later statement fails to parse, the statements before it are returned with
// the error.
//
// A statement using INTERSECT or EXCEPT, which the grammar lacks, is returned
// as a *sqlparser.Union chaining its operands (see parseSetOperation). That
// tree is for inspection only: it must never be rendered back to SQL.
func StatementsFor(query string, d Dialect) ([]sqlparser.Statement, error) {
	parsed, err := statementsFor(query, d)
	var stmts []sqlparser.Statement
	for _, p := range parsed {
		stmts = append(stmts, p.stmt)
	}
	return stmts, err
}

// parsedStatement is one statement of a query with the INTERSECT / EXCEPT
// operators it was split at, if any (see QueryAST.SetOps).
type parsedStatement struct {
	stmt   sqlparser.Statement
	setOps []string
}

func statementsFor(query string, d Dialect) ([]parsedStatement, error) {
	pieces, err := vparser.SplitStatementToPieces(Normalize(query, d))
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	var stmts []parsedStatement
	for _, piece := range pieces {
		// Strict: never accept a DDL statement with unparsed trailing text.
		stmt, err := vparser.ParseStrictDDL(piece)
		if errors.Is(err, sqlparser.ErrEmpty) {
			continue // only whitespace or comments
		}
		if err != nil {
			setOp, ops, ok := parseSetOperation(piece)
			if !ok {
				return stmts, fmt.Errorf("parse error: %w", err)
			}
			stmts = append(stmts, parsedStatement{stmt: setOp, setOps: ops})
			continue
		}
		stmts = append(stmts, parsedStatement{stmt: stmt})
	}
	if len(stmts) == 0 {
		return nil, fmt.Errorf("no valid SQL statement found")
	}
	return stmts, nil
}

// NewTokenizer returns a Vitess tokenizer over sql.
func NewTokenizer(sql string) *sqlparser.Tokenizer { return vparser.NewStringTokenizer(sql) }

// ParseExprSQL parses a single SQL expression.
func ParseExprSQL(sql string) (sqlparser.Expr, error) { return vparser.ParseExpr(sql) }

// Parse is ParseFor with MySQL lexical rules.
func Parse(query string) (*QueryAST, error) {
	return ParseFor(query, MySQL)
}

// ParseFor converts a raw SQL string into an internal QueryAST, reading it
// with the lexical rules of the target dialect. A query holding more than
// one statement is rejected with ErrMultiStatement. Results are cached and
// shared, so callers must not modify the returned tree.
func ParseFor(query string, d Dialect) (*QueryAST, error) {
	if ast, ok := getFromCache(d, query); ok {
		return ast, nil
	}

	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("no valid SQL statement found")
	}

	stmts, err := statementsFor(query, d)
	if len(stmts) > 1 || (err != nil && len(stmts) == 1) {
		// A second statement follows the first, whether or not it parses.
		return nil, ErrMultiStatement
	}
	if err != nil {
		return nil, err
	}
	stmt := stmts[0].stmt

	var ast *QueryAST

	switch node := stmt.(type) {
	case *sqlparser.Select:
		ast, err = parseSelect(node)
	case *sqlparser.Union:
		ast, err = parseUnion(node)
	case *sqlparser.Insert:
		ast, err = parseInsert(node)
	case *sqlparser.Update:
		ast, err = parseUpdate(node)
	case *sqlparser.Delete:
		ast, err = parseDelete(node)
	case sqlparser.DDLStatement:
		ast, err = parseDDL(node)
	case sqlparser.DBDDLStatement:
		ast = &QueryAST{Type: "DDL"}
	case *sqlparser.Show, *sqlparser.Use, *sqlparser.Set, *sqlparser.Begin,
		*sqlparser.Commit, *sqlparser.Rollback, *sqlparser.ExplainStmt, *sqlparser.ExplainTab:
		ast = &QueryAST{Type: "META"}
	default:
		return nil, ErrUnsupportedQuery
	}

	if err != nil {
		return nil, err
	}

	// SELECT without FROM (e.g. "SELECT 1") is valid and targets no table.
	if len(ast.Tables) == 0 && ast.Type != "DDL" && ast.Type != "META" && ast.Type != "SELECT" && ast.Type != "UNION" {
		return nil, ErrInvalidQuery
	}

	ast.RawQuery = query
	ast.Stmt = stmt
	ast.SetOps = stmts[0].setOps
	ast.Dialect = d

	saveToCache(d, query, ast)

	return ast, nil
}
