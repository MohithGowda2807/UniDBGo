package parser

import (
	"errors"
	"fmt"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

// vparser is the Vitess parser, configured for the MySQL 8.0 grammar.
var vparser = func() *sqlparser.Parser {
	p, err := sqlparser.New(sqlparser.Options{MySQLServerVersion: "8.0.40"})
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
func StatementsFor(query string, d Dialect) ([]sqlparser.Statement, error) {
	pieces, err := vparser.SplitStatementToPieces(Normalize(query, d))
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	var stmts []sqlparser.Statement
	for _, piece := range pieces {
		// Strict: never accept a DDL statement with unparsed trailing text.
		stmt, err := vparser.ParseStrictDDL(piece)
		if errors.Is(err, sqlparser.ErrEmpty) {
			continue // only whitespace or comments
		}
		if err != nil {
			return stmts, fmt.Errorf("parse error: %w", err)
		}
		stmts = append(stmts, stmt)
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

	stmts, err := StatementsFor(query, d)
	if len(stmts) > 1 || (err != nil && len(stmts) == 1) {
		// A second statement follows the first, whether or not it parses.
		return nil, ErrMultiStatement
	}
	if err != nil {
		return nil, err
	}
	stmt := stmts[0]

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
	ast.Dialect = d

	saveToCache(d, query, ast)

	return ast, nil
}
