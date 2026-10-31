package parser

import (
	"errors"
	"sync"

	"vitess.io/vitess/go/vt/sqlparser"
)

var (
	ErrUnsupportedQuery = errors.New("unsupported query type")
	ErrInvalidQuery     = errors.New("invalid query AST")
	ErrMultiStatement   = errors.New("query contains more than one statement")
)

// maxCacheEntries bounds the AST cache so that a stream of distinct queries
// cannot grow it without limit. When the bound is reached the cache is reset.
const maxCacheEntries = 10000

// One cache per dialect, keyed by the query text.
var (
	queryCache = map[Dialect]map[string]*QueryAST{}
	cacheMu    sync.RWMutex
)

func getFromCache(d Dialect, query string) (*QueryAST, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	ast, ok := queryCache[d][query]
	return ast, ok
}

func saveToCache(d Dialect, query string, ast *QueryAST) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	m := queryCache[d]
	if m == nil || len(m) >= maxCacheEntries {
		m = make(map[string]*QueryAST)
		queryCache[d] = m
	}
	m[query] = ast
}

func parseInsert(ins *sqlparser.Insert) (*QueryAST, error) {
	ast := &QueryAST{Type: "INSERT"}
	if ins.Table != nil {
		if name, ok := ins.Table.Expr.(sqlparser.TableName); ok {
			addTableName(name, ins.Table.As.String(), ast)
		}
	}
	for _, col := range ins.Columns {
		ast.Fields = append(ast.Fields, FieldNode{Name: col.String()})
	}
	return ast, nil
}

func parseUpdate(upd *sqlparser.Update) (*QueryAST, error) {
	ast := &QueryAST{Type: "UPDATE"}
	for _, t := range upd.TableExprs {
		extractTables(t, ast)
	}
	for _, e := range upd.Exprs {
		ast.Fields = append(ast.Fields, FieldNode{Name: e.Name.Name.String(), Table: e.Name.Qualifier.Name.String()})
	}
	if upd.Where != nil {
		extractConditions(upd.Where.Expr, ast)
	}
	ast.Limit = limitOf(upd.Limit)
	return ast, nil
}

func parseDelete(del *sqlparser.Delete) (*QueryAST, error) {
	ast := &QueryAST{Type: "DELETE"}
	for _, t := range del.TableExprs {
		extractTables(t, ast)
	}
	if del.Where != nil {
		extractConditions(del.Where.Expr, ast)
	}
	ast.Limit = limitOf(del.Limit)
	return ast, nil
}
