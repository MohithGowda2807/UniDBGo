package parser

import (
	"vitess.io/vitess/go/vt/sqlparser"
)

func parseDDL(ddl sqlparser.DDLStatement) (*QueryAST, error) {
	ast := &QueryAST{Type: "DDL"}
	for _, t := range ddl.AffectedTables() {
		addTableName(t, "", ast)
	}
	return ast, nil
}
