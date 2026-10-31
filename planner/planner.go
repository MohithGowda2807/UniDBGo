package planner

import "github.com/Dheeran-git/UniDBGo/parser"

// GeneratePlan creates a physical execution plan from an AST
func GeneratePlan(ast *parser.QueryAST) (*ExecutionPlan, error) {
	meta := Analyze(ast)

	if meta.IsMultiDB {
		return planFederatedQuery(ast, meta)
	}

	// Single DB plan: the whole statement is sent to one backend. A database
	// qualifier such as "mysql.orders" names the backend, not a schema, so it
	// is removed from the text; nothing else is rewritten, so literals and
	// dialect-specific syntax reach the backend exactly as written.
	db := "default"
	queryStr := ast.RawQuery
	if len(ast.Tables) > 0 && ast.Tables[0].Database != "" {
		db = ast.Tables[0].Database
		queryStr = parser.StripQualifier(ast.RawQuery, db, ast.Dialect)
	}

	stepType := "SCAN"
	if ast.Type == "DDL" {
		stepType = "DDL"
	} else if ast.Type == "META" {
		stepType = "META"
	}

	plan := &ExecutionPlan{
		Steps: []ExecutionStep{
			{
				ID:       1,
				Type:     stepType,
				Database: db,
				Query:    queryStr,
			},
		},
	}
	return plan, nil
}
