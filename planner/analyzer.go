package planner

import "github.com/Dheeran-git/UniDBGo/parser"

// Analyze inspects AST to determine query characteristics
func Analyze(ast *parser.QueryAST) QueryMetadata {
	meta := QueryMetadata{
		Tables:  ast.Tables,
		Filters: ast.Conditions,
		HasJoin: len(ast.Joins) > 0,
	}

	if len(ast.Tables) > 1 {
		// Check if multiple databases are used
		firstDB := ast.Tables[0].Database
		for _, tbl := range ast.Tables {
			if tbl.Database != "" && tbl.Database != firstDB {
				meta.IsMultiDB = true
				break
			}
		}
	}

	return meta
}
