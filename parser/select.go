package parser

import (
	"strconv"

	"vitess.io/vitess/go/vt/sqlparser"
)

func parseSelect(sel *sqlparser.Select) (*QueryAST, error) {
	ast := &QueryAST{
		Type: "SELECT",
	}

	// Extract fields
	if sel.SelectExprs != nil {
		for _, expr := range sel.SelectExprs.Exprs {
			switch e := expr.(type) {
			case *sqlparser.AliasedExpr:
				switch subE := e.Expr.(type) {
				case *sqlparser.ColName:
					ast.Fields = append(ast.Fields, FieldNode{
						Name:  subE.Name.String(),
						Table: subE.Qualifier.Name.String(),
						Alias: e.As.String(),
					})
				case *sqlparser.FuncExpr:
					ast.Fields = append(ast.Fields, FieldNode{
						Name:      sqlparser.String(subE),
						Aggregate: subE.Name.String(),
						Alias:     e.As.String(),
					})
				default:
					field := FieldNode{Name: sqlparser.String(subE), Alias: e.As.String()}
					if agg, ok := subE.(sqlparser.AggrFunc); ok {
						field.Aggregate = agg.AggrName()
					}
					ast.Fields = append(ast.Fields, field)
				}
			case *sqlparser.StarExpr:
				ast.Fields = append(ast.Fields, FieldNode{
					Name:  "*",
					Table: e.TableName.Name.String(),
				})
			}
		}
	}

	// Extract tables
	for _, from := range sel.From {
		extractTables(from, ast)
	}

	// Conditions
	if sel.Where != nil {
		extractSubqueries(sel.Where.Expr, ast)
		extractConditions(sel.Where.Expr, ast)
	}

	ast.Limit = limitOf(sel.Limit)

	// A single-table query with only conjunctive comparisons can be expressed
	// as a document-store find command.
	ast.IsNoSQLCompatible = len(ast.Tables) == 1 && len(ast.Joins) == 0 &&
		sel.GroupBy == nil && sel.Having == nil &&
		(sel.Where == nil || isConjunctive(sel.Where.Expr))

	return ast, nil
}

// parseUnion summarises every SELECT branch of a UNION into one QueryAST.
func parseUnion(u *sqlparser.Union) (*QueryAST, error) {
	ast := &QueryAST{Type: "UNION"}
	var walk func(sqlparser.TableStatement)
	walk = func(s sqlparser.TableStatement) {
		switch n := s.(type) {
		case *sqlparser.Select:
			sub, _ := parseSelect(n)
			for _, t := range sub.Tables {
				addTable(t, ast)
			}
			ast.Fields = append(ast.Fields, sub.Fields...)
			ast.Conditions = append(ast.Conditions, sub.Conditions...)
		case *sqlparser.Union:
			walk(n.Left)
			walk(n.Right)
		}
	}
	walk(u)
	ast.Limit = limitOf(u.Limit)
	return ast, nil
}

// limitOf returns the row count of a LIMIT clause, or nil when there is none.
// Bind variables yield -1 (bounded, value unknown until execution).
func limitOf(l *sqlparser.Limit) *int {
	if l == nil || l.Rowcount == nil {
		return nil
	}
	n := -1
	if v, ok := l.Rowcount.(*sqlparser.Literal); ok && v.Type == sqlparser.IntVal {
		if parsed, err := strconv.Atoi(v.Val); err == nil {
			n = parsed
		}
	}
	return &n
}

// extractConditions records every comparison reachable through AND.
func extractConditions(expr sqlparser.Expr, ast *QueryAST) {
	switch e := expr.(type) {
	case *sqlparser.AndExpr:
		extractConditions(e.Left, ast)
		extractConditions(e.Right, ast)
	case *sqlparser.ComparisonExpr:
		ast.Conditions = append(ast.Conditions, ConditionNode{
			Left:     sqlparser.String(e.Left),
			Operator: e.Operator.ToString(),
			Right:    sqlparser.String(e.Right),
		})
	}
}

func isConjunctive(expr sqlparser.Expr) bool {
	switch e := expr.(type) {
	case *sqlparser.AndExpr:
		return isConjunctive(e.Left) && isConjunctive(e.Right)
	case *sqlparser.ComparisonExpr:
		return true
	}
	return false
}

// extractSubqueries records the tables read by sub-queries in a predicate.
func extractSubqueries(expr sqlparser.Expr, ast *QueryAST) {
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		if sq, ok := node.(*sqlparser.Subquery); ok {
			if sel, ok := sq.Select.(*sqlparser.Select); ok {
				for _, from := range sel.From {
					extractTables(from, ast)
				}
			}
		}
		return true, nil
	}, expr)
}

func addTable(t TableNode, ast *QueryAST) {
	for _, existing := range ast.Tables {
		if existing.Name == t.Name && existing.Database == t.Database {
			return
		}
	}
	ast.Tables = append(ast.Tables, t)
}

func addTableName(te sqlparser.TableName, alias string, ast *QueryAST) {
	addTable(TableNode{
		Database: te.Qualifier.String(),
		Name:     te.Name.String(),
		Alias:    alias,
	}, ast)
}

func extractTables(expr sqlparser.TableExpr, ast *QueryAST) {
	switch t := expr.(type) {
	case *sqlparser.AliasedTableExpr:
		switch te := t.Expr.(type) {
		case sqlparser.TableName:
			if te.Qualifier.IsEmpty() && te.Name.String() == "dual" {
				return // SELECT without FROM
			}
			addTableName(te, t.As.String(), ast)
		case *sqlparser.DerivedTable:
			if sel, ok := te.Select.(*sqlparser.Select); ok {
				for _, from := range sel.From {
					extractTables(from, ast)
				}
			}
		}
	case *sqlparser.ParenTableExpr:
		for _, e := range t.Exprs {
			extractTables(e, ast)
		}
	case *sqlparser.JoinTableExpr:
		joinNode := JoinNode{
			Type: t.Join.ToString(),
		}

		if left, ok := t.LeftExpr.(*sqlparser.AliasedTableExpr); ok {
			joinNode.LeftTable = left.As.String()
			if joinNode.LeftTable == "" {
				if te, ok := left.Expr.(sqlparser.TableName); ok {
					joinNode.LeftTable = te.Name.String()
				}
			}
		}

		if right, ok := t.RightExpr.(*sqlparser.AliasedTableExpr); ok {
			joinNode.RightTable = right.As.String()
			if joinNode.RightTable == "" {
				if te, ok := right.Expr.(sqlparser.TableName); ok {
					joinNode.RightTable = te.Name.String()
				}
			}
		}

		if t.Condition != nil && t.Condition.On != nil {
			if comp, ok := t.Condition.On.(*sqlparser.ComparisonExpr); ok {
				joinNode.On = ConditionNode{
					Left:     sqlparser.String(comp.Left),
					Operator: comp.Operator.ToString(),
					Right:    sqlparser.String(comp.Right),
				}
			}
		}

		ast.Joins = append(ast.Joins, joinNode)

		extractTables(t.LeftExpr, ast)
		extractTables(t.RightExpr, ast)
	}
}
