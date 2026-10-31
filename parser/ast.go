package parser

import "vitess.io/vitess/go/vt/sqlparser"

// QueryAST represents the normalized internal AST
type QueryAST struct {
	Type              string // SELECT, INSERT, UPDATE, DELETE, UNION, DDL, META
	RawQuery          string
	Tables            []TableNode
	Fields            []FieldNode
	Conditions        []ConditionNode
	Joins             []JoinNode
	Limit             *int
	IsNoSQLCompatible bool
	// Dialect records the lexical rules the query was read with.
	Dialect Dialect

	// Stmt is the full Vitess syntax tree the summary above was derived from.
	Stmt sqlparser.Statement `json:"-"`
}

type TableNode struct {
	Name     string
	Database string // postgres, mysql, etc.
	Alias    string
}

type FieldNode struct {
	Name      string
	Table     string
	Alias     string
	Aggregate string // COUNT, SUM, etc.
}

type ConditionNode struct {
	Left     string
	Operator string
	Right    any
}

type JoinNode struct {
	Type       string // INNER, LEFT
	LeftTable  string
	RightTable string
	On         ConditionNode
}
