package parser

import "vitess.io/vitess/go/vt/sqlparser"

// QueryAST represents the normalized internal AST
type QueryAST struct {
	Type              string // SELECT, INSERT, UPDATE, DELETE, UNION (any set operation), DDL, META
	RawQuery          string
	Tables            []TableNode
	Fields            []FieldNode
	Conditions        []ConditionNode
	Joins             []JoinNode
	Limit             *int
	IsNoSQLCompatible bool
	// Dialect records the lexical rules the query was read with.
	Dialect Dialect

	// SetOps lists the top-level set operators of a query that uses
	// INTERSECT or EXCEPT, in text order, e.g. ["UNION", "EXCEPT ALL"]; it is
	// nil otherwise. Such a query has Type "UNION" and its Stmt is a
	// synthetic *sqlparser.Union chaining the operands, built because the
	// grammar lacks these operators: every operand is inspected like a UNION
	// branch, but the tree does not follow SQL precedence and renders the
	// operators as UNION, so it must never be turned back into SQL. RawQuery
	// is what executes.
	SetOps []string `json:",omitempty"`

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
