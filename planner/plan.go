package planner

import "github.com/Dheeran-git/UniDBGo/parser"

// ExecutionPlan represents physical execution steps
type ExecutionPlan struct {
	Steps []ExecutionStep
	// Projection lists the output columns of a federated query as
	// "alias.column" (or "alias.*" / "*"); Labels holds the matching output
	// names ("" keeps the column reference, otherwise the AS alias).
	Projection []string `json:",omitempty"`
	Labels     []string `json:",omitempty"`
}

// ExecutionStep is an individual query or operation to perform
type ExecutionStep struct {
	ID       int
	Type     string // "SCAN", "JOIN", "DDL", "META"
	Database string
	Query    string
	// Args are bind values for Query. Federated scans are rendered with
	// MySQL-style identifiers and :vN placeholders; the executor adapts both
	// to the target dialect.
	Args      []any `json:",omitempty"`
	DependsOn []int

	// Alias qualifies the columns a SCAN step produces in a federated plan.
	Alias string `json:",omitempty"`
	// LeftKey and RightKey are the qualified equi-join columns of a JOIN step.
	LeftKey  string `json:",omitempty"`
	RightKey string `json:",omitempty"`
}

// QueryMetadata is the logical info extracted by analyzer
type QueryMetadata struct {
	Tables    []parser.TableNode
	IsMultiDB bool
	HasJoin   bool
	Filters   []parser.ConditionNode
}
