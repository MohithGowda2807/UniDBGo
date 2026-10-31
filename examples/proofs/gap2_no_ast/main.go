// ============================================================
// GAP 2 PROOF: database/sql treats queries as OPAQUE STRINGS
//              It has zero query introspection or AST parsing.
// ============================================================
// WHAT THIS PROVES:
//   In raw Go, you cannot inspect WHAT is inside a query.
//   You cannot extract which tables it touches, what columns
//   it reads, whether it has a WHERE clause, or whether it
//   spans multiple databases. The query is just a plain string.
//
// HOW TO RUN:
//   go run ./examples/proofs/gap2_no_ast
//
// EXPECTED OUTPUT:
//   Shows that all attempts to inspect a query in raw Go
//   result in: "I don't know. It's just a string."
// ============================================================

package main

import (
	"fmt"
	"strings"
)

// This is ALL raw Go gives you to "inspect" a query — manual string parsing.
// No AST, no structure, no guarantees. This breaks on any complex query.
func rawGoQueryInspection(query string) {
	fmt.Println("[RAW GO] Inspecting query:", query)

	// The ONLY thing you can do in raw Go is string operations.
	// No AST. No structure. No semantic understanding.

	upper := strings.ToUpper(query)

	// "Does it have a WHERE clause?" — fragile string search
	if strings.Contains(upper, "WHERE") {
		fmt.Println("[RAW GO]   Has WHERE clause: maybe? (string search — unreliable)")
	}

	// "Which table does it query?" — completely unreliable
	// What if table name is in a subquery? What if aliased? What if it's a CTE?
	fmt.Println("[RAW GO]   Which table? → Cannot determine reliably from a string.")
	fmt.Println("[RAW GO]   Is it multi-DB? → Cannot determine at all.")
	fmt.Println("[RAW GO]   Is it a JOIN? → Cannot determine semantically.")
	fmt.Println("[RAW GO]   What columns does it read? → Cannot determine.")
	fmt.Println()
}

// This is what UniDB-Go gives you — a structured AST.
// (Simulated here to show the contrast — real impl uses Vitess parser)
type QueryAST struct {
	Type      string
	Tables    []TableNode
	Fields    []string
	HasJoin   bool
	IsMultiDB bool
	HasLimit  bool
}
type TableNode struct {
	Name     string
	Database string
}

func unidbQueryParsing(query string) QueryAST {
	// In UniDB-Go, the Vitess parser produces this structured output.
	// For demo purposes we return a hardcoded result showing what the parser extracts.
	_ = query
	return QueryAST{
		Type: "SELECT",
		Tables: []TableNode{
			{Name: "users", Database: "postgres"},
			{Name: "orders", Database: "mysql"},
		},
		Fields:    []string{"u.name", "o.total"},
		HasJoin:   true,
		IsMultiDB: true, // ← THIS is what triggers the federation engine
		HasLimit:  false,
	}
}

func main() {
	fmt.Println("=== GAP 2: database/sql Has NO SQL Parser / AST ===")
	fmt.Println()

	query := `SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.city = 'Bengaluru'`

	// ── What raw Go can do ────────────────────────────────────────────────
	fmt.Println("── What raw database/sql can do with this query: ──────────────────────")
	rawGoQueryInspection(query)

	// The PROOF: database/sql source code literally does this:
	// func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*Rows, error) {
	//     ...
	//     return db.query(ctx, query, driverArgsConnLocked(dc.ci, nil, args), cachedOrNewConn)
	// }
	// It passes the query string DIRECTLY to the driver. No inspection. No parsing.
	// Source: https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/database/sql/sql.go
	fmt.Println("[PROOF] database/sql passes the query string DIRECTLY to the driver.")
	fmt.Println("[PROOF] No parsing. No structure. No understanding. Just a string.")
	fmt.Println("[PROOF] See: golang.org/src/database/sql/sql.go — QueryContext()")
	fmt.Println()

	// ── What UniDB-Go can do ──────────────────────────────────────────────
	fmt.Println("── What UniDB-Go can do with the SAME query: ──────────────────────────")
	ast := unidbQueryParsing(query)
	fmt.Printf("[UNIDB]   Query Type:  %s\n", ast.Type)
	fmt.Printf("[UNIDB]   Tables:      %v (with DB names extracted)\n", ast.Tables)
	fmt.Printf("[UNIDB]   Fields:      %v\n", ast.Fields)
	fmt.Printf("[UNIDB]   Has JOIN:    %v\n", ast.HasJoin)
	fmt.Printf("[UNIDB]   IsMultiDB:   %v  ← triggers federation engine automatically\n", ast.IsMultiDB)
	fmt.Printf("[UNIDB]   Has LIMIT:   %v  ← if false on sensitive table → security flag\n", ast.HasLimit)
	fmt.Println()

	// ── The consequence ───────────────────────────────────────────────────
	fmt.Println("── CONSEQUENCE of no AST in raw Go: ───────────────────────────────────")
	fmt.Println("[PROOF] Without AST:")
	fmt.Println("[PROOF]   → Cannot detect cross-DB queries → federation impossible")
	fmt.Println("[PROOF]   → Cannot detect tautologies like OR 1=1 → security impossible")
	fmt.Println("[PROOF]   → Cannot detect missing LIMIT on sensitive tables → exfiltration undetectable")
	fmt.Println("[PROOF]   → Cannot optimize (push filters down, prune columns)")
	fmt.Println("[PROOF]   → ALL of UniDB-Go's intelligence depends on this AST layer.")
	fmt.Println()
	fmt.Println("[PROOF] UniDB-Go uses the Vitess SQL parser (go.mod: vitess.io/vitess)")
	fmt.Println("[PROOF] Same parser used by YouTube/Vitess — production-grade AST for Go.")
}
