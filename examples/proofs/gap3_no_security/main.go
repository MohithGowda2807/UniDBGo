// ============================================================
// GAP 3 PROOF: database/sql has NO security or injection
//              detection at the framework level.
// ============================================================
// WHAT THIS PROVES:
//   Go's database/sql will execute ANY query you pass it,
//   including SQL injections, bulk data dumps, and time-based
//   attacks. There is no interception, no scanning, no blocking.
//   PreparedStatements help at the driver level but:
//     1. They must be explicitly used by the developer
//     2. They do not detect anomalies or exfiltration
//     3. They cannot be enforced by the framework
//
// HOW TO RUN:
//   go run ./examples/proofs/gap3_no_security
//   (No DB needed — shows the framework gap without connecting)
//
// EXPECTED OUTPUT:
//   Shows that injections pass silently through database/sql
//   vs UniDB-Go's security engine blocking them.
// ============================================================

package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"strings"

	"github.com/Dheeran-git/UniDBGo/security"
)

// ── Simulate what database/sql does with these queries ────────────────────
// database/sql does ZERO analysis. It builds the query and sends it.
// No pattern matching. No AST scan. No logging. No blocking.
func rawGoHandlesQuery(userInput string) {
	// This is EXACTLY what happens in a typical Go web app:
	query := "SELECT * FROM users WHERE id = " + userInput // string concat (bad but common)

	// database/sql does not inspect this. It sends it as-is to the driver.
	// The driver sends it to the database. The database executes it.
	// There is NO layer in between that says "wait, this looks malicious."

	db, err := sql.Open("postgres", "postgres://user:pass@localhost/db")
	if err != nil {
		// Even if the DB isn't running, this proves the point:
		// sql.Open() and db.Query() do ZERO security checks on the query string.
		fmt.Printf("[RAW GO] sql.Open() returned: %v\n", err)
		fmt.Printf("[RAW GO] But it would have sent this query to the DB: %s\n", query)
		fmt.Println("[RAW GO] No scanning. No blocking. No logging. Sent as-is.")
		return
	}
	defer db.Close()

	// This would execute the injection if the DB was running:
	rows, _ := db.Query(query)
	if rows != nil {
		defer rows.Close()
	}
	fmt.Printf("[RAW GO] Query sent to DB with zero inspection: %s\n", query)
}

// ── UniDB-Go's security engine ───────────────────────────────────────────
// The demo calls the real AST-based engine from security/engine.go.

var unidbEngine = security.NewSecurityEngine()

func unidbSecurityEngine(query string) security.Decision {
	return unidbEngine.Analyze(query)
}

func main() {
	fmt.Println("=== GAP 3: database/sql Has NO Security or Injection Detection ===")
	fmt.Println()

	testQueries := []struct {
		label string
		input string
	}{
		{
			"Normal Query (should pass)",
			"1",
		},
		{
			"SQL Injection — OR 1=1 (should block)",
			"1 OR 1=1",
		},
		{
			"Time-based Injection — SLEEP (should block)",
			"1 AND SLEEP(5)",
		},
		{
			"UNION injection (should block)",
			"-1 UNION SELECT username, password FROM users",
		},
		{
			"Data Exfiltration — no LIMIT on users (should flag)",
			"SELECT * FROM users",
		},
	}

	for _, tc := range testQueries {
		fmt.Printf("── Test: %s ─────────────────────────────────\n", tc.label)

		// Show what raw Go does:
		fmt.Printf("[RAW database/sql]:\n")
		rawGoHandlesQuery(tc.input)

		// Show what UniDB-Go does:
		query := "SELECT * FROM users WHERE id = " + tc.input
		if strings.HasPrefix(tc.input, "SELECT") {
			query = tc.input
		}
		decision := unidbSecurityEngine(query)
		if decision.Block {
			fmt.Printf("[UNIDB SecurityEngine]: 🚫 BLOCKED — %s\n", decision.Reason)
		} else if decision.Flag {
			fmt.Printf("[UNIDB SecurityEngine]: ⚠️  FLAGGED — %s\n", decision.Reason)
		} else {
			fmt.Printf("[UNIDB SecurityEngine]: ✅ PASSED — Clean query, proceeding to execution\n")
		}
		fmt.Println()
	}

	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] database/sql provides PreparedStatements as the ONLY defense.")
	fmt.Println("[PROOF] PreparedStatements:")
	fmt.Println("[PROOF]   - Must be explicitly used by every developer (not enforced)")
	fmt.Println("[PROOF]   - Do NOT detect anomalies, exfiltration, or time-based attacks")
	fmt.Println("[PROOF]   - Cannot be composed as middleware — must be in application code")
	fmt.Println("[PROOF]   - Do NOT log or alert on suspicious queries")
	fmt.Println()
	fmt.Println("[PROOF] UniDB-Go's security engine:")
	fmt.Println("[PROOF]   - Works at the FRAMEWORK level — zero changes to app code")
	fmt.Println("[PROOF]   - 3-layer detection: patterns + AST tautology + exfiltration")
	fmt.Println("[PROOF]   - Plugs in as: db.Use(security.SecurityMiddleware(engine))")
	fmt.Println("[PROOF]   - Logs, flags, or blocks — developer configures policy")
}
