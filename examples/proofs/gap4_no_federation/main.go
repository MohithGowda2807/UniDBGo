// ============================================================
// GAP 4 PROOF: database/sql CANNOT do cross-database queries.
//              Joining data from Postgres + MySQL requires
//              60+ lines of manual boilerplate in raw Go.
// ============================================================
// WHAT THIS PROVES:
//   Standard Go provides NO mechanism to write a single query
//   that reads from both PostgreSQL and MySQL simultaneously.
//   The developer must manually connect to both, query both,
//   load everything into memory, and write their own join logic.
//   UniDB-Go automates this entirely.
//
// HOW TO RUN:
//   go run ./examples/proofs/gap4_no_federation
//   (Runs without DB connections to demonstrate the code complexity gap)
// ============================================================

package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// ── BEFORE: What raw Go forces you to write ──────────────────────────────
// This is the ACTUAL code a developer must write to join
// users (Postgres) with orders (MySQL) in standard Go.
// Count the lines. Count the complexity.

type User struct {
	ID   int
	Name string
	City string
}

type Order struct {
	UserID int
	Total  float64
}

type JoinedResult struct {
	Name  string
	Total float64
}

func rawGoJoinAcrossDatabases() ([]JoinedResult, error) {
	fmt.Println("[RAW GO] Step 1: Open Postgres connection separately")
	pgDB, err := sql.Open("postgres", "postgres://user:pass@localhost:5432/appdb?sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	defer pgDB.Close()

	fmt.Println("[RAW GO] Step 2: Open MySQL connection separately (different package, different DSN format)")
	myDB, err := sql.Open("mysql", "user:pass@tcp(localhost:3306)/shopdb")
	if err != nil {
		return nil, fmt.Errorf("mysql open: %w", err)
	}
	defer myDB.Close()

	fmt.Println("[RAW GO] Step 3: Query Postgres — FIRST round trip")
	pgRows, err := pgDB.Query("SELECT id, name, city FROM users WHERE city = $1", "Bengaluru")
	if err != nil {
		return nil, fmt.Errorf("postgres query: %w", err)
	}
	defer pgRows.Close()

	fmt.Println("[RAW GO] Step 4: Manually scan ALL Postgres rows into memory")
	var users []User
	for pgRows.Next() {
		var u User
		if err := pgRows.Scan(&u.ID, &u.Name, &u.City); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := pgRows.Err(); err != nil {
		return nil, err
	}

	fmt.Println("[RAW GO] Step 5: Query MySQL — SECOND round trip")
	myRows, err := myDB.Query("SELECT user_id, total FROM orders WHERE status = ?", "paid")
	if err != nil {
		return nil, fmt.Errorf("mysql query: %w", err)
	}
	defer myRows.Close()

	fmt.Println("[RAW GO] Step 6: Manually scan ALL MySQL rows into memory")
	var orders []Order
	for myRows.Next() {
		var o Order
		if err := myRows.Scan(&o.UserID, &o.Total); err != nil {
			return nil, err
		}
		orders = append(orders, o)
	}
	if err := myRows.Err(); err != nil {
		return nil, err
	}

	fmt.Println("[RAW GO] Step 7: Write join logic BY HAND — nested loop O(n*m)")
	fmt.Println("[RAW GO]         No parallelism. Sequential. No optimization.")
	var results []JoinedResult
	for _, u := range users {
		for _, o := range orders { // O(n*m) — terrible for large datasets
			if u.ID == o.UserID {
				results = append(results, JoinedResult{
					Name:  u.Name,
					Total: o.Total,
				})
			}
		}
	}

	fmt.Println("[RAW GO] Step 8: Return results after 7 manual steps and ~60 lines of code")
	return results, nil
}

// ── AFTER: What UniDB-Go gives you ───────────────────────────────────────
// This is the ACTUAL UniDB-Go code for the same operation.
// (Simulated here — actual execution requires UniDB-Go running)

func unidbJoin() {
	fmt.Println("[UNIDB] ONE query. Zero boilerplate. Automatic.")
	fmt.Println()
	fmt.Println("[UNIDB] db.Query(ctx, `")
	fmt.Println(`[UNIDB]     SELECT u.name, o.total`)
	fmt.Println(`[UNIDB]     FROM postgres.users u`)
	fmt.Println(`[UNIDB]     JOIN mysql.orders o ON u.id = o.user_id`)
	fmt.Println(`[UNIDB]     WHERE u.city = 'Bengaluru'`)
	fmt.Println("[UNIDB] `)")
	fmt.Println()
	fmt.Println("[UNIDB] Internally UniDB-Go:")
	fmt.Println("[UNIDB]   1. Parser detects IsMultiDB = true (postgres.users + mysql.orders)")
	fmt.Println("[UNIDB]   2. Planner splits into: SCAN postgres → SCAN mysql → JOIN")
	fmt.Println("[UNIDB]   3. Federation engine runs both SCANs IN PARALLEL (goroutines)")
	fmt.Println("[UNIDB]   4. Hash join merges results in O(n+m) instead of O(n*m)")
	fmt.Println("[UNIDB]   5. Returns unified []Row to caller")
	fmt.Println("[UNIDB]   Total app code: 5 lines.")
}

func main() {
	fmt.Println("=== GAP 4: database/sql CANNOT Do Cross-Database Federation ===")
	fmt.Println()

	fmt.Println("── RAW GO: Joining postgres.users + mysql.orders ─────────────────────")
	fmt.Println("── (Showing code flow — no DB running, so connections will fail) ──────")
	fmt.Println()

	results, err := rawGoJoinAcrossDatabases()
	if err != nil {
		fmt.Printf("[RAW GO] Failed at: %v\n", err)
		fmt.Println("[RAW GO] Even though it failed, you saw 7 manual steps to write.")
	} else {
		fmt.Printf("[RAW GO] Got %d results after 7 manual steps.\n", len(results))
	}

	fmt.Println()
	fmt.Println("── UNIDB-GO: Same operation ─────────────────────────────────────────")
	unidbJoin()

	fmt.Println()
	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] Raw Go cross-DB join:")
	fmt.Println("[PROOF]   - 2 separate connections (different DSN formats)")
	fmt.Println("[PROOF]   - 2 separate queries (different placeholder syntax: $1 vs ?)")
	fmt.Println("[PROOF]   - Manual row scanning into structs")
	fmt.Println("[PROOF]   - Manual join logic in Go code")
	fmt.Println("[PROOF]   - Sequential execution (no parallelism)")
	fmt.Println("[PROOF]   - O(n*m) nested loop join (inefficient)")
	fmt.Println("[PROOF]   - ~60 lines of boilerplate for a 3-line SQL concept")
	fmt.Println()
	fmt.Println("[PROOF] UniDB-Go:")
	fmt.Println("[PROOF]   - 1 query, 1 API call")
	fmt.Println("[PROOF]   - Parallel execution via goroutines")
	fmt.Println("[PROOF]   - O(n+m) hash join")
	fmt.Println("[PROOF]   - 5 lines of application code")
}
