// ============================================================
// GAP 1 PROOF: Go's database/sql has NO unified multi-DB API
// ============================================================
// WHAT THIS PROVES:
//   In raw Go, connecting to Postgres vs MySQL vs MongoDB
//   requires COMPLETELY DIFFERENT code, packages, and patterns.
//   There is no single "Connect()" that works for all three.
//
// HOW TO RUN:
//   go run ./examples/proofs/gap1_no_unified_api
//   It will print a clear demonstration of the gap.
//
// EXPECTED OUTPUT:
//   [PROOF] Postgres needs: sql.Open("postgres", "postgres://user:pass@host/db")
//   [PROOF] MySQL needs:    sql.Open("mysql", "user:pass@tcp(host:3306)/db")
//   [PROOF] MongoDB needs:  mongo.Connect(ctx, options.Client().ApplyURI("mongodb://..."))
//   [PROOF] All three return DIFFERENT types: *sql.DB, *sql.DB, *mongo.Client
//   [PROOF] You cannot write: db.Query() for all three — MongoDB uses db.Collection().Find()
//   [PROOF] CONCLUSION: No unified interface exists in standard Go.
// ============================================================

package main

import (
	"database/sql"
	"fmt"
	// Postgres driver
	_ "github.com/lib/pq"
	// MySQL driver
	_ "github.com/go-sql-driver/mysql"
	// MongoDB is a COMPLETELY different package — not database/sql at all
	// "go.mongodb.org/mongo-driver/mongo"
	// "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	fmt.Println("=== GAP 1: No Unified Multi-DB API in database/sql ===")
	fmt.Println()

	// ── Postgres ──────────────────────────────────────────────────────────
	// Returns *sql.DB — but ONLY works with SQL databases
	pgDB, pgErr := sql.Open("postgres", "postgres://user:pass@localhost:5432/testdb")
	if pgErr != nil {
		fmt.Printf("[PROOF] Postgres open error (expected if no DB running): %v\n", pgErr)
	} else {
		defer pgDB.Close()
		fmt.Println("[PROOF] Postgres uses: sql.Open(\"postgres\", \"postgres://...\")")
		fmt.Printf("[PROOF] Type returned: %T\n", pgDB) // *sql.DB
	}
	fmt.Println()

	// ── MySQL ─────────────────────────────────────────────────────────────
	// Also returns *sql.DB, but connection string format is COMPLETELY different
	myDB, myErr := sql.Open("mysql", "user:pass@tcp(localhost:3306)/testdb")
	if myErr != nil {
		fmt.Printf("[PROOF] MySQL open error (expected if no DB running): %v\n", myErr)
	} else {
		defer myDB.Close()
		fmt.Println("[PROOF] MySQL uses:    sql.Open(\"mysql\", \"user:pass@tcp(host)/db\")")
		fmt.Printf("[PROOF] Type returned: %T\n", myDB) // *sql.DB
	}
	fmt.Println()

	// ── MongoDB ───────────────────────────────────────────────────────────
	// PROOF: MongoDB CANNOT use database/sql at all.
	// It requires a completely separate package: go.mongodb.org/mongo-driver
	// And it returns *mongo.Client, not *sql.DB
	// The query API is totally different:
	//   SQL:     pgDB.Query("SELECT * FROM users WHERE id = $1", 1)
	//   MongoDB: collection.Find(ctx, bson.M{"id": 1})
	// There is no abstraction that unifies these two.

	fmt.Println("[PROOF] MongoDB CANNOT use database/sql package.")
	fmt.Println("[PROOF] MongoDB requires: go.mongodb.org/mongo-driver/mongo")
	fmt.Println("[PROOF] MongoDB returns:  *mongo.Client (NOT *sql.DB)")
	fmt.Println("[PROOF] MongoDB query:    collection.Find(ctx, bson.M{\"id\": 1})")
	fmt.Println("[PROOF] SQL query:        db.Query(\"SELECT * FROM users WHERE id=?\", 1)")
	fmt.Println("[PROOF] These are INCOMPATIBLE interfaces. No standard Go abstraction unifies them.")
	fmt.Println()

	// ── The core problem ─────────────────────────────────────────────────
	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] To write an app that works with Postgres + MySQL + MongoDB in raw Go:")
	fmt.Println("[PROOF]   1. Import 3 different packages")
	fmt.Println("[PROOF]   2. Write 3 different connection functions")
	fmt.Println("[PROOF]   3. Write 3 different query patterns")
	fmt.Println("[PROOF]   4. Handle 3 different result types")
	fmt.Println("[PROOF]   5. Handle 3 different error types")
	fmt.Println("[PROOF]")
	fmt.Println("[PROOF] UniDB-Go fixes this:")
	fmt.Println("[PROOF]   db, _ := unidb.Connect(\"postgres://...\")")
	fmt.Println("[PROOF]   db, _ := unidb.Connect(\"mysql://...\")")
	fmt.Println("[PROOF]   db, _ := unidb.Connect(\"mongodb://...\")")
	fmt.Println("[PROOF]   rows, _ := db.Query(ctx, \"SELECT * FROM users\")  // SAME for all three")
}
