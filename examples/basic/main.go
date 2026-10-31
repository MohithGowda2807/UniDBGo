// Command basic shows a UniDB-Go handle with security and metrics middleware.
//
//	UNIDB_PG=postgres://postgres:pass@127.0.0.1:5432/unidb go run ./examples/basic
//
// It expects the users table created by "go run ./cmd/unidb-bench setup".
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/metrics"
	"github.com/Dheeran-git/UniDBGo/security"
)

func main() {
	uri := os.Getenv("UNIDB_PG")
	if uri == "" {
		uri = "postgres://postgres:pass@127.0.0.1:5432/unidb"
	}
	db, err := api.Connect(uri, api.WithMaxPool(20))
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer db.Close()

	// Middleware runs in the order it is added, for Query, Exec and transactions.
	db.Use(security.SecurityMiddleware(security.NewSecurityEngine()))
	db.Use(metrics.MetricsMiddleware())

	ctx := context.Background()

	// A normal parameterised query succeeds.
	res, err := db.Query(ctx, "SELECT id, name FROM users WHERE id = $1", 1)
	if err != nil {
		log.Fatalf("query failed: %v", err)
	}
	for res.Next() {
		var id int64
		var name string
		if err := res.Scan(&id, &name); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("user %d: %s\n", id, name)
	}
	if err := res.Err(); err != nil {
		log.Fatal(err)
	}
	res.Close()

	// An injected tautology is blocked before it reaches PostgreSQL.
	_, err = db.Query(ctx, "SELECT * FROM users WHERE id = 1 OR 1=1")
	if errors.Is(err, api.ErrBlockedQuery) {
		fmt.Println("blocked:", err)
	}

	// Constraint violations are portable across drivers.
	_, err = db.Exec(ctx, "INSERT INTO users (id, name, email, country, age) VALUES (1, 'x', 'x', 'IN', 1)")
	if errors.Is(err, api.ErrUniqueViolation) {
		fmt.Println("duplicate key detected via api.ErrUniqueViolation")
	}

	s := metrics.Default.Snapshot()
	fmt.Printf("metrics: %d queries, %d errors, mean %v\n", s.Queries, s.Errors, s.Mean)
}
