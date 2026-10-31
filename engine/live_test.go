package engine

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/security"
)

// liveEngine connects to the servers named by UNIDB_TEST_PG / UNIDB_TEST_MY,
// loaded by "unidb-bench setup", or skips the test.
func liveEngine(t *testing.T) *Engine {
	t.Helper()
	pgURI, myURI := os.Getenv("UNIDB_TEST_PG"), os.Getenv("UNIDB_TEST_MY")
	if pgURI == "" || myURI == "" {
		t.Skip("UNIDB_TEST_PG / UNIDB_TEST_MY not set")
	}
	pg, err := api.Connect(pgURI)
	if err != nil {
		t.Fatal(err)
	}
	my, err := api.Connect(myURI)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Sources: map[string]*api.DB{"postgres": pg, "mysql": my}, Default: "postgres", Security: security.NewSecurityEngine()}
	t.Cleanup(func() { e.Close() })
	return e
}

func count(t *testing.T, res internal.Result, err error) int {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	n := 0
	for res.Next() {
		n++
	}
	if err := res.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

// Payloads that are harmless literals for MySQL but attacks for PostgreSQL,
// whose strings do not treat backslash as an escape.
func TestLivePostgresLexicalAttacks(t *testing.T) {
	e := liveEngine(t)
	ctx := context.Background()
	for _, q := range []string{
		`SELECT id FROM users WHERE name = '\' OR 1=1 -- '`,
		`SELECT id FROM users WHERE name = '\'; DROP TABLE users; --'`,
	} {
		if _, _, err := e.Query(ctx, q); !errors.Is(err, api.ErrBlockedQuery) {
			t.Errorf("%s: expected a block, got %v", q, err)
		}
	}
	// A doubled quote is an ordinary literal and must reach PostgreSQL intact,
	// not be re-escaped into a stacked statement.
	res, _, err := e.Query(ctx, "SELECT id FROM postgres.users WHERE name = 'x''; DROP TABLE users; --'")
	if n := count(t, res, err); n != 0 {
		t.Errorf("literal matched %d rows", n)
	}
	res, _, err = e.Query(ctx, "SELECT id FROM postgres.users ORDER BY id LIMIT 3 OFFSET 2")
	if n := count(t, res, err); n != 3 {
		t.Errorf("LIMIT/OFFSET returned %d rows", n)
	}
	res, _, err = e.Query(ctx, `SELECT count(*) FROM users WHERE name LIKE 'user1\_%' OR "name" = 'C:\x'`)
	if n := count(t, res, err); n != 1 {
		t.Errorf("PostgreSQL-specific syntax: %d rows", n)
	}
}

func TestLivePortableErrors(t *testing.T) {
	e := liveEngine(t)
	ctx := context.Background()
	for _, q := range []string{
		"INSERT INTO postgres.users (id, name, email, country, age) VALUES (1, 'dup', 'd', 'IN', 30)",
		"INSERT INTO mysql.orders (id, user_id, total, status) VALUES (1, 1, 1, 'paid')",
	} {
		_, err := e.Exec(ctx, q)
		if !errors.Is(err, api.ErrUniqueViolation) {
			t.Errorf("%s: expected ErrUniqueViolation, got %v", q, err)
		}
	}
}

func TestLiveReadOnlyTransaction(t *testing.T) {
	e := liveEngine(t)
	ctx := context.Background()
	tx, err := e.Sources["postgres"].BeginTx(ctx, &api.TxOptions{ReadOnly: true, Isolation: "serializable"})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(ctx, "UPDATE users SET age = age WHERE id = 1"); err == nil {
		t.Error("write succeeded inside a read-only transaction")
	}
}

func TestLiveFederatedScansUseMiddleware(t *testing.T) {
	e := liveEngine(t)
	var mu sync.Mutex // the two scans run concurrently
	seen := map[string]int{}
	for name, db := range e.Sources {
		name := name
		db.Use(func(next api.Handler) api.Handler {
			return func(ctx context.Context, q string, a ...any) (internal.Result, error) {
				mu.Lock()
				seen[name]++
				mu.Unlock()
				return next(ctx, q, a...)
			}
		})
	}
	res, _, err := e.Query(context.Background(),
		"SELECT u.Name AS customer, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id <= 50 AND o.status = 'it''s paid'")
	count(t, res, err)
	if seen["postgres"] != 1 || seen["mysql"] != 1 {
		t.Errorf("middleware saw %v, want one scan per source", seen)
	}
	if cols := res.Columns(); cols[0] != "customer" {
		t.Errorf("alias not applied: %v", cols)
	}
}
