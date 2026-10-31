package engine

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/security"
)

// TestLiveFederation runs against real servers loaded by "unidb-bench setup".
// Set UNIDB_TEST_PG and UNIDB_TEST_MY to connection URIs to enable it.
func TestLiveFederation(t *testing.T) {
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
	ctx := context.Background()

	res, tr, err := e.Query(ctx, "SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id <= 100 AND o.status = 'paid'")
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Plan.Steps) != 3 {
		t.Fatalf("expected a federated plan, got %+v", tr.Plan.Steps)
	}
	n := 0
	for res.Next() {
		var name, total string
		if err := res.Scan(&name, &total); err != nil {
			t.Fatal(err)
		}
		n++
	}

	// Cross-check against each source directly.
	var want int
	ids := map[int64]bool{}
	r1, _ := pg.Query(ctx, "SELECT id FROM users WHERE id <= 100")
	for r1.Next() {
		var id int64
		r1.Scan(&id)
		ids[id] = true
	}
	r2, _ := my.Query(ctx, "SELECT user_id FROM orders WHERE status = 'paid'")
	for r2.Next() {
		var uid int64
		r2.Scan(&uid)
		if ids[uid] {
			want++
		}
	}
	if n != want {
		t.Errorf("federated join returned %d rows, direct computation %d", n, want)
	}

	if _, _, err := e.Query(ctx, "SELECT name FROM users WHERE id = 1 OR 1=1"); !errors.Is(err, api.ErrBlockedQuery) {
		t.Errorf("expected injection to be blocked, got %v", err)
	}
	if _, err := e.Exec(ctx, "DELETE FROM users WHERE id = 1; DROP TABLE users"); !errors.Is(err, api.ErrBlockedQuery) {
		t.Errorf("expected stacked write to be blocked, got %v", err)
	}
}
