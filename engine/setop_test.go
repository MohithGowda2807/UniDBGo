package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/planner"
	"github.com/Dheeran-git/UniDBGo/security"
)

// INTERSECT and EXCEPT queries run on one source with their original text,
// are inspected before they get there, and are not federated.
func TestSetOperationsExecuteOriginalText(t *testing.T) {
	srcs, seen := testSources(t)
	e := &Engine{Sources: srcs, Default: "mysql", Security: security.NewSecurityEngine("api_keys")}
	ctx := context.Background()

	q := "SELECT Status FROM city WHERE Population > 1500 INTERSECT SELECT Status FROM city WHERE Population < 500"
	if _, tr, err := e.Query(ctx, q); err != nil {
		t.Fatalf("benign INTERSECT: %v %+v", err, tr.Decision)
	}
	if got := *seen["mysql"]; len(got) != 1 || got[0] != q {
		t.Fatalf("mysql saw %q, want the original text", got)
	}

	q = `SELECT DISTINCT "zip_code" FROM postgres.weather WHERE note = 'it''s' EXCEPT SELECT DISTINCT zip_code FROM postgres.weather WHERE max_dew_point_f >= $1`
	want := `SELECT DISTINCT "zip_code" FROM weather WHERE note = 'it''s' EXCEPT SELECT DISTINCT zip_code FROM weather WHERE max_dew_point_f >= $1`
	if _, tr, err := e.Query(ctx, q); err != nil {
		t.Fatalf("benign EXCEPT: %v %+v", err, tr.Decision)
	}
	if got := *seen["postgres"]; len(got) != 1 || got[0] != want {
		t.Fatalf("postgres saw %q, want %q", got, want)
	}

	for _, bad := range []string{
		"SELECT name FROM accounts WHERE id = 1 INTERSECT SELECT secret FROM api_keys",
		"SELECT name FROM accounts WHERE id = 1 INTERSECT SELECT 1; DROP TABLE x",
	} {
		if _, _, err := e.Query(ctx, bad); !errors.Is(err, api.ErrBlockedQuery) {
			t.Errorf("%q: want blocked, got %v", bad, err)
		}
	}

	if _, _, err := e.Query(ctx, "SELECT name FROM postgres.a INTERSECT SELECT name FROM mysql.b"); !errors.Is(err, planner.ErrUnsupportedFederation) {
		t.Errorf("federated INTERSECT: want ErrUnsupportedFederation, got %v", err)
	}
	if len(*seen["mysql"]) != 1 || len(*seen["postgres"]) != 1 {
		t.Errorf("rejected queries reached a backend: mysql %q postgres %q", *seen["mysql"], *seen["postgres"])
	}
}
