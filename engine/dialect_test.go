package engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/planner"
	"github.com/Dheeran-git/UniDBGo/router"
	"github.com/Dheeran-git/UniDBGo/security"
)

// recConn records every statement it receives.
type recConn struct {
	nopConn
	mu   *sync.Mutex
	seen *[]string
}

func (c recConn) Query(_ context.Context, q string, _ ...any) (internal.Result, error) {
	c.mu.Lock()
	*c.seen = append(*c.seen, q)
	c.mu.Unlock()
	return nopResult{}, nil
}

type recDriver struct{ conn recConn }

func (d recDriver) Connect(internal.Config) (internal.Connection, error) { return d.conn, nil }
func (recDriver) Capabilities() internal.Capabilities                    { return internal.Capabilities{} }

// fixedRouter sends every step to one database.
type fixedRouter string

func (r fixedRouter) Route(p *planner.ExecutionPlan) ([]router.Route, error) {
	var out []router.Route
	for _, s := range p.Steps {
		out = append(out, router.Route{StepID: s.ID, Database: string(r), Confidence: 1})
	}
	return out, nil
}

// testSources registers recording drivers whose names select PostgreSQL
// ("pgx") and MySQL rules, plus a MongoDB-like source.
func testSources(t *testing.T) (map[string]*api.DB, map[string]*[]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]*[]string{}
	srcs := map[string]*api.DB{}
	for name, drv := range map[string]string{"postgres": "pgx", "mysql": "recmysql", "mongodb": "mongorec"} {
		log := &[]string{}
		seen[name] = log
		internal.RegisterDriver(drv, recDriver{recConn{mu: &mu, seen: log}})
		db, err := api.Connect(drv + "://u:p@h:1/db")
		if err != nil {
			t.Fatal(err)
		}
		srcs[name] = db
	}
	return srcs, seen
}

// A query routed to PostgreSQL while the default is MySQL must be checked
// with PostgreSQL's lexical rules: to PostgreSQL the backslash below is an
// ordinary character, so the literal ends early and OR 1=1 is live code.
func TestRoutedQueryRecheckedInTargetDialect(t *testing.T) {
	srcs, seen := testSources(t)
	e := &Engine{Sources: srcs, Default: "mysql", Security: security.NewSecurityEngine(), Router: fixedRouter("postgres")}
	q := `SELECT id FROM accounts WHERE name = '\' OR 1=1 -- '`

	_, tr, err := e.Query(context.Background(), q)
	if !errors.Is(err, api.ErrBlockedQuery) {
		t.Fatalf("routed to PostgreSQL: want blocked, got err=%v decision=%+v", err, tr.Decision)
	}
	if len(*seen["postgres"]) != 0 {
		t.Fatalf("blocked query reached the backend: %q", *seen["postgres"])
	}

	// The same text is a harmless literal for MySQL and must still run there.
	e.Router = fixedRouter("mysql")
	if _, _, err := e.Query(context.Background(), q); err != nil {
		t.Fatalf("routed to MySQL: want allowed, got %v", err)
	}
	if len(*seen["mysql"]) != 1 {
		t.Fatalf("MySQL saw %d statements, want 1", len(*seen["mysql"]))
	}
}

func TestCommandDocumentsRouteToMongo(t *testing.T) {
	srcs, seen := testSources(t)
	e := &Engine{Sources: srcs, Default: "postgres", Security: security.NewSecurityEngine()}
	doc := `{"find": "users", "filter": {"age": {"$gt": 25}}}`
	if _, _, err := e.Query(context.Background(), doc); err != nil {
		t.Fatalf("document: %v", err)
	}
	if got := *seen["mongodb"]; len(got) != 1 || got[0] != doc {
		t.Fatalf("mongodb saw %q", got)
	}
	if len(*seen["postgres"]) != 0 {
		t.Fatal("document reached the SQL default")
	}

	_, tr, err := e.Query(context.Background(), `{"find": "users", "filter": {"$where": "sleep(5000) || true"}}`)
	if !errors.Is(err, api.ErrBlockedQuery) || tr.Decision.Category != security.CatServerCode {
		t.Fatalf("$where: want blocked as server-side code, got %v %+v", err, tr.Decision)
	}

	delete(e.Sources, "mongodb")
	if _, _, err := e.Query(context.Background(), doc); err == nil {
		t.Fatal("document without a MongoDB source: want error")
	}
}
