package planner

import (
	"strings"
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

func singleStep(t *testing.T, q string, d parser.Dialect) ExecutionStep {
	t.Helper()
	ast, err := parser.ParseFor(q, d)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	plan, err := GeneratePlan(ast)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("%s: expected one step, got %+v", q, plan.Steps)
	}
	return plan.Steps[0]
}

// The single-source path must send the original text with only the backend
// qualifier removed: re-rendering would apply MySQL escaping to PostgreSQL.
func TestSingleSourceKeepsText(t *testing.T) {
	cases := []struct {
		in, want string
		d        parser.Dialect
	}{
		{"SELECT name FROM postgres.users WHERE id = $1", "SELECT name FROM users WHERE id = $1", parser.Postgres},
		{"SELECT * FROM postgres.users WHERE name = 'x''; DROP TABLE users; --'", "SELECT * FROM users WHERE name = 'x''; DROP TABLE users; --'", parser.Postgres},
		{"SELECT * FROM postgres.t LIMIT 10 OFFSET 5", "SELECT * FROM t LIMIT 10 OFFSET 5", parser.Postgres},
		{`SELECT * FROM postgres.t WHERE p = 'C:\Users\bob' AND n ILIKE 'a\_b%'`, `SELECT * FROM t WHERE p = 'C:\Users\bob' AND n ILIKE 'a\_b%'`, parser.Postgres},
		{`SELECT "name", 7::float / 2 FROM postgres.t`, `SELECT "name", 7::float / 2 FROM t`, parser.Postgres},
		{"INSERT INTO postgres.files (path) VALUES ('postgres.x')", "INSERT INTO files (path) VALUES ('postgres.x')", parser.Postgres},
		{"UPDATE mysql.orders SET note = 'it\\'s mysql.orders' WHERE id = 1", "UPDATE orders SET note = 'it\\'s mysql.orders' WHERE id = 1", parser.MySQL},
		{"SELECT o.id FROM mysql.orders o JOIN mysql.items i ON i.oid = o.id", "SELECT o.id FROM orders o JOIN items i ON i.oid = o.id", parser.MySQL},
	}
	for _, c := range cases {
		s := singleStep(t, c.in, c.d)
		if s.Query != c.want {
			t.Errorf("%s\n got %s\nwant %s", c.in, s.Query, c.want)
		}
	}
}

func TestFederatedPlan(t *testing.T) {
	ast, err := parser.Parse("SELECT u.Name AS customer, o.total FROM postgres.users u JOIN mysql.orders o ON o.user_id = u.id WHERE u.Country = 'IN' AND o.status = 'it''s' AND o.total > 10")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := GeneratePlan(ast)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %+v", plan.Steps)
	}
	l, r := plan.Steps[0], plan.Steps[1]
	if l.Query != "SELECT id, `name` FROM users WHERE country = :v1" || len(l.Args) != 1 || l.Args[0] != "IN" {
		t.Errorf("left scan: %s %v", l.Query, l.Args)
	}
	if r.Query != "SELECT user_id, total FROM orders WHERE `status` = :v1 AND total > :v2" ||
		len(r.Args) != 2 || r.Args[0] != "it's" || r.Args[1] != int64(10) {
		t.Errorf("right scan: %s %v", r.Query, r.Args)
	}
	if bound := parser.Bind(l.Query, parser.Postgres); bound != `SELECT id, "name" FROM users WHERE country = $1` {
		t.Errorf("postgres binding: %s", bound)
	}
	if bound := parser.Bind(r.Query, parser.Postgres); bound != `SELECT user_id, total FROM orders WHERE "status" = $1 AND total > $2` {
		t.Errorf("postgres binding: %s", bound)
	}
	if bound := parser.Bind(r.Query, parser.MySQL); bound != "SELECT user_id, total FROM orders WHERE `status` = ? AND total > ?" {
		t.Errorf("mysql binding: %s", bound)
	}
	j := plan.Steps[2]
	if j.LeftKey != "u.id" || j.RightKey != "o.user_id" {
		t.Errorf("join keys %s / %s", j.LeftKey, j.RightKey)
	}
	if strings.Join(plan.Projection, ",") != "u.Name,o.total" || plan.Labels[0] != "customer" {
		t.Errorf("projection %v labels %v", plan.Projection, plan.Labels)
	}
}

// A table name that is not a plain identifier must stay quoted.
func TestFederatedQuotesTableNames(t *testing.T) {
	ast, err := parser.Parse("SELECT a.id FROM postgres.`t WHERE 1=0; DROP TABLE users; --` a JOIN mysql.`order` b ON a.id = b.id")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := GeneratePlan(ast)
	if err != nil {
		t.Fatal(err)
	}
	if q := parser.Bind(plan.Steps[0].Query, parser.Postgres); q != `SELECT id FROM "t WHERE 1=0; DROP TABLE users; --"` {
		t.Errorf("left scan: %s", q)
	}
	if q := plan.Steps[1].Query; q != "SELECT id FROM `order`" {
		t.Errorf("right scan: %s", q)
	}
}

func TestFederatedRejects(t *testing.T) {
	for _, q := range []string{
		"SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.a = o.b",
		"SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id = :p1",
		"SELECT u.name FROM postgres.users u LEFT JOIN mysql.orders o ON u.id = o.user_id",
	} {
		ast, err := parser.Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := GeneratePlan(ast); err == nil {
			t.Errorf("%s: expected an error", q)
		}
	}
}

// Planning must not modify the cached syntax tree it was given.
func TestPlanningLeavesCachedTreeIntact(t *testing.T) {
	q := "SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id <= 500 AND o.id <= 500"
	for i := 0; i < 3; i++ {
		ast, err := parser.Parse(q) // the same cached tree every time
		if err != nil {
			t.Fatal(err)
		}
		if _, err := GeneratePlan(ast); err != nil {
			t.Fatalf("planning #%d: %v", i+1, err)
		}
	}
}
