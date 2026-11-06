package planner

import (
	"errors"
	"strings"
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

// INTERSECT and EXCEPT are analysed through a synthetic UNION tree; the
// single-source plan must still carry the original text (qualifier removed),
// never a rendering of that tree.
func TestSetOperationKeepsText(t *testing.T) {
	cases := []struct {
		in, want, db string
		d            parser.Dialect
	}{
		{"SELECT Status FROM city WHERE Population > 1500 INTERSECT SELECT Status FROM city WHERE Population < 500",
			"SELECT Status FROM city WHERE Population > 1500 INTERSECT SELECT Status FROM city WHERE Population < 500", "default", parser.MySQL},
		{"SELECT DISTINCT zip_code FROM mysql.weather EXCEPT ALL SELECT DISTINCT zip_code FROM mysql.weather WHERE max_dew_point_f >= 70",
			"SELECT DISTINCT zip_code FROM weather EXCEPT ALL SELECT DISTINCT zip_code FROM weather WHERE max_dew_point_f >= 70", "mysql", parser.MySQL},
		{`(SELECT "Name" FROM postgres.a WHERE id = $1) INTERSECT (SELECT "Name" FROM postgres.b WHERE n ILIKE 'x%') ORDER BY 1`,
			`(SELECT "Name" FROM a WHERE id = $1) INTERSECT (SELECT "Name" FROM b WHERE n ILIKE 'x%') ORDER BY 1`, "postgres", parser.Postgres},
	}
	for _, c := range cases {
		s := singleStep(t, c.in, c.d)
		if s.Query != c.want || s.Database != c.db {
			t.Errorf("%s\n got %s (%s)\nwant %s (%s)", c.in, s.Query, s.Database, c.want, c.db)
		}
	}
}

// Set operations across databases are rejected explicitly, as UNION is.
func TestFederatedSetOperationRejected(t *testing.T) {
	for q, op := range map[string]string{
		"SELECT name FROM postgres.users INTERSECT SELECT name FROM mysql.customers":  "INTERSECT",
		"SELECT name FROM postgres.users EXCEPT ALL SELECT name FROM mysql.customers": "EXCEPT ALL",
		"SELECT name FROM postgres.users UNION SELECT name FROM mysql.customers":      "UNION",
		"SELECT name FROM users INTERSECT SELECT name FROM mysql.customers":           "INTERSECT",
	} {
		ast, err := parser.Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		_, err = GeneratePlan(ast)
		if !errors.Is(err, ErrUnsupportedFederation) || !strings.Contains(err.Error(), op) {
			t.Errorf("%s: want ErrUnsupportedFederation naming %s, got %v", q, op, err)
		}
	}
}

func TestFederatedClausesRejected(t *testing.T) {
	for _, q := range []string{
		"SELECT DISTINCT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id",
		"SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id FOR UPDATE",
	} {
		ast, err := parser.Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := GeneratePlan(ast); err == nil {
			t.Errorf("%s: want an explicit error", q)
		}
	}
}
