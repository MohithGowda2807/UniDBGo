package parser

import (
	"errors"
	"testing"
)

func TestNormalizeDialect(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t WHERE id = $1 AND x = $12": "SELECT * FROM t WHERE id = :p1 AND x = :p12",
		"SELECT a::text, b::numeric(10,2) FROM t":   "SELECT a, b FROM t",
		"SELECT * FROM t WHERE n ILIKE 'a%'":        "SELECT * FROM t WHERE n LIKE 'a%'",
		"SELECT '$1 :: ILIKE' FROM t -- $2":         "SELECT '$1 :: ILIKE' FROM t -- $2",
		"SELECT * FROM t WHERE note = 'it''s $3'":   "SELECT * FROM t WHERE note = 'it''s $3'",
	}
	for in, want := range cases {
		if got := NormalizeDialect(in); got != want {
			t.Errorf("NormalizeDialect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRejectsStackedStatements(t *testing.T) {
	if _, err := Parse("SELECT * FROM t WHERE id = 1; DROP TABLE t"); !errors.Is(err, ErrMultiStatement) {
		t.Errorf("expected ErrMultiStatement, got %v", err)
	}
	// The stacked statement need not be valid on its own.
	if _, err := Parse("SELECT * FROM t WHERE id = 1; TRUNCATE t ORDER BY x"); !errors.Is(err, ErrMultiStatement) {
		t.Errorf("expected ErrMultiStatement for malformed second statement, got %v", err)
	}
	// A semicolon inside a string literal is not a statement separator.
	if _, err := Parse("SELECT * FROM t WHERE note = 'a;b'"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseLimitAndDML(t *testing.T) {
	ast, err := Parse("SELECT * FROM users LIMIT 25")
	if err != nil || ast.Limit == nil || *ast.Limit != 25 {
		t.Fatalf("limit not parsed: %v %v", ast, err)
	}
	for _, q := range []string{
		"INSERT INTO orders (id, total) VALUES (1, 2)",
		"UPDATE orders SET total = 3 WHERE id = 1",
		"DELETE FROM orders WHERE id = 1",
	} {
		ast, err := Parse(q)
		if err != nil || len(ast.Tables) != 1 || ast.Tables[0].Name != "orders" {
			t.Errorf("%q: %v %+v", q, err, ast)
		}
	}
}

func TestParseUnion(t *testing.T) {
	ast, err := Parse("SELECT a FROM t1 UNION SELECT b FROM t2")
	if err != nil || ast.Type != "UNION" || len(ast.Tables) != 2 {
		t.Fatalf("union: %v %+v", err, ast)
	}
}

func TestDialectSensitive(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT * FROM t WHERE id = $1":      false,
		"SELECT * FROM t WHERE a = 'x' -- c": false,
		`SELECT * FROM t WHERE a = 'C:\x'`:   true,
		`SELECT "Name" FROM t`:               true,
		"SELECT * FROM t WHERE a = $$x$$":    true,
		"SELECT * FROM t WHERE a = E'x'":     true,
		"SELECT 1 # comment":                 true,
		"SELECT * FROM t WHERE name = 'Eve'": false,
	} {
		if got := DialectSensitive(q); got != want {
			t.Errorf("DialectSensitive(%q) = %v, want %v", q, got, want)
		}
	}
}
