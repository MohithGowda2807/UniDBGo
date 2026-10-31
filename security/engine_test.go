package security

import (
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

func TestPostgresLexicalRules(t *testing.T) {
	e := &SecurityEngine{Dialect: parser.Postgres}
	cases := []struct {
		query string
		block bool
	}{
		// In PostgreSQL a backslash does not escape the quote.
		{`SELECT * FROM users WHERE name = '\' OR 1=1 -- '`, true},
		{`SELECT * FROM t WHERE name = '\'; DROP TABLE users; --'`, true},
		{`SELECT * FROM t WHERE id = 1 # 0 OR 1=1`, true},
		{`SELECT * FROM t WHERE path = 'C:\Users\bob'`, false},
		{`SELECT "Name" FROM t WHERE id = $1`, false},
		{`SELECT * FROM t WHERE a = $$it's$$`, false},
		{`SELECT * FROM t WHERE a = E'it\'s'`, false},
	}
	for _, c := range cases {
		if d := e.Analyze(c.query); d.Block != c.block {
			t.Errorf("%s: block=%v (%s), want %v", c.query, d.Block, d.Reason, c.block)
		}
	}
	// The same text read with MySQL rules is a harmless literal.
	if d := (&SecurityEngine{}).Analyze(`SELECT * FROM t WHERE name = '\'; DROP TABLE users; --'`); d.Block {
		t.Errorf("MySQL reading blocked a plain literal: %s", d.Reason)
	}
}

func TestAnalyze(t *testing.T) {
	e := &SecurityEngine{}
	cases := []struct {
		query string
		block bool
		flag  bool
		cat   Category
	}{
		{"SELECT id, name FROM users WHERE id = 1", false, false, CatNone},
		{"SELECT * FROM users WHERE id = $1", false, false, CatNone},
		{"SELECT * FROM orders WHERE note = 'pay 1=1 OR union select'", false, false, CatNone},
		{"SELECT * FROM orders WHERE 1=1 AND status = 'paid'", false, false, CatNone},
		{"SELECT * FROM orders WHERE status = 'a' OR status = 'b'", false, false, CatNone},
		{"SELECT name FROM products -- list products", false, false, CatNone},
		{"SELECT a FROM t1 UNION ALL SELECT a FROM t2", false, false, CatNone},
		{"SELECT x::text FROM orders WHERE name ILIKE 'a%'", false, false, CatNone},
		{"SELECT * FROM users WHERE id = 1 OR 1=1", true, false, CatTautology},
		{"SELECT * FROM users WHERE name = '' OR 'a'='a'", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 OR 0x41=0x41", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 OR CHAR(65)='A'", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 OR 5>2", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 || TRUE", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 OR name = name", true, false, CatTautology},
		{"SELECT * FROM users WHERE id=1/**/OR/**/2-1=1", true, false, CatTautology},
		{"SELECT * FROM users WHERE id = 1 OR 'a'", false, false, CatNone}, // 'a' is false in MySQL
		{"SELECT * FROM t WHERE id = 1; DROP TABLE t", true, false, CatPiggyback},
		{"SELECT * FROM users WHERE name = 'admin'-- ' AND pass = 'x'", true, false, CatCommentTruncation},
		{"SELECT * FROM t WHERE id = 1 UNION SELECT user, password FROM mysql.user", true, false, CatUnionExfiltration},
		{"SELECT name FROM t WHERE id = -1 UNION SELECT NULL, version()", true, false, CatUnionExfiltration},
		{"SELECT * FROM t WHERE id = 1 AND SLEEP(5)", true, false, CatTimingFunction},
		{"SELECT * FROM t WHERE id = 1 AND (SELECT COUNT(*) FROM information_schema.tables) > 0", true, false, CatSystemCatalog},
		{"SELECT * FROM users", false, true, CatUnboundedScan},
		{"SELECT * FROM t WHERE id = 1 AND SUBSTRING(@@version,1,1) = '8'", true, false, CatInference},
		{"SELECT * FROM t WHERE id = 1 AND LENGTH(DATABASE()) > 3", true, false, CatInference},
		{"SELECT version()", false, false, CatNone},
		// Holes found in review.
		{"SELECT pg_catalog.pg_sleep(5)", true, false, CatTimingFunction},
		{"SELECT pg_sleep_for('5 seconds')", true, false, CatTimingFunction},
		{"SELECT * FROM t WHERE id = 1 AND get_lock('a', 10)", true, false, CatTimingFunction},
		{"SELECT name FROM products UNION SELECT usename FROM pg_user", true, false, CatUnionExfiltration},
		{"SELECT * FROM t WHERE id = 1 AND 1 = (SELECT 1 FROM pg_user LIMIT 1)", true, false, CatSystemCatalog},
		{"SELECT name FROM products WHERE id = 1 UNION SELECT (SELECT password FROM users LIMIT 1) FROM products", true, false, CatUnionExfiltration},
		{"SELECT name FROM products WHERE id = 1 UNION SELECT version() FROM products", true, false, CatUnionExfiltration},
		{"SELECT * FROM products ORDER BY CASE WHEN version() LIKE '8%' THEN price ELSE name END", true, false, CatInference},
		{"SELECT * FROM p JOIN orders o ON o.pid = p.id AND version() LIKE '8%'", true, false, CatInference},
		{"SELECT * FROM t WHERE id = 1 OR CASE WHEN 1 THEN 1 END", true, false, CatTautology},
		{"SELECT * FROM t WHERE id = 1 OR COALESCE(1, 0)", true, false, CatTautology},
		{"SELECT * FROM t WHERE id = 1 OR CAST(1 AS SIGNED)", true, false, CatTautology},
		{"SELECT * FROM t WHERE id = 1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 64", true, false, CatInference},
		{"SELECT * FROM t WHERE id = 1 AND GET_LOCK('a', 10)", true, false, CatTimingFunction},
		// Legitimate queries that must pass.
		{"SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE country = 'IN')", false, false, CatNone},
		{"SELECT * FROM mysql.orders WHERE id IN (SELECT order_id FROM mysql.items WHERE qty > 1)", false, false, CatNone},
		{"SELECT id FROM mysql.orders WHERE a = 1 UNION SELECT id FROM mysql.archived_orders WHERE a = 1", false, false, CatNone},
		{"SELECT * FROM docs WHERE owner = CURRENT_USER()", false, false, CatNone},
		{"SELECT * FROM notes WHERE note = 'it''s' -- don't remove", false, false, CatNone},
		{"SELECT * FROM t WHERE ts > '2024-01-01'::date -- from 2024", false, false, CatNone},
		{"SELECT * FROM t WHERE id IN (SELECT 1 UNION SELECT 2)", false, false, CatNone},
		{"SELECT user, host FROM mysql.user", false, true, CatSystemCatalog},
		{"SELECT * FROM t WHERE id = '1", true, false, CatUnparseable},
	}
	for _, c := range cases {
		d := e.Analyze(c.query)
		if d.Block != c.block || d.Flag != c.flag || d.Category != c.cat {
			t.Errorf("%q: got block=%v flag=%v cat=%q (%s), want block=%v flag=%v cat=%q",
				c.query, d.Block, d.Flag, d.Category, d.Reason, c.block, c.flag, c.cat)
		}
	}
}

func TestDecisionCacheRespectsDialectAndReset(t *testing.T) {
	e := &SecurityEngine{}
	q := `SELECT * FROM t WHERE name = '\'; DROP TABLE users; --'`
	if e.AnalyzeFor(q, parser.MySQL).Block {
		t.Fatal("MySQL reading should allow the literal")
	}
	if !e.AnalyzeFor(q, parser.Postgres).Block {
		t.Fatal("cached MySQL decision leaked into the PostgreSQL reading")
	}
	if d := e.Analyze("SELECT * FROM customers"); d.Flag {
		t.Fatal("customers is not restricted by default")
	}
	e.RestrictedTables = []string{"customers"}
	e.ResetCache()
	if e.Analyze("SELECT * FROM customers").Category != CatUnboundedScan {
		t.Fatal("configuration change not applied after ResetCache")
	}
}
