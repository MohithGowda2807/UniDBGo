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

// TestErrorEchoSideChannel covers V5 error-based exfiltration: a function whose
// error message echoes its argument (EXTRACTVALUE, UPDATEXML, GTID_SUBSET /
// GTID_SUBTRACT, ST_*FromGeoHash, JSON_KEYS) is rejected when any argument, at
// any depth, carries a sub-query, a system-information function, or an @@
// system variable, while columns and literals are allowed. The restricted set
// includes api_keys so a sub-query over it is also a restricted-table read.
func TestErrorEchoSideChannel(t *testing.T) {
	e := &SecurityEngine{RestrictedTables: []string{"users", "api_keys"}}
	const base = "SELECT id, name FROM accounts WHERE name = 'alice'"
	cases := []struct {
		query string
		block bool
		cat   Category
	}{
		// Confirmed sqlmap error-based attacks (full statements, MySQL dialect).
		{base + " AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT secret FROM api_keys LIMIT 1)))", true, CatErrorEcho},
		{base + " AND GTID_SUBSET(CONCAT(0x71,(SELECT DATABASE()),0x71),1)", true, CatErrorEcho},
		{base + " AND UPDATEXML(1,CONCAT(0x7e,(SELECT secret FROM api_keys LIMIT 1)),1)", true, CatErrorEcho},
		{base + " AND UPDATEXML(1,CONCAT(0x7e,@@version),1)", true, CatErrorEcho},
		{base + " AND GTID_SUBTRACT(CONCAT(0x71,(SELECT version()),0x71),0x71)", true, CatErrorEcho},
		{base + " AND ST_LatFromGeoHash((SELECT secret FROM api_keys LIMIT 1))", true, CatErrorEcho},
		{base + " AND ST_LongFromGeoHash(version())", true, CatErrorEcho},
		{base + " AND ST_PointFromGeoHash(@@hostname,0)", true, CatErrorEcho},
		{base + " AND JSON_KEYS((SELECT secret FROM api_keys LIMIT 1))", true, CatErrorEcho},
		// Direct metadata argument, no nesting.
		{base + " AND EXTRACTVALUE(1,database())", true, CatErrorEcho},
		// Benign look-alikes: columns and literals only -> allowed.
		{"SELECT EXTRACTVALUE(doc, '/a/b') FROM docs WHERE id = 1", false, CatNone},
		{"SELECT UPDATEXML(doc, '/a', '<a>x</a>') FROM docs WHERE id = 1", false, CatNone},
		{"SELECT id FROM points WHERE id = 1 AND ST_LatFromGeoHash(geohash) > 0", false, CatNone},
		{"SELECT JSON_KEYS(payload, '$.a') FROM events WHERE id = 1", false, CatNone},
		{"SELECT GTID_SUBSET(src_gtid, dst_gtid) FROM replicas WHERE id = 1", false, CatNone},
	}
	for _, c := range cases {
		d := e.Analyze(c.query)
		if d.Block != c.block || (c.block && d.Category != c.cat) {
			t.Errorf("%q: got block=%v cat=%q (%s), want block=%v cat=%q",
				c.query, d.Block, d.Category, d.Reason, c.block, c.cat)
		}
	}
}

// TestConstantConjunctAllowed documents (and asserts) current behaviour: a
// constant conjunct such as "id = 1 AND 4991=4991" is allowed by design. It is
// the idiom query builders emit (e.g. "WHERE 1=1 AND ..."), and the tautology
// invariant V1 only rejects an always-true *disjunct* (an OR branch), not a
// conjunct. This test guards against a future over-broad tautology rule.
func TestConstantConjunctAllowed(t *testing.T) {
	e := &SecurityEngine{}
	for _, q := range []string{
		"SELECT id FROM accounts WHERE id = 1 AND 4991=4991",
		"SELECT * FROM orders WHERE 1=1 AND status = 'paid'",
	} {
		if d := e.Analyze(q); d.Block {
			t.Errorf("constant conjunct should be allowed: %q blocked as %s (%s)", q, d.Category, d.Reason)
		}
	}
}

// TestPostgresCastExtraction verifies PostgreSQL CAST-based extraction stays
// blocked (V3/V5). CAST((SELECT ...) AS int) is rejected fail-closed because
// the MySQL grammar does not accept the PostgreSQL cast target; the postfix
// (SELECT ...)::int form has its cast stripped during normalization, and the
// residual comparison is caught when the sub-query reads a restricted table or
// selects server metadata.
func TestPostgresCastExtraction(t *testing.T) {
	e := &SecurityEngine{RestrictedTables: []string{"users", "api_keys"}, Dialect: parser.Postgres}
	const base = "SELECT id, name FROM accounts WHERE name = 'alice'"
	cases := []struct {
		query string
		block bool
		cat   Category
	}{
		{base + " AND 1 = CAST((SELECT secret FROM api_keys LIMIT 1) AS int)", true, CatUnparseable},
		{base + " AND 1 = CAST((SELECT version()) AS int)", true, CatUnparseable},
		{base + " AND 7 = CAST((CHR(113)||(SELECT secret FROM api_keys LIMIT 1)) AS NUMERIC)", true, CatUnparseable},
		{base + " AND (SELECT secret FROM api_keys LIMIT 1)::int = 1", true, CatInference},
		{base + " AND (SELECT version())::int = 1", true, CatInference},
		{base + " AND 1 = ((SELECT version()))::int", true, CatInference},
		// Metadata used only to filter a sub-query is legitimate.
		{"SELECT * FROM docs WHERE id IN (SELECT doc_id FROM acl WHERE grantee = CURRENT_USER())", false, CatNone},
	}
	for _, c := range cases {
		d := e.Analyze(c.query)
		if d.Block != c.block || d.Category != c.cat {
			t.Errorf("%q: got block=%v cat=%q (%s), want block=%v cat=%q",
				c.query, d.Block, d.Category, d.Reason, c.block, c.cat)
		}
	}
}

func TestAggregateComparisonIsNotInference(t *testing.T) {
	e := NewSecurityEngine()
	for _, q := range []string{
		"SELECT f1 FROM follows GROUP BY f1 HAVING count(*) > (SELECT count(*) FROM users WHERE name = 'Tyler')",
		"SELECT dept FROM staff GROUP BY dept HAVING avg(salary) > (SELECT avg(salary) FROM users)",
	} {
		if d := e.Analyze(q); d.Block {
			t.Errorf("%s: blocked (%s)", q, d.Reason)
		}
	}
	if d := e.Analyze("SELECT id FROM accounts WHERE id = 1 AND (SELECT count(*) FROM users) > 3"); !d.Block {
		t.Error("constant comparison with a restricted sub-query must stay blocked")
	}
}

// Bypasses found by the advanced-technique suite and verified on live servers.
func TestAdvancedBypassesBlocked(t *testing.T) {
	e := NewSecurityEngine("api_keys")
	cases := []struct {
		q string
		d parser.Dialect
	}{
		{"SELECT * FROM accounts WHERE id = 1 /*!80041 OR 1=1 */", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 /*!80046 OR 1=1 */", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 /*!80041 UNION SELECT id,secret,id FROM api_keys */", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 OR (SELECT 1)=1", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 OR EXISTS(SELECT 1)", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 OR UNHEX('41')='A'", parser.MySQL},
		{"SELECT * FROM accounts WHERE id = 1 OR CHR(65)||CHR(66)='AB'", parser.Postgres},
		{"SELECT * FROM accounts WHERE id = 1 OR 'ad'||'min'='admin'", parser.Postgres},
		{"DO SLEEP(5)", parser.MySQL},
	}
	for _, c := range cases {
		if d := e.AnalyzeFor(c.q, c.d); !d.Block {
			t.Errorf("%s (%s): not blocked", c.q, c.d)
		}
	}
	benign := []struct {
		q string
		d parser.Dialect
	}{
		{"SELECT 'Dr. ' || name FROM accounts WHERE id = $1", parser.Postgres},
		{"SELECT id FROM accounts WHERE first || ' ' || last = $1 OR email = $2", parser.Postgres},
		{"SELECT id FROM orders WHERE status = 'paid' OR EXISTS (SELECT 1 FROM refunds r WHERE r.order_id = orders.id)", parser.MySQL},
		{"SELECT id FROM t WHERE a = 1 OR 1=0", parser.MySQL},
		{"SELECT id FROM t WHERE a = ? OR b = ?", parser.MySQL},
		{"SELECT /*!40001 SQL_NO_CACHE */ id FROM t WHERE id = 1", parser.MySQL},
	}
	for _, c := range benign {
		if d := e.AnalyzeFor(c.q, c.d); d.Block {
			t.Errorf("%s (%s): blocked: %s", c.q, c.d, d.Reason)
		}
	}
}

func TestPrepareAndOutfile(t *testing.T) {
	e := NewSecurityEngine("api_keys")
	for _, q := range []string{
		"PREPARE s FROM 'SELECT * FROM accounts WHERE id = 1 OR 1=1'",
		"PREPARE s FROM 'SELECT 1; DROP TABLE accounts'",
		"SELECT secret FROM api_keys WHERE id = 1 INTO OUTFILE '/tmp/x'",
		"SELECT name FROM accounts WHERE id = 1 INTO DUMPFILE '/tmp/y'",
	} {
		if d := e.Analyze(q); !d.Block {
			t.Errorf("%s: not blocked", q)
		}
	}
	for _, q := range []string{
		"PREPARE s FROM 'SELECT name FROM accounts WHERE id = ?'",
		"SELECT name FROM accounts WHERE id = 1 INTO @n",
	} {
		if d := e.Analyze(q); d.Block {
			t.Errorf("%s: blocked: %s", q, d.Reason)
		}
	}
}

// PostgreSQL gives '/', '^' and '||' other meanings than MySQL, so constant
// expressions using them must not be decided with MySQL semantics.
func TestPostgresOperatorSemantics(t *testing.T) {
	e := NewSecurityEngine()
	for _, q := range []string{
		"SELECT id FROM accounts WHERE id = 7 OR 3/2=1",
		"SELECT id FROM accounts WHERE id = 7 OR 2^3=8",
		"SELECT id FROM accounts WHERE id = 7 OR 'a'||'1'='a1'",
		"SELECT id FROM accounts WHERE id = 7 OR 7%3=1",
	} {
		if d := e.AnalyzeFor(q, parser.Postgres); !d.Block {
			t.Errorf("%s: not blocked under PostgreSQL rules", q)
		}
	}
	for _, q := range []string{
		"SELECT id FROM accounts WHERE price / qty > 2 OR id = $1",
		"SELECT first || ' ' || last FROM accounts WHERE id = $1",
	} {
		if d := e.AnalyzeFor(q, parser.Postgres); d.Block {
			t.Errorf("%s: blocked: %s", q, d.Reason)
		}
	}
}

func TestTruncationAfterClosedLiteral(t *testing.T) {
	e := NewSecurityEngine()
	cases := []struct {
		q string
		d parser.Dialect
	}{
		// "--" without a space is a comment only in PostgreSQL; in MySQL it is
		// two minus signs and the password predicate stays in force.
		{"SELECT id FROM accounts WHERE name='admin'--'' AND password='x'", parser.Postgres},
		{"SELECT id FROM accounts WHERE name='admin'--x' AND password='x'", parser.Postgres},
		{"SELECT id FROM accounts WHERE name='admin'-- '' AND password='x'", parser.Postgres},
		{"SELECT id FROM accounts WHERE name='admin'-- '' AND password='x'", parser.MySQL},
	}
	for _, c := range cases {
		if dec := e.AnalyzeFor(c.q, c.d); !dec.Block {
			t.Errorf("%s (%s): not blocked", c.q, c.d)
		}
	}
	for _, q := range []string{
		"SELECT id FROM accounts WHERE id = 1 -- don't change: used by the 'nightly' job",
		"SELECT id FROM accounts WHERE id = 1 /*action='index',controller='users'*/",
	} {
		if dec := e.Analyze(q); dec.Block {
			t.Errorf("%s: blocked: %s", q, dec.Reason)
		}
	}
}

func TestPostgresStringComparisons(t *testing.T) {
	e := NewSecurityEngine()
	for _, q := range []string{
		"SELECT * FROM t WHERE id = 1 OR 'a' <> 'A'",
		"SELECT * FROM t WHERE id = 1 OR 'a' NOT LIKE 'A'",
		"SELECT * FROM t WHERE id = 1 OR 'B' < 'a'",
	} {
		if d := e.AnalyzeFor(q, parser.Postgres); !d.Block {
			t.Errorf("%s: not blocked under PostgreSQL rules", q)
		}
	}
	if d := e.AnalyzeFor("SELECT * FROM t WHERE name = 'x' OR email = 'y'", parser.Postgres); d.Block {
		t.Errorf("benign disjunction blocked: %s", d.Reason)
	}
}
