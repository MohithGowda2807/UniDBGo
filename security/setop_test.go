package security

import (
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

// INTERSECT and EXCEPT queries are parsed and inspected like UNION queries:
// benign ones pass, and every operand is held to the UNION branch rules.
func TestSetOperations(t *testing.T) {
	e := NewSecurityEngine("users", "api_keys")
	allowed := []string{
		// Spider (human-written benign queries) that MySQL accepts.
		"SELECT Status FROM city WHERE Population > 1500 INTERSECT SELECT Status FROM city WHERE Population < 500",
		"SELECT DISTINCT zip_code FROM weather EXCEPT SELECT DISTINCT zip_code FROM weather WHERE max_dew_point_f >= 70",
		"SELECT T1.name FROM department AS T1 JOIN management AS T2 ON T1.department_id = T2.department_id WHERE T2.temporary_acting = 'Yes' INTERSECT SELECT T1.name FROM department AS T1 JOIN management AS T2 ON T1.department_id = T2.department_id WHERE T2.temporary_acting = 'No'",
		"SELECT name FROM people EXCEPT SELECT T2.name FROM candidate AS T1 JOIN people AS T2 ON T1.people_id = T2.people_id WHERE T1.support_rate > 0.5",
		"SELECT country FROM singer WHERE age > 40 INTERSECT SELECT country FROM singer WHERE age < 30",
		"SELECT name FROM stadium EXCEPT SELECT T2.name FROM concert AS T1 JOIN stadium AS T2 ON T1.stadium_id = T2.stadium_id WHERE T1.year = 2014",
		"SELECT id FROM orders GROUP BY id HAVING count(*) > 2 EXCEPT ALL SELECT id FROM refunds",
		"(SELECT a FROM t1) INTERSECT (SELECT a FROM t2 WHERE b IN (SELECT b FROM t3))",
		"SELECT a FROM t1 UNION SELECT a FROM t2 INTERSECT SELECT a FROM t3 ORDER BY a LIMIT 10",
		"SELECT name FROM accounts WHERE id = 1 INTERSECT SELECT name FROM accounts WHERE id = 2",
	}
	for _, q := range allowed {
		if d := e.Analyze(q); d.Block || d.Flag {
			t.Errorf("benign set operation blocked or flagged: %q -> %+v", q, d)
		}
	}

	blocked := map[string]Category{
		// A branch reading a restricted table or catalog leaks it through
		// which rows survive, as a UNION branch would.
		"SELECT name FROM accounts WHERE id = 1 INTERSECT SELECT secret FROM api_keys":            CatUnionExfiltration,
		"SELECT name FROM accounts WHERE id = 1 EXCEPT SELECT password FROM users":                CatUnionExfiltration,
		"SELECT name FROM t1 UNION SELECT name FROM t2 EXCEPT ALL SELECT secret FROM api_keys":    CatUnionExfiltration,
		"SELECT name FROM t1 INTERSECT SELECT table_name FROM information_schema.tables":          CatUnionExfiltration,
		"SELECT name FROM t1 INTERSECT SELECT a FROM t2 WHERE b IN (SELECT secret FROM api_keys)": CatUnionExfiltration,
		"SELECT name FROM t1 EXCEPT SELECT version()":                                             CatUnionExfiltration,
		// A branch without a source table probes the column count.
		"SELECT name FROM products WHERE id = 1 INTERSECT SELECT 1,2,3": CatUnionExfiltration,
		// Every operand is inspected for the other invariants too.
		"SELECT id FROM orders WHERE id = 5 EXCEPT SELECT id FROM orders WHERE status = 'x' OR 1=1": CatTautology,
		"SELECT id FROM orders WHERE id = 5 OR 'a'='a' INTERSECT SELECT id FROM orders":             CatTautology,
		"SELECT id FROM orders INTERSECT SELECT id FROM orders WHERE sleep(5) = 0":                  CatTimingFunction,
		// Stacked statements after a set operation are still piggy-backing.
		"SELECT name FROM accounts WHERE id = 1 INTERSECT SELECT 1; DROP TABLE x":       CatPiggyback,
		"SELECT name FROM accounts EXCEPT SELECT name FROM archive; DELETE FROM orders": CatPiggyback,
		// A trailing comment that swallows a set operation.
		"SELECT id FROM accounts WHERE name = 'admin' -- ' INTERSECT SELECT id FROM accounts": CatCommentTruncation,
		// A set operation nested in a sub-query is not read; fail closed.
		"SELECT a FROM t1 WHERE a IN (SELECT a FROM t2 INTERSECT SELECT a FROM t3)": CatUnparseable,
	}
	for q, want := range blocked {
		if d := e.Analyze(q); !d.Block || d.Category != want {
			t.Errorf("%q: want blocked as %s, got %+v", q, want, d)
		}
	}
}

func TestSetOperationsPostgres(t *testing.T) {
	e := NewSecurityEngine()
	if d := e.AnalyzeFor(`SELECT "Name" FROM city WHERE note = 'C:\' INTERSECT SELECT "Name" FROM town WHERE id = $1`, parser.Postgres); d.Block || d.Flag {
		t.Errorf("benign PostgreSQL INTERSECT: %+v", d)
	}
	// To PostgreSQL the backslash does not escape the quote, so the
	// INTERSECT is live and reads a restricted table; to MySQL it is text.
	q := `SELECT name FROM products WHERE note = 'x\' INTERSECT SELECT password FROM users -- '`
	if d := e.AnalyzeFor(q, parser.Postgres); !d.Block || d.Category != CatUnionExfiltration {
		t.Errorf("postgres: want union-exfiltration, got %+v", d)
	}
	if d := e.AnalyzeFor(q, parser.MySQL); d.Block {
		t.Errorf("mysql: the literal is harmless, got %+v", d)
	}
}
