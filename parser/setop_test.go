package parser

import (
	"errors"
	"reflect"
	"testing"

	"vitess.io/vitess/go/vt/sqlparser"
)

// branches flattens a UNION chain into its SELECT operands.
func branches(s sqlparser.TableStatement) []*sqlparser.Select {
	switch n := s.(type) {
	case *sqlparser.Select:
		return []*sqlparser.Select{n}
	case *sqlparser.Union:
		return append(branches(n.Left), branches(n.Right)...)
	}
	return nil
}

// The fallback exists because the grammar lacks INTERSECT and EXCEPT. If a
// Vitess upgrade adds them, this test fails and the fallback can go.
func TestVitessGrammarLacksIntersectExcept(t *testing.T) {
	for _, q := range []string{
		"SELECT a FROM t INTERSECT SELECT a FROM u",
		"SELECT a FROM t EXCEPT SELECT a FROM u",
	} {
		if _, err := vparser.ParseStrictDDL(q); err == nil {
			t.Errorf("Vitess now parses %q; parseSetOperation may be unnecessary", q)
		}
	}
}

func TestParseSetOperations(t *testing.T) {
	cases := []struct {
		q        string
		ops      []string
		tables   []string // database.name
		branches int
	}{
		{"SELECT Status FROM city WHERE Population > 1500 INTERSECT SELECT Status FROM city WHERE Population < 500",
			[]string{"INTERSECT"}, []string{".city"}, 2},
		{"SELECT DISTINCT zip_code FROM weather EXCEPT SELECT DISTINCT zip_code FROM weather WHERE max_dew_point_f >= 70",
			[]string{"EXCEPT"}, []string{".weather"}, 2},
		{"SELECT a FROM t1 INTERSECT ALL SELECT a FROM t2", []string{"INTERSECT ALL"}, []string{".t1", ".t2"}, 2},
		{"SELECT a FROM t1 except distinct SELECT a FROM t2", []string{"EXCEPT DISTINCT"}, []string{".t1", ".t2"}, 2},
		{"SELECT a FROM t1 UNION SELECT a FROM t2 INTERSECT SELECT a FROM t3 EXCEPT ALL SELECT a FROM t4",
			[]string{"UNION", "INTERSECT", "EXCEPT ALL"}, []string{".t1", ".t2", ".t3", ".t4"}, 4},
		{"SELECT a FROM t1 UNION ALL SELECT a FROM t2 EXCEPT SELECT a FROM t3",
			[]string{"UNION ALL", "EXCEPT"}, []string{".t1", ".t2", ".t3"}, 3},
		{"(SELECT a FROM t1) EXCEPT (SELECT a FROM t2 WHERE b IN (SELECT b FROM t3))",
			[]string{"EXCEPT"}, []string{".t1", ".t2", ".t3"}, 2},
		{"(SELECT a FROM t1 UNION SELECT a FROM t2) INTERSECT (SELECT a FROM t3)",
			[]string{"INTERSECT"}, []string{".t1", ".t2", ".t3"}, 3},
		{"SELECT T1.name FROM mysql.a AS T1 JOIN mysql.b AS T2 ON T1.id = T2.aid INTERSECT SELECT name FROM mysql.c ORDER BY name LIMIT 5",
			[]string{"INTERSECT"}, []string{"mysql.a", "mysql.b", "mysql.c"}, 2},
		{"/* report */ SELECT a FROM t1 -- first\nINTERSECT /* second */ SELECT a FROM t2",
			[]string{"INTERSECT"}, []string{".t1", ".t2"}, 2},
		{"SELECT `except` FROM t1 INTERSECT SELECT 'EXCEPT' FROM t2", []string{"INTERSECT"}, []string{".t1", ".t2"}, 2},
		{"SELECT 1 INTERSECT SELECT 2", []string{"INTERSECT"}, nil, 2},
	}
	for _, c := range cases {
		ast, err := Parse(c.q)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		if ast.Type != "UNION" || ast.RawQuery != c.q {
			t.Errorf("%q: type %s raw %q", c.q, ast.Type, ast.RawQuery)
		}
		if !reflect.DeepEqual(ast.SetOps, c.ops) {
			t.Errorf("%q: SetOps %q, want %q", c.q, ast.SetOps, c.ops)
		}
		var tables []string
		for _, tb := range ast.Tables {
			tables = append(tables, tb.Database+"."+tb.Name)
		}
		if !reflect.DeepEqual(tables, c.tables) {
			t.Errorf("%q: tables %q, want %q", c.q, tables, c.tables)
		}
		u, ok := ast.Stmt.(*sqlparser.Union)
		if !ok {
			t.Errorf("%q: Stmt is %T, want *sqlparser.Union", c.q, ast.Stmt)
			continue
		}
		if n := len(branches(u)); n != c.branches {
			t.Errorf("%q: %d branches, want %d", c.q, n, c.branches)
		}
	}
}

// Set-operator words inside literals, quoted identifiers and comments are
// not operators, and qualified or nested uses are not split.
func TestSetOperatorWordsNotSplit(t *testing.T) {
	// These parse as they always did, with no set operation.
	for _, q := range []string{
		"SELECT 'a INTERSECT b' FROM t",
		"SELECT a FROM t WHERE b = 'x EXCEPT SELECT y FROM z'",
		"SELECT `intersect`, `except` FROM t",
		"SELECT a FROM t /* EXCEPT SELECT b FROM u */",
		"SELECT t.intersect FROM t",
	} {
		ast, err := Parse(q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		if ast.SetOps != nil {
			t.Errorf("%q: unexpected SetOps %q", q, ast.SetOps)
		}
	}
	// These would parse only if a non-keyword were taken as an operator, or
	// use a form the fallback does not read; all must stay errors.
	for _, q := range []string{
		"SELECT a FROM t1 `intersect` SELECT a FROM t2",
		"SELECT a FROM t1 WHERE c = 'x' 'INTERSECT' SELECT a FROM t2",
		"SELECT a FROM t1 /* INTERSECT */ SELECT a FROM t2",
		"SELECT a FROM t1 -- INTERSECT\n SELECT a FROM t2",
		"SELECT a FROM t1 /*!80031 INTERSECT */ SELECT a FROM t2",
		"SELECT a FROM t1 WHERE a IN (SELECT a FROM t2 INTERSECT SELECT a FROM t3)",
		"SELECT a FROM t1 INTERSECT INTERSECT SELECT a FROM t2",
		"INTERSECT SELECT a FROM t2",
		"SELECT a FROM t1 INTERSECT SELECT a FROM t2)",
		"INSERT INTO t1 SELECT a FROM t2 EXCEPT SELECT a FROM t3",
		"SELECT a FROM t1 INTERSECT DELETE FROM t2",
	} {
		if ast, err := Parse(q); err == nil {
			t.Errorf("%q: want a parse error, got %+v", q, ast)
		}
	}
}

func TestSetOperationsPostgres(t *testing.T) {
	q := `SELECT "Name" FROM t1 WHERE p = 'C:\' AND id = $1 INTERSECT SELECT "intersect" FROM t2 WHERE n ILIKE 'a%'`
	ast, err := ParseFor(q, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ast.SetOps, []string{"INTERSECT"}) || len(ast.Tables) != 2 || ast.Dialect != Postgres || ast.RawQuery != q {
		t.Fatalf("postgres: %+v", ast)
	}
	if f := ast.Fields; len(f) != 2 || f[0].Name != "Name" || f[1].Name != "intersect" {
		t.Errorf("fields %+v", f)
	}
}

// The same text is one SELECT to MySQL (the backslash escapes the quote, so
// the string runs to the end) and an INTERSECT to PostgreSQL. Each dialect
// must get its own reading, also through the cache.
func TestSetOperationsDialectCache(t *testing.T) {
	q := `SELECT a FROM t1 WHERE s = 'x\' INTERSECT SELECT b FROM t2 -- '`
	for i := 0; i < 2; i++ {
		my, err := ParseFor(q, MySQL)
		if err != nil || my.SetOps != nil || len(my.Tables) != 1 {
			t.Fatalf("mysql: %v %+v", err, my)
		}
		pg, err := ParseFor(q, Postgres)
		if err != nil || !reflect.DeepEqual(pg.SetOps, []string{"INTERSECT"}) || len(pg.Tables) != 2 {
			t.Fatalf("postgres: %v %+v", err, pg)
		}
	}
}

func TestSetOperationStackedStatements(t *testing.T) {
	for _, q := range []string{
		"SELECT a FROM t1 INTERSECT SELECT 1; DROP TABLE x",
		"SELECT a FROM t1 EXCEPT SELECT a FROM t2; TRUNCATE t ORDER BY x",
		"SELECT a FROM t1; SELECT a FROM t2 INTERSECT SELECT a FROM t3",
	} {
		if _, err := Parse(q); !errors.Is(err, ErrMultiStatement) {
			t.Errorf("%q: want ErrMultiStatement, got %v", q, err)
		}
	}
	stmts, err := Statements("SELECT a FROM t1 INTERSECT SELECT a FROM t2; DROP TABLE x")
	if err != nil || len(stmts) != 2 {
		t.Fatalf("statements: %v %d", err, len(stmts))
	}
	if _, ok := stmts[0].(*sqlparser.Union); !ok {
		t.Errorf("first statement is %T", stmts[0])
	}
	if _, ok := stmts[1].(*sqlparser.DropTable); !ok {
		t.Errorf("second statement is %T", stmts[1])
	}
}
