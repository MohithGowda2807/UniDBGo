package federation

import (
	"context"
	"errors"
	"testing"

	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
)

// fakeConn serves fixed rows and records the query it received.
type fakeConn struct {
	cols    []string
	rows    [][]any
	rowsErr error
	query   string
	args    []any
	driver  string
}

func (c *fakeConn) Driver() string { return c.driver }

func (c *fakeConn) Query(_ context.Context, q string, args ...any) (internal.Result, error) {
	c.query, c.args = q, args
	return &fakeResult{cols: c.cols, rows: c.rows, i: -1, err: c.rowsErr}, nil
}
func (c *fakeConn) Exec(context.Context, string, ...any) (internal.ExecResult, error) {
	return nil, errors.New("not supported")
}
func (c *fakeConn) BeginTx(context.Context, *internal.TxOptions) (internal.Tx, error) {
	return nil, errors.New("not supported")
}
func (c *fakeConn) Close() error { return nil }

type fakeResult struct {
	cols []string
	rows [][]any
	i    int
	err  error // returned by Err once the rows are exhausted
}

func (r *fakeResult) Columns() []string { return r.cols }
func (r *fakeResult) Next() bool        { r.i++; return r.i < len(r.rows) }
func (r *fakeResult) Close() error      { return nil }
func (r *fakeResult) Err() error        { return r.err }
func (r *fakeResult) Scan(dest ...any) error {
	for i, d := range dest {
		*(d.(*any)) = r.rows[r.i][i]
	}
	return nil
}

func TestExecuteFederatedJoin(t *testing.T) {
	pg := &fakeConn{driver: "postgres", cols: []string{"id", "name"}, rows: [][]any{{int64(1), "asha"}, {int64(2), "ravi"}, {int64(3), "meera"}}}
	my := &fakeConn{driver: "mysql", cols: []string{"user_id", "total"}, rows: [][]any{{[]byte("1"), []byte("10.50")}, {[]byte("3"), []byte("7.25")}, {[]byte("3"), []byte("1.00")}, {[]byte("9"), []byte("2.00")}}}

	ast, err := parser.Parse("SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE o.status = 'paid'")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.GeneratePlan(ast)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewEngine(map[string]internal.Connection{"postgres": pg, "mysql": my}).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if my.query != "SELECT user_id, total FROM orders WHERE `status` = ?" || len(my.args) != 1 || my.args[0] != "paid" {
		t.Errorf("mysql received %q %v", my.query, my.args)
	}
	if pg.query != `SELECT id, "name" FROM users` {
		t.Errorf("postgres received %q", pg.query)
	}
	if got := res.Columns(); len(got) != 2 || got[0] != "u.name" || got[1] != "o.total" {
		t.Fatalf("columns %v", got)
	}
	totals := map[string]int{}
	for res.Next() {
		var name, total string
		if err := res.Scan(&name, &total); err != nil {
			t.Fatal(err)
		}
		totals[name]++
	}
	if len(totals) != 2 || totals["asha"] != 1 || totals["meera"] != 2 {
		t.Errorf("unexpected join result %v", totals)
	}
}

func TestExecuteMissingSource(t *testing.T) {
	ast, _ := parser.Parse("SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id")
	plan, _ := planner.GeneratePlan(ast)
	if _, err := NewEngine(map[string]internal.Connection{}).Execute(context.Background(), plan); err == nil {
		t.Error("expected an error for unregistered sources")
	}
}

func TestExecuteReportsRowErrors(t *testing.T) {
	broken := errors.New("connection reset")
	pg := &fakeConn{driver: "postgres", cols: []string{"id", "name"}, rows: [][]any{{int64(1), "a"}}, rowsErr: broken}
	my := &fakeConn{driver: "mysql", cols: []string{"user_id", "total"}, rows: [][]any{{[]byte("1"), []byte("1")}}}
	ast, _ := parser.Parse("SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id")
	plan, _ := planner.GeneratePlan(ast)
	_, err := NewEngine(map[string]internal.Connection{"postgres": pg, "mysql": my}).Execute(context.Background(), plan)
	if !errors.Is(err, broken) {
		t.Fatalf("a failure while reading rows must not yield a partial join, got %v", err)
	}
}

func TestProjectionCaseAndAlias(t *testing.T) {
	// PostgreSQL returns unquoted column names in lower case.
	pg := &fakeConn{driver: "postgres", cols: []string{"id", "name"}, rows: [][]any{{int64(1), "asha"}}}
	my := &fakeConn{driver: "mysql", cols: []string{"user_id"}, rows: [][]any{{[]byte("1")}}}
	ast, _ := parser.Parse("SELECT u.Name AS customer FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id")
	plan, err := planner.GeneratePlan(ast)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewEngine(map[string]internal.Connection{"postgres": pg, "mysql": my}).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if cols := res.Columns(); len(cols) != 1 || cols[0] != "customer" {
		t.Fatalf("columns %v, want [customer]", cols)
	}
}
