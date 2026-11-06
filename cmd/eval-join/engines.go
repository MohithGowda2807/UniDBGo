package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/federation"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/security"
)

//go:embed duckdb_join.py
var duckScript string

// fixture mirrors openFixture(8) in cmd/unidb-bench/live.go: native handles
// and a UniDB-Go engine over both sources with the security engine enabled.
type fixture struct {
	pg, my *sql.DB
	eng    *engine.Engine
}

func nativeDSNs() (pg, my string, err error) {
	pc, err := api.ParseConnectionString(*pgDSN)
	if err != nil {
		return "", "", err
	}
	mc, err := api.ParseConnectionString(*myDSN)
	if err != nil {
		return "", "", err
	}
	pg = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", pc.Username, pc.Password, pc.Host, pc.Port, pc.Database)
	my = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", mc.Username, mc.Password, mc.Host, mc.Port, mc.Database)
	return
}

func openFixture(pool int) (*fixture, error) {
	pgN, myN, err := nativeDSNs()
	if err != nil {
		return nil, err
	}
	f := &fixture{}
	if f.pg, err = sql.Open("postgres", pgN); err != nil {
		return nil, err
	}
	if f.my, err = sql.Open("mysql", myN); err != nil {
		return nil, err
	}
	for _, db := range []*sql.DB{f.pg, f.my} {
		db.SetMaxOpenConns(pool)
		db.SetMaxIdleConns(pool)
	}
	upg, err := api.Connect(*pgDSN, api.WithMaxPool(pool))
	if err != nil {
		return nil, err
	}
	umy, err := api.Connect(*myDSN, api.WithMaxPool(pool))
	if err != nil {
		return nil, err
	}
	for _, c := range []*api.DB{upg, umy} {
		if t, ok := c.Conn().(interface{ SetMaxIdleConns(int) }); ok {
			t.SetMaxIdleConns(pool)
		}
	}
	f.eng = &engine.Engine{
		Sources:  map[string]*api.DB{"postgres": upg, "mysql": umy},
		Default:  "postgres",
		Security: security.NewSecurityEngine(),
	}
	return f, nil
}

// --- co-located copies -------------------------------------------------------

type copyInfo struct {
	PGOrdersCopy, MyUsersCopy string // "verified" or "reloaded+verified"
	OrdersRows, UsersRows     int
}

// dump returns every row of q as "a|b|..." strings.
func dump(ctx context.Context, db *sql.DB, q string) ([]string, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var out []string
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = v.String
		}
		out = append(out, strings.Join(parts, "|"))
	}
	return out, rows.Err()
}

func equalRows(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ensureCopies makes unidb.public.orders_copy (PostgreSQL) an exact copy of
// MySQL unidb.orders and unidb.users_copy (MySQL) an exact copy of PostgreSQL
// unidb.users, with the same keys and indexes, reloading only the copies
// when they are missing or differ. The original tables are only read.
func ensureCopies(ctx context.Context, f *fixture) (copyInfo, error) {
	var info copyInfo
	orders, err := dump(ctx, f.my, "SELECT id, user_id, total, status FROM orders ORDER BY id")
	if err != nil {
		return info, err
	}
	users, err := dump(ctx, f.pg, "SELECT id, name, email, country, age FROM users ORDER BY id")
	if err != nil {
		return info, err
	}
	info.OrdersRows, info.UsersRows = len(orders), len(users)

	check := func(db *sql.DB, q string, want []string) bool {
		got, err := dump(ctx, db, q)
		return err == nil && equalRows(got, want)
	}
	const ordersQ = "SELECT id, user_id, total, status FROM orders_copy ORDER BY id"
	const usersQ = "SELECT id, name, email, country, age FROM users_copy ORDER BY id"

	info.PGOrdersCopy = "verified"
	if !check(f.pg, ordersQ, orders) {
		info.PGOrdersCopy = "reloaded+verified"
		log.Printf("loading PostgreSQL orders_copy (%d rows)", len(orders))
		if err := loadCopy(ctx, f.pg, "$", []string{
			"DROP TABLE IF EXISTS orders_copy",
			"CREATE TABLE orders_copy (id INT PRIMARY KEY, user_id INT NOT NULL, total NUMERIC(10,2) NOT NULL, status VARCHAR(16) NOT NULL)",
			"CREATE INDEX orders_copy_user_id ON orders_copy (user_id)",
		}, "INSERT INTO orders_copy (id, user_id, total, status) VALUES ", orders, "ANALYZE orders_copy"); err != nil {
			return info, err
		}
		if !check(f.pg, ordersQ, orders) {
			return info, fmt.Errorf("orders_copy does not match MySQL orders after loading")
		}
	}
	info.MyUsersCopy = "verified"
	if !check(f.my, usersQ, users) {
		info.MyUsersCopy = "reloaded+verified"
		log.Printf("loading MySQL users_copy (%d rows)", len(users))
		if err := loadCopy(ctx, f.my, "?", []string{
			"DROP TABLE IF EXISTS users_copy",
			"CREATE TABLE users_copy (id INT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, country CHAR(2) NOT NULL, age INT NOT NULL) ENGINE=InnoDB",
		}, "INSERT INTO users_copy (id, name, email, country, age) VALUES ", users, "ANALYZE TABLE users_copy"); err != nil {
			return info, err
		}
		if !check(f.my, usersQ, users) {
			return info, fmt.Errorf("users_copy does not match PostgreSQL users after loading")
		}
	}
	return info, nil
}

// loadCopy runs ddl, inserts rows ("a|b|..." strings) in batches of 1000 with
// bind parameters, then runs analyze.
func loadCopy(ctx context.Context, db *sql.DB, ph string, ddl []string, insert string, rows []string, analyze string) error {
	for _, s := range ddl {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	const batch = 1000
	for start := 0; start < len(rows); start += batch {
		end := min(start+batch, len(rows))
		var tuples []string
		var args []any
		for _, r := range rows[start:end] {
			vals := strings.Split(r, "|")
			marks := make([]string, len(vals))
			for i, v := range vals {
				args = append(args, v)
				if ph == "$" {
					marks[i] = "$" + strconv.Itoa(len(args))
				} else {
					marks[i] = "?"
				}
			}
			tuples = append(tuples, "("+strings.Join(marks, ", ")+")")
		}
		if _, err := db.ExecContext(ctx, insert+strings.Join(tuples, ", "), args...); err != nil {
			return err
		}
	}
	_, err := db.ExecContext(ctx, analyze)
	return err
}

// dropCopies removes the co-located copies (never the original tables).
func dropCopies() error {
	f, err := openFixture(2)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if _, err := f.pg.ExecContext(ctx, "DROP TABLE IF EXISTS orders_copy"); err != nil {
		return err
	}
	_, err = f.my.ExecContext(ctx, "DROP TABLE IF EXISTS users_copy")
	return err
}

// --- contestants -------------------------------------------------------------

// rowSink receives result rows; nil means only count them.
type rowSink func(name, total any)

func toStr(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case nil:
		return "<NULL>"
	default:
		return fmt.Sprint(x)
	}
}

// line normalises one (name, total) row so all engines compare equal:
// totals are DECIMAL(10,2) everywhere, printed with two decimals.
func line(name, total any) string {
	t := toStr(total)
	if f, err := strconv.ParseFloat(t, 64); err == nil {
		t = strconv.FormatFloat(f, 'f', 2, 64)
	}
	return toStr(name) + "|" + t
}

func digestLines(lines []string) string {
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

func drainSQL(rows *sql.Rows, sink rowSink) (int, error) {
	defer rows.Close()
	var name, total any
	n := 0
	for rows.Next() {
		if err := rows.Scan(&name, &total); err != nil {
			return n, err
		}
		if sink != nil {
			sink(name, total)
		}
		n++
	}
	return n, rows.Err()
}

func drainResult(res internal.Result, sink rowSink) (int, error) {
	defer res.Close()
	var name, total any
	n := 0
	for res.Next() {
		if err := res.Scan(&name, &total); err != nil {
			return n, err
		}
		if sink != nil {
			sink(name, total)
		}
		n++
	}
	return n, res.Err()
}

type sqlResult struct{ *sql.Rows }

func (r sqlResult) Columns() []string { c, _ := r.Rows.Columns(); return c }

func qualify(alias string, cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = alias + "." + c
	}
	return out
}

type contestant struct {
	Name        string
	Description string
	CrossServer bool // true: rows are extracted from both servers over the network (loopback here)
	query       string
	run         func(ctx context.Context, sink rowSink) (int, error)
}

func contestants(f *fixture, n int) []*contestant {
	uniQ := fmt.Sprintf("SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id <= %d AND o.id <= %d", n, n)
	pgQ := fmt.Sprintf("SELECT u.name, o.total FROM users u JOIN orders_copy o ON u.id = o.user_id WHERE u.id <= %d AND o.id <= %d", n, n)
	myQ := fmt.Sprintf("SELECT u.name, o.total FROM users_copy u JOIN orders o ON u.id = o.user_id WHERE u.id <= %d AND o.id <= %d", n, n)
	return []*contestant{
		{
			Name: "unidb", CrossServer: true,
			Description: "UniDB-Go engine.Engine.Query (parse, security, plan, concurrent extraction from PostgreSQL and MySQL, HashJoinRelations), all rows drained; query: " + uniQ,
			run: func(ctx context.Context, sink rowSink) (int, error) {
				r, _, err := f.eng.Query(ctx, uniQ)
				if err != nil {
					return 0, err
				}
				return drainResult(r, sink)
			},
		},
		{
			Name: "naive", CrossServer: true,
			Description: "baseline of unidb-bench fedscale: sequential extraction (native drivers, MaterializeRelation) + federation.NestedLoopRelations",
			run: func(ctx context.Context, sink rowSink) (int, error) {
				r1, err := f.pg.QueryContext(ctx, "SELECT id, name FROM users WHERE id <= $1", n)
				if err != nil {
					return 0, err
				}
				c1, _ := r1.Columns()
				users, err := federation.MaterializeRelation(sqlResult{r1}, qualify("u", c1))
				r1.Close()
				if err != nil {
					return 0, err
				}
				r2, err := f.my.QueryContext(ctx, "SELECT user_id, total FROM orders WHERE id <= ?", n)
				if err != nil {
					return 0, err
				}
				c2, _ := r2.Columns()
				orders, err := federation.MaterializeRelation(sqlResult{r2}, qualify("o", c2))
				r2.Close()
				if err != nil {
					return 0, err
				}
				j, err := federation.NestedLoopRelations(users, orders, "u.id", "o.user_id")
				if err != nil {
					return 0, err
				}
				if sink != nil {
					// columns: u.id, u.name, o.user_id, o.total
					for _, row := range j.Rows {
						sink(row[1], row[3])
					}
				}
				return len(j.Rows), nil
			},
		},
		{
			Name: "postgres_native", CrossServer: false, query: pgQ,
			Description: "PostgreSQL 16 native join, both tables in PostgreSQL (orders_copy = copy of MySQL orders), lib/pq client drains all rows; query: " + pgQ,
			run: func(ctx context.Context, sink rowSink) (int, error) {
				r, err := f.pg.QueryContext(ctx, pgQ)
				if err != nil {
					return 0, err
				}
				return drainSQL(r, sink)
			},
		},
		{
			Name: "mysql_native", CrossServer: false, query: myQ,
			Description: "MySQL 8.0 native join, both tables in MySQL (users_copy = copy of PostgreSQL users), go-sql-driver client drains all rows; query: " + myQ,
			run: func(ctx context.Context, sink rowSink) (int, error) {
				r, err := f.my.QueryContext(ctx, myQ)
				if err != nil {
					return 0, err
				}
				return drainSQL(r, sink)
			},
		},
	}
}

type contestantResult struct {
	Name         string
	Description  string
	CrossServer  bool
	Rows         int
	Digest       string
	Times        summary
	ColdMS       float64 `json:",omitempty"` // DuckDB only: connect + LOAD + ATTACH + first query
	ColdAttachMS float64 `json:",omitempty"` // DuckDB only: connect + LOAD + ATTACH part of ColdMS
	Skipped      string  `json:",omitempty"`
	Error        string  `json:",omitempty"`
}

type enginePoint struct {
	N            int
	Contestants  []*contestantResult
	RowsMatch    bool
	DigestsMatch bool
	PGPlan       string
	MyPlan       string
	DuckExplain  string `json:",omitempty"`
	// SourceRows counts (untimed) the rows each cross-server plan extracts:
	// UniDB-Go and the naive baseline push only the single-table filters
	// (users id <= n, orders id <= n); DuckDB additionally infers
	// orders.user_id <= n from the join condition (see DuckExplain).
	SourceRows map[string]int
}

type enginesReport struct {
	Meta        meta
	Description string
	Copies      copyInfo
	DuckDB      map[string]any `json:",omitempty"`
	Points      []*enginePoint
}

func explain(ctx context.Context, db *sql.DB, q string) string {
	lines, err := dump(ctx, db, q)
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.Join(lines, "\n")
}

// runEngines compares the contestants for each n. Go contestants run
// interleaved (rotating order each repetition) after one untimed run each
// that also verifies the result multiset; DuckDB runs in a Python child.
func runEngines() error {
	sizes, err := parseSizes([]int{1000, 5000, 10000, 25000, 50000})
	if err != nil {
		return err
	}
	r := repsOr(10)
	nr := *naiveReps
	if nr == 0 {
		nr = r
	}
	f, err := openFixture(8)
	if err != nil {
		return err
	}
	defer f.eng.Close()
	ctx := context.Background()
	rep := enginesReport{Meta: newMeta(), Description: fmt.Sprintf(
		"Join of the first n users (PostgreSQL unidb.users) with the first n orders (MySQL unidb.orders) on users.id = orders.user_id selecting u.name, o.total (same query as unidb-bench fedscale). "+
			"CrossServer=true contestants (unidb, naive, duckdb) extract rows from both servers; CrossServer=false contestants (postgres_native, mysql_native) join inside one server against a co-located copy and only ship the result. "+
			"All servers are on the same host (loopback TCP). Times are client wall-clock ms per query including draining every result row; median and p90 (nearest rank) over -r=%d repetitions (naive: %d). "+
			"Go contestants are interleaved in rotating order; DuckDB runs afterwards in a Python process (ATTACH once, outside the timed region; ColdMS includes connect+LOAD+ATTACH+first query).", r, nr)}
	if rep.Copies, err = ensureCopies(ctx, f); err != nil {
		return err
	}
	log.Printf("copies: %+v", rep.Copies)

	for _, n := range sizes {
		pt := &enginePoint{N: n}
		cs := contestants(f, n)
		results := map[string]*contestantResult{}
		var active []*contestant
		for _, c := range cs {
			res := &contestantResult{Name: c.Name, Description: c.Description, CrossServer: c.CrossServer}
			results[c.Name] = res
			pt.Contestants = append(pt.Contestants, res)
			if c.Name == "naive" && nr < 0 {
				res.Skipped = "-naive-reps=-1"
				continue
			}
			// Untimed verification run, also the warm-up.
			var lines []string
			cnt, err := c.run(ctx, func(a, b any) { lines = append(lines, line(a, b)) })
			if err != nil {
				res.Error = err.Error()
				log.Printf("n=%d %s: %v", n, c.Name, err)
				continue
			}
			res.Rows, res.Digest = cnt, digestLines(lines)
			active = append(active, c)
		}
		pt.PGPlan = explain(ctx, f.pg, "EXPLAIN "+cs[2].query)
		pt.MyPlan = explain(ctx, f.my, "EXPLAIN FORMAT=TREE "+cs[3].query)
		pt.SourceRows = map[string]int{}
		for k, q := range map[string]struct {
			db *sql.DB
			q  string
		}{
			"users_id_le_n":                   {f.pg, fmt.Sprintf("SELECT count(*) FROM users WHERE id <= %d", n)},
			"orders_id_le_n":                  {f.my, fmt.Sprintf("SELECT count(*) FROM orders WHERE id <= %d", n)},
			"orders_id_le_n_and_user_id_le_n": {f.my, fmt.Sprintf("SELECT count(*) FROM orders WHERE id <= %d AND user_id <= %d", n, n)},
		} {
			var c int
			if err := q.db.QueryRowContext(ctx, q.q).Scan(&c); err != nil {
				return err
			}
			pt.SourceRows[k] = c
		}

		times := map[string][]float64{}
		for i := 0; i < r; i++ {
			for k := range active {
				c := active[(i+k)%len(active)]
				if c.Name == "naive" && i >= nr {
					continue
				}
				t := time.Now()
				cnt, err := c.run(ctx, nil)
				d := time.Since(t)
				if err != nil {
					return fmt.Errorf("n=%d %s: %w", n, c.Name, err)
				}
				if cnt != results[c.Name].Rows {
					return fmt.Errorf("n=%d %s: %d rows, verification run had %d", n, c.Name, cnt, results[c.Name].Rows)
				}
				times[c.Name] = append(times[c.Name], msf(d))
			}
		}
		for name, ts := range times {
			results[name].Times = summarize(ts)
		}

		if *pythonBin != "" {
			res := &contestantResult{Name: "duckdb", CrossServer: true}
			pt.Contestants = append(pt.Contestants, res)
			if err := runDuck(n, r, res, pt, &rep); err != nil {
				res.Error = err.Error()
				log.Printf("n=%d duckdb: %v", n, err)
			}
		}

		pt.RowsMatch, pt.DigestsMatch = true, true
		var ref *contestantResult
		for _, c := range pt.Contestants {
			if c.Skipped != "" {
				continue
			}
			if c.Error != "" {
				pt.RowsMatch, pt.DigestsMatch = false, false
				continue
			}
			if ref == nil {
				ref = c
				continue
			}
			pt.RowsMatch = pt.RowsMatch && c.Rows == ref.Rows
			pt.DigestsMatch = pt.DigestsMatch && c.Digest == ref.Digest
		}
		var parts []string
		for _, c := range pt.Contestants {
			parts = append(parts, fmt.Sprintf("%s=%.2f/%.2f", c.Name, c.Times.Median, c.Times.P90))
		}
		log.Printf("n=%6d rows=%d rowsMatch=%v digestsMatch=%v median/p90 ms: %s", n, ref.Rows, pt.RowsMatch, pt.DigestsMatch, strings.Join(parts, " "))
		if !pt.RowsMatch || !pt.DigestsMatch {
			for _, c := range pt.Contestants {
				log.Printf("   %s rows=%d digest=%s err=%s", c.Name, c.Rows, c.Digest, c.Error)
			}
		}
		rep.Points = append(rep.Points, pt)
	}
	return writeJSON("join_engines.json", rep)
}

// runDuck runs the embedded DuckDB script for one n in a fresh Python process.
func runDuck(n, r int, res *contestantResult, pt *enginePoint, rep *enginesReport) error {
	q := fmt.Sprintf("SELECT u.name, o.total FROM pg.public.users u JOIN my.unidb.orders o ON u.id = o.user_id WHERE u.id <= %d AND o.id <= %d", n, n)
	res.Description = "DuckDB (Python) federating both live servers through the postgres and mysql scanner extensions; fetchall() of every row; query: " + q
	cmd := exec.Command(*pythonBin, "-I", "-c", duckScript, *duckPGConn, *duckMyConn, q, strconv.Itoa(r))
	cmd.Dir = os.TempDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, stderr.String())
	}
	var out struct {
		Version      string         `json:"version"`
		ColdMS       float64        `json:"cold_ms"`
		ColdAttachMS float64        `json:"cold_attach_ms"`
		Rows         int            `json:"rows"`
		WarmRows     []int          `json:"warm_rows"`
		Digest       string         `json:"digest"`
		WarmMS       []float64      `json:"warm_ms"`
		Settings     map[string]any `json:"settings"`
		Explain      string         `json:"explain"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return fmt.Errorf("duckdb output: %w (%s)", err, stderr.String())
	}
	for _, w := range out.WarmRows {
		if w != out.Rows {
			return fmt.Errorf("duckdb warm run returned %d rows, cold run %d", w, out.Rows)
		}
	}
	res.Rows, res.Digest, res.ColdMS, res.ColdAttachMS = out.Rows, out.Digest, out.ColdMS, out.ColdAttachMS
	res.Times = summarize(out.WarmMS)
	pt.DuckExplain = out.Explain
	rep.DuckDB = map[string]any{"version": out.Version, "settings": out.Settings, "python": *pythonBin}
	return nil
}
