package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/federation"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/security"
)

var countries = []string{"IN", "US", "DE", "BR", "JP", "FR", "GB", "CA", "AU", "SG"}
var statuses = []string{"paid", "shipped", "pending", "cancelled", "refunded"}

// nativeDSNs converts the URIs into the DSN formats each native driver expects.
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

func runSetup() error {
	pgN, myN, err := nativeDSNs()
	if err != nil {
		return err
	}
	pg, err := sql.Open("postgres", pgN)
	if err != nil {
		return err
	}
	defer pg.Close()
	my, err := sql.Open("mysql", myN)
	if err != nil {
		return err
	}
	defer my.Close()
	rng := rand.New(rand.NewSource(*seed))
	ctx := context.Background()

	for _, s := range []string{
		"DROP TABLE IF EXISTS users",
		"CREATE TABLE users (id INT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, country CHAR(2) NOT NULL, age INT NOT NULL)",
	} {
		if _, err := pg.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	for _, s := range []string{
		"DROP TABLE IF EXISTS orders",
		"CREATE TABLE orders (id INT PRIMARY KEY, user_id INT NOT NULL, total DECIMAL(10,2) NOT NULL, status VARCHAR(16) NOT NULL, KEY (user_id)) ENGINE=InnoDB",
	} {
		if _, err := my.ExecContext(ctx, s); err != nil {
			return err
		}
	}

	const batch = 1000
	for start := 1; start <= *rows; start += batch {
		var vals []string
		for i := start; i < start+batch && i <= *rows; i++ {
			vals = append(vals, fmt.Sprintf("(%d, 'user%d', 'user%d@example.com', '%s', %d)",
				i, i, i, countries[rng.Intn(len(countries))], 18+rng.Intn(60)))
		}
		if _, err := pg.ExecContext(ctx, "INSERT INTO users VALUES "+strings.Join(vals, ",")); err != nil {
			return err
		}
		vals = vals[:0]
		for i := start; i < start+batch && i <= *rows; i++ {
			vals = append(vals, fmt.Sprintf("(%d, %d, %d.%02d, '%s')",
				i, 1+rng.Intn(*rows), rng.Intn(500), rng.Intn(100), statuses[rng.Intn(len(statuses))]))
		}
		if _, err := my.ExecContext(ctx, "INSERT INTO orders VALUES "+strings.Join(vals, ",")); err != nil {
			return err
		}
	}
	if _, err := pg.ExecContext(ctx, "ANALYZE users"); err != nil {
		return err
	}
	if _, err := my.ExecContext(ctx, "ANALYZE TABLE orders"); err != nil {
		return err
	}
	fmt.Printf("loaded %d users (PostgreSQL) and %d orders (MySQL)\n", *rows, *rows)
	return nil
}

// fixture holds the native handles and the UniDB-Go engine over the same
// drivers and pool sizes.
type fixture struct {
	pg, my *sql.DB
	eng    *engine.Engine
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

func drainNative(rows *sql.Rows) (int, error) {
	defer rows.Close()
	cols, _ := rows.Columns()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	n := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func drainUnified(res internal.Result) int {
	defer res.Close()
	cols := res.Columns()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	n := 0
	for res.Next() {
		if res.Scan(ptrs...) == nil {
			n++
		}
	}
	return n
}

type archetype struct {
	Name   string
	Runs   int
	native func(ctx context.Context, i int) (int, error)
	unidb  func(ctx context.Context, i int) (int, *engine.Trace, error)
}

type latencySummary struct {
	Name                 string
	Runs                 int
	NativeMean, NativeSD float64
	UniMean, UniSD       float64
	NativeP50, NativeP99 float64
	UniP50, UniP99       float64
	DeltaMS, OverheadPct float64
	WelchT, PValue       float64
	ParseUS, SecurityUS  float64
	PlanUS, RouteUS      float64
	Rows                 int
}

func (f *fixture) archetypes(rng *rand.Rand) []archetype {
	n := *rows
	keys := make([]int, 20000)
	for i := range keys {
		keys[i] = 1 + rng.Intn(n)
	}
	fedRuns := *runs / 5
	if fedRuns < 200 {
		fedRuns = 200
	}
	return []archetype{
		{
			Name: "Point lookup (literal)", Runs: *runs,
			native: func(ctx context.Context, i int) (int, error) {
				r, err := f.pg.QueryContext(ctx, "SELECT id, name, email FROM users WHERE id = "+strconv.Itoa(keys[i%len(keys)]))
				if err != nil {
					return 0, err
				}
				return drainNative(r)
			},
			unidb: func(ctx context.Context, i int) (int, *engine.Trace, error) {
				r, tr, err := f.eng.Query(ctx, "SELECT id, name, email FROM users WHERE id = "+strconv.Itoa(keys[i%len(keys)]))
				if err != nil {
					return 0, tr, err
				}
				return drainUnified(r), tr, nil
			},
		},
		{
			Name: "Parameterised filter", Runs: *runs,
			native: func(ctx context.Context, i int) (int, error) {
				r, err := f.pg.QueryContext(ctx, "SELECT id, name FROM users WHERE country = $1 AND id > $2 ORDER BY id LIMIT 20",
					countries[i%len(countries)], keys[i%len(keys)])
				if err != nil {
					return 0, err
				}
				return drainNative(r)
			},
			unidb: func(ctx context.Context, i int) (int, *engine.Trace, error) {
				r, tr, err := f.eng.Query(ctx, "SELECT id, name FROM users WHERE country = $1 AND id > $2 ORDER BY id LIMIT 20",
					countries[i%len(countries)], keys[i%len(keys)])
				if err != nil {
					return 0, tr, err
				}
				return drainUnified(r), tr, nil
			},
		},
		{
			Name: "Aggregation", Runs: *runs / 5,
			native: func(ctx context.Context, i int) (int, error) {
				r, err := f.pg.QueryContext(ctx, "SELECT country, COUNT(*), AVG(age) FROM users GROUP BY country")
				if err != nil {
					return 0, err
				}
				return drainNative(r)
			},
			unidb: func(ctx context.Context, i int) (int, *engine.Trace, error) {
				r, tr, err := f.eng.Query(ctx, "SELECT country, COUNT(*), AVG(age) FROM users GROUP BY country")
				if err != nil {
					return 0, tr, err
				}
				return drainUnified(r), tr, nil
			},
		},
		{
			Name: "Federated join", Runs: fedRuns,
			native: func(ctx context.Context, i int) (int, error) {
				return f.handWrittenJoin(ctx, countries[i%len(countries)], statuses[i%len(statuses)])
			},
			unidb: func(ctx context.Context, i int) (int, *engine.Trace, error) {
				q := fmt.Sprintf("SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.country = '%s' AND o.status = '%s'",
					countries[i%len(countries)], statuses[i%len(statuses)])
				r, tr, err := f.eng.Query(ctx, q)
				if err != nil {
					return 0, tr, err
				}
				return drainUnified(r), tr, nil
			},
		},
	}
}

// handWrittenJoin is what an application writes without UniDB-Go: two
// concurrent queries and a map-based join with manual key conversion.
func (f *fixture) handWrittenJoin(ctx context.Context, country, status string) (int, error) {
	type user struct{ name string }
	users := map[int64]user{}
	var orders [][2]any
	var wg sync.WaitGroup
	var e1, e2 error
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, err := f.pg.QueryContext(ctx, "SELECT id, name FROM users WHERE country = $1", country)
		if err != nil {
			e1 = err
			return
		}
		defer r.Close()
		for r.Next() {
			var id int64
			var name string
			if e1 = r.Scan(&id, &name); e1 != nil {
				return
			}
			users[id] = user{name}
		}
	}()
	go func() {
		defer wg.Done()
		r, err := f.my.QueryContext(ctx, "SELECT user_id, total FROM orders WHERE status = ?", status)
		if err != nil {
			e2 = err
			return
		}
		defer r.Close()
		for r.Next() {
			var uid int64
			var total string
			if e2 = r.Scan(&uid, &total); e2 != nil {
				return
			}
			orders = append(orders, [2]any{uid, total})
		}
	}()
	wg.Wait()
	if e1 != nil {
		return 0, e1
	}
	if e2 != nil {
		return 0, e2
	}
	n := 0
	for _, o := range orders {
		if _, ok := users[o[0].(int64)]; ok {
			n++
		}
	}
	return n, nil
}

func runLatency() error {
	f, err := openFixture(16)
	if err != nil {
		return err
	}
	ctx := context.Background()
	rng := rand.New(rand.NewSource(*seed))
	var out []latencySummary
	for _, a := range f.archetypes(rng) {
		// Warm-up both paths.
		for i := 0; i < 200; i++ {
			if _, err := a.native(ctx, i); err != nil {
				return fmt.Errorf("%s native: %w", a.Name, err)
			}
			if _, _, err := a.unidb(ctx, i); err != nil {
				return fmt.Errorf("%s unidb: %w", a.Name, err)
			}
		}
		nat := make([]float64, a.Runs)
		uni := make([]float64, a.Runs)
		var parse, sec, plan, route time.Duration
		var nrows, urows int
		// Interleave the two paths so that drift affects both equally.
		for i := 0; i < a.Runs; i++ {
			j := i + 1000
			if i%2 == 0 {
				t := time.Now()
				nrows, _ = a.native(ctx, j)
				nat[i] = msf(time.Since(t))
				t = time.Now()
				var tr *engine.Trace
				urows, tr, _ = a.unidb(ctx, j)
				uni[i] = msf(time.Since(t))
				parse, sec, plan, route = parse+tr.ParseTime, sec+tr.SecurityTime, plan+tr.PlanTime, route+tr.RouteTime
			} else {
				t := time.Now()
				var tr *engine.Trace
				urows, tr, _ = a.unidb(ctx, j)
				uni[i] = msf(time.Since(t))
				parse, sec, plan, route = parse+tr.ParseTime, sec+tr.SecurityTime, plan+tr.PlanTime, route+tr.RouteTime
				t = time.Now()
				nrows, _ = a.native(ctx, j)
				nat[i] = msf(time.Since(t))
			}
			if nrows != urows {
				return fmt.Errorf("%s: row count mismatch native=%d unidb=%d", a.Name, nrows, urows)
			}
		}
		s := latencySummary{Name: a.Name, Runs: a.Runs, Rows: urows}
		s.NativeMean, s.NativeSD = meanSD(nat)
		s.UniMean, s.UniSD = meanSD(uni)
		s.NativeP50, s.NativeP99 = pct(nat, 50), pct(nat, 99)
		s.UniP50, s.UniP99 = pct(uni, 50), pct(uni, 99)
		s.DeltaMS = s.UniMean - s.NativeMean
		s.OverheadPct = 100 * s.DeltaMS / s.NativeMean
		s.WelchT, s.PValue = welch(nat, uni)
		perRunUS := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / float64(a.Runs) / 1e3 }
		s.ParseUS, s.SecurityUS = perRunUS(parse), perRunUS(sec)
		s.PlanUS, s.RouteUS = perRunUS(plan), perRunUS(route)
		out = append(out, s)
		fmt.Printf("%-24s native %.3f±%.3f  unidb %.3f±%.3f  Δ=%+.3f ms (%+.1f%%) p=%.2g  parse=%.1fµs sec=%.1fµs plan=%.1fµs rows=%d\n",
			s.Name, s.NativeMean, s.NativeSD, s.UniMean, s.UniSD, s.DeltaMS, s.OverheadPct, s.PValue, s.ParseUS, s.SecurityUS, s.PlanUS, s.Rows)
	}
	return writeJSON("latency.json", out)
}

type tpPoint struct {
	Workers              int
	NativeQPS, UniQPS    float64
	NativeP50, NativeP99 float64
	UniP50, UniP99       float64
}

func runThroughput() error {
	const pool = 64
	f, err := openFixture(pool)
	if err != nil {
		return err
	}
	ctx := context.Background()
	q := "SELECT id, name, email FROM users WHERE id = $1"
	dur := 4 * time.Second
	const rounds = 5

	// Both paths open up to `pool` connections to the same server, whose
	// default max_connections is 100. Before measuring one path, release the
	// idle connections held by the other so neither is starved.
	uniConn := f.eng.Sources["postgres"].Conn().(interface{ SetMaxIdleConns(int) })
	var failed int64
	measure := func(workers int, isNative bool, call func(id int) error) (float64, float64, float64) {
		if isNative {
			uniConn.SetMaxIdleConns(0)
			uniConn.SetMaxIdleConns(pool)
		} else {
			f.pg.SetMaxIdleConns(0)
			f.pg.SetMaxIdleConns(pool)
		}
		var done int64
		lat := make([][]float64, workers)
		stop := time.Now().Add(dur)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(int64(w) + *seed))
				for time.Now().Before(stop) {
					t := time.Now()
					if err := call(1 + rng.Intn(*rows)); err != nil {
						atomic.AddInt64(&failed, 1)
						continue
					}
					lat[w] = append(lat[w], msf(time.Since(t)))
					atomic.AddInt64(&done, 1)
				}
			}(w)
		}
		wg.Wait()
		var all []float64
		for _, l := range lat {
			all = append(all, l...)
		}
		return float64(done) / dur.Seconds(), pct(all, 50), pct(all, 99)
	}

	nativeCall := func(id int) error {
		r, err := f.pg.QueryContext(ctx, q, id)
		if err != nil {
			return err
		}
		_, err = drainNative(r)
		return err
	}
	unified := func(id int) error {
		r, _, err := f.eng.Query(ctx, q, id)
		if err != nil {
			return err
		}
		drainUnified(r)
		return nil
	}

	var pts []tpPoint
	for _, w := range []int{1, 2, 4, 8, 16, 32, 64} {
		// Alternate the two paths over several rounds and keep the round with
		// the median throughput of each, so that a transient disturbance on
		// the shared host does not decide the comparison.
		type obs struct{ qps, p50, p99 float64 }
		var nat, uni []obs
		for r := 0; r < rounds; r++ {
			// Alternate which path goes first so neither always runs on a
			// colder or warmer server.
			runNative := func() {
				a, b, c := measure(w, true, nativeCall)
				nat = append(nat, obs{a, b, c})
			}
			runUnified := func() {
				a, b, c := measure(w, false, unified)
				uni = append(uni, obs{a, b, c})
			}
			if r%2 == 0 {
				runNative()
				runUnified()
			} else {
				runUnified()
				runNative()
			}
		}
		med := func(xs []obs) obs {
			sort.Slice(xs, func(i, j int) bool { return xs[i].qps < xs[j].qps })
			return xs[len(xs)/2]
		}
		n, u := med(nat), med(uni)
		p := tpPoint{Workers: w, NativeQPS: n.qps, NativeP50: n.p50, NativeP99: n.p99, UniQPS: u.qps, UniP50: u.p50, UniP99: u.p99}
		pts = append(pts, p)
		fmt.Printf("workers=%2d native %8.0f qps p50=%.3f p99=%.3f | unidb %8.0f qps p50=%.3f p99=%.3f\n",
			w, p.NativeQPS, p.NativeP50, p.NativeP99, p.UniQPS, p.UniP50, p.UniP99)
	}
	if failed > 0 {
		return fmt.Errorf("throughput: %d queries failed", failed)
	}
	var csv strings.Builder
	csv.WriteString("workers nqps uqps np50 np99 up50 up99\n")
	for _, p := range pts {
		fmt.Fprintf(&csv, "%d %.1f %.1f %.4f %.4f %.4f %.4f\n", p.Workers, p.NativeQPS, p.UniQPS, p.NativeP50, p.NativeP99, p.UniP50, p.UniP99)
	}
	if err := writeFile("throughput.dat", csv.String()); err != nil {
		return err
	}
	return writeJSON("throughput.json", pts)
}

type fedPoint struct {
	N         int
	UniMS     float64
	NestedMS  float64
	ExtractMS float64
	Rows      int
}

// runFedScale joins the first N users with the first N orders across the two
// live databases: UniDB-Go (concurrent extraction + hash join) against
// sequential extraction followed by an application-side nested loop.
func runFedScale() error {
	f, err := openFixture(8)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var pts []fedPoint
	for _, n := range []int{500, 1000, 2500, 5000, 10000, 25000, 50000} {
		q := fmt.Sprintf("SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id <= %d AND o.id <= %d", n, n)
		var urows int
		uni := timeIt(5, func() {
			r, _, err := f.eng.Query(ctx, q)
			if err != nil {
				panic(err)
			}
			urows = drainUnified(r)
		})
		var users, orders federation.Relation
		extract := func() {
			r1, _ := f.pg.QueryContext(ctx, "SELECT id, name FROM users WHERE id <= $1", n)
			c1, _ := r1.Columns()
			users, _ = federation.MaterializeRelation(sqlResult{r1}, qualify("u", c1))
			r1.Close()
			r2, _ := f.my.QueryContext(ctx, "SELECT user_id, total FROM orders WHERE id <= ?", n)
			c2, _ := r2.Columns()
			orders, _ = federation.MaterializeRelation(sqlResult{r2}, qualify("o", c2))
			r2.Close()
		}
		ext := timeIt(3, extract)
		reps := 3
		if n >= 25000 {
			reps = 1
		}
		var nrows int
		nested := timeIt(reps, func() {
			extract()
			j, _ := federation.NestedLoopRelations(users, orders, "u.id", "o.user_id")
			nrows = len(j.Rows)
		})
		if nrows != urows {
			return fmt.Errorf("n=%d: row mismatch unidb=%d nested=%d", n, urows, nrows)
		}
		p := fedPoint{N: n, UniMS: ms(uni), NestedMS: ms(nested), ExtractMS: ms(ext), Rows: urows}
		pts = append(pts, p)
		fmt.Printf("n=%6d unidb=%9.2f ms  extract+nested=%11.1f ms (extract %.1f ms) rows=%d speedup=%.1fx\n",
			n, p.UniMS, p.NestedMS, p.ExtractMS, p.Rows, p.NestedMS/p.UniMS)
	}
	var csv strings.Builder
	csv.WriteString("n unidb nested extract\n")
	for _, p := range pts {
		fmt.Fprintf(&csv, "%d %.4f %.4f %.4f\n", p.N, p.UniMS, p.NestedMS, p.ExtractMS)
	}
	if err := writeFile("fedscale.dat", csv.String()); err != nil {
		return err
	}
	return writeJSON("fedscale.json", pts)
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

func msf(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64{}, xs...)
	sort.Float64s(s)
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return s[i]
}

// welch returns Welch's t statistic and a two-sided p-value from the normal
// approximation, which is accurate for the sample sizes used here (n ≥ 200).
func welch(a, b []float64) (float64, float64) {
	ma, sa := meanSD(a)
	mb, sb := meanSD(b)
	se := math.Sqrt(sa*sa/float64(len(a)) + sb*sb/float64(len(b)))
	if se == 0 {
		return 0, 1
	}
	t := (mb - ma) / se
	p := math.Erfc(math.Abs(t) / math.Sqrt2)
	return t, p
}
