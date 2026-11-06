// Command eval-fault runs reproducible fault-injection scenarios against
// UniDB-Go: sources are reached through in-process TCP proxies (proxy.go)
// that refuse, cut, blackhole or delay connections, so the shared database
// servers are never stopped. It also checks transaction behaviour. Results
// are written as JSON.
//
//	go run ./cmd/eval-fault -setup -n 20 -out bench/results/revision/fault.json
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/pool"
	"github.com/Dheeran-git/UniDBGo/security"
)

var (
	pgURI    = flag.String("pg", "postgres://postgres:pass@127.0.0.1:5432/unidb_fault", "PostgreSQL source (a scratch database)")
	myURI    = flag.String("my", "mysql://unidb:pass@127.0.0.1:3306/unidb_fault", "MySQL source (a scratch database)")
	trials   = flag.Int("n", 20, "repetitions per scenario")
	rowsN    = flag.Int("rows", 500000, "rows per side for -setup")
	doSetup  = flag.Bool("setup", false, "(re)create the fault_* tables in the scratch databases")
	only     = flag.String("only", "", "comma-separated scenario numbers to run (default all)")
	outPath  = flag.String("out", "bench/results/revision/fault.json", "output JSON")
	poolSize = flag.Int("pool", 4, "max open connections per source")
)

const (
	fullQ  = "SELECT u.name, o.total FROM postgres.fault_users u JOIN mysql.fault_orders o ON u.id = o.user_id"
	smallQ = "SELECT u.name, o.total FROM postgres.fault_users u JOIN mysql.fault_orders o ON u.id = o.user_id WHERE u.id <= 1000 AND o.id <= 1000"
)

// env holds the proxies, the proxied connection strings and direct
// (unproxied) handles used to verify server-side state.
type env struct {
	pgP, myP           *proxy
	pgVia, myVia       string
	pgDirect, myDirect *sql.DB
	sec                *security.SecurityEngine
}

func (e *env) proxyOf(side string) *proxy {
	if side == "postgres" {
		return e.pgP
	}
	return e.myP
}

func other(side string) string {
	if side == "postgres" {
		return "mysql"
	}
	return "postgres"
}

// via rewrites the host:port of a connection URI.
func via(uri, addr string) string {
	i := strings.Index(uri, "@")
	j := strings.Index(uri[i:], "/")
	return uri[:i+1] + addr + uri[i+j:]
}

func setupEnv() (*env, error) {
	pc, err := api.ParseConnectionString(*pgURI)
	if err != nil {
		return nil, err
	}
	mc, err := api.ParseConnectionString(*myURI)
	if err != nil {
		return nil, err
	}
	if pc.Database == "unidb" || mc.Database == "unidb" {
		return nil, fmt.Errorf("refusing to use the benchmark database unidb; use a scratch database")
	}
	e := &env{sec: security.NewSecurityEngine()}
	if e.pgP, err = newProxy("postgres", net.JoinHostPort(pc.Host, strconv.Itoa(pc.Port))); err != nil {
		return nil, err
	}
	if e.myP, err = newProxy("mysql", net.JoinHostPort(mc.Host, strconv.Itoa(mc.Port))); err != nil {
		return nil, err
	}
	e.pgVia, e.myVia = via(*pgURI, e.pgP.addr), via(*myURI, e.myP.addr)
	e.pgDirect, err = sql.Open("postgres", fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", pc.Username, pc.Password, pc.Host, pc.Port, pc.Database))
	if err != nil {
		return nil, err
	}
	e.myDirect, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", mc.Username, mc.Password, mc.Host, mc.Port, mc.Database))
	if err != nil {
		return nil, err
	}
	// One pre-opened connection each, so verification queries never change
	// the goroutine count used for leak detection.
	for _, db := range []*sql.DB{e.pgDirect, e.myDirect} {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		if err := db.Ping(); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// newEngine connects both sources through the proxies, with the security
// middleware installed on each handle, as a deployment would.
func (e *env) newEngine() (*engine.Engine, error) { return e.newEngineWith("") }

// newEngineWith is newEngine with extra URI parameters for PostgreSQL.
func (e *env) newEngineWith(pgParams string) (*engine.Engine, error) {
	uri := e.pgVia
	if pgParams != "" {
		sep := "?"
		if strings.Contains(uri, "?") {
			sep = "&"
		}
		uri += sep + pgParams
	}
	pg, err := api.Connect(uri, api.WithMaxPool(*poolSize))
	if err != nil {
		return nil, err
	}
	my, err := api.Connect(e.myVia, api.WithMaxPool(*poolSize))
	if err != nil {
		pg.Close()
		return nil, err
	}
	for _, db := range []*api.DB{pg, my} {
		db.Use(security.SecurityMiddleware(e.sec))
	}
	return &engine.Engine{Sources: map[string]*api.DB{"postgres": pg, "mysql": my}, Default: "postgres", Security: e.sec}, nil
}

func (e *env) healAll() {
	for _, p := range []*proxy{e.pgP, e.myP} {
		if err := p.heal(); err != nil {
			log.Fatalf("heal %s: %v", p.name, err)
		}
	}
}

func runSetup(e *env) error {
	ctx := context.Background()
	for _, s := range []string{
		"DROP TABLE IF EXISTS fault_users, fault_tx, fault_snap",
		"CREATE TABLE fault_users (id INT PRIMARY KEY, name TEXT NOT NULL, country CHAR(2) NOT NULL)",
		fmt.Sprintf("INSERT INTO fault_users SELECT g, 'user_' || g, (ARRAY['IN','US','DE','BR','JP'])[1 + g %% 5] FROM generate_series(1, %d) g", *rowsN),
		"CREATE TABLE fault_tx (id INT PRIMARY KEY, note TEXT NOT NULL)",
		"CREATE TABLE fault_snap (id INT PRIMARY KEY, ver INT NOT NULL)",
		"INSERT INTO fault_snap VALUES (1, 0)",
		"ANALYZE",
	} {
		if _, err := e.pgDirect.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("postgres setup %q: %w", s, err)
		}
	}
	conn, err := e.myDirect.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, s := range []string{
		"DROP TABLE IF EXISTS fault_orders, fault_tx, fault_snap",
		"CREATE TABLE fault_orders (id INT PRIMARY KEY, user_id INT NOT NULL, total DECIMAL(10,2) NOT NULL, status VARCHAR(16) NOT NULL) ENGINE=InnoDB",
		"SET SESSION cte_max_recursion_depth = 10000000",
		fmt.Sprintf("INSERT INTO fault_orders WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < %d) SELECT n, n, (n %% 1000) + 0.99, ELT(1 + n %% 5, 'paid','shipped','pending','cancelled','refunded') FROM s", *rowsN),
		"CREATE TABLE fault_tx (id INT PRIMARY KEY, note VARCHAR(64) NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE fault_snap (id INT PRIMARY KEY, ver INT NOT NULL) ENGINE=InnoDB",
		"INSERT INTO fault_snap VALUES (1, 0)",
	} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("mysql setup %q: %w", s, err)
		}
	}
	return nil
}

// clientGoroutines counts goroutines outside the fault proxy, so proxy
// relays do not hide or fake a leak in the code under test.
func clientGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if len(bytes.TrimSpace(g)) > 0 && !bytes.Contains(g, []byte("main.(*proxy)")) {
			count++
		}
	}
	return count
}

// settle waits up to max for client goroutines to fall to base and returns
// the remaining excess.
func settle(base int, max time.Duration) int {
	deadline := time.Now().Add(max)
	for {
		d := clientGoroutines() - base
		if d <= 0 || time.Now().After(deadline) {
			return d
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// poolStats reports database/sql pool counters of a source.
type poolStats struct {
	Open  int `json:"open"`
	InUse int `json:"in_use"`
	Idle  int `json:"idle"`
}

func statsOf(db *api.DB) poolStats {
	t, ok := db.Conn().(pool.Tunable)
	if !ok {
		return poolStats{-1, -1, -1}
	}
	s := t.PoolStats()
	return poolStats{s.OpenConnections, s.InUse, s.Idle}
}

// serverActive counts statements on the server (seen directly, not through
// the proxy) whose text mentions table.
func (e *env) serverActive(side, table string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n int
	var err error
	if side == "postgres" {
		err = e.pgDirect.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid() AND query LIKE '%"+table+"%'").Scan(&n)
	} else {
		err = e.myDirect.QueryRowContext(ctx, "SELECT COUNT(*) FROM performance_schema.processlist WHERE db = DATABASE() AND command = 'Query' AND id <> CONNECTION_ID() AND info LIKE '%"+table+"%'").Scan(&n)
	}
	if err != nil {
		return -1
	}
	return n
}

// serverStopMs polls until no statement mentioning table runs on side and
// returns the elapsed milliseconds (0 if none was running), or -1 on timeout.
func (e *env) serverStopMs(side, table string, max time.Duration) float64 {
	t0 := time.Now()
	for time.Since(t0) < max {
		if e.serverActive(side, table) == 0 {
			return ms(time.Since(t0))
		}
		time.Sleep(10 * time.Millisecond)
	}
	return -1
}

func ms(d time.Duration) float64 { return math.Round(float64(d.Nanoseconds())/100) / 10000 }

// dist summarises a sample of durations in milliseconds.
type dist struct {
	N    int     `json:"n"`
	Min  float64 `json:"min_ms"`
	P50  float64 `json:"p50_ms"`
	P95  float64 `json:"p95_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

func summarize(xs []float64) dist {
	if len(xs) == 0 {
		return dist{}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	q := func(p float64) float64 { return s[int(math.Ceil(p*float64(len(s))))-1] }
	r := func(x float64) float64 { return math.Round(x*10000) / 10000 }
	return dist{len(s), r(s[0]), r(q(0.5)), r(q(0.95)), r(s[len(s)-1]), r(sum / float64(len(s)))}
}

// drain reads every row of res and returns the count and the final error.
func drain(res internal.Result) (int, error) {
	defer res.Close()
	cols := res.Columns()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	n := 0
	for res.Next() {
		if err := res.Scan(ptrs...); err != nil {
			return n, err
		}
		n++
	}
	return n, res.Err()
}

// runQuery executes q through the engine and drains it.
func runQuery(ctx context.Context, eng *engine.Engine, q string) (int, error) {
	res, _, err := eng.Query(ctx, q)
	if err != nil {
		return 0, err
	}
	return drain(res)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// countErrs groups error messages, trimming volatile port numbers.
func countErrs(errs []string) map[string]int {
	out := map[string]int{}
	for _, s := range errs {
		if s == "" {
			s = "<nil>"
		}
		out[normalizeErr(s)]++
	}
	return out
}

var portRE = regexp.MustCompile(`127\.0\.0\.1:\d+`)

// normalizeErr replaces ephemeral loopback ports so equal errors group.
func normalizeErr(s string) string { return portRE.ReplaceAllString(s, "127.0.0.1:<port>") }

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)
	e, err := setupEnv()
	if err != nil {
		log.Fatal(err)
	}
	if *doSetup {
		log.Print("setup: creating fault_* tables")
		if err := runSetup(e); err != nil {
			log.Fatal(err)
		}
	}
	want := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}
	out := map[string]any{
		"experiment": "fault tolerance and transaction behaviour (cmd/eval-fault)",
		"date":       time.Now().UTC().Format(time.RFC3339),
		"config": map[string]any{
			"trials_per_scenario": *trials, "pool_max_open": *poolSize,
			"go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0),
			"full_query": fullQ, "small_query": smallQ,
			"pg_source": redact(*pgURI), "mysql_source": redact(*myURI),
			"proxy": "in-process TCP forwarder per source; refuse=listener closed + live conns closed (FIN); cut=all relayed conns closed (FIN); blackhole=no bytes relayed, new conns accepted but never answered; latency=each client->server chunk is held for the given delay (adds that delay to every request/response round trip)",
		},
	}
	scenarios := []struct {
		id  string
		key string
		run func(*env) (any, error)
	}{
		{"0", "baseline", baseline},
		{"1", "s1_source_refused", scenarioRefused},
		{"2", "s2_cut_mid_scan", scenarioCut},
		{"3", "s3_blackhole_deadline", scenarioBlackhole},
		{"4", "s4_latency_injection", scenarioLatency},
		{"5", "s5_recovery", scenarioRecovery},
		{"6", "s6_circuit_breaker", scenarioBreaker},
		{"7", "s7_transactions", scenarioTx},
	}
	prev := map[string]any{}
	if b, err := os.ReadFile(*outPath); err == nil && len(want) > 0 {
		_ = json.Unmarshal(b, &prev)
	}
	for _, s := range scenarios {
		if len(want) > 0 && !want[s.id] {
			if v, ok := prev[s.key]; ok {
				out[s.key] = v // keep results of scenarios not re-run
			}
			continue
		}
		log.Printf("scenario %s: %s", s.id, s.key)
		e.healAll()
		r, err := s.run(e)
		e.healAll()
		if err != nil {
			log.Printf("scenario %s failed: %v", s.id, err)
			out[s.key] = map[string]any{"harness_error": err.Error()}
			continue
		}
		out[s.key] = r
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		log.Fatal(err)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(*outPath, b, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *outPath)
}

func redact(uri string) string {
	i := strings.Index(uri, "://")
	j := strings.Index(uri, "@")
	if i < 0 || j < 0 {
		return uri
	}
	user := uri[i+3 : j]
	if k := strings.Index(user, ":"); k >= 0 {
		user = user[:k] + ":***"
	}
	return uri[:i+3] + user + uri[j:]
}
