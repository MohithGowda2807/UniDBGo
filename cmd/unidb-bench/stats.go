package main

// Repeated-measures protocol for the live latency and throughput benchmarks.
//
//	unidb-bench -reps 10 -out bench/results/revision latencyci
//	unidb-bench -reps 10 -out bench/results/revision throughputci
//
// The parent process runs -reps independent repetitions. Each repetition is a
// fresh child process (a re-exec of this binary with the hidden -child-rep and
// -child-result flags) that opens its own connection pools, performs its own
// warm-up, draws its workload from its own seed and starts the native/UniDB-Go
// alternation on the opposite path from the previous repetition. The child
// writes its raw observations to <out>/<kind>_runs/repNN.json; the parent then
// computes per-run statistics, t-intervals across runs and bootstrap intervals
// over the pooled per-query samples, and writes latency_ci.json or
// throughput_ci.json. The procedure inside a repetition mirrors runLatency and
// runThroughput, which are left unchanged.

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	randv2 "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	reps      = flag.Int("reps", 10, "independent repetitions (one child process each) for latencyci/throughputci")
	bootN     = flag.Int("boot", 10000, "bootstrap resamples for latencyci")
	tpDur     = flag.Duration("tpdur", 4*time.Second, "measurement window per path and round in throughputci")
	tpRounds  = flag.Int("tprounds", 5, "alternating rounds per worker count and repetition in throughputci")
	tpWorkers = flag.String("workers", "1,2,4,8,16,32,64", "comma-separated worker counts for throughputci")
	// Hidden flags used when the parent re-executes itself for one repetition.
	childRep    = flag.Int("child-rep", -1, "internal: repetition index of a child process")
	childResult = flag.String("child-result", "", "internal: file a child process writes its raw observations to")
)

const (
	latWarmup  = 200    // warm-up iterations per path and archetype (as in runLatency)
	latPool    = 16     // connection pool per source and path (as in runLatency)
	tpPool     = 64     // connection pool per path (as in runThroughput)
	latKeyBase = 1000   // measured query i uses parameter index i+1000 (as in runLatency)
	ciLevel    = 0.95   // confidence level of every interval
	bootSalt   = 0x5EED // added to the base seed for the bootstrap generator
)

// ---------------------------------------------------------------------------
// Child-side measurement.

// latArchRep holds one repetition's raw observations for one archetype.
type latArchRep struct {
	Name          string
	Runs          int
	Rows          int       // rows returned by the last measured UniDB-Go call
	Native, Uni   []float64 // per-query latency (ms) of successful calls, in execution order
	NativeErrors  int
	UniErrors     int
	RowMismatches int    // pairs where both calls succeeded but returned different row counts
	FirstError    string `json:",omitempty"`
	FirstMismatch string `json:",omitempty"`
	ParseUS       float64
	SecurityUS    float64
	PlanUS        float64
	RouteUS       float64
}

// latRep is what a latencyci child writes.
type latRep struct {
	Rep             int
	Seed            int64
	NativeFirstEven bool // true if the native path runs first in pairs with even i
	PID             int
	ElapsedS        float64
	Archetypes      []latArchRep
}

// latencyRep runs the runLatency procedure once, with seed *seed and the
// alternation start determined by rep, counting errors instead of aborting.
func latencyRep(rep int) (*latRep, error) {
	start := time.Now()
	f, err := openFixture(latPool)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	rng := rand.New(rand.NewSource(*seed))
	out := &latRep{Rep: rep, Seed: *seed, NativeFirstEven: rep%2 == 0, PID: os.Getpid()}
	for _, a := range f.archetypes(rng) {
		for i := 0; i < latWarmup; i++ {
			if _, err := a.native(ctx, i); err != nil {
				return nil, fmt.Errorf("%s native warm-up: %w", a.Name, err)
			}
			if _, _, err := a.unidb(ctx, i); err != nil {
				return nil, fmt.Errorf("%s unidb warm-up: %w", a.Name, err)
			}
		}
		ar := latArchRep{Name: a.Name, Runs: a.Runs}
		var parse, sec, plan, route time.Duration
		noteErr := func(path string, i int, err error) {
			if ar.FirstError == "" {
				ar.FirstError = fmt.Sprintf("%s i=%d: %v", path, i, err)
			}
		}
		native := func(j int) (int, bool) {
			t := time.Now()
			n, err := a.native(ctx, j)
			d := msf(time.Since(t))
			if err != nil {
				ar.NativeErrors++
				noteErr("native", j, err)
				return 0, false
			}
			ar.Native = append(ar.Native, d)
			return n, true
		}
		unidb := func(j int) (int, bool) {
			t := time.Now()
			n, tr, err := a.unidb(ctx, j)
			d := msf(time.Since(t))
			if tr != nil {
				parse, sec, plan, route = parse+tr.ParseTime, sec+tr.SecurityTime, plan+tr.PlanTime, route+tr.RouteTime
			}
			if err != nil {
				ar.UniErrors++
				noteErr("unidb", j, err)
				return 0, false
			}
			ar.Uni = append(ar.Uni, d)
			return n, true
		}
		for i := 0; i < a.Runs; i++ {
			j := i + latKeyBase
			var n, u int
			var okN, okU bool
			if (i+rep)%2 == 0 {
				n, okN = native(j)
				u, okU = unidb(j)
			} else {
				u, okU = unidb(j)
				n, okN = native(j)
			}
			if okU {
				ar.Rows = u
			}
			if okN && okU && n != u {
				ar.RowMismatches++
				if ar.FirstMismatch == "" {
					ar.FirstMismatch = fmt.Sprintf("j=%d native=%d unidb=%d", j, n, u)
				}
			}
		}
		perRunUS := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / float64(a.Runs) / 1e3 }
		ar.ParseUS, ar.SecurityUS, ar.PlanUS, ar.RouteUS = perRunUS(parse), perRunUS(sec), perRunUS(plan), perRunUS(route)
		out.Archetypes = append(out.Archetypes, ar)
		nm, _ := meanSD(ar.Native)
		um, _ := meanSD(ar.Uni)
		fmt.Printf("  rep %d %-24s native %.4f ms unidb %.4f ms  errors %d/%d mismatches %d\n",
			rep, a.Name, nm, um, ar.NativeErrors, ar.UniErrors, ar.RowMismatches)
	}
	for _, s := range f.eng.Sources {
		s.Close()
	}
	f.pg.Close()
	f.my.Close()
	out.ElapsedS = time.Since(start).Seconds()
	return out, nil
}

// tpRound is one measurement window of one path.
type tpRound struct {
	Round      int
	First      bool    // this path ran first in its round
	QPS        float64 // successful queries / nominal window (runThroughput's definition)
	QPSWall    float64 // successful queries / wall time until the last worker returned
	P50, P99   float64 // ms, successful queries pooled across workers
	Done       int64
	Errors     int64
	ElapsedS   float64
	FirstError string `json:",omitempty"`
}

// tpRepPoint is one repetition's observations for one worker count.
type tpRepPoint struct {
	Workers           int
	Native, Uni       []tpRound
	NativeMed, UniMed tpRound // round with the median QPS, as kept by runThroughput
}

// tpRep is what a throughputci child writes.
type tpRep struct {
	Rep             int
	Seed            int64
	NativeFirstEven bool // true if the native path runs first in even rounds
	PID             int
	ElapsedS        float64
	Points          []tpRepPoint
}

func parseWorkers() ([]int, error) {
	var ws []int
	for _, s := range strings.Split(*tpWorkers, ",") {
		w, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || w < 1 || w > tpPool {
			return nil, fmt.Errorf("bad -workers entry %q (want 1..%d)", s, tpPool)
		}
		ws = append(ws, w)
	}
	return ws, nil
}

// throughputRep runs the runThroughput procedure once with seed *seed. Unlike
// runThroughput it also checks Scan/Err on the UniDB-Go result, counts errors
// per window instead of aborting, and records every round.
func throughputRep(rep int) (*tpRep, error) {
	start := time.Now()
	ws, err := parseWorkers()
	if err != nil {
		return nil, err
	}
	f, err := openFixture(tpPool)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	q := "SELECT id, name, email FROM users WHERE id = $1"
	dur := *tpDur
	uniConn := f.eng.Sources["postgres"].Conn().(interface{ SetMaxIdleConns(int) })

	measure := func(workers int, isNative bool, call func(id int) error) tpRound {
		if isNative {
			uniConn.SetMaxIdleConns(0)
			uniConn.SetMaxIdleConns(tpPool)
		} else {
			f.pg.SetMaxIdleConns(0)
			f.pg.SetMaxIdleConns(tpPool)
		}
		var done, failed int64
		var firstErr sync.Once
		var errText string
		lat := make([][]float64, workers)
		begin := time.Now()
		stop := begin.Add(dur)
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
						firstErr.Do(func() { errText = err.Error() })
						continue
					}
					lat[w] = append(lat[w], msf(time.Since(t)))
					atomic.AddInt64(&done, 1)
				}
			}(w)
		}
		wg.Wait()
		elapsed := time.Since(begin)
		var all []float64
		for _, l := range lat {
			all = append(all, l...)
		}
		return tpRound{
			QPS: float64(done) / dur.Seconds(), QPSWall: float64(done) / elapsed.Seconds(),
			P50: pct(all, 50), P99: pct(all, 99), Done: done, Errors: failed,
			ElapsedS: elapsed.Seconds(), FirstError: errText,
		}
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
		defer r.Close()
		var a, b, c any
		for r.Next() {
			if err := r.Scan(&a, &b, &c); err != nil {
				return err
			}
		}
		return r.Err()
	}

	out := &tpRep{Rep: rep, Seed: *seed, NativeFirstEven: rep%2 == 0, PID: os.Getpid()}
	for _, w := range ws {
		p := tpRepPoint{Workers: w}
		for r := 0; r < *tpRounds; r++ {
			nativeFirst := (r+rep)%2 == 0
			runN := func() {
				o := measure(w, true, nativeCall)
				o.Round, o.First = r, nativeFirst
				p.Native = append(p.Native, o)
			}
			runU := func() {
				o := measure(w, false, unified)
				o.Round, o.First = r, !nativeFirst
				p.Uni = append(p.Uni, o)
			}
			if nativeFirst {
				runN()
				runU()
			} else {
				runU()
				runN()
			}
		}
		p.NativeMed, p.UniMed = medianRound(p.Native), medianRound(p.Uni)
		out.Points = append(out.Points, p)
		fmt.Printf("  rep %d workers=%2d native %8.0f qps (err %d) | unidb %8.0f qps (err %d)\n",
			rep, w, p.NativeMed.QPS, sumErr(p.Native), p.UniMed.QPS, sumErr(p.Uni))
	}
	for _, s := range f.eng.Sources {
		s.Close()
	}
	f.pg.Close()
	f.my.Close()
	out.ElapsedS = time.Since(start).Seconds()
	return out, nil
}

// medianRound returns the round with the median QPS (upper median for an even
// count), exactly as runThroughput selects it.
func medianRound(xs []tpRound) tpRound {
	s := append([]tpRound{}, xs...)
	sort.Slice(s, func(i, j int) bool { return s[i].QPS < s[j].QPS })
	return s[len(s)/2]
}

func sumErr(xs []tpRound) (n int64) {
	for _, x := range xs {
		n += x.Errors
	}
	return
}

func sumDone(xs []tpRound) (n int64) {
	for _, x := range xs {
		n += x.Done
	}
	return
}

// ---------------------------------------------------------------------------
// Parent-side orchestration.

// repSeed derives the workload seed of repetition r from the base seed with
// one splitmix64 step, so that repetitions (and the per-worker seeds
// seed+w used inside a throughput repetition) do not share streams.
func repSeed(base int64, r int) int64 {
	z := uint64(base) + uint64(r+1)*0x9E3779B97F4A7C15
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	z ^= z >> 31
	return int64(z >> 1)
}

// runChildren re-executes this binary once per repetition and decodes each
// child's result file. It returns the decoded results and the seeds used.
func runChildren[T any](sub, kind string) ([]*T, []int64, error) {
	if *reps < 2 {
		return nil, nil, fmt.Errorf("%s needs -reps >= 2 for confidence intervals", sub)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(*outDir, kind+"_runs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	var forward []string
	flag.VisitAll(func(f *flag.Flag) {
		switch f.Name {
		case "seed", "child-rep", "child-result":
			return
		}
		forward = append(forward, "-"+f.Name+"="+f.Value.String())
	})
	var out []*T
	var seeds []int64
	for r := 0; r < *reps; r++ {
		s := repSeed(*seed, r)
		path := filepath.Join(dir, fmt.Sprintf("rep%02d.json", r))
		args := append(append([]string{}, forward...),
			fmt.Sprintf("-seed=%d", s), fmt.Sprintf("-child-rep=%d", r), "-child-result="+path, sub)
		fmt.Printf("%s: repetition %d/%d (seed %d) in a fresh process\n", sub, r+1, *reps, s)
		cmd := exec.Command(exe, args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, nil, fmt.Errorf("repetition %d: %w", r, err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		v := new(T)
		if err := json.Unmarshal(b, v); err != nil {
			return nil, nil, fmt.Errorf("repetition %d: %w", r, err)
		}
		out = append(out, v)
		seeds = append(seeds, s)
	}
	return out, seeds, nil
}

func writeChild(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(*childResult, b, 0o644)
}

var dsnPassword = regexp.MustCompile(`(://[^:/@]*:)[^@]*@`)

// environment records the software, host and dataset the run used.
func environment() map[string]any {
	env := map[string]any{
		"go":         runtime.Version(),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
		"num_cpu":    runtime.NumCPU(),
		"gomaxprocs": runtime.GOMAXPROCS(0),
		"pg_dsn":     dsnPassword.ReplaceAllString(*pgDSN, "$1***@"),
		"mysql_dsn":  dsnPassword.ReplaceAllString(*myDSN, "$1***@"),
		"started":    time.Now().UTC().Format(time.RFC3339),
	}
	if h, err := os.Hostname(); err == nil {
		env["hostname"] = h
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if strings.HasPrefix(s.Key, "vcs.") {
				env[s.Key] = s.Value
			}
		}
	}
	if b, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		env["git_head"] = strings.TrimSpace(string(b))
	}
	if b, err := exec.Command("git", "status", "--porcelain", "--", "cmd/unidb-bench").Output(); err == nil {
		env["git_bench_dir_dirty"] = len(strings.TrimSpace(string(b))) > 0
	}
	pgN, myN, err := nativeDSNs()
	if err != nil {
		return env
	}
	query := func(driver, dsn string, qs map[string]string) {
		db, err := sql.Open(driver, dsn)
		if err != nil {
			return
		}
		defer db.Close()
		for k, q := range qs {
			var v string
			if err := db.QueryRow(q).Scan(&v); err == nil {
				env[k] = v
			} else {
				env[k] = "error: " + err.Error()
			}
		}
	}
	query("postgres", pgN, map[string]string{
		"pg_version":         "SELECT version()",
		"pg_max_connections": "SHOW max_connections",
		"pg_users":           "SELECT count(*)::text || ' rows, id ' || min(id) || '..' || max(id) FROM users",
	})
	query("mysql", myN, map[string]string{
		"mysql_version":         "SELECT @@version",
		"mysql_max_connections": "SELECT @@max_connections",
		"mysql_orders":          "SELECT CONCAT(count(*), ' rows, id ', min(id), '..', max(id), ', user_id ', min(user_id), '..', max(user_id)) FROM orders",
	})
	return env
}

// ---------------------------------------------------------------------------
// latencyci

// pathStats summarises one path's per-query latencies (ms).
type pathStats struct {
	N                int
	Mean, SD         float64
	Median, P95, P99 float64
	Min, Max         float64
	Errors           int
}

func describe(xs []float64, errors int) pathStats {
	s := pathStats{N: len(xs), Errors: errors}
	if len(xs) == 0 {
		return s
	}
	s.Mean, s.SD = meanSD(xs)
	s.Median, s.P95, s.P99 = pct(xs, 50), pct(xs, 95), pct(xs, 99)
	s.Min, s.Max = pct(xs, 0), pct(xs, 100)
	return s
}

// latRunStats is one repetition's statistics for one archetype.
type latRunStats struct {
	Rep                                  int
	Seed                                 int64
	NativeFirstEven                      bool
	Native, Uni                          pathStats
	DiffMeanMS, DiffMedianMS             float64
	DiffP95MS, DiffP99MS                 float64
	RelMeanPct, RelMedianPct             float64
	RowMismatches                        int
	FirstError, FirstMismatch            string `json:",omitempty"`
	ParseUS, SecurityUS, PlanUS, RouteUS float64
	Rows                                 int
}

// latArchCI is the cross-run report for one archetype.
type latArchCI struct {
	Name     string
	Workload map[string]any
	PerRun   []latRunStats
	// (i) Across-run t-intervals of per-run differences (UniDB-Go - native).
	MeanDiffMS, MedianDiffMS, P95DiffMS, P99DiffMS tInterval
	// (iii) Across-run t-intervals of per-run relative overhead.
	RelOverheadMeanPct, RelOverheadMedianPct tInterval
	// Across-run t-intervals of each path's per-run mean and median.
	NativeMeanMS, UniMeanMS, NativeMedianMS, UniMedianMS tInterval
	// (ii) Percentile bootstrap over the pooled per-query samples.
	BootMedianDiffMS, BootRelMedianPct bootInterval
	Pooled                             struct{ Native, Uni pathStats }
	TotalNativeErrors, TotalUniErrors  int
	TotalNativeCalls, TotalUniCalls    int
	TotalRowMismatches                 int
}

func runLatencyCI() error {
	if *childResult != "" {
		r, err := latencyRep(*childRep)
		if err != nil {
			return err
		}
		return writeChild(r)
	}
	env := environment()
	t0 := time.Now()
	runsOut, seeds, err := runChildren[latRep]("latencyci", "latency_ci")
	if err != nil {
		return err
	}
	wall := time.Since(t0)
	workloads := latencyWorkloads()
	var archs []latArchCI
	for k := range runsOut[0].Archetypes {
		name := runsOut[0].Archetypes[k].Name
		a := latArchCI{Name: name, Workload: workloads[name]}
		var dMean, dMed, dP95, dP99, rMean, rMed, nMean, uMean, nMed, uMed []float64
		var poolN, poolU []float64
		for _, rr := range runsOut {
			ar := rr.Archetypes[k]
			if ar.Name != name {
				return fmt.Errorf("repetition %d: archetype %d is %q, want %q", rr.Rep, k, ar.Name, name)
			}
			st := latRunStats{
				Rep: rr.Rep, Seed: rr.Seed, NativeFirstEven: rr.NativeFirstEven,
				Native: describe(ar.Native, ar.NativeErrors), Uni: describe(ar.Uni, ar.UniErrors),
				RowMismatches: ar.RowMismatches, FirstError: ar.FirstError, FirstMismatch: ar.FirstMismatch,
				ParseUS: ar.ParseUS, SecurityUS: ar.SecurityUS, PlanUS: ar.PlanUS, RouteUS: ar.RouteUS, Rows: ar.Rows,
			}
			st.DiffMeanMS = st.Uni.Mean - st.Native.Mean
			st.DiffMedianMS = st.Uni.Median - st.Native.Median
			st.DiffP95MS = st.Uni.P95 - st.Native.P95
			st.DiffP99MS = st.Uni.P99 - st.Native.P99
			st.RelMeanPct = 100 * div(st.DiffMeanMS, st.Native.Mean)
			st.RelMedianPct = 100 * div(st.DiffMedianMS, st.Native.Median)
			a.PerRun = append(a.PerRun, st)
			dMean, dMed = append(dMean, st.DiffMeanMS), append(dMed, st.DiffMedianMS)
			dP95, dP99 = append(dP95, st.DiffP95MS), append(dP99, st.DiffP99MS)
			rMean, rMed = append(rMean, st.RelMeanPct), append(rMed, st.RelMedianPct)
			nMean, uMean = append(nMean, st.Native.Mean), append(uMean, st.Uni.Mean)
			nMed, uMed = append(nMed, st.Native.Median), append(uMed, st.Uni.Median)
			poolN, poolU = append(poolN, ar.Native...), append(poolU, ar.Uni...)
			a.TotalNativeErrors += ar.NativeErrors
			a.TotalUniErrors += ar.UniErrors
			a.TotalNativeCalls += ar.Runs
			a.TotalUniCalls += ar.Runs
			a.TotalRowMismatches += ar.RowMismatches
		}
		a.MeanDiffMS, a.MedianDiffMS = tCI(dMean), tCI(dMed)
		a.P95DiffMS, a.P99DiffMS = tCI(dP95), tCI(dP99)
		a.RelOverheadMeanPct, a.RelOverheadMedianPct = tCI(rMean), tCI(rMed)
		a.NativeMeanMS, a.UniMeanMS = tCI(nMean), tCI(uMean)
		a.NativeMedianMS, a.UniMedianMS = tCI(nMed), tCI(uMed)
		a.Pooled.Native, a.Pooled.Uni = describe(poolN, a.TotalNativeErrors), describe(poolU, a.TotalUniErrors)
		bt := time.Now()
		bs := uint64(*seed) + bootSalt + uint64(k)
		a.BootMedianDiffMS, a.BootRelMedianPct = bootMedianDiff(poolN, poolU, *bootN, bs)
		archs = append(archs, a)
		fmt.Printf("%-24s Δmean %+.4f ms [%+.4f, %+.4f]  rel %+.2f%% [%+.2f, %+.2f]  Δmedian(boot) %+.4f [%+.4f, %+.4f]  errors %d/%d mismatches %d  (bootstrap %.1fs)\n",
			name, a.MeanDiffMS.Mean, a.MeanDiffMS.Lo, a.MeanDiffMS.Hi,
			a.RelOverheadMeanPct.Mean, a.RelOverheadMeanPct.Lo, a.RelOverheadMeanPct.Hi,
			a.BootMedianDiffMS.Estimate, a.BootMedianDiffMS.Lo, a.BootMedianDiffMS.Hi,
			a.TotalNativeErrors, a.TotalUniErrors, a.TotalRowMismatches, time.Since(bt).Seconds())
	}
	var repElapsed []float64
	for _, rr := range runsOut {
		repElapsed = append(repElapsed, rr.ElapsedS)
	}
	env["finished"] = time.Now().UTC().Format(time.RFC3339)
	report := map[string]any{
		"Experiment":  "latencyci",
		"Command":     redactArgs(os.Args),
		"Environment": env,
		"Protocol": map[string]any{
			"repetitions":          *reps,
			"base_seed":            *seed,
			"rep_seeds":            seeds,
			"seed_derivation":      "rep r uses splitmix64(base_seed + (r+1)*0x9E3779B97F4A7C15) >> 1",
			"independence":         "each repetition is a separate OS process (re-exec of the binary) with fresh connection pools, its own warm-up and its own workload seed; repetitions run serially",
			"pool_per_source":      latPool,
			"warmup":               fmt.Sprintf("%d calls per path per archetype (parameter index j=0..%d, native then UniDB-Go), immediately before that archetype's measured runs", latWarmup, latWarmup-1),
			"alternation":          "measured pair i (parameter index j=i+1000) runs native then UniDB-Go when (i+rep)%2==0, otherwise UniDB-Go then native; so consecutive repetitions start on opposite paths",
			"timer":                "client-side wall time (time.Now/time.Since, monotonic clock) around the call including draining every row, in ms",
			"errors":               "a failed call is counted per path and excluded from the latency samples; row-count mismatches between successful paired calls are counted (runLatency aborts on them instead)",
			"archetype_order":      "fixed: point lookup, parameterised filter, aggregation, federated join",
			"percentiles":          "nearest-rank: sorted[ceil(p/100*n)-1]; the median is the nearest-rank 50th percentile",
			"t_interval":           "for each archetype, statistic computed per repetition, then mean ± t(0.975, R-1)·sd/√R across the R repetitions",
			"bootstrap":            fmt.Sprintf("percentile bootstrap, %d resamples; native and UniDB-Go pooled per-query samples resampled independently with replacement (sizes equal to the pooled sizes); statistic median(UniDB-Go*) - median(native*) and 100·(median(UniDB-Go*)/median(native*) - 1); interval = order statistics floor(0.025·B) and ceil(0.975·B)-1 (0-based); generator PCG(base_seed+0x5EED+archetype_index, 0) from math/rand/v2", *bootN),
			"relative_overhead":    "per repetition 100·(mean_uni - mean_native)/mean_native (and the same with medians), then t-interval across repetitions",
			"confidence_level":     ciLevel,
			"child_raw_data":       filepath.Join(*outDir, "latency_ci_runs", "repNN.json"),
			"measurement_wall_s":   wall.Seconds(),
			"repetition_elapsed_s": repElapsed,
		},
		"Archetypes": archs,
	}
	return writeJSON("latency_ci.json", report)
}

// latencyWorkloads documents, per archetype, the SQL and how its parameters
// are drawn; it must be kept in step with fixture.archetypes.
func latencyWorkloads() map[string]map[string]any {
	keys := fmt.Sprintf("keys[0..19999]: 20,000 ids drawn once per repetition, i.i.d. uniform on {1..%d} (1+rng.Intn(%d), Go math/rand with rand.NewSource(rep_seed)); shared by the point lookup and the filter", *rows, *rows)
	fed := *runs / 5
	if fed < 200 {
		fed = 200
	}
	return map[string]map[string]any{
		"Point lookup (literal)": {
			"runs_per_rep": *runs,
			"unidb_sql":    "SELECT id, name, email FROM users WHERE id = <k>",
			"native_sql":   "SELECT id, name, email FROM users WHERE id = <k> (same literal text, PostgreSQL driver)",
			"parameters":   "k = keys[j mod 20000], j = i+1000 for measured run i (warm-up j = 0..199); " + keys,
			"rows":         "1 per call",
		},
		"Parameterised filter": {
			"runs_per_rep": *runs,
			"unidb_sql":    "SELECT id, name FROM users WHERE country = $1 AND id > $2 ORDER BY id LIMIT 20",
			"native_sql":   "same text with bound parameters on the PostgreSQL driver",
			"parameters":   "$1 = countries[j mod 10] with countries = IN,US,DE,BR,JP,FR,GB,CA,AU,SG (deterministic round robin); $2 = keys[j mod 20000]; j = i+1000; " + keys,
			"rows":         "up to 20 per call",
		},
		"Aggregation": {
			"runs_per_rep": *runs / 5,
			"unidb_sql":    "SELECT country, COUNT(*), AVG(age) FROM users GROUP BY country",
			"native_sql":   "same text on the PostgreSQL driver",
			"parameters":   "none (identical query every run; full scan of users)",
		},
		"Federated join": {
			"runs_per_rep": fed,
			"unidb_sql":    "SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.country = '<c>' AND o.status = '<s>'",
			"native_sql":   "hand-written: concurrently SELECT id, name FROM users WHERE country = $1 (PostgreSQL) and SELECT user_id, total FROM orders WHERE status = ? (MySQL), then a Go map join on id = user_id",
			"parameters":   "c = countries[j mod 10], s = statuses[j mod 5] with statuses = paid,shipped,pending,cancelled,refunded; j = i+1000; deterministic round robin, so only 10 distinct (c, s) pairs occur",
			"runs_rule":    "max(runs/5, 200)",
		},
	}
}

// ---------------------------------------------------------------------------
// throughputci

// tpRunStats is one repetition's statistics for one worker count.
type tpRunStats struct {
	Rep                             int
	Seed                            int64
	NativeFirstEven                 bool
	Native, Uni                     tpRound // median-QPS rounds
	QPSRatio                        float64 // Uni.QPS / Native.QPS (median rounds)
	QPSRatioAllRounds               float64 // mean QPS over all rounds, UniDB-Go / native
	NativeErrors, UniErrors         int64   // over all rounds
	NativeQueries, UniQueries       int64   // successful + failed, over all rounds
	NativeErrorRate, UniErrorRate   float64
	NativeFirstError, UniFirstError string `json:",omitempty"`
}

// tpPointCI is the cross-run report for one worker count.
type tpPointCI struct {
	Workers                              int
	PerRun                               []tpRunStats
	QPSRatio, QPSRatioAllRounds          tInterval
	RelQPSPct                            tInterval // 100·(ratio-1)
	NativeQPS, UniQPS                    tInterval
	NativeP50, NativeP99, UniP50, UniP99 tInterval
	NativeErrors, UniErrors              int64
	NativeQueries, UniQueries            int64
	NativeErrorRate, UniErrorRate        float64
	TotalErrors, TotalQueries            int64
	TotalErrorRate                       float64
}

func runThroughputCI() error {
	if *childResult != "" {
		r, err := throughputRep(*childRep)
		if err != nil {
			return err
		}
		return writeChild(r)
	}
	if _, err := parseWorkers(); err != nil {
		return err
	}
	env := environment()
	t0 := time.Now()
	runsOut, seeds, err := runChildren[tpRep]("throughputci", "throughput_ci")
	if err != nil {
		return err
	}
	wall := time.Since(t0)
	var pts []tpPointCI
	var csv strings.Builder
	csv.WriteString("workers ratio ratio_lo ratio_hi nqps nqps_lo nqps_hi uqps uqps_lo uqps_hi nerr uerr nqueries uqueries\n")
	for k := range runsOut[0].Points {
		w := runsOut[0].Points[k].Workers
		p := tpPointCI{Workers: w}
		var ratio, ratioAll, rel, nq, uq, np50, np99, up50, up99 []float64
		for _, rr := range runsOut {
			rp := rr.Points[k]
			if rp.Workers != w {
				return fmt.Errorf("repetition %d: point %d has %d workers, want %d", rr.Rep, k, rp.Workers, w)
			}
			st := tpRunStats{Rep: rr.Rep, Seed: rr.Seed, NativeFirstEven: rr.NativeFirstEven, Native: rp.NativeMed, Uni: rp.UniMed}
			st.QPSRatio = div(rp.UniMed.QPS, rp.NativeMed.QPS)
			st.QPSRatioAllRounds = div(meanQPS(rp.Uni), meanQPS(rp.Native))
			st.NativeErrors, st.UniErrors = sumErr(rp.Native), sumErr(rp.Uni)
			st.NativeQueries, st.UniQueries = st.NativeErrors+sumDone(rp.Native), st.UniErrors+sumDone(rp.Uni)
			st.NativeErrorRate = frac(st.NativeErrors, st.NativeQueries)
			st.UniErrorRate = frac(st.UniErrors, st.UniQueries)
			st.NativeFirstError, st.UniFirstError = firstErr(rp.Native), firstErr(rp.Uni)
			p.PerRun = append(p.PerRun, st)
			ratio, ratioAll, rel = append(ratio, st.QPSRatio), append(ratioAll, st.QPSRatioAllRounds), append(rel, 100*(st.QPSRatio-1))
			nq, uq = append(nq, rp.NativeMed.QPS), append(uq, rp.UniMed.QPS)
			np50, np99 = append(np50, rp.NativeMed.P50), append(np99, rp.NativeMed.P99)
			up50, up99 = append(up50, rp.UniMed.P50), append(up99, rp.UniMed.P99)
			p.NativeErrors += st.NativeErrors
			p.UniErrors += st.UniErrors
			p.NativeQueries += st.NativeQueries
			p.UniQueries += st.UniQueries
		}
		p.QPSRatio, p.QPSRatioAllRounds, p.RelQPSPct = tCI(ratio), tCI(ratioAll), tCI(rel)
		p.NativeQPS, p.UniQPS = tCI(nq), tCI(uq)
		p.NativeP50, p.NativeP99, p.UniP50, p.UniP99 = tCI(np50), tCI(np99), tCI(up50), tCI(up99)
		p.NativeErrorRate, p.UniErrorRate = frac(p.NativeErrors, p.NativeQueries), frac(p.UniErrors, p.UniQueries)
		p.TotalErrors, p.TotalQueries = p.NativeErrors+p.UniErrors, p.NativeQueries+p.UniQueries
		p.TotalErrorRate = frac(p.TotalErrors, p.TotalQueries)
		pts = append(pts, p)
		fmt.Printf("workers=%2d ratio %.4f [%.4f, %.4f]  native %.0f qps  unidb %.0f qps  errors native %d/%d unidb %d/%d\n",
			w, p.QPSRatio.Mean, p.QPSRatio.Lo, p.QPSRatio.Hi, p.NativeQPS.Mean, p.UniQPS.Mean,
			p.NativeErrors, p.NativeQueries, p.UniErrors, p.UniQueries)
		fmt.Fprintf(&csv, "%d %.5f %.5f %.5f %.1f %.1f %.1f %.1f %.1f %.1f %d %d %d %d\n", w,
			p.QPSRatio.Mean, p.QPSRatio.Lo, p.QPSRatio.Hi, p.NativeQPS.Mean, p.NativeQPS.Lo, p.NativeQPS.Hi,
			p.UniQPS.Mean, p.UniQPS.Lo, p.UniQPS.Hi, p.NativeErrors, p.UniErrors, p.NativeQueries, p.UniQueries)
	}
	var repElapsed []float64
	for _, rr := range runsOut {
		repElapsed = append(repElapsed, rr.ElapsedS)
	}
	env["finished"] = time.Now().UTC().Format(time.RFC3339)
	report := map[string]any{
		"Experiment":  "throughputci",
		"Command":     redactArgs(os.Args),
		"Environment": env,
		"Protocol": map[string]any{
			"repetitions":          *reps,
			"base_seed":            *seed,
			"rep_seeds":            seeds,
			"seed_derivation":      "rep r uses splitmix64(base_seed + (r+1)*0x9E3779B97F4A7C15) >> 1",
			"independence":         "each repetition is a separate OS process (re-exec of the binary) with fresh connection pools and its own workload seed; repetitions run serially",
			"pool_per_path":        tpPool,
			"pool_release":         "before each window the other path's idle PostgreSQL connections are released (SetMaxIdleConns(0) then restored) so the two pools never exceed max_connections together",
			"workers":              *tpWorkers,
			"window_s":             tpDur.Seconds(),
			"rounds":               *tpRounds,
			"warmup":               "none beyond the alternating rounds themselves (as in runThroughput); every round is recorded in the raw data so early rounds can be inspected",
			"alternation":          "per worker count, round r runs native then UniDB-Go when (r+rep)%2==0, otherwise UniDB-Go then native",
			"per_run_statistic":    "per repetition, path and worker count, the round with the median QPS (sorted by QPS, element len/2) as in runThroughput; QPS = successful queries / nominal window",
			"qps_wall":             "QPSWall = successful queries / time until the last worker returned (in-flight queries finish after the window closes); recorded in raw data and PerRun",
			"latency":              "per-query client latency of successful calls, pooled over workers of the median round, nearest-rank p50/p99 in ms",
			"errors":               "every failed call (query, scan, rows.Err) is counted per window and path; the failing worker continues immediately; error rate = failed / (failed + successful) over all rounds",
			"t_interval":           "mean ± t(0.975, R-1)·sd/√R of the per-repetition values across the R repetitions",
			"confidence_level":     ciLevel,
			"child_raw_data":       filepath.Join(*outDir, "throughput_ci_runs", "repNN.json"),
			"measurement_wall_s":   wall.Seconds(),
			"repetition_elapsed_s": repElapsed,
		},
		"Workload": map[string]any{
			"sql":         "SELECT id, name, email FROM users WHERE id = $1 (bound parameter, both paths, PostgreSQL)",
			"parameters":  fmt.Sprintf("each worker w draws id = 1+rng.Intn(%d), i.i.d. uniform on {1..%d}, from Go math/rand with rand.NewSource(rep_seed + w); the generator is re-created for every window, so within a repetition every round and both paths replay the same per-worker id streams (truncated where the window ends)", *rows, *rows),
			"closed_loop": "each worker issues its next query as soon as the previous one returns (no think time)",
		},
		"Points": pts,
	}
	if err := writeFile("throughput_ci.dat", csv.String()); err != nil {
		return err
	}
	return writeJSON("throughput_ci.json", report)
}

func meanQPS(xs []tpRound) float64 {
	s := 0.0
	for _, x := range xs {
		s += x.QPS
	}
	return s / float64(len(xs))
}

func firstErr(xs []tpRound) string {
	for _, x := range xs {
		if x.FirstError != "" {
			return x.FirstError
		}
	}
	return ""
}

// div returns a/b, or 0 when b is 0 (a path with no successful query; the
// error counts in the report show when this happened). JSON cannot hold NaN.
func div(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func frac(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = dsnPassword.ReplaceAllString(a, "$1***@")
	}
	return out
}

// ---------------------------------------------------------------------------
// Statistics.

// tInterval is a Student-t confidence interval for the mean of per-run values.
type tInterval struct {
	N            int
	Mean, SD, SE float64
	DF           int
	TCrit        float64
	Lo, Hi       float64
	PValueZero   float64 // two-sided one-sample t-test of mean = 0
	Values       []float64
}

func tCI(xs []float64) tInterval {
	m, sd := meanSD(xs)
	n := len(xs)
	ti := tInterval{N: n, Mean: m, SD: sd, DF: n - 1, Values: xs}
	if n < 2 {
		return ti
	}
	ti.SE = sd / math.Sqrt(float64(n))
	ti.TCrit = tQuantile(1-(1-ciLevel)/2, float64(n-1))
	ti.Lo, ti.Hi = m-ti.TCrit*ti.SE, m+ti.TCrit*ti.SE
	if ti.SE > 0 {
		ti.PValueZero = 2 * (1 - tCDF(math.Abs(m/ti.SE), float64(n-1)))
	} else {
		ti.PValueZero = 1
	}
	return ti
}

// bootInterval is a percentile-bootstrap confidence interval.
type bootInterval struct {
	Estimate  float64 // statistic on the observed pooled samples
	Lo, Hi    float64
	Resamples int
	Seed      uint64
	NNative   int
	NUni      int
	BootMean  float64
	BootSD    float64
}

// bootMedianDiff bootstraps median(uni) - median(native) and the relative
// difference 100·(median(uni)/median(native) - 1), resampling each pooled
// sample independently with replacement.
func bootMedianDiff(nat, uni []float64, b int, seed uint64) (diff, rel bootInterval) {
	sn := append([]float64{}, nat...)
	su := append([]float64{}, uni...)
	sort.Float64s(sn)
	sort.Float64s(su)
	diff = bootInterval{Resamples: b, Seed: seed, NNative: len(sn), NUni: len(su)}
	rel = diff
	if len(sn) == 0 || len(su) == 0 || b < 1 {
		return
	}
	mn, mu := pct(sn, 50), pct(su, 50)
	diff.Estimate, rel.Estimate = mu-mn, 100*(div(mu, mn)-1)
	rng := randv2.New(randv2.NewPCG(seed, 0))
	cn := make([]int32, len(sn))
	cu := make([]int32, len(su))
	ds := make([]float64, b)
	rs := make([]float64, b)
	for i := 0; i < b; i++ {
		bn := resampledMedian(sn, cn, rng)
		bu := resampledMedian(su, cu, rng)
		ds[i], rs[i] = bu-bn, 100*(div(bu, bn)-1)
	}
	fill := func(bi *bootInterval, xs []float64) {
		bi.BootMean, bi.BootSD = meanSD(xs)
		sort.Float64s(xs)
		bi.Lo = xs[int(math.Floor((1-ciLevel)/2*float64(b)))]
		bi.Hi = xs[int(math.Ceil((1+ciLevel)/2*float64(b)))-1]
	}
	fill(&diff, ds)
	fill(&rel, rs)
	return
}

// resampledMedian draws len(sorted) indices uniformly with replacement and
// returns the nearest-rank median of the resample. Because sorted is
// ascending, the k-th smallest resampled value is sorted[idx] for the
// smallest idx whose cumulative draw count exceeds k.
func resampledMedian(sorted []float64, counts []int32, rng *randv2.Rand) float64 {
	n := len(sorted)
	clear(counts)
	for i := 0; i < n; i++ {
		counts[rng.IntN(n)]++
	}
	k := int(math.Ceil(0.5*float64(n))) - 1
	cum := 0
	for idx, c := range counts {
		cum += int(c)
		if cum > k {
			return sorted[idx]
		}
	}
	return sorted[n-1]
}

// tCDF is the Student-t distribution function with df degrees of freedom.
func tCDF(t, df float64) float64 {
	ib := regIncBeta(df/2, 0.5, df/(df+t*t))
	if t >= 0 {
		return 1 - 0.5*ib
	}
	return 0.5 * ib
}

// tQuantile inverts tCDF by bisection for p in (0.5, 1).
func tQuantile(p, df float64) float64 {
	lo, hi := 0.0, 1e4
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		if tCDF(mid, df) < p {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// regIncBeta is the regularised incomplete beta function I_x(a, b),
// evaluated with the continued fraction of Numerical Recipes (betacf).
func regIncBeta(a, b, x float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	lab, _ := math.Lgamma(a + b)
	la, _ := math.Lgamma(a)
	lb, _ := math.Lgamma(b)
	front := math.Exp(lab - la - lb + a*math.Log(x) + b*math.Log(1-x))
	if x < (a+1)/(a+b+2) {
		return front * betaCF(a, b, x) / a
	}
	return 1 - front*betaCF(b, a, 1-x)/b
}

func betaCF(a, b, x float64) float64 {
	const tiny = 1e-300
	clamp := func(v float64) float64 {
		if math.Abs(v) < tiny {
			return tiny
		}
		return v
	}
	qab, qap, qam := a+b, a+1, a-1
	c, d := 1.0, 1/clamp(1-qab*x/qap)
	h := d
	for m := 1; m <= 500; m++ {
		mf, m2 := float64(m), float64(2*m)
		aa := mf * (b - mf) * x / ((qam + m2) * (a + m2))
		d = 1 / clamp(1+aa*d)
		c = clamp(1 + aa/c)
		h *= d * c
		aa = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2))
		d = 1 / clamp(1+aa*d)
		c = clamp(1 + aa/c)
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-15 {
			break
		}
	}
	return h
}
