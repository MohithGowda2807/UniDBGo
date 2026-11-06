package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Dheeran-git/UniDBGo/federation"
)

// buildUsers and buildOrders mirror syntheticRelations in
// cmd/unidb-bench/join.go: n users with int64 ids (as lib/pq returns them)
// and m orders whose values are []byte (as the MySQL text protocol returns
// them; -right-type=string gives the strings that
// federation.MaterializeRelation actually stores), each order referencing a
// uniformly random user. -payload adds 16-byte string columns to both sides.
// Call buildUsers first: both draw from rng in that order.
func buildUsers(n int, rng *rand.Rand) (users federation.Relation) {
	users.Columns = []string{"u.id", "u.name"}
	for p := 0; p < *payload; p++ {
		users.Columns = append(users.Columns, "u.p"+strconv.Itoa(p))
	}
	users.Rows = make([][]any, 0, n)
	for i := 0; i < n; i++ {
		row := []any{int64(i + 1), "user" + strconv.Itoa(i+1)}
		for p := 0; p < *payload; p++ {
			row = append(row, fmt.Sprintf("%016x", rng.Uint64()))
		}
		users.Rows = append(users.Rows, row)
	}
	return
}

func buildOrders(n, m int, rng *rand.Rand) (orders federation.Relation) {
	orders.Columns = []string{"o.id", "o.user_id", "o.total"}
	for p := 0; p < *payload; p++ {
		orders.Columns = append(orders.Columns, "o.p"+strconv.Itoa(p))
	}
	val := func(s string) any {
		if *rightTyp == "string" {
			return s
		}
		return []byte(s)
	}
	orders.Rows = make([][]any, 0, m)
	for i := 0; i < m; i++ {
		row := []any{
			val(strconv.Itoa(i + 1)),
			val(strconv.Itoa(rng.Intn(n) + 1)),
			val(fmt.Sprintf("%d.%02d", rng.Intn(500), rng.Intn(100))),
		}
		for p := 0; p < *payload; p++ {
			row = append(row, val(fmt.Sprintf("%016x", rng.Uint64())))
		}
		orders.Rows = append(orders.Rows, row)
	}
	return
}

// heapPeaks are the largest values seen by a sampler, in bytes.
type heapPeaks struct {
	HeapObjects uint64 // live + not-yet-swept heap objects (= MemStats.HeapAlloc)
	HeapInuse   uint64 // heap objects + fragmentation in in-use spans (= MemStats.HeapInuse)
	RuntimeMem  uint64 // all memory mapped by the Go runtime minus released pages: what GOMEMLIMIT governs
}

// sampler polls runtime/metrics on a ticker and keeps the maxima.
type sampler struct {
	stop chan struct{}
	done chan heapPeaks
}

var sampleNames = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/total:bytes",
	"/memory/classes/heap/released:bytes",
}

func readPeaks(ms []metrics.Sample, p *heapPeaks) {
	metrics.Read(ms)
	obj, unused := ms[0].Value.Uint64(), ms[1].Value.Uint64()
	rt := ms[2].Value.Uint64() - ms[3].Value.Uint64()
	p.HeapObjects = max(p.HeapObjects, obj)
	p.HeapInuse = max(p.HeapInuse, obj+unused)
	p.RuntimeMem = max(p.RuntimeMem, rt)
}

func startSampler() *sampler {
	s := &sampler{stop: make(chan struct{}), done: make(chan heapPeaks, 1)}
	go func() {
		ms := make([]metrics.Sample, len(sampleNames))
		for i, n := range sampleNames {
			ms[i].Name = n
		}
		var p heapPeaks
		t := time.NewTicker(time.Duration(*sampleUS) * time.Microsecond)
		defer t.Stop()
		for {
			readPeaks(ms, &p)
			select {
			case <-s.stop:
				readPeaks(ms, &p)
				s.done <- p
				return
			case <-t.C:
			}
		}
	}()
	return s
}

func (s *sampler) Stop() heapPeaks { close(s.stop); return <-s.done }

// liveHeap forces two full collections and returns the live heap in bytes.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// buildTableReplica repeats the build phase of federation.HashJoinRelations
// (same key normalisation, FNV-1a hash, entry type and map layout) so that the
// memory retained by the hash table alone can be measured; the library does
// not expose it separately.
func buildTableReplica(build federation.Relation, bi int) map[uint64][]tableEntry {
	table := make(map[uint64][]tableEntry, len(build.Rows))
	for _, row := range build.Rows {
		k, ok := federation.NormalizeKey(row[bi])
		if !ok {
			continue
		}
		h := fnv64a(k)
		table[h] = append(table[h], tableEntry{k, row})
	}
	return table
}

type tableEntry struct {
	key string
	row []any
}

// fnv64a copies the unexported hash of federation/join.go.
func fnv64a(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// typedHashJoin is a type-specialised reference join on the same relations:
// int64 keys parsed directly from the MySQL-side bytes (no string
// normalisation), a map from key to the first build row with chained
// duplicates, and output rows carved from shared slabs. It produces the same
// output rows as HashJoinRelations (users columns, then orders columns) and
// shows how much of the generic join's cost is due to driver-agnostic keys.
func typedHashJoin(users, orders federation.Relation, ui, oi int) [][]any {
	head := make(map[int64]int32, len(users.Rows))
	next := make([]int32, len(users.Rows))
	for i, row := range users.Rows {
		id := row[ui].(int64)
		if h, ok := head[id]; ok {
			next[i] = h
		} else {
			next[i] = -1
		}
		head[id] = int32(i)
	}
	wl := len(users.Columns)
	w := wl + len(orders.Columns)
	var out [][]any
	var slab []any
	for _, p := range orders.Rows {
		k, ok := parseIntKey(p[oi])
		if !ok {
			continue
		}
		h, ok := head[k]
		if !ok {
			continue
		}
		for j := h; j >= 0; j = next[j] {
			if len(slab) < w {
				slab = make([]any, w*4096)
			}
			m := slab[:w:w]
			slab = slab[w:]
			copy(m, users.Rows[j])
			copy(m[wl:], p)
			out = append(out, m)
		}
	}
	return out
}

func parseIntKey(v any) (int64, bool) {
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	case string:
		b = []byte(x)
	case int64:
		return x, true
	default:
		return 0, false
	}
	if len(b) == 0 {
		return 0, false
	}
	neg := b[0] == '-'
	if neg {
		b = b[1:]
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

// joinChildResult is what one child process measures for one size.
type joinChildResult struct {
	N, M, Reps, PayloadCols int
	RightType               string
	BuildSide               string
	GOMEMLIMIT              int64 // bytes, as set in the runtime (math.MaxInt64 = none)
	GOGC                    string
	SampleIntervalUS        int
	OutputRows              int

	JoinMS summary

	// Retained (live after full GC) heap, bytes.
	BaselineHeapBytes uint64
	UsersBytes        uint64
	OrdersBytes       uint64
	InputBytes        uint64
	HashTableBytes    uint64 `json:",omitempty"` // replica of the build phase, see buildTableReplica
	OutputBytes       uint64 `json:",omitempty"`

	// Per repetition of the join.
	AllocBytesPerJoin []uint64
	MallocsPerJoin    []uint64
	GCsPerJoin        []uint32
	GCPauseMSPerJoin  []float64
	GCCPUFraction     float64 // MemStats.GCCPUFraction at the end of the child

	// Sampled peaks during the joins (max over repetitions) and over the
	// child's whole life (input construction included).
	PreJoinHeapBytes  uint64
	JoinPeak          heapPeaks
	LifetimePeak      heapPeaks
	JoinTransientPeak uint64 // JoinPeak.HeapObjects - PreJoinHeapBytes

	// Derived ratios.
	InputBytesPerRow          float64
	HashTableBytesPerBuildRow float64 `json:",omitempty"`
	OutputBytesPerOutputRow   float64 `json:",omitempty"`
	AllocBytesPerInputRow     float64 // median AllocBytesPerJoin / (N+M)
	PeakHeapBytesPerInputRow  float64 // (JoinPeak.HeapObjects - BaselineHeapBytes) / (N+M)

	Typed *typedResult `json:",omitempty"`
}

type typedResult struct {
	Description       string
	OutputRows        int
	JoinMS            summary
	AllocBytesPerJoin []uint64
	JoinPeakHeap      uint64
	OutputBytes       uint64
}

// runJoinChild runs inside a fresh process: build the relations, measure
// their retained size, then time HashJoinRelations -r times while sampling
// the heap. The JSON result goes to stdout.
func runJoinChild() error {
	life := startSampler()
	n := *childN
	r := repsOr(5)
	res := joinChildResult{N: n, M: n, Reps: r, PayloadCols: *payload, RightType: *rightTyp,
		GOMEMLIMIT: debug.SetMemoryLimit(-1), GOGC: os.Getenv("GOGC"), SampleIntervalUS: *sampleUS}
	rng := rand.New(rand.NewSource(*seed))

	res.BaselineHeapBytes = liveHeap()
	users := buildUsers(n, rng)
	h1 := liveHeap()
	orders := buildOrders(n, n, rng)
	h2 := liveHeap()
	fmt.Fprintf(os.Stderr, "phase: inputs built (live heap %d bytes)\n", h2)
	res.UsersBytes = h1 - res.BaselineHeapBytes
	res.OrdersBytes = h2 - h1
	res.InputBytes = h2 - res.BaselineHeapBytes
	res.BuildSide = "users (left)"
	build, bi := users, 0
	if len(orders.Rows) < len(users.Rows) {
		res.BuildSide, build, bi = "orders (right)", orders, 1
	}
	inputs := liveHeap()

	if *childParts {
		tbl := buildTableReplica(build, bi)
		res.HashTableBytes = liveHeap() - inputs
		runtime.KeepAlive(tbl)
		tbl = nil
		inputs = liveHeap()
	}

	var times []float64
	var out federation.Relation
	var pre uint64
	for i := 0; i < r; i++ {
		out = federation.Relation{}
		pre = liveHeap()
		fmt.Fprintf(os.Stderr, "phase: join %d start (live heap %d bytes)\n", i+1, pre)
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		s := startSampler()
		t := time.Now()
		j, err := federation.HashJoinRelations(users, orders, "u.id", "o.user_id")
		d := time.Since(t)
		p := s.Stop()
		runtime.ReadMemStats(&m1)
		if err != nil {
			return err
		}
		out = j
		fmt.Fprintf(os.Stderr, "phase: join %d done in %.1f ms\n", i+1, msf(d))
		times = append(times, msf(d))
		res.AllocBytesPerJoin = append(res.AllocBytesPerJoin, m1.TotalAlloc-m0.TotalAlloc)
		res.MallocsPerJoin = append(res.MallocsPerJoin, m1.Mallocs-m0.Mallocs)
		res.GCsPerJoin = append(res.GCsPerJoin, m1.NumGC-m0.NumGC)
		res.GCPauseMSPerJoin = append(res.GCPauseMSPerJoin, float64(m1.PauseTotalNs-m0.PauseTotalNs)/1e6)
		res.JoinPeak.HeapObjects = max(res.JoinPeak.HeapObjects, p.HeapObjects)
		res.JoinPeak.HeapInuse = max(res.JoinPeak.HeapInuse, p.HeapInuse)
		res.JoinPeak.RuntimeMem = max(res.JoinPeak.RuntimeMem, p.RuntimeMem)
	}
	res.OutputRows = len(out.Rows)
	res.PreJoinHeapBytes = pre
	res.JoinMS = summarize(times)
	if *childParts {
		res.OutputBytes = liveHeap() - pre
	}
	runtime.KeepAlive(out.Rows)
	out = federation.Relation{}

	rows := float64(n + n)
	res.InputBytesPerRow = float64(res.InputBytes) / rows
	if res.HashTableBytes > 0 {
		res.HashTableBytesPerBuildRow = float64(res.HashTableBytes) / float64(len(build.Rows))
	}
	if res.OutputBytes > 0 && res.OutputRows > 0 {
		res.OutputBytesPerOutputRow = float64(res.OutputBytes) / float64(res.OutputRows)
	}
	allocs := make([]float64, len(res.AllocBytesPerJoin))
	for i, a := range res.AllocBytesPerJoin {
		allocs[i] = float64(a)
	}
	res.AllocBytesPerInputRow = summarize(allocs).Median / rows
	res.JoinTransientPeak = res.JoinPeak.HeapObjects - min(res.PreJoinHeapBytes, res.JoinPeak.HeapObjects)
	res.PeakHeapBytesPerInputRow = float64(res.JoinPeak.HeapObjects-min(res.BaselineHeapBytes, res.JoinPeak.HeapObjects)) / rows

	if !*noTyped && *childParts {
		t := &typedResult{Description: "type-specialised Go hash join: int64 keys parsed from bytes, map[int64]int32 + chain, slab-allocated output rows"}
		var ttimes []float64
		var tout [][]any
		var tpre uint64
		for i := 0; i < r; i++ {
			tout = nil
			tpre = liveHeap()
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			s := startSampler()
			st := time.Now()
			tout = typedHashJoin(users, orders, 0, 1)
			d := time.Since(st)
			p := s.Stop()
			runtime.ReadMemStats(&m1)
			ttimes = append(ttimes, msf(d))
			t.AllocBytesPerJoin = append(t.AllocBytesPerJoin, m1.TotalAlloc-m0.TotalAlloc)
			t.JoinPeakHeap = max(t.JoinPeakHeap, p.HeapObjects)
		}
		t.OutputRows = len(tout)
		t.JoinMS = summarize(ttimes)
		t.OutputBytes = liveHeap() - tpre
		runtime.KeepAlive(tout)
		if t.OutputRows != res.OutputRows {
			return fmt.Errorf("typed join returned %d rows, HashJoinRelations %d", t.OutputRows, res.OutputRows)
		}
		res.Typed = t
	}
	runtime.KeepAlive(users)
	runtime.KeepAlive(orders)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.GCCPUFraction = ms.GCCPUFraction
	res.LifetimePeak = life.Stop()
	// Both samplers poll; the lifetime peak is at least the join peak.
	res.LifetimePeak.HeapObjects = max(res.LifetimePeak.HeapObjects, res.JoinPeak.HeapObjects)
	res.LifetimePeak.HeapInuse = max(res.LifetimePeak.HeapInuse, res.JoinPeak.HeapInuse)
	res.LifetimePeak.RuntimeMem = max(res.LifetimePeak.RuntimeMem, res.JoinPeak.RuntimeMem)
	return json.NewEncoder(os.Stdout).Encode(res)
}

// childOutcome is what the parent observes about one child process.
type childOutcome struct {
	Env         []string `json:",omitempty"`
	Completed   bool
	ExitCode    int
	Signal      string `json:",omitempty"`
	TimedOut    bool   `json:",omitempty"`
	WallMS      float64
	MaxRSSBytes int64            // getrusage ru_maxrss of the child
	StderrTail  string           `json:",omitempty"`
	LastPhase   string           `json:",omitempty"` // last "phase:" line the child printed (where a killed child stopped)
	Cgroup      *cgroupStats     `json:",omitempty"`
	Result      *joinChildResult `json:",omitempty"`
}

type cgroupStats struct {
	LimitBytes    int64
	MaxUsageBytes int64 // memory.max_usage_in_bytes (includes page cache charged to the group)
	FailCnt       int64
	OOMKills      int64
}

// childEnv returns the environment without GOGC/GOMEMLIMIT plus extra.
func childEnv(extra ...string) []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GOGC=") || strings.HasPrefix(e, "GOMEMLIMIT=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, extra...)
}

// runChild re-executes this binary as a join-child for n rows. When cg is
// non-empty the child is moved into that cgroup before it execs.
func runChild(n, r int, parts bool, extraEnv []string, cg string) (*childOutcome, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-child-n", strconv.Itoa(n), "-r", strconv.Itoa(r), "-seed", strconv.FormatInt(*seed, 10),
		"-payload", strconv.Itoa(*payload), "-right-type", *rightTyp, "-sample-us", strconv.Itoa(*sampleUS),
		"-child-parts=" + strconv.FormatBool(parts), "-no-typed=" + strconv.FormatBool(*noTyped), "join-child",
	}
	ctx, cancel := context.WithTimeout(context.Background(), *childTmout)
	defer cancel()
	var cmd *exec.Cmd
	if cg != "" {
		cmd = exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", `echo $$ > "$0/cgroup.procs" && exec "$@"`, cg, exe}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, exe, args...)
	}
	cmd.Env = childEnv(extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	runErr := cmd.Run()
	o := &childOutcome{Env: extraEnv, WallMS: msf(time.Since(start)), TimedOut: ctx.Err() != nil}
	if ps := cmd.ProcessState; ps != nil {
		o.ExitCode = ps.ExitCode()
		if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
			o.MaxRSSBytes = ru.Maxrss * 1024 // Linux reports KiB
		}
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			o.Signal = ws.Signal().String()
		}
	}
	for _, l := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(l, "phase: ") {
			o.LastPhase = strings.TrimPrefix(l, "phase: ")
		}
	}
	tail := stderr.String()
	if len(tail) > 2000 {
		tail = "..." + tail[len(tail)-2000:]
	}
	o.StderrTail = tail
	if runErr == nil {
		var res joinChildResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			return o, fmt.Errorf("child output: %w", err)
		}
		o.Result, o.Completed = &res, true
	}
	return o, nil
}

type memoryReport struct {
	Meta        meta
	Description string
	Points      []*childOutcome
}

// runMemory measures each size in its own child process.
func runMemory() error {
	sizes, err := parseSizes([]int{10000, 50000, 100000, 250000, 500000, 1000000})
	if err != nil {
		return err
	}
	rep := memoryReport{Meta: newMeta(), Description: "federation.HashJoinRelations on synthetic relations shaped like cmd/unidb-bench/join.go (users: int64 id + name; orders: id, user_id, total as -right-type), n = m, each size in a fresh child process with default GOGC and no memory limit. Retained sizes are live heap after two forced GCs; peaks are sampled from runtime/metrics every -sample-us."}
	for _, n := range sizes {
		o, err := runChild(n, repsOr(5), true, nil, "")
		if err != nil {
			return err
		}
		if !o.Completed {
			return fmt.Errorf("n=%d child failed (exit %d %s): %s", n, o.ExitCode, o.Signal, o.StderrTail)
		}
		c := o.Result
		log.Printf("n=%7d join median %8.2f ms  inputs %6.1f MB  table %6.1f MB  output %6.1f MB  join peak heap %6.1f MB  alloc/join %6.1f MB  maxRSS %6.1f MB  GCs/join %v",
			n, c.JoinMS.Median, mb(c.InputBytes), mb(c.HashTableBytes), mb(c.OutputBytes), mb(c.JoinPeak.HeapObjects),
			mb(c.AllocBytesPerJoin[len(c.AllocBytesPerJoin)-1]), mb(uint64(o.MaxRSSBytes)), c.GCsPerJoin)
		if c.Typed != nil {
			log.Printf("          typed reference median %8.2f ms  alloc/join %6.1f MB", c.Typed.JoinMS.Median, mb(c.Typed.AllocBytesPerJoin[len(c.Typed.AllocBytesPerJoin)-1]))
		}
		rep.Points = append(rep.Points, o)
	}
	return writeJSON("join_memory.json", rep)
}

func mb(b uint64) float64 { return float64(b) / (1 << 20) }

type memlimitRun struct {
	Kind         string // "calibration", "soft" (GOMEMLIMIT only) or "hard" (cgroup cap, optional GOMEMLIMIT)
	Fraction     float64
	GOMEMLIMIT   int64 `json:",omitempty"`
	HardCapBytes int64 `json:",omitempty"`
	Outcome      *childOutcome
}

type memlimitReport struct {
	Meta                 meta
	Description          string
	N                    int
	CalibPeakRuntimeMem  uint64
	CalibPeakHeapObjects uint64
	CalibMaxRSS          int64
	HardCapAvailable     bool
	HardCapNote          string
	Runs                 []memlimitRun
}

// runMemLimit runs one large join under a series of soft (GOMEMLIMIT) and
// hard (cgroup v1 memory.limit_in_bytes, no swap) limits derived from an
// unconstrained calibration run.
func runMemLimit() error {
	r := repsOr(3)
	n := *mlN
	rep := memlimitReport{Meta: newMeta(), N: n, Description: "HashJoinRelations with n = m = N in a child process (input construction included in the process). Soft limits set GOMEMLIMIT to a fraction of the calibration run's peak runtime memory (mapped minus released, what GOMEMLIMIT governs); hard limits place the child in a cgroup v1 memory group capped at a fraction of the calibration run's max RSS (the host has no swap, so exceeding it triggers the kernel OOM killer)."}
	calib, err := runChild(n, r, false, nil, "")
	if err != nil {
		return err
	}
	if !calib.Completed {
		return fmt.Errorf("calibration failed: exit %d %s %s", calib.ExitCode, calib.Signal, calib.StderrTail)
	}
	rep.CalibPeakRuntimeMem = calib.Result.LifetimePeak.RuntimeMem
	rep.CalibPeakHeapObjects = calib.Result.LifetimePeak.HeapObjects
	rep.CalibMaxRSS = calib.MaxRSSBytes
	rep.Runs = append(rep.Runs, memlimitRun{Kind: "calibration", Outcome: calib})
	logRun := func(run memlimitRun) {
		o := run.Outcome
		status := "completed"
		if !o.Completed {
			status = fmt.Sprintf("FAILED exit=%d signal=%q timeout=%v last phase %q", o.ExitCode, o.Signal, o.TimedOut, o.LastPhase)
		}
		line := fmt.Sprintf("%-11s frac=%.2f gomemlimit=%.0fMB cap=%.0fMB maxRSS=%.0fMB %s", run.Kind, run.Fraction,
			mb(uint64(max(run.GOMEMLIMIT, 0))), mb(uint64(max(run.HardCapBytes, 0))), mb(uint64(o.MaxRSSBytes)), status)
		if o.Result != nil {
			line += fmt.Sprintf(" join median %.1f ms GCs/join %v", o.Result.JoinMS.Median, o.Result.GCsPerJoin)
		}
		if o.Cgroup != nil {
			line += fmt.Sprintf(" cg max %.0fMB failcnt %d oomkills %d", mb(uint64(o.Cgroup.MaxUsageBytes)), o.Cgroup.FailCnt, o.Cgroup.OOMKills)
		}
		log.Print(line)
	}
	logRun(rep.Runs[0])

	soft, err := parseFloats(*softFracs)
	if err != nil {
		return err
	}
	for _, f := range soft {
		run := memlimitRun{Kind: "soft", Fraction: f}
		var env []string
		if f > 0 {
			run.GOMEMLIMIT = int64(f * float64(rep.CalibPeakRuntimeMem))
			env = []string{"GOMEMLIMIT=" + strconv.FormatInt(run.GOMEMLIMIT, 10)}
		}
		if run.Outcome, err = runChild(n, r, false, env, ""); err != nil {
			return err
		}
		rep.Runs = append(rep.Runs, run)
		logRun(run)
	}

	base, cgErr := memCgroupBase()
	rep.HardCapAvailable = cgErr == nil
	if cgErr != nil {
		rep.HardCapNote = "hard caps skipped: " + cgErr.Error()
		log.Print(rep.HardCapNote)
		return writeJSON("join_memlimit.json", rep)
	}
	rep.HardCapNote = "cgroup v1 memory controller at " + base + "; memory.limit_in_bytes, no swap on host"
	hard, err := parseFloats(*hardFracs)
	if err != nil {
		return err
	}
	for _, f := range hard {
		limit := int64(f * float64(rep.CalibMaxRSS))
		variants := []int64{0}
		if *hardSoft > 0 {
			variants = append(variants, int64(*hardSoft*float64(limit)))
		}
		for _, gml := range variants {
			run := memlimitRun{Kind: "hard", Fraction: f, HardCapBytes: limit, GOMEMLIMIT: gml}
			var env []string
			if gml > 0 {
				env = []string{"GOMEMLIMIT=" + strconv.FormatInt(gml, 10)}
			}
			o, err := runInCgroup(base, limit, n, r, env)
			if err != nil {
				return err
			}
			run.Outcome = o
			rep.Runs = append(rep.Runs, run)
			logRun(run)
		}
	}
	return writeJSON("join_memlimit.json", rep)
}

// memCgroupBase returns this process's cgroup v1 memory directory if a
// sub-group can be created in it.
func memCgroupBase() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[1] == "memory" {
			dir := filepath.Join("/sys/fs/cgroup/memory", parts[2])
			probe := filepath.Join(dir, fmt.Sprintf("evaljoin-probe-%d", os.Getpid()))
			if err := os.Mkdir(probe, 0o755); err != nil {
				return "", fmt.Errorf("cannot create memory cgroup: %w", err)
			}
			_ = os.Remove(probe)
			return dir, nil
		}
	}
	return "", errors.New("no cgroup v1 memory controller (cgroup v2 is not supported by this harness)")
}

var cgSeq int

func runInCgroup(base string, limit int64, n, r int, env []string) (*childOutcome, error) {
	cgSeq++
	dir := filepath.Join(base, fmt.Sprintf("evaljoin-%d-%d", os.Getpid(), cgSeq))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	defer func() {
		for i := 0; i < 50; i++ {
			if os.Remove(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"), []byte(strconv.FormatInt(limit, 10)), 0o644); err != nil {
		return nil, err
	}
	o, err := runChild(n, r, false, env, dir)
	if err != nil {
		return o, err
	}
	readInt := func(name string) int64 {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	st := &cgroupStats{LimitBytes: readInt("memory.limit_in_bytes"), MaxUsageBytes: readInt("memory.max_usage_in_bytes"), FailCnt: readInt("memory.failcnt")}
	if b, err := os.ReadFile(filepath.Join(dir, "memory.oom_control")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "oom_kill" {
				st.OOMKills, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	o.Cgroup = st
	return o, nil
}
