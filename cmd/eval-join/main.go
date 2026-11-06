// Command eval-join measures the memory behaviour of UniDB-Go's in-memory
// hash join and compares the federated join end to end against native
// single-server joins and DuckDB federation. Sub-commands:
//
//	eval-join [flags] memory     # time, allocation and peak heap per size (child process per size)
//	eval-join [flags] memlimit   # one large join under GOMEMLIMIT and cgroup hard caps
//	eval-join [flags] engines    # UniDB-Go vs naive vs PostgreSQL vs MySQL vs DuckDB
//	eval-join [flags] drop-copies # drop the co-located copies created by engines
//
// Every sub-command writes one JSON file into -out.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	outDir   = flag.String("out", "bench/results/revision", "directory for result files")
	sizesArg = flag.String("sizes", "", "comma-separated sizes n (default depends on the sub-command)")
	reps     = flag.Int("r", 0, "repetitions per size (default: memory 5, memlimit 3, engines 10)")
	seed     = flag.Int64("seed", 42, "random seed for synthetic relations")
	payload  = flag.Int("payload", 0, "extra 16-byte string payload columns per synthetic relation")
	rightTyp = flag.String("right-type", "bytes", "Go type of the MySQL-side values in synthetic relations: bytes or string")
	sampleUS = flag.Int("sample-us", 1000, "heap sampling interval in microseconds")
	noTyped  = flag.Bool("no-typed", false, "memory: skip the type-specialised Go hash join reference")

	// memlimit
	mlN        = flag.Int("memlimit-n", 1000000, "memlimit: rows per input relation")
	softFracs  = flag.String("soft-fracs", "0,2,1,0.75,0.5", "memlimit: GOMEMLIMIT as fractions of the calibrated peak runtime memory (0 = no limit)")
	hardFracs  = flag.String("hard-fracs", "1.5,1,0.75,0.5", "memlimit: cgroup hard caps as fractions of the calibrated peak RSS")
	hardSoft   = flag.Float64("hard-gomemlimit", 0.9, "memlimit: with a hard cap, also run with GOMEMLIMIT = this fraction of the cap (0 = skip)")
	childTmout = flag.Duration("child-timeout", 20*time.Minute, "memlimit/memory: kill a child after this long")

	// engines
	pgDSN      = flag.String("pg", "postgres://postgres:pass@127.0.0.1:5432/unidb", "PostgreSQL connection URI")
	myDSN      = flag.String("my", "mysql://unidb:pass@127.0.0.1:3306/unidb", "MySQL connection URI")
	naiveReps  = flag.Int("naive-reps", 3, "engines: repetitions for the naive nested-loop baseline (0 = same as -r, -1 = skip)")
	pythonBin  = flag.String("python", "/tmp/claude-0/-home-user-UniDBGo/d6a18366-798c-5084-b92d-a0accba2c5a9/scratchpad/venv/bin/python", "engines: Python interpreter with duckdb installed (empty = skip DuckDB)")
	duckPGConn = flag.String("duck-pg", "dbname=unidb user=postgres password=pass host=127.0.0.1 port=5432", "engines: DuckDB ATTACH string for PostgreSQL")
	duckMyConn = flag.String("duck-my", "host=127.0.0.1 port=3306 user=unidb password=pass database=unidb", "engines: DuckDB ATTACH string for MySQL")
	outName    = flag.String("name", "", "override the output file name")

	// child-process flags (internal)
	childN     = flag.Int("child-n", 0, "internal: rows per relation in a child")
	childParts = flag.Bool("child-parts", true, "internal: child measures input/hash-table/output parts")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: eval-join [flags] memory|memlimit|engines|drop-copies")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	var err error
	switch flag.Arg(0) {
	case "join-child":
		err = runJoinChild()
	case "memory":
		err = runMemory()
	case "memlimit":
		err = runMemLimit()
	case "engines":
		err = runEngines()
	case "drop-copies":
		err = dropCopies()
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// meta describes the host and build, attached to every result file.
type meta struct {
	Command    string
	Args       []string
	GoVersion  string
	GOMAXPROCS int
	NumCPU     int
	Host       string
	GitHead    string
	Started    string
}

func newMeta() meta {
	h, _ := os.Hostname()
	head, _ := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	return meta{
		Command: flag.Arg(0), Args: os.Args[1:], GoVersion: runtime.Version(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), NumCPU: runtime.NumCPU(), Host: h,
		GitHead: strings.TrimSpace(string(head)), Started: time.Now().UTC().Format(time.RFC3339),
	}
}

func writeJSON(def string, v any) error {
	name := def
	if *outName != "" {
		name = *outName
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(*outDir, name)
	log.Printf("wrote %s", path)
	return os.WriteFile(path, b, 0o644)
}

// parseSizes reads -sizes, falling back to def.
func parseSizes(def []int) ([]int, error) {
	if *sizesArg == "" {
		return def, nil
	}
	var out []int
	for _, f := range strings.Split(*sizesArg, ",") {
		f = strings.TrimSpace(strings.ToLower(f))
		mult := 1
		switch {
		case strings.HasSuffix(f, "k"):
			mult, f = 1000, strings.TrimSuffix(f, "k")
		case strings.HasSuffix(f, "m"):
			mult, f = 1000000, strings.TrimSuffix(f, "m")
		}
		n, err := strconv.Atoi(f)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad size %q", f)
		}
		out = append(out, n*mult)
	}
	return out, nil
}

func parseFloats(s string) ([]float64, error) {
	var out []float64
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		x, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func repsOr(def int) int {
	if *reps > 0 {
		return *reps
	}
	return def
}

// summary holds order statistics of a sample in milliseconds.
type summary struct {
	N                     int
	Median, P90, Min, Max float64
	Mean                  float64
	Samples               []float64
}

func summarize(xs []float64) summary {
	if len(xs) == 0 {
		return summary{}
	}
	s := append([]float64{}, xs...)
	sort.Float64s(s)
	var sum float64
	for _, x := range s {
		sum += x
	}
	return summary{N: len(s), Median: median(s), P90: nearestRank(s, 90), Min: s[0], Max: s[len(s)-1], Mean: sum / float64(len(s)), Samples: xs}
}

// median of a sorted sample (mean of the two middle values for even sizes).
func median(s []float64) float64 {
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// nearestRank is the p-th percentile of a sorted sample by the nearest-rank method.
func nearestRank(s []float64, p float64) float64 {
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return s[i]
}

func msf(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }
