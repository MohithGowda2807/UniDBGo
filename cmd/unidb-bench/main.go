// Command unidb-bench runs the UniDB-Go evaluation workloads. Each
// sub-command writes a JSON summary (and CSV series for plots) into -out.
//
//	unidb-bench security            # injection corpus: AST engine vs regex baseline
//	unidb-bench router              # Naive Bayes dialect routing accuracy
//	unidb-bench join                # in-memory hash join vs nested loop
//	unidb-bench setup  -pg DSN -my DSN   # load the e-commerce dataset
//	unidb-bench latency -pg DSN -my DSN  # native driver vs UniDB-Go latency
//	unidb-bench throughput -pg DSN       # QPS under concurrent workers
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

var (
	outDir = flag.String("out", "bench/results", "directory for result files")
	pgDSN  = flag.String("pg", "postgres://postgres:pass@127.0.0.1:5432/unidb", "PostgreSQL connection URI")
	myDSN  = flag.String("my", "mysql://unidb:pass@127.0.0.1:3306/unidb", "MySQL connection URI")
	seed   = flag.Int64("seed", 42, "random seed for corpora and workloads")
	runs   = flag.Int("runs", 10000, "measured runs per latency archetype")
	rows   = flag.Int("rows", 50000, "rows per table for setup")
	secDB  = flag.String("secdb", "unidb_sec", "scratch MySQL database for corpus verification")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: unidb-bench [flags] security|router|join|setup|latency|throughput|fedscale")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	log.Printf("go %s, GOMAXPROCS=%d, %s/%s", runtime.Version(), runtime.GOMAXPROCS(0), runtime.GOOS, runtime.GOARCH)

	var err error
	switch flag.Arg(0) {
	case "security":
		err = runSecurity()
	case "router":
		err = runRouter()
	case "join":
		err = runJoin()
	case "setup":
		err = runSetup()
	case "latency":
		err = runLatency()
	case "throughput":
		err = runThroughput()
	case "fedscale":
		err = runFedScale()
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(*outDir, name)
	log.Printf("wrote %s", path)
	return os.WriteFile(path, b, 0o644)
}

func writeFile(name, content string) error {
	path := filepath.Join(*outDir, name)
	log.Printf("wrote %s", path)
	return os.WriteFile(path, []byte(content), 0o644)
}
