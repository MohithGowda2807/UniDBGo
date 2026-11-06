// Command eval-benign measures the false-positive rate of the UniDB-Go
// security checker on an independent corpus of benign, human-written SQL
// (for example the Spider text-to-SQL queries). Every query is analysed with
// several restricted-table configurations and both lexical dialects, and the
// regex signature baseline is run on the same queries. Optionally each query
// is also prepared on live MySQL and PostgreSQL servers to tell queries the
// servers themselves reject as syntax errors from parser coverage gaps.
//
//	eval-benign -in spider_unique.jsonl -out bench/results/revision/benign_spider.json [-syntax]
package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/security"
)

var (
	metaFiles = flag.String("meta", "", "comma-separated JSON files (dataset provenance) to embed in the result under \"dataset\"")
	inPath    = flag.String("in", "", "JSONL file with one {\"query\": ...} object per line, or a .txt file with one query per line")
	outPath   = flag.String("out", "bench/results/revision/benign_spider.json", "result JSON")
	reps      = flag.Int("reps", 5, "cold (first-sight) timing repetitions per dialect")
	passes    = flag.Int("passes", 20, "cached timing passes per dialect")
	syntax    = flag.Bool("syntax", false, "also prepare every query on live MySQL and PostgreSQL servers")
	myDSN     = flag.String("my", "unidb:pass@tcp(127.0.0.1:3306)/unidb_spider_syntax", "MySQL DSN for -syntax (an empty scratch database)")
	tables    = flag.String("tables", "", "optional JSON file [[table, count], ...] of every table the corpus references; adds the stress configuration all_tables")
	pgDSN     = flag.String("pg", "postgres://postgres:pass@127.0.0.1:5432/unidb_spider_syntax?sslmode=disable", "PostgreSQL DSN for -syntax (an empty scratch database)")
)

// item is one benign query with its provenance.
type item struct {
	Query string `json:"query"`
	DBID  string `json:"db_id,omitempty"`
	Split string `json:"split,omitempty"`
	Idx   int    `json:"idx,omitempty"`
}

// config is one restricted-table configuration of the engine.
type config struct {
	Name       string
	Restricted []string // nil: NewSecurityEngine() defaults
	Note       string
}

// noTables is a restricted-table list that matches no real table name; an
// empty list would select security.DefaultRestrictedTables.
var noTables = []string{"\x00no-restricted-table"}

var credentialTables = []string{"users", "accounts", "useracct", "user_profiles", "customers_cards", "passwords", "tokens", "credentials", "sessions"}

var configs = []config{
	{"none", noTables, "RestrictedTables set to a sentinel that matches no table: no restricted tables at all"},
	{"default", nil, "security.NewSecurityEngine() with no arguments, i.e. DefaultRestrictedTables"},
	{"credentials", credentialTables, "account/credential tables present in Spider plus the default names"},
	{"pii_broad", append(append([]string{}, credentialTables...),
		"customers", "customer", "people", "person", "employee", "employees", "staff", "student", "students", "member"),
		"credentials plus the most frequent person-data tables in Spider (stress configuration)"},
}

var dialects = []parser.Dialect{parser.MySQL, parser.Postgres}

// example records one non-allowed decision.
type example struct {
	Query    string `json:"query"`
	DBID     string `json:"db_id,omitempty"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// reasonGroup aggregates unparseable rejections by error text.
type reasonGroup struct {
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"`
}

// runResult is the outcome of one (configuration, dialect) run.
type runResult struct {
	Config              string               `json:"config"`
	Dialect             string               `json:"dialect"`
	Restricted          []string             `json:"restricted_tables"`
	Total               int                  `json:"total"`
	Blocked             int                  `json:"blocked"`
	BlockedByCategory   map[string]int       `json:"blocked_by_category"`
	Unparseable         int                  `json:"unparseable_blocked"`
	BlockedParseable    int                  `json:"blocked_excluding_unparseable"`
	Flagged             int                  `json:"flagged"`
	FlaggedByCategory   map[string]int       `json:"flagged_by_category"`
	Allowed             int                  `json:"allowed_clean"`
	FPR                 float64              `json:"fpr_blocked_over_total"`
	FPRParseable        float64              `json:"fpr_excluding_unparseable"`
	FalsePositives      []example            `json:"false_positives_excluding_unparseable"`
	UnparseableReasons  []reasonGroup        `json:"unparseable_reasons"`
	UnparseableByConstr map[string]int       `json:"unparseable_by_construct"`
	FlaggedExamples     map[string][]example `json:"flagged_examples"`
	unparseableQueryIDs map[int]bool
}

func main() {
	flag.Parse()
	if *inPath == "" {
		log.Fatal("-in is required")
	}
	items, err := load(*inPath)
	if err != nil {
		log.Fatal(err)
	}
	runtime.GOMAXPROCS(1)
	log.Printf("%d queries, go %s, GOMAXPROCS=%d", len(items), runtime.Version(), runtime.GOMAXPROCS(0))

	// Timing first, so that the parser cache is cold for the first pass.
	timing := map[string]any{}
	for _, d := range dialects {
		timing[string(d)] = measure(items, d)
	}

	if *tables != "" {
		var tc [][2]any
		b, err := os.ReadFile(*tables)
		if err == nil {
			err = json.Unmarshal(b, &tc)
		}
		if err != nil {
			log.Fatal(err)
		}
		var all []string
		for _, t := range tc {
			all = append(all, fmt.Sprint(t[0]))
		}
		configs = append(configs, config{"all_tables", all,
			fmt.Sprintf("every one of the %d table names referenced in the corpus is restricted (upper bound of the restricted-table rules)", len(all))})
	}

	var runs []*runResult
	for _, c := range configs {
		for _, d := range dialects {
			r := analyse(items, c, d)
			runs = append(runs, r)
			log.Printf("%-11s %-8s blocked=%d (unparseable=%d, other=%d) flagged=%d FPR=%.4f FPR(parseable)=%.4f",
				c.Name, d, r.Blocked, r.Unparseable, r.BlockedParseable, r.Flagged, r.FPR, r.FPRParseable)
		}
	}

	regexRes := runRegex(items)
	log.Printf("regex baseline matched %d/%d (FPR=%.4f)", regexRes["matched"], len(items), regexRes["fpr"])

	out := map[string]any{
		"input":        *inPath,
		"queries":      len(items),
		"go":           runtime.Version(),
		"gomaxprocs":   1,
		"configs":      configs,
		"runs":         runs,
		"regex":        regexRes,
		"timing_us":    timing,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	if *metaFiles != "" {
		meta := map[string]any{}
		for _, f := range strings.Split(*metaFiles, ",") {
			var v any
			b, err := os.ReadFile(f)
			if err == nil {
				err = json.Unmarshal(b, &v)
			}
			if err != nil {
				log.Fatal(err)
			}
			meta[f] = v
		}
		out["dataset"] = meta
	}
	if *syntax {
		sx, err := syntaxCheck(items, runs)
		if err != nil {
			log.Fatal(err)
		}
		out["server_syntax_check"] = sx
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		log.Fatal(err)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*outPath, b, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *outPath)
}

// load reads JSONL ({"query": ...} per line) or plain text (one query per line).
func load(path string) ([]item, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	jsonl := strings.HasSuffix(path, ".jsonl")
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !jsonl {
			out = append(out, item{Query: line})
			continue
		}
		var it item
		if err := json.Unmarshal([]byte(line), &it); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, it)
	}
	return out, sc.Err()
}

func analyse(items []item, c config, d parser.Dialect) *runResult {
	eng := security.NewSecurityEngine(c.Restricted...)
	restricted := c.Restricted
	if restricted == nil {
		restricted = security.DefaultRestrictedTables
	}
	r := &runResult{
		Config: c.Name, Dialect: string(d), Restricted: restricted, Total: len(items),
		BlockedByCategory: map[string]int{}, FlaggedByCategory: map[string]int{},
		FlaggedExamples: map[string][]example{}, unparseableQueryIDs: map[int]bool{},
		UnparseableByConstr: map[string]int{},
	}
	groups := map[string]*reasonGroup{}
	for i, it := range items {
		dec := eng.AnalyzeFor(it.Query, d)
		cat := string(dec.Category)
		ex := example{Query: it.Query, DBID: it.DBID, Category: cat, Reason: dec.Reason}
		switch {
		case dec.Block:
			r.Blocked++
			r.BlockedByCategory[cat]++
			if dec.Category == security.CatUnparseable {
				r.Unparseable++
				r.unparseableQueryIDs[i] = true
				r.UnparseableByConstr[construct(it.Query)]++
				key := reasonKey(dec.Reason)
				g := groups[key]
				if g == nil {
					g = &reasonGroup{Reason: key}
					groups[key] = g
				}
				g.Count++
				if len(g.Examples) < 3 {
					g.Examples = append(g.Examples, it.Query)
				}
			} else {
				r.BlockedParseable++
				r.FalsePositives = append(r.FalsePositives, ex)
			}
		case dec.Flag:
			r.Flagged++
			r.FlaggedByCategory[cat]++
			if len(r.FlaggedExamples[cat]) < 5 {
				r.FlaggedExamples[cat] = append(r.FlaggedExamples[cat], ex)
			}
		default:
			r.Allowed++
		}
	}
	for _, g := range groups {
		r.UnparseableReasons = append(r.UnparseableReasons, *g)
	}
	sort.Slice(r.UnparseableReasons, func(i, j int) bool {
		a, b := r.UnparseableReasons[i], r.UnparseableReasons[j]
		return a.Count > b.Count || a.Count == b.Count && a.Reason < b.Reason
	})
	r.FPR = ratio(r.Blocked, r.Total)
	r.FPRParseable = ratio(r.BlockedParseable, r.Total-r.Unparseable)
	return r
}

var setOpRE = regexp.MustCompile(`(?i)\b(intersect|except)\b`)

// construct labels a query by whether it uses the INTERSECT or EXCEPT set
// operators, the main construct the Vitess grammar lacks.
func construct(q string) string {
	if setOpRE.MatchString(q) {
		return "INTERSECT/EXCEPT"
	}
	return "other"
}

var posRE = regexp.MustCompile(`at position \d+`)

// reasonKey removes the position from a parse error, keeping the token the
// parser stopped at, so that equal causes group together.
func reasonKey(reason string) string {
	s := posRE.ReplaceAllString(reason, "at position N")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// measure times Analyze over the corpus on one core: cold is the first sight
// of each query (fresh engine and a query text the parser cache has not
// seen; repetition r appends r spaces, which the tokenizer ignores), cached
// repeats the same texts on the same engine. Decisions of the space-suffixed
// copies are checked against the original texts.
func measure(items []item, d parser.Dialect) map[string]any {
	ref := security.NewSecurityEngine(credentialTables...)
	var coldMeans []float64
	var all []float64
	mismatch := 0
	var cachedMeans []float64
	for r := 1; r <= *reps; r++ {
		eng := security.NewSecurityEngine(credentialTables...)
		qs := make([]string, len(items))
		for i, it := range items {
			qs[i] = it.Query + strings.Repeat(" ", r)
		}
		runtime.GC()
		durs := make([]float64, len(qs))
		start := time.Now()
		for i, q := range qs {
			t0 := time.Now()
			eng.AnalyzeFor(q, d)
			durs[i] = float64(time.Since(t0).Nanoseconds()) / 1000
		}
		coldMeans = append(coldMeans, float64(time.Since(start).Nanoseconds())/1000/float64(len(qs)))
		all = append(all, durs...)

		runtime.GC()
		start = time.Now()
		for p := 0; p < *passes; p++ {
			for _, q := range qs {
				eng.AnalyzeFor(q, d)
			}
		}
		cachedMeans = append(cachedMeans, float64(time.Since(start).Nanoseconds())/1000/float64(*passes*len(qs)))

		if r == 1 {
			for i, q := range qs {
				a, b := eng.AnalyzeFor(q, d), ref.AnalyzeFor(items[i].Query, d)
				if a.Block != b.Block || a.Flag != b.Flag || a.Category != b.Category {
					mismatch++
				}
			}
		}
	}
	sort.Float64s(all)
	cm, csd := meanSD(coldMeans)
	km, ksd := meanSD(cachedMeans)
	res := map[string]any{
		"engine_config":            "credentials",
		"repetitions":              *reps,
		"cached_passes":            *passes,
		"cold_mean_us_per_rep":     coldMeans,
		"cold_mean_us":             cm,
		"cold_mean_us_sd":          csd,
		"cold_p50_us":              pct(all, 0.50),
		"cold_p95_us":              pct(all, 0.95),
		"cold_p99_us":              pct(all, 0.99),
		"cold_max_us":              all[len(all)-1],
		"cached_mean_us_per_rep":   cachedMeans,
		"cached_mean_us":           km,
		"cached_mean_us_sd":        ksd,
		"suffix_decision_mismatch": mismatch,
	}
	log.Printf("timing %s: cold %.1f±%.1f µs (p50 %.1f, p99 %.1f), cached %.3f±%.3f µs, mismatches %d",
		d, cm, csd, pct(all, 0.5), pct(all, 0.99), km, ksd, mismatch)
	return res
}

// regexRules copies bench.NewRegexBaseline's signatures only to attribute
// matches to a rule; Match itself is always taken from bench.RegexBaseline.
var regexRules = []string{
	`(?i)\bor\b\s+['"]?\w+['"]?\s*(=|<>|>|<|like)\s*['"]?\w+`,
	`(?i)'\s*or\s*'`,
	`(?i)\bunion\b(\s+(all|distinct))?\s+select\b`,
	`(?i)(--|#)\s*$`,
	`(?i);\s*(drop|delete|insert|update|truncate|create|alter|shutdown)\b`,
	`(?i)\b(sleep|benchmark|pg_sleep)\s*\(`,
	`(?i)\binformation_schema\b`,
	`(?i)/\*.*?\*/`,
	`(?i)\bor\s+true\b`,
}

func runRegex(items []item) map[string]any {
	re := bench.NewRegexBaseline()
	var rules []*regexp.Regexp
	for _, s := range regexRules {
		rules = append(rules, regexp.MustCompile(s))
	}
	perRule := map[string]int{}
	examples := map[string][]string{}
	matched, disagree := 0, 0
	for _, it := range items {
		m := re.Match(it.Query)
		any := false
		for _, r := range rules {
			if r.MatchString(it.Query) {
				any = true
				perRule[r.String()]++
				if len(examples[r.String()]) < 5 {
					examples[r.String()] = append(examples[r.String()], it.Query)
				}
			}
		}
		if any != m {
			disagree++
		}
		if m {
			matched++
		}
	}
	return map[string]any{
		"matched":                 matched,
		"total":                   len(items),
		"fpr":                     ratio(matched, len(items)),
		"matches_per_rule":        perRule,
		"examples_per_rule":       examples,
		"rule_copy_disagreements": disagree,
	}
}

// syntaxCheck prepares every query on MySQL and PostgreSQL (server-side
// PREPARE against an empty scratch database: nothing is executed). A syntax
// error (MySQL 1064, PostgreSQL 42601) means the server itself rejects the
// text; any other outcome, typically "table does not exist", means the text
// is syntactically valid for that server.
func syntaxCheck(items []item, runs []*runResult) (map[string]any, error) {
	ctx := context.Background()
	my, err := sql.Open("mysql", *myDSN)
	if err != nil {
		return nil, err
	}
	defer my.Close()
	pg, err := sql.Open("postgres", *pgDSN)
	if err != nil {
		return nil, err
	}
	defer pg.Close()
	my.SetMaxOpenConns(1)
	pg.SetMaxOpenConns(1)

	type server struct {
		d        parser.Dialect
		db       *sql.DB
		isSynErr func(error) (bool, string)
	}
	servers := []server{
		{parser.MySQL, my, func(err error) (bool, string) {
			var me *mysql.MySQLError
			if errors.As(err, &me) {
				return me.Number == 1064, fmt.Sprint(me.Number)
			}
			return false, "other:" + err.Error()
		}},
		{parser.Postgres, pg, func(err error) (bool, string) {
			var pe *pq.Error
			if errors.As(err, &pe) {
				return pe.Code == "42601", string(pe.Code)
			}
			return false, "other:" + err.Error()
		}},
	}
	out := map[string]any{"mysql_dsn_db": "unidb_spider_syntax", "postgres_dsn_db": "unidb_spider_syntax"}
	for _, s := range servers {
		if err := s.db.PingContext(ctx); err != nil {
			return nil, fmt.Errorf("%s: %w", s.d, err)
		}
		codes := map[string]int{}
		synErr := make([]bool, len(items))
		nSyn := 0
		var synExamples []string
		for i, it := range items {
			st, err := s.db.PrepareContext(ctx, it.Query)
			if err == nil {
				st.Close()
				codes["ok"]++
				continue
			}
			bad, code := s.isSynErr(err)
			if strings.HasPrefix(code, "other:") {
				code = "other"
			}
			codes[code]++
			if bad {
				synErr[i] = true
				nSyn++
				if len(synExamples) < 10 {
					synExamples = append(synExamples, it.Query)
				}
			}
		}
		// Cross-tabulate with the checker's fail-closed (unparseable) blocks,
		// which do not depend on the restricted-table configuration.
		var unp map[int]bool
		for _, r := range runs {
			if r.Config == "credentials" && r.Dialect == string(s.d) {
				unp = r.unparseableQueryIDs
			}
		}
		both, onlyChecker, onlyServer := 0, 0, 0
		gapByConstruct := map[string]int{}
		var gapExamples []string
		for i := range items {
			switch {
			case unp[i] && synErr[i]:
				both++
			case unp[i]:
				onlyChecker++
				gapByConstruct[construct(items[i].Query)]++
				if len(gapExamples) < 15 {
					gapExamples = append(gapExamples, items[i].Query)
				}
			case synErr[i]:
				onlyServer++
			}
		}
		out[string(s.d)] = map[string]any{
			"prepare_outcomes":                                    codes,
			"server_syntax_errors":                                nSyn,
			"server_syntax_error_examples":                        synExamples,
			"checker_unparseable_and_server_syntax_error":         both,
			"checker_unparseable_but_server_accepts":              onlyChecker,
			"server_syntax_error_but_checker_parses":              onlyServer,
			"parser_gap_examples":                                 gapExamples,
			"checker_unparseable_but_server_accepts_by_construct": gapByConstruct,
		}
		log.Printf("syntax %s: server syntax errors=%d; checker-unparseable & server-error=%d, checker-unparseable only=%d, server-error only=%d",
			s.d, nSyn, both, onlyChecker, onlyServer)
	}
	return out, nil
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func meanSD(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	m := 0.0
	for _, x := range xs {
		m += x
	}
	m /= float64(len(xs))
	v := 0.0
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	if len(xs) > 1 {
		v /= float64(len(xs) - 1)
	}
	return m, math.Sqrt(v)
}

// pct returns the q-quantile of sorted xs (nearest rank).
func pct(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	i := int(q*float64(len(xs))+0.5) - 1
	i = max(0, min(len(xs)-1, i))
	return xs[i]
}
