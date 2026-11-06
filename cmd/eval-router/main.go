// Command eval-router evaluates the Naive Bayes dialect router beyond the
// single split reported by unidb-bench router:
//
//  1. in-domain: the harness split (seed 42, stratified 80/20) with the full
//     confusion matrix and per-class, macro and weighted metrics; 10 repeated
//     splits; 10 regenerated corpora; stratified k-fold cross-validation; and
//     the overlap of test texts with training texts;
//
//  2. cross-domain: the model trained on the whole synthetic corpus applied
//     to statements written by others (SQL scripts shipped with PostgreSQL and
//     MySQL, MySQL query logs and test cases bundled with Vitess, and MongoDB
//     command documents from the MongoDB driver specification tests),
//     labelled by the dialect of their source;
//
//  3. dialect-neutral SQL: how the router treats the Spider queries.
//
//     eval-router -spider spider_unique.jsonl -export crossdomain.jsonl -out bench/results/revision/router_eval.json
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/router"
)

var (
	metaFiles = flag.String("meta", "", "comma-separated JSON files (dataset provenance) to embed in the result under \"dataset\"")
	outPath   = flag.String("out", "bench/results/revision/router_eval.json", "result JSON")
	seed      = flag.Int64("seed", 42, "corpus and split seed (as in unidb-bench)")
	folds     = flag.Int("k", 5, "folds for stratified cross-validation")
	spider    = flag.String("spider", "", "optional JSONL of dialect-neutral queries ({\"query\": ...}) to route")
	export    = flag.String("export", "", "optional JSONL path to write the cross-domain test set to")
	pgDir     = flag.String("pgdir", "/usr/share/postgresql/16", "PostgreSQL share directory (*.sql, extension/*.sql)")
	myDir     = flag.String("mydir", "/usr/share/mysql", "MySQL share directory (*.sql)")
	modCache  = flag.String("modcache", filepath.Join(build.Default.GOPATH, "pkg", "mod"), "Go module cache holding vitess, lib/pq and mongo-driver sources")
	vitessV   = flag.String("vitess", "vitess.io/vitess@v0.24.5", "vitess module (MySQL query logs and test cases)")
	pqV       = flag.String("pq", "github.com/lib/pq@v1.12.3", "lib/pq module (PostgreSQL test scripts)")
	mongoV    = flag.String("mongo", "go.mongodb.org/mongo-driver@v1.17.10", "mongo-driver module (specification tests)")
	minLen    = flag.Int("minlen", 15, "drop statements shorter than this many bytes")
	maxLen    = flag.Int("maxlen", 4000, "drop statements longer than this many bytes")
	thetaMain = flag.Float64("theta", router.DefaultThreshold, "operating threshold")
)

var classes = []string{"postgres", "mysql", "mongodb"}

var thetas = []float64{0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99}

func main() {
	flag.Parse()
	corpus := bench.RouterCorpus(*seed, 900, 900, 700, 0.15)
	out := map[string]any{
		"corpus":       map[string]any{"seed": *seed, "postgres": 900, "mysql": 900, "mongodb": 700, "ambiguous_share": 0.15, "size": len(corpus)},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	out["in_domain"] = inDomain(corpus)

	full := router.NewRoutingModel()
	full.Train(corpus)
	train := map[string]bool{}
	for _, r := range corpus {
		train[collapse(r.Query)] = true
	}

	test, provenance := crossDomainSet(train)
	if *export != "" {
		sum, err := writeJSONL(*export, test)
		if err != nil {
			log.Fatal(err)
		}
		provenance["export_path"] = *export
		provenance["export_sha256"] = sum
	}
	cd := map[string]any{"provenance": provenance, "trained_on": "full synthetic corpus", "vocabulary": full.VocabularySize()}
	cd["all"] = evaluate(full, test)
	cd["template_deduplicated"] = evaluate(full, templateDedup(test))
	bySource := map[string]any{}
	for _, src := range sources(test) {
		var sub []labelled
		for _, t := range test {
			if t.Source == src {
				sub = append(sub, t)
			}
		}
		bySource[src] = brief(full, sub)
	}
	cd["by_source"] = bySource
	bySourceT := map[string]any{}
	dedup := templateDedup(test)
	for _, src := range sources(dedup) {
		var sub []labelled
		for _, t := range dedup {
			if t.Source == src {
				sub = append(sub, t)
			}
		}
		bySourceT[src] = brief(full, sub)
	}
	cd["by_source_template_deduplicated"] = bySourceT
	byKind := map[string]any{}
	for _, t := range test {
		k := t.Label + ":" + kind(t.Query)
		byKind[k] = nil
	}
	for k := range byKind {
		var sub []labelled
		for _, t := range test {
			if t.Label+":"+kind(t.Query) == k {
				sub = append(sub, t)
			}
		}
		byKind[k] = brief(full, sub)
	}
	cd["by_label_and_leading_keyword"] = byKind
	cd["misrouted_examples_at_theta"] = misrouted(full, test, 40)
	out["cross_domain"] = cd

	if *spider != "" {
		s, err := routeNeutral(full, *spider)
		if err != nil {
			log.Fatal(err)
		}
		out["spider_neutral"] = s
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

// ---------------------------------------------------------------- metrics

// metrics summarises a 3-class confusion matrix (gold -> predicted).
type metrics struct {
	N          int                           `json:"n"`
	Support    map[string]int                `json:"support"`
	Accuracy   float64                       `json:"accuracy"`
	MacroF1    float64                       `json:"macro_f1"`
	WeightedF1 float64                       `json:"weighted_f1"`
	PerClass   map[string]map[string]float64 `json:"per_class"`
	Confusion  map[string]map[string]int     `json:"confusion_gold_to_pred"`
}

func newConf() map[string]map[string]int {
	c := map[string]map[string]int{}
	for _, g := range classes {
		c[g] = map[string]int{}
		for _, p := range classes {
			c[g][p] = 0
		}
	}
	return c
}

func summarize(conf map[string]map[string]int) metrics {
	m := metrics{Support: map[string]int{}, PerClass: map[string]map[string]float64{}, Confusion: conf}
	correct := 0
	for _, g := range classes {
		for _, p := range classes {
			m.N += conf[g][p]
			m.Support[g] += conf[g][p]
		}
		correct += conf[g][g]
	}
	m.Accuracy = ratio(correct, m.N)
	present := 0
	for _, c := range classes {
		tp, fp, fn := conf[c][c], 0, 0
		for _, o := range classes {
			if o != c {
				fn += conf[c][o]
				fp += conf[o][c]
			}
		}
		p, r := ratio(tp, tp+fp), ratio(tp, tp+fn)
		f := 0.0
		if p+r > 0 {
			f = 2 * p * r / (p + r)
		}
		m.PerClass[c] = map[string]float64{"precision": p, "recall": r, "f1": f, "support": float64(m.Support[c])}
		if m.Support[c] > 0 {
			present++
			m.MacroF1 += f
			m.WeightedF1 += f * float64(m.Support[c])
		}
	}
	if present > 0 {
		m.MacroF1 /= float64(present) // classes absent from the gold labels are left out
	}
	m.WeightedF1 = m.WeightedF1 / math.Max(1, float64(m.N))
	return m
}

type labelled struct {
	Query  string `json:"query"`
	Label  string `json:"label"`
	Source string `json:"source"`
}

type pred struct {
	gold, got string
	p         float64
}

func predictAll(m *router.RoutingModel, xs []labelled) []pred {
	out := make([]pred, len(xs))
	for i, x := range xs {
		p := m.Predict(x.Query)
		out[i] = pred{x.Label, p.TargetDatabase, p.Confidence}
	}
	return out
}

func confOf(ps []pred, theta float64) map[string]map[string]int {
	c := newConf()
	for _, p := range ps {
		if p.p >= theta {
			c[p.gold][p.got]++
		}
	}
	return c
}

type thresholdPoint struct {
	Theta        float64 `json:"theta"`
	Coverage     float64 `json:"coverage"`
	SelectiveAcc float64 `json:"selective_accuracy"`
	Misroute     float64 `json:"misroute_rate"`
	Fallback     float64 `json:"fallback_rate"`
	Routed       int     `json:"routed"`
	Wrong        int     `json:"routed_wrong"`
}

func sweep(ps []pred) []thresholdPoint {
	var out []thresholdPoint
	for _, th := range thetas {
		acc, ok := 0, 0
		for _, p := range ps {
			if p.p >= th {
				acc++
				if p.gold == p.got {
					ok++
				}
			}
		}
		out = append(out, thresholdPoint{th, ratio(acc, len(ps)), ratio(ok, acc), ratio(acc-ok, len(ps)), ratio(len(ps)-acc, len(ps)), acc, acc - ok})
	}
	return out
}

func evaluate(m *router.RoutingModel, xs []labelled) map[string]any {
	ps := predictAll(m, xs)
	all := summarize(confOf(ps, 0))
	at := summarize(confOf(ps, *thetaMain))
	log.Printf("cross-domain n=%d acc=%.4f macroF1=%.4f weightedF1=%.4f", all.N, all.Accuracy, all.MacroF1, all.WeightedF1)
	return map[string]any{
		"argmax":                   all,
		"accepted_at_theta":        at,
		"theta":                    *thetaMain,
		"threshold_sweep":          sweep(ps),
		"posterior_quantiles":      quantiles(ps),
		"posterior_quantiles_note": "quantiles of the winning posterior over all statements",
	}
}

// brief is evaluate without the per-class detail, for subsets.
func brief(m *router.RoutingModel, xs []labelled) map[string]any {
	ps := predictAll(m, xs)
	all := summarize(confOf(ps, 0))
	var pt thresholdPoint
	for _, s := range sweep(ps) {
		if s.Theta == *thetaMain {
			pt = s
		}
	}
	pred := map[string]int{}
	for _, p := range ps {
		pred[p.got]++
	}
	return map[string]any{"n": len(xs), "accuracy": all.Accuracy, "predicted": pred, "at_theta": pt}
}

func quantiles(ps []pred) map[string]float64 {
	var v []float64
	for _, p := range ps {
		v = append(v, p.p)
	}
	sort.Float64s(v)
	q := func(f float64) float64 {
		if len(v) == 0 {
			return 0
		}
		return v[max(0, min(len(v)-1, int(f*float64(len(v)))))]
	}
	return map[string]float64{"p05": q(0.05), "p25": q(0.25), "p50": q(0.5), "p75": q(0.75), "p95": q(0.95)}
}

func misrouted(m *router.RoutingModel, xs []labelled, limit int) []map[string]any {
	var out []map[string]any
	perLabel := map[string]int{}
	for _, x := range xs {
		p := m.Predict(x.Query)
		if p.TargetDatabase != x.Label && p.Confidence >= *thetaMain && perLabel[x.Label] < limit/len(classes)+1 {
			perLabel[x.Label]++
			q := x.Query
			if len(q) > 300 {
				q = q[:300] + "..."
			}
			out = append(out, map[string]any{"source": x.Source, "gold": x.Label, "predicted": p.TargetDatabase, "posterior": p.Confidence, "query": q})
		}
	}
	return out
}

// ---------------------------------------------------------------- in-domain

func inDomain(corpus []router.TrainingRecord) map[string]any {
	res := map[string]any{}

	tr, te := stratifiedSplit(corpus, 0.8, *seed)
	m := router.NewRoutingModel()
	m.Train(tr)
	ps := predictRecords(m, te)
	base := summarize(confOf(ps, 0))
	seen := map[string]bool{}
	for _, r := range tr {
		seen[r.Query] = true
	}
	overlap := 0
	var unseen []pred
	for i, r := range te {
		if seen[r.Query] {
			overlap++
		} else {
			unseen = append(unseen, ps[i])
		}
	}
	log.Printf("in-domain seed %d: acc=%.4f macroF1=%.4f weightedF1=%.4f; %d/%d test texts also in train",
		*seed, base.Accuracy, base.MacroF1, base.WeightedF1, overlap, len(te))
	res["harness_split"] = map[string]any{
		"split_seed": *seed, "train": len(tr), "test": len(te), "vocabulary": m.VocabularySize(),
		"metrics":                              base,
		"accepted_at_theta":                    summarize(confOf(ps, *thetaMain)),
		"threshold_sweep":                      sweep(ps),
		"test_texts_identical_to_a_train_text": overlap,
		"metrics_on_test_texts_not_in_train":   summarize(confOf(unseen, 0)),
	}

	// Duplicate texts in the corpus as a whole.
	distinct := map[string]bool{}
	for _, r := range corpus {
		distinct[r.Query] = true
	}
	res["corpus_distinct_texts"] = len(distinct)

	// 10 splits of the seed-42 corpus, with the harness's split seeds.
	var splitSeeds []int64
	for i := int64(0); i < 10; i++ {
		splitSeeds = append(splitSeeds, *seed+100+i)
	}
	res["repeated_splits"] = repeat(splitSeeds, func(s int64) ([]router.TrainingRecord, []router.TrainingRecord) {
		return stratifiedSplit(corpus, 0.8, s)
	}, "same seed-42 corpus, stratified 80/20 with split seeds seed+100..seed+109 (as unidb-bench)")

	// 10 independently generated corpora, each with its own split.
	var corpusSeeds []int64
	for i := int64(0); i < 10; i++ {
		corpusSeeds = append(corpusSeeds, *seed+i)
	}
	res["repeated_corpora"] = repeat(corpusSeeds, func(s int64) ([]router.TrainingRecord, []router.TrainingRecord) {
		return stratifiedSplit(bench.RouterCorpus(s, 900, 900, 700, 0.15), 0.8, s)
	}, "corpus regenerated with seeds seed..seed+9, each split 80/20 with the same seed")

	// Stratified k-fold cross-validation on the seed-42 corpus.
	foldSets := stratifiedFolds(corpus, *folds, *seed)
	pooled := newConf()
	var accs, macros, weights []float64
	for i := range foldSets {
		var trn []router.TrainingRecord
		for j, f := range foldSets {
			if j != i {
				trn = append(trn, f...)
			}
		}
		mm := router.NewRoutingModel()
		mm.Train(trn)
		c := confOf(predictRecords(mm, foldSets[i]), 0)
		s := summarize(c)
		accs, macros, weights = append(accs, s.Accuracy), append(macros, s.MacroF1), append(weights, s.WeightedF1)
		for _, g := range classes {
			for _, p := range classes {
				pooled[g][p] += c[g][p]
			}
		}
	}
	am, asd := meanSD(accs)
	mm, msd := meanSD(macros)
	wm, wsd := meanSD(weights)
	log.Printf("%d-fold CV: acc %.4f±%.4f macroF1 %.4f±%.4f", *folds, am, asd, mm, msd)
	res["cross_validation"] = map[string]any{
		"k": *folds, "fold_seed": *seed,
		"accuracy_per_fold": accs, "accuracy_mean": am, "accuracy_sd": asd,
		"macro_f1_per_fold": macros, "macro_f1_mean": mm, "macro_f1_sd": msd,
		"weighted_f1_mean": wm, "weighted_f1_sd": wsd,
		"pooled": summarize(pooled),
	}
	return res
}

func predictRecords(m *router.RoutingModel, rs []router.TrainingRecord) []pred {
	out := make([]pred, len(rs))
	for i, r := range rs {
		p := m.Predict(r.Query)
		out[i] = pred{r.Database, p.TargetDatabase, p.Confidence}
	}
	return out
}

func repeat(seeds []int64, split func(int64) ([]router.TrainingRecord, []router.TrainingRecord), note string) map[string]any {
	var accs, macros, weights []float64
	perClass := map[string][]float64{}
	for _, s := range seeds {
		tr, te := split(s)
		m := router.NewRoutingModel()
		m.Train(tr)
		r := summarize(confOf(predictRecords(m, te), 0))
		accs, macros, weights = append(accs, r.Accuracy), append(macros, r.MacroF1), append(weights, r.WeightedF1)
		for _, c := range classes {
			for _, k := range []string{"precision", "recall", "f1"} {
				perClass[c+"_"+k] = append(perClass[c+"_"+k], r.PerClass[c][k])
			}
		}
	}
	out := map[string]any{"note": note, "seeds": seeds, "accuracy": accs, "macro_f1": macros, "weighted_f1": weights}
	stats := map[string]map[string]float64{}
	add := func(name string, xs []float64) {
		m, sd := meanSD(xs)
		stats[name] = map[string]float64{"mean": m, "sd": sd, "min": minOf(xs), "max": maxOf(xs)}
	}
	add("accuracy", accs)
	add("macro_f1", macros)
	add("weighted_f1", weights)
	for k, v := range perClass {
		add(k, v)
	}
	out["summary"] = stats
	log.Printf("%s: acc %.4f±%.4f macroF1 %.4f±%.4f", note, stats["accuracy"]["mean"], stats["accuracy"]["sd"], stats["macro_f1"]["mean"], stats["macro_f1"]["sd"])
	return out
}

// stratifiedSplit is copied from cmd/unidb-bench/router.go (unexported there).
func stratifiedSplit(rs []router.TrainingRecord, frac float64, seed int64) (train, test []router.TrainingRecord) {
	by := map[string][]router.TrainingRecord{}
	var keys []string
	for _, r := range rs {
		if _, ok := by[r.Database]; !ok {
			keys = append(keys, r.Database)
		}
		by[r.Database] = append(by[r.Database], r)
	}
	sort.Strings(keys)
	rng := rand.New(rand.NewSource(seed))
	for _, k := range keys {
		g := append([]router.TrainingRecord{}, by[k]...)
		rng.Shuffle(len(g), func(i, j int) { g[i], g[j] = g[j], g[i] })
		n := int(math.Round(frac * float64(len(g))))
		train = append(train, g[:n]...)
		test = append(test, g[n:]...)
	}
	return
}

// stratifiedFolds deals each class's shuffled records round-robin into k folds.
func stratifiedFolds(rs []router.TrainingRecord, k int, seed int64) [][]router.TrainingRecord {
	by := map[string][]router.TrainingRecord{}
	for _, r := range rs {
		by[r.Database] = append(by[r.Database], r)
	}
	rng := rand.New(rand.NewSource(seed))
	out := make([][]router.TrainingRecord, k)
	for _, c := range classes {
		g := append([]router.TrainingRecord{}, by[c]...)
		rng.Shuffle(len(g), func(i, j int) { g[i], g[j] = g[j], g[i] })
		for i, r := range g {
			out[i%k] = append(out[i%k], r)
		}
	}
	return out
}

// ---------------------------------------------------------------- cross-domain data

// crossDomainSet collects, filters and de-duplicates the independent test
// statements. Statements whose text equals a training text are removed.
func crossDomainSet(train map[string]bool) ([]labelled, map[string]any) {
	var raw []labelled
	files := map[string][]string{}
	addFile := func(label, source, path string, stmts []string) {
		files[source] = append(files[source], path)
		for _, s := range stmts {
			raw = append(raw, labelled{s, label, source})
		}
	}

	// PostgreSQL: scripts shipped with the server and extensions, lib/pq tests.
	var pgFiles []string
	for _, pat := range []string{filepath.Join(*pgDir, "*.sql"), filepath.Join(*pgDir, "extension", "*.sql"),
		filepath.Join(*modCache, *pqV, "testdata", "postgres", "*", "*.sql")} {
		m, _ := filepath.Glob(pat)
		pgFiles = append(pgFiles, m...)
	}
	for _, f := range pgFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		src := "pg-share"
		if strings.Contains(f, "/extension/") {
			src = "pg-extension"
		} else if strings.Contains(f, *pqV) {
			src = "pg-libpq-test"
		}
		addFile("postgres", src, f, splitSQL(string(b), false))
	}

	// MySQL: scripts shipped with the server.
	myFiles, _ := filepath.Glob(filepath.Join(*myDir, "*.sql"))
	for _, f := range myFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		addFile("mysql", "mysql-share", f, splitSQL(string(b), true))
	}
	// MySQL: query logs and parser test cases bundled with Vitess.
	vt := filepath.Join(*modCache, *vitessV, "go", "vt", "sqlparser", "testdata")
	for _, x := range []struct{ file, source string }{
		{"lobsters.sql.gz", "mysql-vitess-lobsters-log"},
		{"django_queries.txt", "mysql-vitess-django-log"},
		{"select_cases.txt", "mysql-vitess-select-cases"},
		{"union_cases.txt", "mysql-vitess-union-cases"},
	} {
		path := filepath.Join(vt, x.file)
		text, err := readMaybeGz(path)
		if err != nil {
			log.Fatal(err)
		}
		var stmts []string
		if strings.HasSuffix(x.file, "_cases.txt") {
			stmts = inputBlocks(text)
		} else {
			stmts = strings.Split(text, "\n")
		}
		addFile("mysql", x.source, path, stmts)
	}

	// MongoDB: command documents from the driver specification tests.
	mroot := filepath.Join(*modCache, *mongoV, "testdata")
	var mongoFiles int
	_ = filepath.WalkDir(mroot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		cmds := mongoCommands(b)
		if len(cmds) > 0 {
			mongoFiles++
			addFile("mongodb", "mongo-driver-spec-tests", path, cmds)
		}
		return nil
	})

	// Filter and de-duplicate.
	stats := map[string]map[string]int{}
	seen := map[string]bool{}
	var out []labelled
	for _, r := range raw {
		st := stats[r.Source]
		if st == nil {
			st = map[string]int{}
			stats[r.Source] = st
		}
		st["raw"]++
		q := collapse(strings.TrimRight(strings.TrimSpace(r.Query), ";"))
		switch {
		case q == "":
			st["empty"]++
			continue
		case len(q) < *minLen:
			st["too_short"]++
			continue
		case len(q) > *maxLen:
			st["too_long"]++
			continue
		case train[q]:
			st["in_training_corpus"]++
			continue
		case seen[r.Label+"\x00"+q]:
			st["duplicate"]++
			continue
		}
		seen[r.Label+"\x00"+q] = true
		st["kept"]++
		r.Query = q
		out = append(out, r)
	}
	conflict := 0
	for _, r := range out {
		for _, c := range classes {
			if c != r.Label && seen[c+"\x00"+r.Query] {
				conflict++
			}
		}
	}
	fileCount := map[string]int{}
	for s, fs := range files {
		fileCount[s] = len(fs)
	}
	perLabel := map[string]int{}
	for _, r := range out {
		perLabel[r.Label]++
	}
	log.Printf("cross-domain set: %v (%d texts appear under two labels)", perLabel, conflict)
	return out, map[string]any{
		"per_source_filtering":           stats,
		"files_per_source":               fileCount,
		"files":                          files,
		"per_label":                      perLabel,
		"texts_under_two_labels":         conflict,
		"min_len":                        *minLen,
		"max_len":                        *maxLen,
		"modules":                        []string{*vitessV, *pqV, *mongoV},
		"mongo_json_files_with_commands": mongoFiles,
	}
}

func readMaybeGz(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		r = gz
	}
	b, err := io.ReadAll(r)
	return string(b), err
}

// inputBlocks extracts the INPUT ... END sections of Vitess parser test files.
func inputBlocks(text string) []string {
	var out []string
	var cur []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case line == "INPUT":
			in, cur = true, nil
		case line == "END" && in:
			in = false
			out = append(out, strings.Join(cur, "\n"))
		case in:
			cur = append(cur, line)
		}
	}
	return out
}

var wordRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)
var dollarRE = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$`)
var routineRE = regexp.MustCompile(`(?is)^\s*CREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE)\b`)

// splitSQL splits a script into statements, dropping comments. It honours
// quoted strings and identifiers, PostgreSQL dollar quotes, psql
// meta-commands and BEGIN ATOMIC ... END routine bodies, and MySQL
// DELIMITER directives, backticks and # comments.
func splitSQL(src string, mysql bool) []string {
	var out []string
	var cur strings.Builder
	delim := ";"
	depth := 0
	n := len(src)
	emit := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
		depth = 0
	}
	lineStart := true
	for i := 0; i < n; {
		if lineStart && strings.TrimSpace(cur.String()) == "" {
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = n - i
			}
			line := strings.TrimSpace(src[i : i+end])
			if mysql && len(line) > 10 && strings.EqualFold(line[:10], "DELIMITER ") {
				delim = strings.TrimSpace(line[10:])
				i += end
				continue
			}
			if !mysql && strings.HasPrefix(line, `\`) {
				i += end
				continue
			}
		}
		c := src[i]
		lineStart = c == '\n'
		switch {
		case strings.HasPrefix(src[i:], "--") || mysql && c == '#':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				j = n - i
			}
			i += j
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				i = n
			} else {
				i += j + 4
			}
			cur.WriteByte(' ')
		case c == '\'' || c == '"' || mysql && c == '`':
			backslash := mysql || c == '\'' && i > 0 && (src[i-1] == 'E' || src[i-1] == 'e')
			j := i + 1
			for j < n {
				if backslash && src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == c {
					if j+1 < n && src[j+1] == c {
						j += 2
						continue
					}
					break
				}
				j++
			}
			j = min(n, j+1)
			cur.WriteString(src[i:j])
			i = j
		case !mysql && c == '$' && (i == 0 || !isIdent(src[i-1])) && dollarRE.MatchString(src[i:]):
			tag := dollarRE.FindString(src[i:])
			j := strings.Index(src[i+len(tag):], tag)
			if j < 0 {
				j = n - i - len(tag)*2
			}
			end := min(n, i+len(tag)*2+j)
			cur.WriteString(src[i:end])
			i = end
		case strings.HasPrefix(src[i:], delim) && depth == 0:
			emit()
			i += len(delim)
		case isIdent(c) && (i == 0 || !isIdent(src[i-1])):
			w := wordRE.FindString(src[i:])
			if w == "" {
				w = src[i : i+1]
			}
			if !mysql && routineRE.MatchString(cur.String()) {
				switch strings.ToUpper(w) {
				case "BEGIN":
					if rest := strings.TrimSpace(src[i+len(w):]); len(rest) >= 6 && strings.EqualFold(rest[:6], "ATOMIC") {
						depth++
					}
				case "CASE":
					if depth > 0 {
						depth++
					}
				case "END":
					if depth > 0 {
						depth--
					}
				}
			}
			cur.WriteString(w)
			i += len(w)
		default:
			cur.WriteByte(c)
			i++
		}
	}
	emit()
	return out
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// mongoCommands extracts the command documents a driver is expected to send
// (commandStartedEvent.command, or command_started_event.command in the
// legacy format) from a specification test file. Test-runner matchers are
// resolved: {"$$unsetOrMatches": x} and {"$$matchAsDocument": x} become x,
// and fields whose value is any other {"$$...": ...} matcher are dropped.
func mongoCommands(b []byte) []string {
	v, err := decodeOrdered(b)
	if err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case *object:
			for i, k := range t.keys {
				if k == "commandStartedEvent" || k == "command_started_event" {
					if ev, ok := t.vals[i].(*object); ok {
						if cmd, ok := ev.get("command").(*object); ok {
							if c, keep := resolveMatchers(cmd); keep {
								out = append(out, render(c))
							}
						}
					}
				}
				walk(t.vals[i])
			}
		case []any:
			for _, y := range t {
				walk(y)
			}
		}
	}
	walk(v)
	return out
}

// object is a JSON object that keeps its key order.
type object struct {
	keys []string
	vals []any
}

func (o *object) get(k string) any {
	for i, kk := range o.keys {
		if kk == k {
			return o.vals[i]
		}
	}
	return nil
}

func decodeOrdered(b []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var read func() (any, error)
	read = func() (any, error) {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				o := &object{}
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return nil, err
					}
					val, err := read()
					if err != nil {
						return nil, err
					}
					o.keys = append(o.keys, kt.(string))
					o.vals = append(o.vals, val)
				}
				_, err := dec.Token()
				return o, err
			case '[':
				var a []any
				for dec.More() {
					val, err := read()
					if err != nil {
						return nil, err
					}
					a = append(a, val)
				}
				if a == nil {
					a = []any{}
				}
				_, err := dec.Token()
				return a, err
			}
		}
		return tok, nil
	}
	return read()
}

func resolveMatchers(x any) (any, bool) {
	switch t := x.(type) {
	case *object:
		if len(t.keys) >= 1 && strings.HasPrefix(t.keys[0], "$$") {
			switch t.keys[0] {
			case "$$unsetOrMatches", "$$matchAsDocument", "$$matchAsRoot":
				return resolveMatchers(t.vals[0])
			}
			return nil, false
		}
		o := &object{}
		for i, k := range t.keys {
			if v, keep := resolveMatchers(t.vals[i]); keep {
				o.keys = append(o.keys, k)
				o.vals = append(o.vals, v)
			}
		}
		return o, true
	case []any:
		a := []any{}
		for _, y := range t {
			if v, keep := resolveMatchers(y); keep {
				a = append(a, v)
			}
		}
		return a, true
	}
	return x, true
}

// render writes a document in the spacing the training corpus uses:
// { "k": v, "k2": [ a, b ] }.
func render(x any) string {
	switch t := x.(type) {
	case *object:
		if len(t.keys) == 0 {
			return "{}"
		}
		parts := make([]string, len(t.keys))
		for i, k := range t.keys {
			kb, _ := json.Marshal(k)
			parts[i] = string(kb) + ": " + render(t.vals[i])
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	case []any:
		if len(t) == 0 {
			return "[]"
		}
		parts := make([]string, len(t))
		for i, y := range t {
			parts[i] = render(y)
		}
		return "[ " + strings.Join(parts, ", ") + " ]"
	case nil:
		return "null"
	}
	b, _ := json.Marshal(x)
	return string(b)
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

var (
	strLitRE  = regexp.MustCompile(`'(?:[^'\\]|\\.|'')*'`)
	numLitRE  = regexp.MustCompile(`\b\d+(\.\d+)?\b`)
	jsonValRE = regexp.MustCompile(`:\s*"(?:[^"\\]|\\.)*"`)
)

// templateDedup keeps one statement per (label, literal-masked text), so
// that statements differing only in constants count once.
func templateDedup(xs []labelled) []labelled {
	seen := map[string]bool{}
	var out []labelled
	for _, x := range xs {
		t := strLitRE.ReplaceAllString(x.Query, "'S'")
		if x.Label == "mongodb" {
			t = jsonValRE.ReplaceAllString(t, `: "S"`)
		}
		t = strings.ToLower(numLitRE.ReplaceAllString(t, "N"))
		if !seen[x.Label+"\x00"+t] {
			seen[x.Label+"\x00"+t] = true
			out = append(out, x)
		}
	}
	return out
}

// kind is the leading keyword of a statement ("{" for documents).
func kind(q string) string {
	if strings.HasPrefix(q, "{") {
		return "{document}"
	}
	w := strings.ToUpper(wordRE.FindString(q))
	switch w {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "COMMENT", "SET", "WITH", "REPLACE", "SHOW":
		return w
	}
	return "other"
}

func sources(xs []labelled) []string {
	m := map[string]bool{}
	for _, x := range xs {
		m[x.Source] = true
	}
	var out []string
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func writeJSONL(path string, xs []labelled) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	w := bufio.NewWriter(io.MultiWriter(f, h))
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, x := range xs {
		if err := enc.Encode(x); err != nil {
			f.Close()
			return "", err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), f.Close()
}

// ---------------------------------------------------------------- neutral SQL

// routeNeutral routes dialect-neutral queries (no gold label) and reports
// where they go at the operating threshold.
func routeNeutral(m *router.RoutingModel, path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	argmax, routed := map[string]int{}, map[string]int{}
	// Spider writes string literals in double quotes, which the tokenizer
	// reads as quoted identifiers (a PostgreSQL marker in the training data).
	byQuote := map[string]map[string]int{"with_double_quote": {}, "without_double_quote": {}}
	var ps []pred
	n, fallback := 0, 0
	perTheta := map[string]map[string]int{}
	for sc.Scan() {
		var it struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(sc.Bytes(), &it); err != nil {
			return nil, err
		}
		p := m.Predict(it.Query)
		n++
		argmax[p.TargetDatabase]++
		ps = append(ps, pred{"", p.TargetDatabase, p.Confidence})
		dest := "fallback"
		if p.Confidence >= *thetaMain {
			routed[p.TargetDatabase]++
			dest = p.TargetDatabase
		} else {
			fallback++
		}
		q := "without_double_quote"
		if strings.Contains(it.Query, `"`) {
			q = "with_double_quote"
		}
		byQuote[q][dest]++
		byQuote[q]["n"]++
		for _, th := range thetas {
			k := fmt.Sprintf("%.2f", th)
			if perTheta[k] == nil {
				perTheta[k] = map[string]int{}
			}
			if p.Confidence >= th {
				perTheta[k][p.TargetDatabase]++
			} else {
				perTheta[k]["fallback"]++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	share := map[string]float64{"fallback": ratio(fallback, n)}
	for c, k := range routed {
		share[c] = ratio(k, n)
	}
	log.Printf("spider: n=%d argmax=%v routed@%.2f=%v fallback=%d", n, argmax, *thetaMain, routed, fallback)
	return map[string]any{
		"input": path, "n": n, "theta": *thetaMain,
		"argmax_class":             argmax,
		"routed_at_theta":          routed,
		"fallback_at_theta":        fallback,
		"share_at_theta":           share,
		"counts_per_theta":         perTheta,
		"at_theta_by_double_quote": byQuote,
		"posterior_quantiles":      quantiles(ps),
	}, nil
}

// ---------------------------------------------------------------- helpers

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

func minOf(xs []float64) float64 {
	m := math.Inf(1)
	for _, x := range xs {
		m = math.Min(m, x)
	}
	return m
}

func maxOf(xs []float64) float64 {
	m := math.Inf(-1)
	for _, x := range xs {
		m = math.Max(m, x)
	}
	return m
}
