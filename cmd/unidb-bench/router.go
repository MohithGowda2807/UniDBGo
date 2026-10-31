package main

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/router"
)

type thresholdPoint struct {
	Theta           float64
	Coverage        float64 // share of queries routed by the model
	SelectiveAcc    float64 // accuracy among routed queries
	MisrouteRate    float64 // wrong and accepted, over all queries
	FallbackRate    float64
	MacroF1Accepted float64
}

func runRouter() error {
	corpus := bench.RouterCorpus(*seed, 900, 900, 700, 0.15)

	train, test := stratifiedSplit(corpus, 0.8, *seed)
	m := router.NewRoutingModel()
	m.Train(train)

	type pred struct {
		gold, got string
		p         float64
	}
	var preds []pred
	start := time.Now()
	for _, r := range test {
		p := m.Predict(r.Query)
		preds = append(preds, pred{r.Database, p.TargetDatabase, p.Confidence})
	}
	perQuery := float64(time.Since(start).Nanoseconds()) / float64(len(test)) / 1000

	classes := []string{"postgres", "mysql", "mongodb"}
	conf := map[string]map[string]int{}
	for _, c := range classes {
		conf[c] = map[string]int{}
	}
	correct := 0
	for _, p := range preds {
		conf[p.gold][p.got]++
		if p.gold == p.got {
			correct++
		}
	}
	acc := ratio(correct, len(preds))
	perClass, macro := classF1(conf, classes)
	fmt.Printf("router: train=%d test=%d vocab=%d accuracy=%.4f macroF1=%.4f %.1fµs/query\n",
		len(train), len(test), m.VocabularySize(), acc, macro, perQuery)

	var sweep []thresholdPoint
	for _, theta := range []float64{0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99} {
		accepted, ok, wrong := 0, 0, 0
		c2 := map[string]map[string]int{}
		for _, c := range classes {
			c2[c] = map[string]int{}
		}
		for _, p := range preds {
			if p.p >= theta {
				accepted++
				c2[p.gold][p.got]++
				if p.gold == p.got {
					ok++
				} else {
					wrong++
				}
			}
		}
		_, mf := classF1(c2, classes)
		pt := thresholdPoint{
			Theta: theta, Coverage: ratio(accepted, len(preds)), SelectiveAcc: ratio(ok, accepted),
			MisrouteRate: ratio(wrong, len(preds)), FallbackRate: ratio(len(preds)-accepted, len(preds)),
			MacroF1Accepted: mf,
		}
		sweep = append(sweep, pt)
		fmt.Printf("  θ=%.2f coverage=%.3f selectiveAcc=%.4f misroute=%.4f\n", theta, pt.Coverage, pt.SelectiveAcc, pt.MisrouteRate)
	}

	// Stability over repeated random splits.
	var accs []float64
	for i := int64(0); i < 10; i++ {
		tr, te := stratifiedSplit(corpus, 0.8, *seed+100+i)
		mm := router.NewRoutingModel()
		mm.Train(tr)
		ok := 0
		for _, r := range te {
			if mm.Predict(r.Query).TargetDatabase == r.Database {
				ok++
			}
		}
		accs = append(accs, ratio(ok, len(te)))
	}
	mean, sd := meanSD(accs)
	fmt.Printf("  10 random splits: accuracy %.4f ± %.4f\n", mean, sd)

	// Accuracy restricted to queries carrying dialect-specific syntax vs generic SQL.
	counts := map[string]int{}
	for _, r := range corpus {
		counts[r.Database]++
	}

	var csv strings.Builder
	csv.WriteString("theta coverage selacc misroute\n")
	for _, p := range sweep {
		fmt.Fprintf(&csv, "%.2f %.4f %.4f %.4f\n", p.Theta, p.Coverage, p.SelectiveAcc, p.MisrouteRate)
	}
	if err := writeFile("router_threshold.dat", csv.String()); err != nil {
		return err
	}
	return writeJSON("router.json", map[string]any{
		"corpus":          counts,
		"ambiguous_share": 0.15,
		"train":           len(train),
		"test":            len(test),
		"vocabulary":      m.VocabularySize(),
		"accuracy":        acc,
		"macro_f1":        macro,
		"per_class":       perClass,
		"confusion":       conf,
		"threshold_sweep": sweep,
		"split_acc_mean":  mean,
		"split_acc_sd":    sd,
		"predict_us":      perQuery,
	})
}

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

func classF1(conf map[string]map[string]int, classes []string) (map[string]map[string]float64, float64) {
	out := map[string]map[string]float64{}
	sum := 0.0
	for _, c := range classes {
		tp := conf[c][c]
		fn, fp := 0, 0
		for _, o := range classes {
			if o != c {
				fn += conf[c][o]
				fp += conf[o][c]
			}
		}
		cm := confusion{TP: tp, FP: fp, FN: fn}
		out[c] = map[string]float64{"precision": cm.Precision(), "recall": cm.Recall(), "f1": cm.F1()}
		sum += cm.F1()
	}
	return out, sum / float64(len(classes))
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
