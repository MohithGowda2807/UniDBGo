package main

import (
	"fmt"
	"time"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/security"
)

type confusion struct{ TP, FP, TN, FN int }

func (c confusion) Precision() float64 { return ratio(c.TP, c.TP+c.FP) }
func (c confusion) Recall() float64    { return ratio(c.TP, c.TP+c.FN) }
func (c confusion) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}
func (c confusion) Accuracy() float64 { return ratio(c.TP+c.TN, c.TP+c.TN+c.FP+c.FN) }
func (c confusion) FPR() float64      { return ratio(c.FP, c.FP+c.TN) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

type detectorSummary struct {
	Name              string
	Confusion         confusion
	Precision         float64
	Recall            float64
	F1                float64
	Accuracy          float64
	FalsePositiveRate float64
	PerFamilyRecall   map[string]float64
	MeanMicros        float64
	Missed            []string       `json:",omitempty"`
	FalseAlarms       []string       `json:",omitempty"`
	CategoryCounts    map[string]int `json:",omitempty"`
}

func runSecurity() error {
	corpus := bench.SecurityCorpus(*seed, 100)
	eng := security.NewSecurityEngine("accounts", "tokens", "users", "passwords")
	re := bench.NewRegexBaseline()

	type detector struct {
		name string
		fn   func(q string) (bool, string)
	}
	dets := []detector{
		{"Regex signatures", func(q string) (bool, string) { return re.Match(q), "" }},
		{"UniDB-Go AST", func(q string) (bool, string) {
			d := eng.Analyze(q)
			return d.Block, string(d.Category)
		}},
	}

	var summaries []detectorSummary
	for _, d := range dets {
		s := detectorSummary{Name: d.name, PerFamilyRecall: map[string]float64{}, CategoryCounts: map[string]int{}}
		hit := map[string]int{}
		total := map[string]int{}
		start := time.Now()
		for _, smp := range corpus {
			blocked, cat := d.fn(smp.Query)
			if blocked && cat != "" {
				s.CategoryCounts[cat]++
			}
			switch {
			case smp.Malicious && blocked:
				s.Confusion.TP++
				hit[smp.Family]++
			case smp.Malicious && !blocked:
				s.Confusion.FN++
				if len(s.Missed) < 25 {
					s.Missed = append(s.Missed, smp.Query)
				}
			case !smp.Malicious && blocked:
				s.Confusion.FP++
				if len(s.FalseAlarms) < 25 {
					s.FalseAlarms = append(s.FalseAlarms, smp.Query)
				}
			default:
				s.Confusion.TN++
			}
			total[smp.Family]++
		}
		s.MeanMicros = float64(time.Since(start).Microseconds()) / float64(len(corpus))
		for _, f := range bench.Families {
			s.PerFamilyRecall[f] = ratio(hit[f], total[f])
		}
		s.Precision, s.Recall, s.F1 = s.Confusion.Precision(), s.Confusion.Recall(), s.Confusion.F1()
		s.Accuracy, s.FalsePositiveRate = s.Confusion.Accuracy(), s.Confusion.FPR()
		summaries = append(summaries, s)

		fmt.Printf("%-18s P=%.3f R=%.3f F1=%.3f Acc=%.3f FPR=%.3f (%+v) %.1fµs/query\n",
			s.Name, s.Precision, s.Recall, s.F1, s.Accuracy, s.FalsePositiveRate, s.Confusion, s.MeanMicros)
		for _, f := range bench.Families {
			fmt.Printf("    %-34s %.1f%%\n", f, 100*s.PerFamilyRecall[f])
		}
	}

	// Measure the AST engine latency on its own with repeated passes.
	start := time.Now()
	const passes = 20
	for i := 0; i < passes; i++ {
		for _, smp := range corpus {
			eng.Analyze(smp.Query)
		}
	}
	perQuery := float64(time.Since(start).Nanoseconds()) / float64(passes*len(corpus)) / 1000

	verification, err := verifyCorpus(corpus)
	if err != nil {
		return err
	}

	var benign []string
	for _, smp := range corpus {
		if !smp.Malicious && len(benign) < 8 {
			benign = append(benign, smp.Query)
		}
	}
	return writeJSON("security.json", map[string]any{
		"corpus_size":        len(corpus),
		"attacks_per_family": 100,
		"benign":             len(corpus) / 2,
		"detectors":          summaries,
		"ast_engine_us_warm": perQuery,
		"benign_examples":    benign,
		"attack_examples":    sampleAttacks(corpus),
		"mysql_verification": verification,
	})
}

func sampleAttacks(c []bench.Sample) map[string][]string {
	out := map[string][]string{}
	for _, s := range c {
		if s.Malicious && len(out[s.Family]) < 4 {
			out[s.Family] = append(out[s.Family], s.Query)
		}
	}
	return out
}
