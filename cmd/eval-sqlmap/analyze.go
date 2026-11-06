package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/security"
)

// benignOriginal maps each endpoint to the benign parameter value used in the
// sqlmap target URL. A captured query whose parameter value differs is an
// attack; one that equals it is benign.
var benignOriginal = map[string]string{
	"/account": "1",
	"/user":    "alice",
	"/search":  "al",
}

// counters is a confusion matrix for one detector over a slice of records.
type counters struct {
	TP, FP, TN, FN int
}

func (c counters) recall() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

func (c counters) fpr() float64 {
	if c.FP+c.TN == 0 {
		return 0
	}
	return float64(c.FP) / float64(c.FP+c.TN)
}

// genuineFamilies are the payload families that form real injected SQL (as
// opposed to inert encoded text or harmless probes). Detection rate over these
// is the meaningful measure of the engine against sqlmap.
var genuineFamilies = map[string]bool{
	"union": true, "boolean-based": true, "error-based": true,
	"time-based": true, "stacked": true, "inference": true,
}

// classifyTechnique labels an attack query by payload family, best-effort,
// from the SQL text and the raw parameter value. Order matters: the first
// match wins. "encoded-inert" marks payloads whose obfuscation (double- or
// unicode-URL-encoding) was not decoded by the vulnerable app and so survives
// into the query as a harmless string literal, never forming injected SQL.
func classifyTechnique(q, paramVal string) string {
	// An empty value means the obfuscation (e.g. %uXXXX unicode-encoding, stray
	// percent signs) failed URL-decoding, so the query degenerated to a benign
	// "col = ''"; residual %XX likewise survives only as literal text.
	if paramVal == "" || rePercentEnc.MatchString(paramVal) {
		return "encoded-inert"
	}
	l := strings.ToLower(q)
	switch {
	case reUnion.MatchString(l):
		return "union"
	case reTime.MatchString(l):
		return "time-based"
	case reStacked.MatchString(l):
		return "stacked"
	case reError.MatchString(l):
		return "error-based"
	case reInference.MatchString(l):
		return "inference"
	case reBoolean.MatchString(l):
		return "boolean-based"
	case reSyntax.MatchString(strings.TrimSpace(q)):
		return "syntax-probe"
	default:
		return "other"
	}
}

var (
	reUnion      = regexp.MustCompile(`union[\s/*!0-9]+(all[\s/*!0-9]+)?select`)
	reTime       = regexp.MustCompile(`\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay`)
	reStacked    = regexp.MustCompile(`;\s*[^'"]*\b(select|insert|update|delete|drop|create|alter|grant|exec|declare|waitfor)\b`)
	reError      = regexp.MustCompile(`extractvalue|updatexml|gtid_subset|floor\s*\(\s*rand|\bexp\s*\(|\belt\s*\(|json_keys|\bcast\b|::(int|integer|numeric|bigint)`)
	reInference  = regexp.MustCompile(`\b(ascii|substring|substr|mid|ord|length|char_length)\s*\(|@@version|@@|\b(database|version|current_user|user|current_schema|current_database)\s*\(\s*\)`)
	reBoolean    = regexp.MustCompile(`\b(and|or|xor)\b[\s(]+[^=<>]*([=<>]|\blike\b|\bis\b|\bbetween\b)`)
	reSyntax     = regexp.MustCompile(`^[^']*'[^']*$|^-?\d+$|^[^a-z]*$`)
	rePercentEnc = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
)

// rate is a per-bucket detection summary for both detectors.
type rate struct {
	Attacks      int     `json:"attacks"`
	EngineBlock  int     `json:"engine_blocked"`
	RegexMatch   int     `json:"regex_matched"`
	EngineRecall float64 `json:"engine_recall"`
	RegexRecall  float64 `json:"regex_recall"`
}

func runAnalyze(logPaths []string, restricted []string, outPath string) error {
	type row struct {
		rec       record
		dialect   parser.Dialect
		attack    bool
		technique string
	}
	var rows []row
	for _, p := range logPaths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			d := parser.MySQL
			if rec.Backend == "postgres" {
				d = parser.Postgres
			}
			attack := rec.ParamVal != benignOriginal[rec.Endpoint]
			tech := "benign"
			if attack {
				tech = classifyTechnique(rec.Query, rec.ParamVal)
			}
			rows = append(rows, row{rec, d, attack, tech})
		}
		f.Close()
	}

	eng := security.NewSecurityEngine(restricted...)
	regex := bench.NewRegexBaseline()

	var engAll, reAll counters
	var engGenuine, reGenuine counters // over genuine-injection families only
	byTech := map[string]*rate{}
	byTamper := map[string]*rate{}
	byBackend := map[string]*counters{}
	engCat := map[string]int{} // engine block category among attacks
	missedByTech := map[string][]string{}
	uniqueAttack := map[string]bool{}
	uniqueAttackBlocked := map[string]bool{}

	get := func(m map[string]*rate, k string) *rate {
		if m[k] == nil {
			m[k] = &rate{}
		}
		return m[k]
	}
	getc := func(m map[string]*counters, k string) *counters {
		if m[k] == nil {
			m[k] = &counters{}
		}
		return m[k]
	}

	for _, r := range rows {
		dec := eng.AnalyzeFor(r.rec.Query, r.dialect)
		engBlock := dec.Block
		reMatch := regex.Match(r.rec.Query)
		bc := getc(byBackend, r.rec.Backend)

		if r.attack {
			uniqueAttack[r.rec.Query] = true
			genuine := genuineFamilies[r.technique]
			if engBlock {
				uniqueAttackBlocked[r.rec.Query] = true
				engAll.TP++
				bc.TP++
				engCat[string(dec.Category)]++
				if genuine {
					engGenuine.TP++
				}
			} else {
				engAll.FN++
				bc.FN++
				if genuine {
					engGenuine.FN++
				}
				if len(missedByTech[r.technique]) < 12 {
					missedByTech[r.technique] = append(missedByTech[r.technique], r.rec.Query)
				}
			}
			if reMatch {
				reAll.TP++
				if genuine {
					reGenuine.TP++
				}
			} else {
				reAll.FN++
				if genuine {
					reGenuine.FN++
				}
			}
			tr := get(byTech, r.technique)
			tr.Attacks++
			if engBlock {
				tr.EngineBlock++
			}
			if reMatch {
				tr.RegexMatch++
			}
			if r.rec.Tag != "" {
				tp := get(byTamper, r.rec.Tag)
				tp.Attacks++
				if engBlock {
					tp.EngineBlock++
				}
				if reMatch {
					tp.RegexMatch++
				}
			}
		} else {
			if engBlock {
				engAll.FP++
				bc.FP++
			} else {
				engAll.TN++
				bc.TN++
			}
			if reMatch {
				reAll.FP++
			} else {
				reAll.TN++
			}
		}
	}

	finalize := func(m map[string]*rate) {
		for _, r := range m {
			if r.Attacks > 0 {
				r.EngineRecall = float64(r.EngineBlock) / float64(r.Attacks)
				r.RegexRecall = float64(r.RegexMatch) / float64(r.Attacks)
			}
		}
	}
	finalize(byTech)
	finalize(byTamper)

	backendOut := map[string]any{}
	for k, c := range byBackend {
		backendOut[k] = map[string]any{
			"attacks": c.TP + c.FN, "benign": c.FP + c.TN,
			"engine_blocked": c.TP, "engine_recall": c.recall(),
			"engine_false_positives": c.FP, "engine_fpr": c.fpr(),
		}
	}

	out := map[string]any{
		"log_paths":      logPaths,
		"restricted":     restricted,
		"total_captured": len(rows),
		"unique_attacks": len(uniqueAttack),
		"attacks":        engAll.TP + engAll.FN,
		"benign":         engAll.FP + engAll.TN,
		"engine": map[string]any{
			"blocked": engAll.TP, "missed": engAll.FN, "recall": engAll.recall(),
			"false_positives": engAll.FP, "true_negatives": engAll.TN, "fpr": engAll.fpr(),
			"unique_attacks_blocked": len(uniqueAttackBlocked),
			"block_category_counts":  engCat,
		},
		"regex_baseline": map[string]any{
			"matched": reAll.TP, "missed": reAll.FN, "recall": reAll.recall(),
			"false_positives": reAll.FP, "true_negatives": reAll.TN, "fpr": reAll.fpr(),
		},
		"genuine_injections": map[string]any{
			"families":       []string{"union", "boolean-based", "error-based", "time-based", "stacked", "inference"},
			"attacks":        engGenuine.TP + engGenuine.FN,
			"engine_blocked": engGenuine.TP, "engine_recall": engGenuine.recall(),
			"regex_matched": reGenuine.TP, "regex_recall": reGenuine.recall(),
		},
		"by_technique":        byTech,
		"by_tamper":           byTamper,
		"by_backend":          backendOut,
		"missed_by_technique": missedByTech,
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		return err
	}

	// Console summary.
	fmt.Printf("captured=%d attacks=%d benign=%d unique_attacks=%d\n",
		len(rows), engAll.TP+engAll.FN, engAll.FP+engAll.TN, len(uniqueAttack))
	fmt.Printf("engine: recall=%.4f (blocked %d/%d) fpr=%.4f (%d/%d)\n",
		engAll.recall(), engAll.TP, engAll.TP+engAll.FN, engAll.fpr(), engAll.FP, engAll.FP+engAll.TN)
	fmt.Printf("regex:  recall=%.4f (matched %d/%d) fpr=%.4f\n",
		reAll.recall(), reAll.TP, reAll.TP+reAll.FN, reAll.fpr())
	fmt.Printf("GENUINE injections only: engine recall=%.4f (%d/%d), regex recall=%.4f (%d/%d)\n",
		engGenuine.recall(), engGenuine.TP, engGenuine.TP+engGenuine.FN,
		reGenuine.recall(), reGenuine.TP, reGenuine.TP+reGenuine.FN)
	var techs []string
	for k := range byTech {
		techs = append(techs, k)
	}
	sort.Strings(techs)
	for _, t := range techs {
		r := byTech[t]
		fmt.Printf("  %-14s n=%-4d engine=%.3f regex=%.3f\n", t, r.Attacks, r.EngineRecall, r.RegexRecall)
	}
	fmt.Printf("engine block categories (attacks): %v\n", engCat)
	fmt.Printf("wrote %s\n", outPath)
	return nil
}
