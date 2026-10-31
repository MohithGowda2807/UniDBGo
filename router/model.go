package router

import (
	"math"
	"strings"
	"sync"
	"unicode"
)

// RoutingPrediction contains the model's recommendation.
type RoutingPrediction struct {
	TargetDatabase string
	TargetDialect  string
	// Confidence is the posterior probability P(class | query) in [0, 1].
	Confidence float64
}

// RoutingModel is a multinomial Naive Bayes text classifier over query tokens.
type RoutingModel struct {
	mu sync.RWMutex

	// Alpha is the additive (Laplace) smoothing constant; 1.0 by default.
	Alpha float64

	// Word occurrences per (Database + "|" + Dialect) class
	wordCounts  map[string]map[string]int
	classTotals map[string]int
	classCounts map[string]int
	vocab       map[string]bool
	totalDocs   int
}

// NewRoutingModel initializes an empty model.
func NewRoutingModel() *RoutingModel {
	return &RoutingModel{
		Alpha:       1.0,
		wordCounts:  make(map[string]map[string]int),
		classTotals: make(map[string]int),
		classCounts: make(map[string]int),
		vocab:       make(map[string]bool),
	}
}

// tokenize splits a query into normalized terms. Literals are replaced by
// placeholders (<NUM>, <STR>) so that the model learns syntax rather than
// data values; operators such as ->>, ::, $gt or ` are kept as tokens
// because they are strong dialect markers.
func tokenize(query string) []string {
	var tokens []string
	s := query
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ';' || c == '(' || c == ')':
			i++
		case c == '\'':
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			tokens = append(tokens, "<STR>")
			i = j + 1
		case c == '"' || c == '`':
			// Quoted identifier (or JSON key): keep the quote style as a marker
			// and the identifier itself.
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				j = len(s) - i - 1
			}
			word := s[i+1 : i+1+j]
			tokens = append(tokens, string(c)+"Q")
			if strings.HasPrefix(word, "$") {
				tokens = append(tokens, strings.ToUpper(word))
			} else if word != "" {
				tokens = append(tokens, "<ID>")
			}
			i += j + 2
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			tokens = append(tokens, "<NUM>")
			i = j
		case c == '$' || c == '_' || c == '@' || unicode.IsLetter(rune(c)):
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] == '$' || unicode.IsLetter(rune(s[j])) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			w := strings.ToUpper(s[i:j])
			if c == '$' && j > i+1 && s[i+1] >= '0' && s[i+1] <= '9' {
				w = "$N" // PostgreSQL positional parameter
			}
			tokens = append(tokens, w)
			i = j
		default:
			// Operator run: ->>, ::, <=>, ||, {, }, :, ...
			j := i + 1
			for j < len(s) && strings.IndexByte("-<>=!:|&~*+/%#?@{}[]", s[j]) >= 0 && strings.IndexByte("{}[]", c) < 0 {
				j++
			}
			tokens = append(tokens, s[i:j])
			i = j
		}
	}
	return tokens
}

// Train fits the classifier on a dataset of records.
func (m *RoutingModel) Train(records []TrainingRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reset model to retrain
	m.wordCounts = make(map[string]map[string]int)
	m.classTotals = make(map[string]int)
	m.classCounts = make(map[string]int)
	m.vocab = make(map[string]bool)
	m.totalDocs = 0

	for _, r := range records {
		m.totalDocs++
		class := r.Database + "|" + r.Dialect
		m.classCounts[class]++

		if m.wordCounts[class] == nil {
			m.wordCounts[class] = make(map[string]int)
		}

		for _, w := range tokenize(r.Query) {
			m.wordCounts[class][w]++
			m.classTotals[class]++
			m.vocab[w] = true
		}
	}
}

// VocabularySize returns the number of distinct tokens seen in training.
func (m *RoutingModel) VocabularySize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.vocab)
}

// Predict returns the maximum a posteriori class and its posterior
// probability, computed as
//
//	P(c | x) ∝ P(c) · Π_i P(x_i | c),  P(w | c) = (n_wc + α) / (n_c + α|V|)
//
// in log space and normalised with log-sum-exp. Tokens never seen in
// training carry no class information and are ignored.
func (m *RoutingModel) Predict(query string) RoutingPrediction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.totalDocs == 0 {
		return RoutingPrediction{TargetDatabase: "default", TargetDialect: "SQL", Confidence: 0.0}
	}

	alpha := m.Alpha
	if alpha <= 0 {
		alpha = 1.0
	}
	words := tokenize(query)
	vocabSize := float64(len(m.vocab))

	bestScore := math.Inf(-1)
	bestClass := ""
	scores := make([]float64, 0, len(m.classCounts))

	for class, count := range m.classCounts {
		// log P(Class)
		score := math.Log(float64(count) / float64(m.totalDocs))
		denom := float64(m.classTotals[class]) + alpha*vocabSize

		// log P(Word | Class)
		for _, w := range words {
			if !m.vocab[w] {
				continue
			}
			score += math.Log((float64(m.wordCounts[class][w]) + alpha) / denom)
		}

		scores = append(scores, score)
		if score > bestScore || (score == bestScore && class < bestClass) {
			bestScore = score
			bestClass = class
		}
	}

	// Posterior of the best class: 1 / Σ_c exp(score_c - best).
	sum := 0.0
	for _, s := range scores {
		sum += math.Exp(s - bestScore)
	}

	parts := strings.SplitN(bestClass, "|", 2)
	db := "default"
	dialect := "SQL"
	if len(parts) == 2 {
		db = parts[0]
		dialect = parts[1]
	}

	return RoutingPrediction{
		TargetDatabase: db,
		TargetDialect:  dialect,
		Confidence:     1 / sum,
	}
}
