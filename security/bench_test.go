package security

import (
	"strconv"
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

// BenchmarkParseCold measures parsing of a point lookup
// whose text changes on every iteration (no AST cache hits).
func BenchmarkParseCold(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parser.Parse("SELECT id, name, email FROM users WHERE id = " + strconv.Itoa(i))
	}
}

func BenchmarkParseWarm(b *testing.B) {
	q := "SELECT id, name FROM users WHERE country = $1 AND id > $2 ORDER BY id LIMIT 20"
	for i := 0; i < b.N; i++ {
		parser.Parse(q)
	}
}

func BenchmarkInspect(b *testing.B) {
	e := NewSecurityEngine()
	q := "SELECT id, name, email FROM users WHERE id = 42"
	ast, err := parser.Parse(q)
	for i := 0; i < b.N; i++ {
		e.AnalyzeAST(q, ast, err)
	}
}
