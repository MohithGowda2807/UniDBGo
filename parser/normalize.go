package parser

import (
	"strings"
	"unicode"
)

// Dialect selects the lexical rules used to read a query. The grammar itself
// is MySQL-flavoured; for PostgreSQL the text is first rewritten so that the
// MySQL tokenizer sees the same values and structure PostgreSQL would.
type Dialect string

const (
	MySQL    Dialect = "mysql"
	Postgres Dialect = "postgres"
)

// DialectOf maps a driver name to its dialect; unknown drivers use MySQL rules.
func DialectOf(driver string) Dialect {
	switch strings.ToLower(driver) {
	case "postgres", "postgresql", "pgx":
		return Postgres
	}
	return MySQL
}

// NormalizeDialect is Normalize with MySQL lexical rules.
func NormalizeDialect(query string) string { return Normalize(query, MySQL) }

// Normalize rewrites query into text the Vitess grammar accepts, preserving
// what the target database would see. The rewrite is used for analysis only;
// the original text is what is sent to the backend driver.
//
// For both dialects:
//
//	$1, $2 ...   ->  :p1, :p2 ...   (positional placeholders)
//	expr::type   ->  expr           (type casts)
//	ILIKE        ->  LIKE
//
// For PostgreSQL additionally, because its lexical rules differ from MySQL's:
//
//	'a\b'        ->  'a\\b'         (backslash is an ordinary character)
//	"Name"       ->  `Name`         (double quotes delimit identifiers)
//	$$text$$     ->  'text'         (dollar-quoted strings)
//	a # b        ->  a ^ b          (# is XOR, not a comment)
//
// E'...' strings keep backslash escapes, as in PostgreSQL.
func Normalize(query string, d Dialect) string {
	if !needsNormalization(query, d) {
		return query
	}
	pg := d == Postgres
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := len(query)
	for i := 0; i < n; {
		c := query[i]
		switch {
		case c == '\'' && pg && !isEscapeString(query, i):
			j := skipQuotedStandard(query, i)
			b.WriteString(strings.ReplaceAll(query[i:j], `\`, `\\`))
			i = j
		case c == '"' && pg:
			j := skipQuotedStandard(query, i)
			ident := query[i+1 : max(i+1, j-1)]
			ident = strings.ReplaceAll(ident, `""`, `"`)
			b.WriteByte('`')
			b.WriteString(strings.ReplaceAll(ident, "`", "``"))
			b.WriteByte('`')
			i = j
		case c == '$' && pg && dollarTagAt(query, i) != "":
			tag := dollarTagAt(query, i)
			end := strings.Index(query[i+len(tag):], tag)
			if end < 0 {
				b.WriteString(query[i:]) // unterminated: leave it for the parser to reject
				i = n
				break
			}
			body := query[i+len(tag) : i+len(tag)+end]
			b.WriteByte('\'')
			b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, `\`, `\\`), `'`, `''`))
			b.WriteByte('\'')
			i += len(tag)*2 + end
		case c == '#' && pg:
			b.WriteByte('^')
			i++
		case pg && (c == 'E' || c == 'e') && i+1 < n && query[i+1] == '\'' && (i == 0 || !isIdent(query[i-1])):
			i++ // E'...' keeps backslash escapes, which MySQL also uses; drop the prefix
		case c == '\'' || c == '"' || c == '`':
			j := skipQuoted(query, i)
			b.WriteString(query[i:j])
			i = j
		case c == '-' && i+1 < n && query[i+1] == '-', c == '#':
			j := strings.IndexByte(query[i:], '\n')
			if j < 0 {
				j = n - i
			}
			b.WriteString(query[i : i+j])
			i += j
		case c == '/' && i+1 < n && query[i+1] == '*':
			j := strings.Index(query[i+2:], "*/")
			if j < 0 {
				b.WriteString(query[i:])
				i = n
			} else {
				b.WriteString(query[i : i+j+4])
				i += j + 4
			}
		case c == '$' && i+1 < n && isDigit(query[i+1]):
			j := i + 1
			for j < n && isDigit(query[j]) {
				j++
			}
			b.WriteString(":p")
			b.WriteString(query[i+1 : j])
			i = j
		case c == ':' && i+1 < n && query[i+1] == ':':
			// Drop the cast and its (possibly qualified or parameterised) type name.
			j := i + 2
			for j < n && (isIdent(query[j]) || query[j] == '.' || query[j] == ' ' && j+1 < n && query[j+1] == '(') {
				j++
			}
			if j < n && query[j] == '(' {
				if k := strings.IndexByte(query[j:], ')'); k >= 0 {
					j += k + 1
				}
			}
			for j+1 < n && query[j] == '[' && query[j+1] == ']' {
				j += 2
			}
			i = j
		case (c == 'i' || c == 'I') && hasWordAt(query, i, "ILIKE"):
			b.WriteString("LIKE")
			i += 5
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// needsNormalization is a fast pre-check that avoids rewriting queries
// without any token the rewrite would change.
func needsNormalization(q string, d Dialect) bool {
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '$', ':':
			return true
		case '\\', '"', '#':
			if d == Postgres {
				return true
			}
		case 'i', 'I':
			if hasWordAt(q, i, "ILIKE") {
				return true
			}
		}
	}
	return false
}

// skipQuoted returns the index just past the quoted section starting at i,
// with MySQL rules: doubled quotes and backslash escapes are honoured.
func skipQuoted(s string, i int) int {
	q := s[i]
	j := i + 1
	for j < len(s) {
		switch s[j] {
		case '\\':
			j += 2
			continue
		case q:
			if j+1 < len(s) && s[j+1] == q {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(s)
}

// skipQuotedStandard is skipQuoted with SQL-standard rules: only a doubled
// quote escapes a quote; backslash is an ordinary character.
func skipQuotedStandard(s string, i int) int {
	q := s[i]
	j := i + 1
	for j < len(s) {
		if s[j] == q {
			if j+1 < len(s) && s[j+1] == q {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(s)
}

// isEscapeString reports whether the quote at i opens a PostgreSQL E'...' string.
func isEscapeString(s string, i int) bool {
	return i > 0 && (s[i-1] == 'E' || s[i-1] == 'e') && (i == 1 || !isIdent(s[i-2]))
}

// dollarTagAt returns the dollar-quote tag ("$$" or "$tag$") starting at i,
// or "" if there is none.
func dollarTagAt(s string, i int) string {
	if i > 0 && (isIdent(s[i-1]) || s[i-1] == '$') {
		return ""
	}
	if i+1 < len(s) && isDigit(s[i+1]) {
		return "" // $1 is a placeholder
	}
	j := i + 1
	for j < len(s) && isIdent(s[j]) {
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1]
	}
	return ""
}

func hasWordAt(s string, i int, word string) bool {
	if i+len(word) > len(s) || !strings.EqualFold(s[i:i+len(word)], word) {
		return false
	}
	if i > 0 && isIdent(s[i-1]) {
		return false
	}
	end := i + len(word)
	return end == len(s) || !isIdent(s[end])
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdent(c byte) bool {
	return c == '_' || unicode.IsLetter(rune(c)) || isDigit(c)
}

// RenderFor adapts SQL produced by sqlparser.String (MySQL conventions) to the
// target database. For PostgreSQL, back-quoted identifiers become
// double-quoted identifiers; other targets are returned unchanged. The input
// must not contain string literals with backslashes (callers pass literals as
// bind parameters).
func RenderFor(d Dialect, sql string) string {
	if d != Postgres {
		return sql
	}
	var b strings.Builder
	for i := 0; i < len(sql); {
		switch sql[i] {
		case '\'':
			j := skipQuoted(sql, i)
			b.WriteString(sql[i:j])
			i = j
		case '`':
			j := skipQuoted(sql, i)
			ident := strings.ReplaceAll(sql[i+1:j-1], "``", "`")
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(ident, `"`, `""`))
			b.WriteByte('"')
			i = j
		default:
			b.WriteByte(sql[i])
			i++
		}
	}
	return b.String()
}

// StripQualifier removes the database qualifier db from table references in
// query ("mysql.orders" -> "orders") without otherwise changing the text, so
// literals and dialect-specific syntax reach the backend exactly as written.
// Quoted strings, quoted identifiers and comments are skipped using the
// lexical rules of d.
func StripQualifier(query, db string, d Dialect) string {
	if db == "" || !strings.Contains(query, db) {
		return query
	}
	var b strings.Builder
	n := len(query)
	for i := 0; i < n; {
		c := query[i]
		switch {
		case c == '\'' && (d != Postgres || isEscapeString(query, i)):
			j := skipQuoted(query, i)
			b.WriteString(query[i:j])
			i = j
		case c == '\'' || c == '"' && d == Postgres:
			j := skipQuotedStandard(query, i)
			b.WriteString(query[i:j])
			i = j
		case c == '"' || c == '`':
			j := skipQuoted(query, i)
			b.WriteString(query[i:j])
			i = j
		case c == '-' && i+1 < n && query[i+1] == '-', c == '#' && d != Postgres:
			j := strings.IndexByte(query[i:], '\n')
			if j < 0 {
				j = n - i
			}
			b.WriteString(query[i : i+j])
			i += j
		case c == '/' && i+1 < n && query[i+1] == '*':
			stop := n
			if end := strings.Index(query[i+2:], "*/"); end >= 0 {
				stop = i + 2 + end + 2
			}
			b.WriteString(query[i:stop])
			i = stop
		case isIdent(c) && (i == 0 || !isIdent(query[i-1]) && query[i-1] != '.' && query[i-1] != '$'):
			j := i
			for j < n && isIdent(query[j]) {
				j++
			}
			if query[i:j] == db && j < n && query[j] == '.' {
				i = j + 1 // drop "db."
				continue
			}
			b.WriteString(query[i:j])
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// Bind renders the :vN placeholders of a planner-generated statement in the
// placeholder style of d ($N for PostgreSQL, ? for MySQL) and adapts quoted
// identifiers with RenderFor. Quoted text is left untouched.
func Bind(sql string, d Dialect) string {
	sql = RenderFor(d, sql)
	var b strings.Builder
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case c == '\'' || c == '`' || c == '"':
			j := skipQuotedStandard(sql, i)
			b.WriteString(sql[i:j])
			i = j
		case c == ':' && i+2 < n && sql[i+1] == 'v' && isDigit(sql[i+2]):
			j := i + 2
			for j < n && isDigit(sql[j]) {
				j++
			}
			if d == Postgres {
				b.WriteString("$" + sql[i+2:j])
			} else {
				b.WriteByte('?')
			}
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// DialectSensitive reports whether query contains anything that PostgreSQL
// and MySQL read differently: backslashes, double quotes, '#', E” or
// dollar-quoted strings. It allocates nothing, so callers can skip a second,
// dialect-specific parse for the common case.
func DialectSensitive(query string) bool {
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case '\\', '"', '#':
			return true
		case '$':
			if dollarTagAt(query, i) != "" {
				return true
			}
		case '\'':
			if isEscapeString(query, i) {
				return true
			}
		}
	}
	return false
}
