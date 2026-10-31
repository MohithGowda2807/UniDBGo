// Package bench holds the reproducible workloads and corpora used in the
// UniDB-Go evaluation (see cmd/unidb-bench).
package bench

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

// Sample is one labelled query: the template an application filled in, the
// user-controlled input and the resulting SQL text.
type Sample struct {
	Family    string // attack family, or "benign"
	Template  string
	Input     string
	Query     string
	Malicious bool
}

// Attack families used in the security evaluation (after Halfond et al.).
const (
	FamTautology  = "Tautology"
	FamPiggyback  = "Piggy-backed statements"
	FamUnion      = "UNION extraction"
	FamObfuscated = "Obfuscated (comments/hex/CHAR)"
	FamBlind      = "Truncation and blind/timing"
)

var Families = []string{FamTautology, FamPiggyback, FamUnion, FamObfuscated, FamBlind}

// Vulnerable application templates: %s is the unescaped user input.
var (
	tplName   = "SELECT id, name, email FROM customers WHERE name = '%s'"
	tplLogin  = "SELECT id FROM accounts WHERE username = '%s' AND password_hash = 'e3b0c44298fc1c14'"
	tplSearch = "SELECT id, title, price FROM products WHERE title LIKE '%%%s%%' LIMIT 50"
	tplID     = "SELECT id, customer_id, total FROM orders WHERE id = %s"
	tplCust   = "SELECT id, total, status FROM orders WHERE customer_id = %s ORDER BY created_at DESC LIMIT 20"
	strTpls   = []string{tplName, tplLogin, tplSearch}
	numTpls   = []string{tplID, tplCust}
)

type gen struct{ r *rand.Rand }

func (g gen) pick(xs []string) string { return xs[g.r.Intn(len(xs))] }
func (g gen) n(lo, hi int) int        { return lo + g.r.Intn(hi-lo+1) }

// ws returns a separator: usually a space, sometimes a tab, newline or an
// inline comment, as used by evasion tools.
func (g gen) ws() string {
	switch g.r.Intn(10) {
	case 0:
		return "\t"
	case 1:
		return "\n"
	case 2:
		return "  "
	}
	return " "
}

// mixCase randomly changes the case of letters outside string literals.
func (g gen) mixCase(s string) string {
	b := []byte(s)
	inStr := false
	for i, c := range b {
		if c == '\'' {
			inStr = !inStr
		}
		if inStr {
			continue
		}
		if c >= 'a' && c <= 'z' && g.r.Intn(2) == 0 {
			b[i] = c - 32
		} else if c >= 'A' && c <= 'Z' && g.r.Intn(2) == 0 {
			b[i] = c + 32
		}
	}
	return string(b)
}

func (g gen) word() string {
	return g.pick([]string{"a", "x", "abc", "foo", "admin", "test", "1", "z9"})
}

// tautology returns an always-true predicate in one of several forms.
func (g gen) tautology(numCtx bool) string {
	a := g.n(1, 99)
	w := g.word()
	forms := []string{
		fmt.Sprintf("%d=%d", a, a),
		fmt.Sprintf("'%s'='%s'", w, w),
		fmt.Sprintf("%d>%d", a+1, a),
		fmt.Sprintf("%d<>%d", a, a+3),
		fmt.Sprintf("%d-%d=%d", a+2, 2, a),
		"TRUE",
		fmt.Sprintf("%d LIKE %d", a, a),
		fmt.Sprintf("%d BETWEEN %d AND %d", a, a-1, a+1),
		fmt.Sprintf("NOT %d=%d", a, a+1),
		fmt.Sprintf("%d IN (%d,%d)", a, a+1, a),
		fmt.Sprintf("'%s' IS NOT NULL", w),
	}
	if numCtx {
		forms = append(forms, "id=id")
	}
	return g.pick(forms)
}

// obfuscatedTautology hides an always-true predicate behind encodings that
// defeat lexical signatures.
func (g gen) obfuscatedTautology() string {
	a := g.n(1, 99)
	w := g.word()
	hexW := fmt.Sprintf("%x", w)
	switch g.r.Intn(9) {
	case 0:
		return fmt.Sprintf("%d/**/=/**/%d", a, a)
	case 1:
		return fmt.Sprintf("0x%s=0x%s", hexW, hexW)
	case 2:
		return fmt.Sprintf("0x%s='%s'", hexW, w)
	case 3:
		return fmt.Sprintf("CHAR(%d,%d)=CHAR(%d,%d)", 65+a%26, 66, 65+a%26, 66)
	case 4:
		return fmt.Sprintf("(((%d))=((%d)))", a, a)
	case 5:
		return "CONCAT('a','b')='ab'"
	case 6:
		return "ASCII('a')=97"
	case 7:
		return "LOWER('AB')='ab'"
	}
	return fmt.Sprintf("X'%s'='%s'", hexW, w)
}

// columns of each template's select list, used to build UNION branches with
// a matching column count.
var tplColumns = map[string]int{tplName: 3, tplLogin: 1, tplSearch: 3, tplID: 3, tplCust: 3}

func unionBranch(src string, ncol int) string {
	// src is "a, b FROM t" style; pad or trim to ncol columns.
	parts := strings.SplitN(src, " FROM ", 2)
	cols := strings.Split(parts[0], ", ")
	for len(cols) < ncol {
		cols = append(cols, "NULL")
	}
	cols = cols[:ncol]
	q := "SELECT " + strings.Join(cols, ", ")
	if len(parts) == 2 {
		q += " FROM " + parts[1]
	}
	return q
}

// attack builds an injection that is effective in its template context: a
// string-context payload closes the literal, adds its clause, and re-opens a
// literal that the template's closing quote terminates.
func (g gen) attack(family string) Sample {
	s := Sample{Family: family, Malicious: true}
	numCtx := g.r.Intn(2) == 0
	if numCtx {
		s.Template = g.pick(numTpls)
	} else {
		s.Template = g.pick(strTpls)
	}
	val := fmt.Sprint(g.n(1, 5000))
	w := g.ws
	pre := g.word()
	if s.Template == tplSearch {
		pre += "%"
	}
	or := func() string { return g.pick([]string{"OR", "or", "||", "Or"}) }
	// closeTrue re-opens a literal so that, with the template's closing
	// quote (and "%" for the LIKE template), it forms a true comparison.
	closeTrue := "'1'='1"
	if s.Template == tplSearch {
		closeTrue = "'1' LIKE '1"
	}
	// strWrap embeds clause between a closed and a re-opened literal.
	strWrap := func(clause string) string {
		return fmt.Sprintf("%s'%s%s%s%s%s'", pre, w(), clause, w(), or(), w())
	}

	switch family {
	case FamTautology:
		t := g.tautology(numCtx)
		if numCtx {
			s.Input = fmt.Sprintf("%s%s%s%s%s", val, w(), or(), w(), t)
		} else {
			s.Input = strWrap(or() + w() + t)
		}
	case FamPiggyback:
		stmt := g.pick([]string{
			"DROP TABLE customers",
			"DELETE FROM orders",
			"UPDATE accounts SET role = 'admin' WHERE id = " + val,
			"INSERT INTO accounts (username, role) VALUES ('mallory', 'admin')",
			"TRUNCATE TABLE orders",
			"CREATE TABLE pwn (x int)",
			"SELECT username, password_hash FROM accounts",
		})
		if numCtx {
			s.Input = fmt.Sprintf("%s;%s%s", val, w(), stmt)
		} else {
			s.Input = fmt.Sprintf("%s';%s%s;%sSELECT '1", pre, w(), stmt, w())
		}
	case FamUnion:
		src := g.pick([]string{
			"username, password_hash FROM accounts",
			"table_name, table_schema FROM information_schema.tables",
			"column_name, data_type FROM information_schema.columns",
			"user, authentication_string FROM mysql.user",
			"token, user_id FROM tokens",
			"NULL, NULL",
			"1, version()",
			"@@version, database()",
			"email, password FROM users",
		})
		branch := unionBranch(src, tplColumns[s.Template])
		all := g.pick([]string{"UNION", "UNION ALL", "union", "UNION DISTINCT"})
		if numCtx && s.Template == tplCust {
			// Cut the template's ORDER BY, which cannot apply to the UNION.
			s.Input = fmt.Sprintf("-%s%s%s%s%s%s", val, w(), all, w(), branch, g.pick([]string{"-- ", "#"}))
		} else if numCtx {
			s.Input = fmt.Sprintf("-%s%s%s%s%s", val, w(), all, w(), branch)
		} else if s.Template == tplLogin {
			s.Input = fmt.Sprintf("%s'%s%s%s%s%s", pre, w(), all, w(), branch, g.pick([]string{"-- ", "#"}))
		} else if strings.Contains(branch, " FROM ") {
			s.Input = fmt.Sprintf("%s'%s%s%s%s%sWHERE%s%s", pre, w(), all, w(), branch, w(), w(), closeTrue)
		} else {
			// No FROM to attach a WHERE to: let the template's quote close a
			// trailing string column instead.
			s.Input = fmt.Sprintf("%s'%s%s%s%s,%s'", pre, w(), all, w(), unionBranch(src, tplColumns[s.Template]-1), w())
		}
	case FamObfuscated:
		c := "/**/"
		if g.r.Intn(5) == 0 {
			// Comment-spaced UNION with mixed case.
			// Keywords are mixed-case; identifiers keep their case because
			// table names are case-sensitive on Linux MySQL servers.
			cols := strings.SplitN(unionBranch("username, password_hash FROM accounts", tplColumns[s.Template]), " FROM ", 2)[0]
			cols = strings.TrimPrefix(cols, "SELECT ")
			u := g.mixCase("UNION") + c + g.mixCase("SELECT") + c + strings.ReplaceAll(cols, " ", c) + c + g.mixCase("FROM") + c + "accounts"
			if numCtx && s.Template == tplCust {
				s.Input = "-" + val + c + u + "#"
			} else if numCtx {
				s.Input = "-" + val + c + u
			} else if s.Template == tplLogin {
				s.Input = pre + "'" + c + u + "#"
			} else {
				s.Input = fmt.Sprintf("%s'%s%s%sWHERE%s%s", pre, c, u, c, c, strings.ReplaceAll(closeTrue, " ", c))
			}
		} else {
			core := g.pick([]string{"OR", "or", "Or", "oR"}) + c + g.obfuscatedTautology()
			if numCtx {
				s.Input = val + c + core
			} else {
				s.Input = fmt.Sprintf("%s'%s%s%s%s%s'", pre, c, core, c, g.pick([]string{"OR", "oR", "Or"}), c)
			}
		}
	case FamBlind:
		switch g.r.Intn(6) {
		case 0, 1: // comment truncation of the remaining predicate
			end := g.pick([]string{"-- ", "#"})
			if numCtx {
				s.Template = tplCust
				s.Input = val + w() + end
			} else {
				s.Template = tplLogin
				s.Input = g.pick([]string{"admin", "root", "alice"}) + "'" + end
			}
		case 2: // time-based
			f := g.pick([]string{"SLEEP(5)", "BENCHMARK(5000000,MD5(1))", "SLEEP(3)"})
			if numCtx {
				s.Input = fmt.Sprintf("%s%sAND%s%s", val, w(), w(), f)
			} else {
				s.Input = fmt.Sprintf("%s'%sAND%s%s%sAND%s%s", pre, w(), w(), f, w(), w(), closeTrue)
			}
		case 3: // catalog probing
			probe := fmt.Sprintf("(SELECT COUNT(*) FROM information_schema.tables) > %d", g.n(0, 50))
			if numCtx {
				s.Input = fmt.Sprintf("%s AND %s", val, probe)
			} else {
				s.Input = fmt.Sprintf("%s' AND %s AND %s", pre, probe, closeTrue)
			}
		default: // boolean inference without a tautology
			probe := g.pick([]string{
				fmt.Sprintf("ASCII(SUBSTRING((SELECT password_hash FROM accounts LIMIT 1),%d,1))>%d", g.n(1, 16), g.n(48, 122)),
				fmt.Sprintf("SUBSTRING(@@version,1,1)='%d'", g.n(5, 8)),
				fmt.Sprintf("%d=%d", g.n(1, 9), g.n(10, 20)),
				fmt.Sprintf("LENGTH(DATABASE())>%d", g.n(1, 12)),
			})
			if numCtx {
				s.Input = fmt.Sprintf("%s AND %s", val, probe)
			} else {
				s.Input = fmt.Sprintf("%s' AND %s AND %s", pre, probe, closeTrue)
			}
		}
	}
	s.Query = fmt.Sprintf(s.Template, s.Input)
	return s
}

var (
	firstNames = []string{"Asha", "Ravi", "Meera", "John", "Liam", "Noah", "Olivia", "Priya", "Arjun", "Fatima", "Chen", "Sofia", "Kiran", "Ananya", "Mateo"}
	lastNames  = []string{"Rao", "O''Brien", "D''Souza", "Smith", "Gowda", "Kumar", "Nguyen", "Garcia", "Iyer", "Shah", "Lee", "Müller"}
	searches   = []string{"usb cable", "rock--n--roll vinyl", "c# programming", "50% off", "salt & pepper", "union jack flag", "select comfort pillow", "drop earrings", "1=1 puzzle book", "or-else t-shirt", "tom''s diner", "a/b testing guide", "#1 bestseller", "rock; paper; scissors", "insert molding kit", "desk lamp"}
	statuses   = []string{"paid", "shipped", "pending", "cancelled", "refunded"}
)

// benign returns legitimate queries an application issues: templates filled
// with properly escaped inputs plus hand-written report and builder queries.
func (g gen) benign() Sample {
	s := Sample{Family: "benign"}
	switch g.r.Intn(12) {
	case 0, 1:
		s.Template = tplName
		s.Input = g.pick(firstNames) + " " + g.pick(lastNames)
	case 2:
		s.Template = tplLogin
		s.Input = strings.ToLower(g.pick(firstNames)) + fmt.Sprint(g.n(1, 999))
	case 3, 4:
		s.Template = tplSearch
		s.Input = g.pick(searches)
	case 5:
		s.Template = tplID
		s.Input = fmt.Sprint(g.n(1, 100000))
	case 6:
		s.Template = tplCust
		s.Input = fmt.Sprint(g.n(1, 50000))
	default:
		s.Template = "%s"
		s.Input = g.pick([]string{
			fmt.Sprintf("SELECT c.name, SUM(o.total) AS spend FROM customers c JOIN orders o ON o.customer_id = c.id WHERE o.status = '%s' GROUP BY c.name ORDER BY spend DESC LIMIT %d", g.pick(statuses), g.n(5, 50)),
			fmt.Sprintf("SELECT * FROM orders WHERE 1=1 AND status = '%s' AND total > %d", g.pick(statuses), g.n(10, 900)),
			fmt.Sprintf("SELECT id FROM orders WHERE status = '%s' OR status = '%s'", g.pick(statuses), g.pick(statuses)),
			fmt.Sprintf("SELECT id, total FROM orders WHERE created_at BETWEEN '2026-0%d-01' AND '2026-0%d-28'", g.n(1, 4), g.n(5, 9)),
			fmt.Sprintf("SELECT id FROM orders_2025 WHERE customer_id = %d UNION ALL SELECT id FROM orders WHERE customer_id = %d", g.n(1, 999), g.n(1, 999)),
			fmt.Sprintf("SELECT name FROM products WHERE id IN (SELECT product_id FROM order_items WHERE order_id = %d)", g.n(1, 9999)),
			fmt.Sprintf("SELECT COUNT(*) FROM customers WHERE country = '%s' AND name IS NOT NULL", g.pick([]string{"IN", "US", "DE", "BR"})),
			fmt.Sprintf("SELECT id, note FROM tickets WHERE note = 'retry; then -- escalate' AND priority >= %d", g.n(1, 5)),
			fmt.Sprintf("SELECT id, name FROM products ORDER BY price DESC LIMIT %d /* controller='catalog',route='/top' */", g.n(3, 30)),
			fmt.Sprintf("UPDATE orders SET status = '%s' WHERE id = %d", g.pick(statuses), g.n(1, 9999)),
			fmt.Sprintf("INSERT INTO audit_log (actor, action) VALUES ('%s', 'login OR logout')", strings.ToLower(g.pick(firstNames))),
			fmt.Sprintf("DELETE FROM carts WHERE updated_at < '2026-0%d-01' LIMIT 1000", g.n(1, 9)),
			fmt.Sprintf("SELECT id FROM customers WHERE email LIKE '%%@%s' -- weekly report", g.pick([]string{"example.com", "rvce.edu.in", "mail.org"})),
			fmt.Sprintf("SELECT p.id, p.title FROM products p WHERE p.price < %d AND (p.stock > 0 OR p.backorder = 1)", g.n(10, 500)),
		})
	}
	s.Query = fmt.Sprintf(s.Template, s.Input)
	return s
}

// SecurityCorpus returns perFamily attacks for each family followed by
// len(Families)*perFamily benign queries, generated from seed.
func SecurityCorpus(seed int64, perFamily int) []Sample {
	g := gen{rand.New(rand.NewSource(seed))}
	var out []Sample
	for _, f := range Families {
		for i := 0; i < perFamily; i++ {
			out = append(out, g.attack(f))
		}
	}
	for i := 0; i < perFamily*len(Families); i++ {
		out = append(out, g.benign())
	}
	return out
}

// RegexBaseline is a lexical signature filter of the kind deployed in front of
// applications: it matches the full query text against common SQL-injection
// signatures. It is our own implementation for comparison, not OWASP CRS.
type RegexBaseline struct{ rules []*regexp.Regexp }

func NewRegexBaseline() *RegexBaseline {
	src := []string{
		`(?i)\bor\b\s+['"]?\w+['"]?\s*(=|<>|>|<|like)\s*['"]?\w+`, // OR a=a, OR 1>0
		`(?i)'\s*or\s*'`, // ' or '
		`(?i)\bunion\b(\s+(all|distinct))?\s+select\b`,
		`(?i)(--|#)\s*$`, // trailing line comment
		`(?i);\s*(drop|delete|insert|update|truncate|create|alter|shutdown)\b`,
		`(?i)\b(sleep|benchmark|pg_sleep)\s*\(`,
		`(?i)\binformation_schema\b`,
		`(?i)/\*.*?\*/`, // inline comment
		`(?i)\bor\s+true\b`,
	}
	b := &RegexBaseline{}
	for _, s := range src {
		b.rules = append(b.rules, regexp.MustCompile(s))
	}
	return b
}

// Match reports whether any signature matches the query.
func (b *RegexBaseline) Match(query string) bool {
	for _, r := range b.rules {
		if r.MatchString(query) {
			return true
		}
	}
	return false
}
