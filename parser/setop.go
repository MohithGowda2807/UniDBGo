package parser

import (
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

// The Vitess grammar knows UNION but not INTERSECT and EXCEPT, which MySQL
// (8.0.31+) and PostgreSQL both support; Vitess reads both words as plain
// identifiers. A statement the grammar rejects is therefore given a second
// reading: it is split at every INTERSECT or EXCEPT keyword outside
// parentheses, each operand is parsed on its own, and the operands are
// chained into a *sqlparser.Union so that every rule that inspects UNION
// branches inspects these branches too. The real operators are recorded in
// QueryAST.SetOps.
//
// The synthetic Union exists for analysis only. Its shape follows the text
// left to right, not SQL precedence (INTERSECT binds tighter than UNION and
// EXCEPT), and rendering it with sqlparser.String would print UNION where
// the query said INTERSECT or EXCEPT. Execution always uses the original text.

// parseSetOperation parses sql, a single statement already normalized for its
// dialect, as a chain of INTERSECT / EXCEPT operands. It reports false when
// sql has no such operator at the top level or when any operand fails to
// parse as a query expression (SELECT, UNION, or a parenthesised one).
func parseSetOperation(sql string) (sqlparser.Statement, []string, bool) {
	operands, distinct, ops, ok := splitSetOperation(sql)
	if !ok {
		return nil, nil, false
	}
	var acc sqlparser.TableStatement
	for i, text := range operands {
		stmt, err := vparser.ParseStrictDDL(text)
		if err != nil {
			return nil, nil, false
		}
		switch stmt.(type) {
		case *sqlparser.Select, *sqlparser.Union:
		default:
			return nil, nil, false // e.g. "INSERT ... SELECT ... EXCEPT ..." is not supported
		}
		ts := stmt.(sqlparser.TableStatement)
		if acc == nil {
			acc = ts
			continue
		}
		acc = &sqlparser.Union{Left: acc, Right: ts, Distinct: distinct[i-1]}
	}
	return acc, ops, true
}

// splitSetOperation scans sql with the Vitess tokenizer, so that string
// literals, quoted identifiers and comments are never mistaken for keywords,
// and cuts it at every INTERSECT or EXCEPT (optionally followed by ALL or
// DISTINCT) at parenthesis depth 0. It returns the operand texts, whether
// each operator removes duplicates, and every top-level set operator in text
// order, UNION included (e.g. "UNION", "INTERSECT", "EXCEPT ALL").
//
// It refuses (ok == false) text it cannot read with certainty: a lexical
// error, a statement separator, unbalanced parentheses, or a MySQL versioned
// comment (/*! ... */), whose contents MySQL executes as SQL.
func splitSetOperation(sql string) (operands []string, distinct []bool, ops []string, ok bool) {
	tkn := NewTokenizer(sql)
	depth, segStart, prevEnd, prevTyp := 0, 0, 0, 0
	pending, pendingSplit := -1, false // operator that may take ALL / DISTINCT
	for {
		typ, _ := tkn.Scan()
		if typ == 0 {
			break
		}
		if typ == sqlparser.LEX_ERROR || typ == ';' {
			return nil, nil, nil, false
		}
		start := prevEnd
		for start < len(sql) && isBlank(sql[start]) {
			start++
		}
		if strings.HasPrefix(sql[start:], "/*!") || strings.HasPrefix(sql[start:], "*/") {
			return nil, nil, nil, false
		}
		end := tkn.Pos
		prevEnd = end
		if typ == sqlparser.COMMENT {
			continue
		}
		raw := sql[start:min(end, len(sql))]

		modifier := pending >= 0 && (typ == sqlparser.ALL || typ == sqlparser.DISTINCT)
		pending = -1
		switch {
		case typ == '(':
			depth++
		case typ == ')':
			depth--
			if depth < 0 {
				return nil, nil, nil, false
			}
		case depth != 0:
		case modifier:
			ops[len(ops)-1] += " " + strings.ToUpper(raw)
			if pendingSplit {
				distinct[len(distinct)-1] = typ == sqlparser.DISTINCT
				segStart = end
			}
		case typ == sqlparser.UNION:
			ops = append(ops, "UNION")
			pending, pendingSplit = len(ops)-1, false
		case typ == sqlparser.ID && prevTyp != '.' &&
			(strings.EqualFold(raw, "INTERSECT") || strings.EqualFold(raw, "EXCEPT")):
			// raw is the text as written, so a quoted `intersect` never matches.
			operands = append(operands, sql[segStart:start])
			distinct = append(distinct, true)
			ops = append(ops, strings.ToUpper(raw))
			pending, pendingSplit = len(ops)-1, true
			segStart = end
		}
		prevTyp = typ
	}
	if depth != 0 || len(operands) == 0 {
		return nil, nil, nil, false
	}
	operands = append(operands, sql[segStart:])
	return operands, distinct, ops, true
}

// isBlank matches the whitespace the Vitess tokenizer skips between tokens.
func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}
