package federation

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Relation is a materialised intermediate result: rows are stored as slices
// aligned with Columns, which avoids allocating a map per row.
type Relation struct {
	Columns []string
	Rows    [][]any
}

// index finds col exactly, or else case-insensitively.
func (r Relation) index(col string) int {
	for i, c := range r.Columns {
		if c == col {
			return i
		}
	}
	for i, c := range r.Columns {
		if strings.EqualFold(c, col) {
			return i
		}
	}
	return -1
}

// HashJoinRelations joins l and r on l[leftKey] = r[rightKey]. The smaller
// input is the build side: its normalised keys are hashed with 64-bit FNV-1a
// into an in-memory table that the larger input then probes. Candidates in a
// bucket are confirmed by comparing normalised keys, so hash collisions never
// produce false matches. NULL keys never match. Expected cost is O(n + m).
// Output columns are l.Columns followed by r.Columns.
func HashJoinRelations(l, r Relation, leftKey, rightKey string) (Relation, error) {
	return hashJoinRelations(l, r, leftKey, rightKey, true)
}

// hashJoinRelations implements HashJoinRelations. When allowFast is true it
// first attempts the int64-specialised fast path (fastHashJoin); the generic
// NormalizeKey/FNV path is used when the fast path does not apply, or always
// when allowFast is false (used by tests to force the generic path).
func hashJoinRelations(l, r Relation, leftKey, rightKey string, allowFast bool) (Relation, error) {
	li, ri := l.index(leftKey), r.index(rightKey)
	if li < 0 || ri < 0 {
		return Relation{}, fmt.Errorf("join key %s or %s not found", leftKey, rightKey)
	}
	out := Relation{Columns: append(append([]string{}, l.Columns...), r.Columns...)}

	build, probe, bi, pi, buildIsLeft := l, r, li, ri, true
	if len(r.Rows) < len(l.Rows) {
		build, probe, bi, pi, buildIsLeft = r, l, ri, li, false
	}
	width := len(l.Columns) + len(r.Columns)

	if allowFast {
		if ok := fastHashJoin(&out, build, probe, bi, pi, buildIsLeft, width); ok {
			return out, nil
		}
	}

	type entry struct {
		key string
		row []any
	}
	table := make(map[uint64][]entry, len(build.Rows))
	for _, row := range build.Rows {
		k, ok := NormalizeKey(row[bi])
		if !ok {
			continue
		}
		h := fnv64a(k)
		table[h] = append(table[h], entry{k, row})
	}

	for _, p := range probe.Rows {
		k, ok := NormalizeKey(p[pi])
		if !ok {
			continue
		}
		for _, e := range table[fnv64a(k)] {
			if e.key != k {
				continue // hash collision
			}
			merged := make([]any, 0, width)
			if buildIsLeft {
				merged = append(append(merged, e.row...), p...)
			} else {
				merged = append(append(merged, p...), e.row...)
			}
			out.Rows = append(out.Rows, merged)
		}
	}
	return out, nil
}

// fastHashJoin is a type-specialised join that avoids NormalizeKey's per-key
// string allocation and FNV hashing when every non-NULL build key is an
// integral value of NormalizeKey's "n:" class (Go integers, bool, integral
// floats with |f| < 2^63, and []byte/string that trim to such an integer).
// It builds a map[int64][]int of build-row indices and probes it with the
// same conversion. It reports ok=false (leaving out untouched) when any
// non-NULL build key is not integral, so the caller falls back to the generic
// path. Semantics are identical to the generic path: a build key that is NULL
// is skipped (NULL never matches); a probe key that is NULL or not an integral
// int64 can never equal an integral build key under NormalizeKey, so it is
// skipped. Rows are emitted in probe order, and within a probe row in build
// insertion order, exactly as the generic path does.
func fastHashJoin(out *Relation, build, probe Relation, bi, pi int, buildIsLeft bool, width int) (ok bool) {
	table := make(map[int64][]int, len(build.Rows))
	for idx, row := range build.Rows {
		n, kind := intKey(row[bi])
		switch kind {
		case keyNull:
			continue // NULL build key never matches
		case keyOther:
			return false // not integral: generic path required
		}
		table[n] = append(table[n], idx)
	}
	for _, p := range probe.Rows {
		n, kind := intKey(p[pi])
		if kind != keyInt {
			continue // NULL or non-integral probe key cannot match an integral key
		}
		for _, bidx := range table[n] {
			brow := build.Rows[bidx]
			merged := make([]any, 0, width)
			if buildIsLeft {
				merged = append(append(merged, brow...), p...)
			} else {
				merged = append(append(merged, p...), brow...)
			}
			out.Rows = append(out.Rows, merged)
		}
	}
	return true
}

// intKey classifies v exactly as NormalizeKey's "n:" branch does, without
// allocating a key string for the common cases. keyNull mirrors NormalizeKey
// returning ok=false (NULL). keyInt means v is an integral int64 "n:" key and
// n is its value. keyOther means v is present but not an integral int64 key
// (a non-integral number, a non-numeric string, a uint64/float outside int64's
// range, a time, or any other type) and so has a non-"n:" NormalizeKey.
func intKey(v any) (n int64, kind int) {
	switch x := v.(type) {
	case nil:
		return 0, keyNull
	case int:
		return int64(x), keyInt
	case int8:
		return int64(x), keyInt
	case int16:
		return int64(x), keyInt
	case int32:
		return int64(x), keyInt
	case int64:
		return x, keyInt
	case uint:
		if uint64(x) > math.MaxInt64 {
			return 0, keyOther // NormalizeKey formats it as a value no int64 key equals
		}
		return int64(x), keyInt
	case uint8:
		return int64(x), keyInt
	case uint16:
		return int64(x), keyInt
	case uint32:
		return int64(x), keyInt
	case uint64:
		if x > math.MaxInt64 {
			return 0, keyOther
		}
		return int64(x), keyInt
	case float32:
		return floatIntKey(float64(x))
	case float64:
		return floatIntKey(x)
	case bool:
		if x {
			return 1, keyInt
		}
		return 0, keyInt
	case []byte:
		return numericBytesIntKey(bytes.TrimSpace(x))
	case string:
		return numericBytesIntKey([]byte(strings.TrimSpace(x)))
	}
	return 0, keyOther
}

const (
	keyNull  = iota // NULL: NormalizeKey ok=false
	keyInt          // integral int64 "n:" key
	keyOther        // present but not an integral int64 key
)

// floatIntKey mirrors normFloat: an integral float with |f| < 2^63 is an "n:"
// key; anything else (fractional, NaN, Inf, or out of range) is not.
func floatIntKey(f float64) (int64, int) {
	if f == math.Trunc(f) && math.Abs(f) < 1<<63 {
		return int64(f), keyInt
	}
	return 0, keyOther
}

// numericBytesIntKey mirrors normString for an already-trimmed byte slice: it
// is an "n:" key when strconv.ParseInt(.,10,64) accepts it, or when it parses
// as a finite integral float with |f| < 2^63 (ParseInt's fallback in
// normString). b must already be whitespace-trimmed.
func numericBytesIntKey(b []byte) (int64, int) {
	if n, ok := parseInt64(b); ok {
		return n, keyInt
	}
	// normString's fallback: SQL number syntax, ParseFloat, then normFloat.
	if !sqlNumeric(string(b)) {
		return 0, keyOther // a non-numeric "s:" key
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, keyOther // a non-numeric "s:" key
	}
	return floatIntKey(f)
}

// parseInt64 parses b as strconv.ParseInt(string(b), 10, 64) does, without
// allocating. It reports ok=false on any input ParseInt would reject (empty,
// a lone sign, a non-digit, or overflow), so the caller can apply the float
// fallback for inputs such as "42.0" or "4e1" exactly as normString does.
func parseInt64(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	neg := false
	i := 0
	if b[0] == '+' || b[0] == '-' {
		neg = b[0] == '-'
		i = 1
	}
	if i == len(b) {
		return 0, false // a lone sign
	}
	const cutoff = uint64(1) << 63
	var u uint64
	for ; i < len(b); i++ {
		c := b[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if u > (math.MaxUint64-uint64(c-'0'))/10 {
			return 0, false // decimal overflow
		}
		u = u*10 + uint64(c-'0')
	}
	if neg {
		if u > cutoff {
			return 0, false // < math.MinInt64
		}
		return -int64(u), true
	}
	if u >= cutoff {
		return 0, false // > math.MaxInt64
	}
	return int64(u), true
}

// NestedLoopRelations is the O(n * m) baseline: every pair of rows is
// compared. Keys are normalised once per row so the comparison is cheap.
func NestedLoopRelations(l, r Relation, leftKey, rightKey string) (Relation, error) {
	li, ri := l.index(leftKey), r.index(rightKey)
	if li < 0 || ri < 0 {
		return Relation{}, fmt.Errorf("join key %s or %s not found", leftKey, rightKey)
	}
	out := Relation{Columns: append(append([]string{}, l.Columns...), r.Columns...)}
	rk := make([]string, len(r.Rows))
	rok := make([]bool, len(r.Rows))
	for i, row := range r.Rows {
		rk[i], rok[i] = NormalizeKey(row[ri])
	}
	width := len(out.Columns)
	for _, lrow := range l.Rows {
		k, ok := NormalizeKey(lrow[li])
		if !ok {
			continue
		}
		for i, rrow := range r.Rows {
			if rok[i] && rk[i] == k {
				merged := make([]any, 0, width)
				out.Rows = append(out.Rows, append(append(merged, lrow...), rrow...))
			}
		}
	}
	return out, nil
}

// HashJoin is HashJoinRelations over map-based rows; keys must be present in
// the first row of each input.
func HashJoin(leftRows, rightRows []Row, leftKey, rightKey string) []Row {
	l, r := toRelation(leftRows), toRelation(rightRows)
	out, err := HashJoinRelations(l, r, leftKey, rightKey)
	if err != nil {
		return nil
	}
	return out.Maps()
}

// NestedLoopJoin is NestedLoopRelations over map-based rows.
func NestedLoopJoin(leftRows, rightRows []Row, leftKey, rightKey string) []Row {
	out, err := NestedLoopRelations(toRelation(leftRows), toRelation(rightRows), leftKey, rightKey)
	if err != nil {
		return nil
	}
	return out.Maps()
}

func toRelation(rows []Row) Relation {
	var rel Relation
	if len(rows) == 0 {
		return rel
	}
	for k := range rows[0] {
		rel.Columns = append(rel.Columns, k)
	}
	sort.Strings(rel.Columns)
	rel.Rows = make([][]any, len(rows))
	for i, row := range rows {
		vals := make([]any, len(rel.Columns))
		for j, c := range rel.Columns {
			vals[j] = row[c]
		}
		rel.Rows[i] = vals
	}
	return rel
}

// Maps converts the relation into map-based rows.
func (r Relation) Maps() []Row {
	out := make([]Row, len(r.Rows))
	for i, vals := range r.Rows {
		row := make(Row, len(r.Columns))
		for j, c := range r.Columns {
			row[c] = vals[j]
		}
		out[i] = row
	}
	return out
}

// fnv64a is the 64-bit FNV-1a hash (offset basis 14695981039346656037,
// prime 1099511628211), computed inline to avoid allocating a hash.Hash.
func fnv64a(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// NormalizeKey maps driver values to a canonical string so that equal keys
// from different engines compare equal: lib/pq returns int64 while the MySQL
// text protocol returns []byte("42"), and both must match. Integral numbers
// (including integral floats and numeric strings) become "n:<int>", other
// numbers "f:<float>", text "s:<text>", times "t:<RFC3339 UTC>" and any other
// type "o:<type>:<value>". NULL yields ok=false. Mixed numeric types compare
// as MySQL compares them: integers exactly up to 64 bits, everything else as
// float64.
func NormalizeKey(v any) (key string, ok bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case int:
		return "n:" + strconv.FormatInt(int64(x), 10), true
	case int8:
		return "n:" + strconv.FormatInt(int64(x), 10), true
	case int16:
		return "n:" + strconv.FormatInt(int64(x), 10), true
	case int32:
		return "n:" + strconv.FormatInt(int64(x), 10), true
	case int64:
		return "n:" + strconv.FormatInt(x, 10), true
	case uint:
		return "n:" + strconv.FormatUint(uint64(x), 10), true
	case uint8:
		return "n:" + strconv.FormatUint(uint64(x), 10), true
	case uint16:
		return "n:" + strconv.FormatUint(uint64(x), 10), true
	case uint32:
		return "n:" + strconv.FormatUint(uint64(x), 10), true
	case uint64:
		return "n:" + strconv.FormatUint(x, 10), true
	case float32:
		return normFloat(float64(x)), true
	case float64:
		return normFloat(x), true
	case bool:
		if x {
			return "n:1", true
		}
		return "n:0", true
	case []byte:
		return normString(string(x)), true
	case string:
		return normString(x), true
	case time.Time:
		return "t:" + x.UTC().Format(time.RFC3339Nano), true
	}
	// Other driver types (UUID arrays, custom scanners, ...) join only with
	// values of the same Go type and printed form, never across types.
	return fmt.Sprintf("o:%T:%v", v, v), true
}

func normFloat(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1<<63 {
		return "n:" + strconv.FormatInt(int64(f), 10)
	}
	return "f:" + strconv.FormatFloat(f, 'g', -1, 64)
}

func normString(s string) string {
	t := strings.TrimSpace(s)
	if !sqlNumeric(t) {
		return "s:" + s
	}
	if i, err := strconv.ParseInt(t, 10, 64); err == nil {
		return "n:" + strconv.FormatInt(i, 10)
	}
	if f, err := strconv.ParseFloat(t, 64); err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
		return normFloat(f)
	}
	return "s:" + s
}

// sqlNumeric reports whether t is a number in SQL literal syntax: optional
// sign, digits with an optional fraction, and an optional exponent. Go-only
// forms such as "1_000", "0x1Ap0", "Inf" or "NaN" stay text.
func sqlNumeric(t string) bool {
	i, n := 0, len(t)
	if i < n && (t[i] == '+' || t[i] == '-') {
		i++
	}
	digits := 0
	for i < n && t[i] >= '0' && t[i] <= '9' {
		i++
		digits++
	}
	if i < n && t[i] == '.' {
		i++
		for i < n && t[i] >= '0' && t[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < n && (t[i] == 'e' || t[i] == 'E') {
		i++
		if i < n && (t[i] == '+' || t[i] == '-') {
			i++
		}
		exp := 0
		for i < n && t[i] >= '0' && t[i] <= '9' {
			i++
			exp++
		}
		if exp == 0 {
			return false
		}
	}
	return i == n
}

func toInt64(v any) (int64, bool) {
	k, ok := NormalizeKey(v)
	if !ok || !strings.HasPrefix(k, "n:") {
		return 0, false
	}
	n, err := strconv.ParseInt(k[2:], 10, 64)
	return n, err == nil
}

func toFloat64(v any) (float64, bool) {
	k, ok := NormalizeKey(v)
	if !ok || (!strings.HasPrefix(k, "n:") && !strings.HasPrefix(k, "f:")) {
		return 0, false
	}
	f, err := strconv.ParseFloat(k[2:], 64)
	return f, err == nil
}
