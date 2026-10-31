package federation

import (
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
	li, ri := l.index(leftKey), r.index(rightKey)
	if li < 0 || ri < 0 {
		return Relation{}, fmt.Errorf("join key %s or %s not found", leftKey, rightKey)
	}
	out := Relation{Columns: append(append([]string{}, l.Columns...), r.Columns...)}

	build, probe, bi, pi, buildIsLeft := l, r, li, ri, true
	if len(r.Rows) < len(l.Rows) {
		build, probe, bi, pi, buildIsLeft = r, l, ri, li, false
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

	width := len(l.Columns) + len(r.Columns)
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
// numbers "f:<float>", text "s:<text>" and times "t:<RFC3339 UTC>". NULL
// yields ok=false.
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
	return "", false
}

func normFloat(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1<<63 {
		return "n:" + strconv.FormatInt(int64(f), 10)
	}
	return "f:" + strconv.FormatFloat(f, 'g', -1, 64)
}

func normString(s string) string {
	t := strings.TrimSpace(s)
	if i, err := strconv.ParseInt(t, 10, 64); err == nil {
		return "n:" + strconv.FormatInt(i, 10)
	}
	if f, err := strconv.ParseFloat(t, 64); err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
		return normFloat(f)
	}
	return "s:" + s
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
