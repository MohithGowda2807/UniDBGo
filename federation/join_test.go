package federation

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
)

func TestFNV64a(t *testing.T) {
	for _, s := range []string{"", "a", "n:42", "s:hello world"} {
		h := fnv.New64a()
		h.Write([]byte(s))
		if got, want := fnv64a(s), h.Sum64(); got != want {
			t.Errorf("fnv64a(%q) = %x, want %x", s, got, want)
		}
	}
}

func TestNormalizeKeyAcrossDrivers(t *testing.T) {
	same := [][]any{
		{int64(42), []byte("42"), "42", float64(42), int32(42), uint8(42)},
		{"alice", []byte("alice")},
		{3.5, "3.5", []byte("3.50")},
	}
	for _, group := range same {
		want, _ := NormalizeKey(group[0])
		for _, v := range group[1:] {
			if got, _ := NormalizeKey(v); got != want {
				t.Errorf("NormalizeKey(%#v) = %q, want %q", v, got, want)
			}
		}
	}
	if _, ok := NormalizeKey(nil); ok {
		t.Error("NULL must not produce a join key")
	}
}

func TestHashJoinMatchesNestedLoop(t *testing.T) {
	users := []Row{
		{"u.id": int64(1), "u.name": "a"},
		{"u.id": int64(2), "u.name": "b"},
		{"u.id": nil, "u.name": "null"},
		{"u.id": int64(3), "u.name": "c"},
	}
	orders := []Row{
		{"o.id": []byte("10"), "o.user_id": []byte("1")},
		{"o.id": []byte("11"), "o.user_id": []byte("1")},
		{"o.id": []byte("12"), "o.user_id": []byte("3")},
		{"o.id": []byte("13"), "o.user_id": nil},
		{"o.id": []byte("14"), "o.user_id": []byte("9")},
	}
	for _, swap := range []bool{false, true} {
		l, r, lk, rk := users, orders, "u.id", "o.user_id"
		if swap {
			l, r, lk, rk = orders, users, "o.user_id", "u.id"
		}
		h := HashJoin(l, r, lk, rk)
		n := NestedLoopJoin(l, r, lk, rk)
		if len(h) != 3 || len(n) != 3 {
			t.Fatalf("swap=%v: hash join %d rows, nested loop %d rows, want 3", swap, len(h), len(n))
		}
		for _, row := range h {
			if _, ok := row["u.name"]; !ok {
				t.Errorf("merged row lacks left columns: %v", row)
			}
		}
	}
}

func TestNormalizeKeyOtherTypes(t *testing.T) {
	type uuid [4]byte
	a, okA := NormalizeKey(uuid{1, 2, 3, 4})
	b, okB := NormalizeKey(uuid{1, 2, 3, 4})
	c, _ := NormalizeKey(uuid{9, 9, 9, 9})
	if !okA || !okB || a != b || a == c {
		t.Fatalf("same-typed keys: %q %q %q", a, b, c)
	}
	if k, _ := NormalizeKey([4]int{1, 2, 3, 4}); k == a {
		t.Fatal("different Go types must not join")
	}
	if _, ok := NormalizeKey(nil); ok {
		t.Fatal("NULL must not join")
	}
}

// randKey returns a random join-key value of a mix of types. About 1/8 of
// values are NULL. The remaining values span the types NormalizeKey treats as
// the integral "n:" class (so the fast path applies) and types that are not
// (non-integral floats, non-numeric strings), so that generated relations
// exercise both the fast path and its fall-back to the generic path.
func randKey(rng *rand.Rand) any {
	// Keep the integer domain small so joins actually produce matches.
	switch rng.Intn(12) {
	case 0:
		return nil
	case 1:
		return int64(rng.Intn(10))
	case 2:
		return int32(rng.Intn(10))
	case 3:
		return uint(rng.Intn(10))
	case 4:
		return float64(rng.Intn(10)) // integral float -> "n:" class
	case 5:
		return rng.Intn(2) == 1 // bool -> n:0 / n:1
	case 6:
		// []byte numeric with surrounding spaces -> "n:" class after trim.
		return []byte(fmt.Sprintf("  %d ", rng.Intn(10)))
	case 7:
		return []byte(strconv.Itoa(rng.Intn(10)))
	case 8:
		return strconv.Itoa(rng.Intn(10)) // numeric string
	case 9:
		return float64(rng.Intn(10)) + 0.5 // non-integral -> not "n:" class
	case 10:
		return "x" + strconv.Itoa(rng.Intn(3)) // non-numeric string
	default:
		return []byte("tag" + strconv.Itoa(rng.Intn(3))) // non-numeric bytes
	}
}

func randRelation(rng *rand.Rand, keyCol string, n int) Relation {
	rel := Relation{Columns: []string{keyCol, keyCol + "_v"}}
	for i := 0; i < n; i++ {
		rel.Rows = append(rel.Rows, []any{randKey(rng), i})
	}
	return rel
}

// TestFastHashJoinMatchesGeneric is a property-style check: for many random
// relations with mixed key types, the fast path (default) and the forced
// generic path must produce byte-for-byte identical output (same rows, same
// order, same columns).
func TestFastHashJoinMatchesGeneric(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 400; iter++ {
		ln := rng.Intn(40)
		rn := rng.Intn(40)
		l := randRelation(rng, "l.k", ln)
		r := randRelation(rng, "r.k", rn)

		fast, err1 := HashJoinRelations(l, r, "l.k", "r.k")
		gen, err2 := hashJoinRelations(l, r, "l.k", "r.k", false)
		if err1 != nil || err2 != nil {
			t.Fatalf("iter %d: errors fast=%v gen=%v", iter, err1, err2)
		}
		if !reflect.DeepEqual(fast.Columns, gen.Columns) {
			t.Fatalf("iter %d: columns differ: %v vs %v", iter, fast.Columns, gen.Columns)
		}
		if !reflect.DeepEqual(fast.Rows, gen.Rows) {
			t.Fatalf("iter %d: rows differ (ln=%d rn=%d)\n fast=%v\n gen =%v",
				iter, ln, rn, fast.Rows, gen.Rows)
		}
	}
}

// TestIntKeyMatchesNormalizeKey checks that intKey agrees with NormalizeKey on
// exactly which values are integral "n:" keys, and on their int64 value.
func TestIntKeyMatchesNormalizeKey(t *testing.T) {
	cases := []any{
		nil, int(0), int8(-5), int16(300), int32(-7), int64(42),
		uint(42), uint8(255), uint16(1), uint32(9), uint64(42),
		uint64(math.MaxInt64), uint64(math.MaxInt64) + 1, uint(math.MaxInt64),
		float64(42), float64(-42), float64(3.5), float64(math.MaxInt64),
		float64(1 << 63), float32(42), float32(2.5),
		math.Inf(1), math.NaN(),
		true, false,
		[]byte("42"), []byte("  42 "), []byte("-9223372036854775808"),
		[]byte("9223372036854775808"), []byte("42.0"), []byte("4e1"),
		[]byte("3.5"), []byte("alice"), []byte(""), []byte("+"),
		"42", "  -7 ", "3.5", "x", "9999999999999999999999",
		int64(math.MinInt64), int64(math.MaxInt64),
	}
	for _, v := range cases {
		n, kind := intKey(v)
		key, ok := NormalizeKey(v)
		isNKey := ok && len(key) > 2 && key[:2] == "n:"
		switch kind {
		case keyNull:
			// NULL must coincide exactly with NormalizeKey ok=false.
			if ok {
				t.Errorf("intKey(%#v) said NULL but NormalizeKey ok=true (%q)", v, key)
			}
		case keyInt:
			// A keyInt value must be a faithful "n:<n>" key, so two keyInt
			// values compare equal iff their NormalizeKeys do.
			if got := "n:" + strconv.FormatInt(n, 10); got != key {
				t.Errorf("intKey(%#v)=%d renders %q, NormalizeKey=%q", v, n, got, key)
			}
		case keyOther:
			// keyOther must never collide with any in-range int64 "n:" key:
			// either it is not "n:" class at all, or its integer is outside
			// int64's range (so no keyInt build key can equal it).
			if isNKey {
				if _, err := strconv.ParseInt(key[2:], 10, 64); err == nil {
					t.Errorf("intKey(%#v)=keyOther but NormalizeKey=%q is an in-range int64 key", v, key)
				}
			}
		}
	}
}

// benchRelations builds n users with int64 keys (as lib/pq returns) and n
// orders with []byte user_id keys (as the MySQL text protocol returns), each
// order referencing a random user, mirroring cmd/unidb-bench/join.go.
func benchRelations(n int, rng *rand.Rand) (users, orders Relation) {
	users.Columns = []string{"u.id", "u.name"}
	for i := 0; i < n; i++ {
		users.Rows = append(users.Rows, []any{int64(i + 1), "user" + strconv.Itoa(i+1)})
	}
	orders.Columns = []string{"o.id", "o.user_id", "o.total"}
	for i := 0; i < n; i++ {
		orders.Rows = append(orders.Rows, []any{
			[]byte(strconv.Itoa(i + 1)),
			[]byte(strconv.Itoa(rng.Intn(n) + 1)),
			[]byte(fmt.Sprintf("%d.%02d", rng.Intn(500), rng.Intn(100))),
		})
	}
	return
}

func BenchmarkHashJoinFast(b *testing.B) {
	users, orders := benchRelations(50000, rand.New(rand.NewSource(1)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := HashJoinRelations(users, orders, "u.id", "o.user_id")
		if err != nil || len(r.Rows) != 50000 {
			b.Fatalf("rows=%d err=%v", len(r.Rows), err)
		}
	}
}

func BenchmarkHashJoinGeneric(b *testing.B) {
	users, orders := benchRelations(50000, rand.New(rand.NewSource(1)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := hashJoinRelations(users, orders, "u.id", "o.user_id", false)
		if err != nil || len(r.Rows) != 50000 {
			b.Fatalf("rows=%d err=%v", len(r.Rows), err)
		}
	}
}

func TestNormalizeKeySQLNumericSyntax(t *testing.T) {
	for _, s := range []string{"1_000", "0x1Ap0", "Inf", "NaN", "1e", "."} {
		if k, _ := NormalizeKey(s); k != "s:"+s {
			t.Errorf("%q: got %q, want text", s, k)
		}
	}
	for s, want := range map[string]string{"42": "n:42", " 42 ": "n:42", "42.0": "n:42", "4.2e1": "n:42", "-7": "n:-7", "2.5": "f:2.5"} {
		if k, _ := NormalizeKey(s); k != want {
			t.Errorf("%q: got %q, want %q", s, k, want)
		}
	}
}
