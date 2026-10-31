package main

import (
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/federation"
)

// syntheticRelations builds n users (int64 keys, as returned by lib/pq) and n
// orders whose user_id is []byte (as returned by the MySQL text protocol),
// each order referencing a random user.
func syntheticRelations(n int, rng *rand.Rand) (users, orders federation.Relation) {
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

func timeIt(reps int, f func()) (median time.Duration) {
	ds := make([]time.Duration, reps)
	for i := range ds {
		start := time.Now()
		f()
		ds[i] = time.Since(start)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}

type joinPoint struct {
	N          int
	HashMS     float64
	NestedMS   float64
	Speedup    float64
	OutputRows int
}

func runJoin() error {
	rng := rand.New(rand.NewSource(*seed))
	var pts []joinPoint
	for _, n := range []int{500, 1000, 2500, 5000, 10000, 25000, 50000} {
		users, orders := syntheticRelations(n, rng)
		var out int
		hash := timeIt(9, func() {
			r, _ := federation.HashJoinRelations(users, orders, "u.id", "o.user_id")
			out = len(r.Rows)
		})
		reps := 5
		if n >= 25000 {
			reps = 3
		}
		var nout int
		nested := timeIt(reps, func() {
			r, _ := federation.NestedLoopRelations(users, orders, "u.id", "o.user_id")
			nout = len(r.Rows)
		})
		if out != nout || out != n {
			return fmt.Errorf("join mismatch at n=%d: hash=%d nested=%d", n, out, nout)
		}
		p := joinPoint{N: n, HashMS: ms(hash), NestedMS: ms(nested), Speedup: float64(nested) / float64(hash), OutputRows: out}
		pts = append(pts, p)
		fmt.Printf("n=%6d hash=%9.3f ms nested=%11.1f ms speedup=%7.1fx\n", n, p.HashMS, p.NestedMS, p.Speedup)
	}
	var csv strings.Builder
	csv.WriteString("n hash nested\n")
	for _, p := range pts {
		fmt.Fprintf(&csv, "%d %.4f %.4f\n", p.N, p.HashMS, p.NestedMS)
	}
	if err := writeFile("join.dat", csv.String()); err != nil {
		return err
	}
	return writeJSON("join.json", pts)
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }
