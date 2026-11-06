package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// mixClass is one statement class of the heterogeneous workload, issued with
// probability Weight through the native drivers or through the UniDB-Go engine.
type mixClass struct {
	Name   string
	Weight float64
	Native func(ctx context.Context, rng *rand.Rand) error
	Unidb  func(ctx context.Context, rng *rand.Rand) error
}

type mixRun struct {
	Rep           int
	Workers       int
	Path          string
	QPS           float64
	Errors        int64
	Completed     int64
	PerClassP50MS map[string]float64
	PerClassP99MS map[string]float64
	PerClassN     map[string]int
}

// mixClasses builds a workload that touches both databases: indexed point
// reads on PostgreSQL, indexed reads and small aggregates on MySQL, and a
// selective federated join, with bind parameters where an application would
// use them.
func (f *fixture) mixClasses() []mixClass {
	n := *rows
	drainN := func(r *sql.Rows, err error) error {
		if err != nil {
			return err
		}
		_, err = drainNative(r)
		return err
	}
	return []mixClass{
		{"PostgreSQL point read", 0.60,
			func(ctx context.Context, rng *rand.Rand) error {
				return drainN(f.pg.QueryContext(ctx, "SELECT id, name, email FROM users WHERE id = $1", 1+rng.Intn(n)))
			},
			func(ctx context.Context, rng *rand.Rand) error {
				r, _, err := f.eng.Query(ctx, "SELECT id, name, email FROM postgres.users WHERE id = $1", 1+rng.Intn(n))
				if err != nil {
					return err
				}
				drainUnified(r)
				return nil
			}},
		{"MySQL orders of a user", 0.30,
			func(ctx context.Context, rng *rand.Rand) error {
				return drainN(f.my.QueryContext(ctx, "SELECT id, total, status FROM orders WHERE user_id = ?", 1+rng.Intn(n)))
			},
			func(ctx context.Context, rng *rand.Rand) error {
				r, _, err := f.eng.Query(ctx, "SELECT id, total, status FROM mysql.orders WHERE user_id = ?", 1+rng.Intn(n))
				if err != nil {
					return err
				}
				drainUnified(r)
				return nil
			}},
		{"MySQL aggregate over 100 users", 0.08,
			func(ctx context.Context, rng *rand.Rand) error {
				lo := 1 + rng.Intn(n-100)
				return drainN(f.my.QueryContext(ctx, "SELECT status, COUNT(*), SUM(total) FROM orders WHERE user_id BETWEEN ? AND ? GROUP BY status", lo, lo+99))
			},
			func(ctx context.Context, rng *rand.Rand) error {
				lo := 1 + rng.Intn(n-100)
				r, _, err := f.eng.Query(ctx, "SELECT status, COUNT(*), SUM(total) FROM mysql.orders WHERE user_id BETWEEN ? AND ? GROUP BY status", lo, lo+99)
				if err != nil {
					return err
				}
				drainUnified(r)
				return nil
			}},
		{"Federated join (200 users)", 0.02,
			func(ctx context.Context, rng *rand.Rand) error {
				lo := 1 + rng.Intn(n-200)
				_, err := f.handWrittenRangeJoin(ctx, lo, lo+199)
				return err
			},
			func(ctx context.Context, rng *rand.Rand) error {
				lo := 1 + rng.Intn(n-200)
				q := fmt.Sprintf("SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE u.id BETWEEN %d AND %d AND o.user_id BETWEEN %d AND %d", lo, lo+199, lo, lo+199)
				r, _, err := f.eng.Query(ctx, q)
				if err != nil {
					return err
				}
				drainUnified(r)
				return nil
			}},
	}
}

// handWrittenRangeJoin is the application-side equivalent of the federated
// join class: two concurrent indexed range reads and a map join.
func (f *fixture) handWrittenRangeJoin(ctx context.Context, lo, hi int) (int, error) {
	names := map[int64]string{}
	type order struct {
		uid   int64
		total string
	}
	var orders []order
	var e1, e2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, err := f.pg.QueryContext(ctx, "SELECT id, name FROM users WHERE id BETWEEN $1 AND $2", lo, hi)
		if err != nil {
			e1 = err
			return
		}
		defer r.Close()
		for r.Next() {
			var id int64
			var name string
			if e1 = r.Scan(&id, &name); e1 != nil {
				return
			}
			names[id] = name
		}
		e1 = r.Err()
	}()
	go func() {
		defer wg.Done()
		r, err := f.my.QueryContext(ctx, "SELECT user_id, total FROM orders WHERE user_id BETWEEN ? AND ?", lo, hi)
		if err != nil {
			e2 = err
			return
		}
		defer r.Close()
		for r.Next() {
			var o order
			if e2 = r.Scan(&o.uid, &o.total); e2 != nil {
				return
			}
			orders = append(orders, o)
		}
		e2 = r.Err()
	}()
	wg.Wait()
	if e1 != nil {
		return 0, e1
	}
	if e2 != nil {
		return 0, e2
	}
	n := 0
	for _, o := range orders {
		if _, ok := names[o.uid]; ok {
			n++
		}
	}
	return n, nil
}

// runMixed measures a heterogeneous closed-loop workload (see mixClasses)
// through the native drivers and through UniDB-Go, alternating which path
// runs first, for -reps repetitions with fresh pools and seeds.
func runMixed() error {
	const pool = 32
	dur := *tpDur
	workerSets := []int{8, 32}
	var runsOut []mixRun
	ratios := map[int][]float64{}
	for rep := 0; rep < *reps; rep++ {
		f, err := openFixture(pool)
		if err != nil {
			return err
		}
		classes := f.mixClasses()
		for _, workers := range workerSets {
			order := []bool{true, false}
			if rep%2 == 1 {
				order = []bool{false, true}
			}
			qps := map[bool]float64{}
			for _, native := range order {
				r := f.mixWindow(classes, workers, native, dur, *seed+int64(rep*1000+workers))
				r.Rep = rep
				runsOut = append(runsOut, r)
				qps[native] = r.QPS
				fmt.Printf("rep %d workers %d %-7s %8.0f q/s errors %d\n", rep, workers, r.Path, r.QPS, r.Errors)
			}
			ratios[workers] = append(ratios[workers], qps[false]/qps[true])
		}
		f.pg.Close()
		f.my.Close()
		f.eng.Close()
	}
	summary := map[string]any{}
	for _, w := range workerSets {
		m, lo, hi := meanTCI(ratios[w])
		summary[fmt.Sprintf("workers_%d", w)] = map[string]any{
			"uni_over_native_qps_mean": m, "ci95_low": lo, "ci95_high": hi, "per_rep": ratios[w],
		}
		fmt.Printf("workers %d: UniDB-Go/native QPS = %.3f [%.3f, %.3f]\n", w, m, lo, hi)
	}
	mix := map[string]float64{}
	for _, c := range (&fixture{}).mixClasses() {
		mix[c.Name] = c.Weight
	}
	return writeJSON("mixed.json", map[string]any{
		"protocol": fmt.Sprintf("closed loop, %d reps with fresh pools (%d connections per source and path), window %s per path, alternating first path, workers %v, per-worker seeds", *reps, pool, dur, workerSets),
		"mix":      mix,
		"summary":  summary,
		"runs":     runsOut,
	})
}

func (f *fixture) mixWindow(classes []mixClass, workers int, native bool, dur time.Duration, seed int64) mixRun {
	ctx := context.Background()
	var done, failed int64
	type sample struct {
		class int
		ms    float64
	}
	lat := make([][]sample, workers)
	stop := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(w)))
			for time.Now().Before(stop) {
				x, ci := rng.Float64(), 0
				for acc := classes[0].Weight; x > acc && ci < len(classes)-1; acc += classes[ci].Weight {
					ci++
				}
				call := classes[ci].Unidb
				if native {
					call = classes[ci].Native
				}
				t := time.Now()
				if err := call(ctx, rng); err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				lat[w] = append(lat[w], sample{ci, msf(time.Since(t))})
				atomic.AddInt64(&done, 1)
			}
		}(w)
	}
	wg.Wait()
	per := map[int][]float64{}
	for _, l := range lat {
		for _, s := range l {
			per[s.class] = append(per[s.class], s.ms)
		}
	}
	r := mixRun{Workers: workers, Path: "unidb", QPS: float64(done) / dur.Seconds(), Errors: failed, Completed: done,
		PerClassP50MS: map[string]float64{}, PerClassP99MS: map[string]float64{}, PerClassN: map[string]int{}}
	if native {
		r.Path = "native"
	}
	for ci, xs := range per {
		sort.Float64s(xs)
		r.PerClassP50MS[classes[ci].Name] = pct(xs, 50)
		r.PerClassP99MS[classes[ci].Name] = pct(xs, 99)
		r.PerClassN[classes[ci].Name] = len(xs)
	}
	return r
}

// meanTCI returns the mean of xs and its 95% t-confidence interval.
func meanTCI(xs []float64) (mean, lo, hi float64) {
	n := float64(len(xs))
	if n == 0 {
		return 0, 0, 0
	}
	for _, x := range xs {
		mean += x
	}
	mean /= n
	if n < 2 {
		return mean, mean, mean
	}
	var ss float64
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	half := tQuantile(0.975, n-1) * math.Sqrt(ss/(n-1)) / math.Sqrt(n)
	return mean, mean - half, mean + half
}
