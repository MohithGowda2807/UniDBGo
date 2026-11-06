package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/circuit"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
)

var tableOf = map[string]string{"postgres": "fault_users", "mysql": "fault_orders"}

// singleQ is a single-source full scan per side (streamed, not materialised).
var singleQ = map[string]string{
	"postgres": "SELECT id, name FROM postgres.fault_users",
	"mysql":    "SELECT id, user_id, total FROM mysql.fault_orders",
}

// measured during baseline and reused to place mid-stream cuts.
var fullBytes = map[string]int64{}
var singleBytes = map[string]int64{}

func baseline(e *env) (any, error) {
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	defer eng.Close()
	ctx := context.Background()
	if _, err := runQuery(ctx, eng, smallQ); err != nil {
		return nil, err
	}
	var fedMs, smallMs []float64
	rows := 0
	bytes := map[string][]int64{}
	for i := 0; i < 5; i++ {
		b0 := map[string]int64{"postgres": e.pgP.s2c.Load(), "mysql": e.myP.s2c.Load()}
		t0 := time.Now()
		n, err := runQuery(ctx, eng, fullQ)
		if err != nil {
			return nil, err
		}
		fedMs = append(fedMs, ms(time.Since(t0)))
		rows = n
		for _, s := range []string{"postgres", "mysql"} {
			bytes[s] = append(bytes[s], e.proxyOf(s).s2c.Load()-b0[s])
		}
	}
	for i := 0; i < 20; i++ {
		t0 := time.Now()
		if _, err := runQuery(ctx, eng, smallQ); err != nil {
			return nil, err
		}
		smallMs = append(smallMs, ms(time.Since(t0)))
	}
	single := map[string]any{}
	for _, s := range []string{"postgres", "mysql"} {
		fullBytes[s] = bytes[s][len(bytes[s])-1]
		var ts []float64
		var n int
		for i := 0; i < 3; i++ {
			b0 := e.proxyOf(s).s2c.Load()
			t0 := time.Now()
			if n, err = runQuery(ctx, eng, singleQ[s]); err != nil {
				return nil, err
			}
			ts = append(ts, ms(time.Since(t0)))
			singleBytes[s] = e.proxyOf(s).s2c.Load() - b0
		}
		single[s] = map[string]any{"query": singleQ[s], "rows": n, "bytes_server_to_client": singleBytes[s], "latency": summarize(ts)}
	}
	return map[string]any{
		"full_federated":          map[string]any{"rows": rows, "latency": summarize(fedMs), "bytes_server_to_client": map[string]any{"postgres": fullBytes["postgres"], "mysql": fullBytes["mysql"]}},
		"small_federated":         map[string]any{"latency": summarize(smallMs)},
		"single_source_full_scan": single,
	}, nil
}

// fedTrial is one federated query run under a fault on one side.
type fedTrial struct {
	Err                   string               `json:"err,omitempty"`
	Rows                  int                  `json:"rows"`
	Ms                    float64              `json:"ms"`
	SiblingBytes          int64                `json:"sibling_bytes_relayed"`
	SiblingActiveAtReturn int                  `json:"sibling_statements_active_on_server_at_return"`
	SiblingServerStopMs   float64              `json:"sibling_server_stop_ms"`
	GoroutineExcess       int                  `json:"goroutine_excess_after_settle"`
	Pool                  map[string]poolStats `json:"pool_after"`
}

// faultedFederated warms the pools, injects a fault on side, runs the full
// federated query and records what the caller and the servers saw.
func faultedFederated(e *env, eng *engine.Engine, side string, inject func()) fedTrial {
	ctx := context.Background()
	if _, err := runQuery(ctx, eng, smallQ); err != nil {
		log.Printf("warm-up failed: %v", err)
	}
	sib := other(side)
	base := clientGoroutines()
	b0 := e.proxyOf(sib).s2c.Load()
	inject()
	qctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	t0 := time.Now()
	n, err := runQuery(qctx, eng, fullQ)
	dt := time.Since(t0)
	cancel()
	tr := fedTrial{Err: errText(err), Rows: n, Ms: ms(dt), SiblingBytes: e.proxyOf(sib).s2c.Load() - b0}
	tr.SiblingActiveAtReturn = e.serverActive(sib, tableOf[sib])
	tr.SiblingServerStopMs = e.serverStopMs(sib, tableOf[sib], 10*time.Second)
	tr.GoroutineExcess = settle(base, 3*time.Second)
	tr.Pool = map[string]poolStats{"postgres": statsOf(eng.Sources["postgres"]), "mysql": statsOf(eng.Sources["mysql"])}
	return tr
}

func summarizeFed(ts []fedTrial) map[string]any {
	var errs []string
	var times, stops []float64
	ok, partial, sibActive, leaks := 0, 0, 0, 0
	for _, t := range ts {
		errs = append(errs, t.Err)
		times = append(times, t.Ms)
		if t.Err == "" {
			ok++
		} else if t.Rows > 0 {
			partial++
		}
		if t.SiblingActiveAtReturn > 0 {
			sibActive++
		}
		if t.SiblingServerStopMs >= 0 {
			stops = append(stops, t.SiblingServerStopMs)
		}
		if t.GoroutineExcess > 0 {
			leaks++
		}
	}
	return map[string]any{
		"trials": len(ts), "returned_error": len(ts) - ok, "returned_success": ok,
		"error_with_partial_rows": partial,
		"time_to_return":          summarize(times),
		"errors":                  countErrs(errs),
		"sibling_still_active_on_server_at_return": sibActive,
		"sibling_server_stop_after_return":         summarize(stops),
		"trials_with_goroutine_excess_after_3s":    leaks,
		"per_trial":                                ts,
	}
}

// engineLeak closes eng and reports client goroutines above the count
// measured before the engine was created.
func engineLeak(eng *engine.Engine, before int) map[string]int {
	eng.Close()
	time.Sleep(200 * time.Millisecond)
	excess := settle(before, 5*time.Second)
	return map[string]int{"goroutines_before_engine": before, "excess_after_engine_close": excess}
}

func scenarioRefused(e *env) (any, error) {
	out := map[string]any{}
	// Connect while the source is down.
	var cms []float64
	var cerrs []string
	isConnFailed := 0
	for i := 0; i < *trials; i++ {
		e.pgP.refuse()
		t0 := time.Now()
		db, err := api.Connect(e.pgVia)
		cms = append(cms, ms(time.Since(t0)))
		cerrs = append(cerrs, errText(err))
		if errors.Is(err, api.ErrConnectionFailed) {
			isConnFailed++
		}
		if db != nil {
			db.Close()
		}
		e.healAll()
	}
	out["connect_while_down"] = map[string]any{"side": "postgres", "trials": *trials, "errors": countErrs(cerrs),
		"errors_is_ErrConnectionFailed": isConnFailed, "time_to_error": summarize(cms)}

	before := clientGoroutines()
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	for _, side := range []string{"postgres", "mysql"} {
		var ts []fedTrial
		for i := 0; i < *trials; i++ {
			ts = append(ts, faultedFederated(e, eng, side, e.proxyOf(side).refuse))
			e.healAll()
		}
		out["down_"+side] = summarizeFed(ts)
	}
	out["leak_check"] = engineLeak(eng, before)
	return out, nil
}

// singleTrial is a streamed single-source scan cut mid-stream.
type singleTrial struct {
	RowsBeforeEnd int     `json:"rows_before_next_false"`
	Err           string  `json:"err_from_result_Err,omitempty"`
	Ms            float64 `json:"ms"`
}

func scenarioCut(e *env) (any, error) {
	if len(fullBytes) == 0 {
		if _, err := baseline(e); err != nil {
			return nil, err
		}
	}
	out := map[string]any{}
	before := clientGoroutines()
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	for _, side := range []string{"postgres", "mysql"} {
		var ts []fedTrial
		p := e.proxyOf(side)
		at := fullBytes[side] / 2
		for i := 0; i < *trials; i++ {
			ts = append(ts, faultedFederated(e, eng, side, func() { p.cutAfter(at) }))
			e.healAll()
		}
		s := summarizeFed(ts)
		s["cut_after_server_bytes"] = at
		s["full_scan_server_bytes"] = fullBytes[side]
		out["cut_"+side] = s

		// Single-source streamed scan: the error must surface through Err().
		var st []singleTrial
		silent := 0
		for i := 0; i < *trials; i++ {
			p.cutAfter(singleBytes[side] / 2)
			t0 := time.Now()
			res, _, qerr := eng.Query(context.Background(), singleQ[side])
			var n int
			if qerr == nil {
				n, qerr = drain(res)
			}
			st = append(st, singleTrial{n, errText(qerr), ms(time.Since(t0))})
			if qerr == nil {
				silent++
			}
			e.healAll()
		}
		var errs []string
		var times []float64
		for _, t := range st {
			errs = append(errs, t.Err)
			times = append(times, t.Ms)
		}
		out["cut_single_source_"+side] = map[string]any{
			"query": singleQ[side], "trials": *trials, "cut_after_server_bytes": singleBytes[side] / 2,
			"silently_truncated_success": silent, "errors": countErrs(errs), "time_to_error": summarize(times), "per_trial": st,
		}
	}
	out["leak_check"] = engineLeak(eng, before)
	return out, nil
}

// bhTrial is one query against a blackholed source with a deadline.
type bhTrial struct {
	ReturnedBeforeWatchdog bool    `json:"returned_before_watchdog"`
	Ms                     float64 `json:"ms"`
	Err                    string  `json:"err,omitempty"`
	StuckGoroutines        int     `json:"stuck_goroutines_at_watchdog"`
	MsAfterHeal            float64 `json:"ms_after_heal,omitempty"`
	ErrAfterHeal           string  `json:"err_after_heal,omitempty"`
	ReturnedAfterHeal      bool    `json:"returned_after_heal"`
	GoroutineExcess        int     `json:"goroutine_excess_after_settle"`
}

// blackholeTrial runs q with the given deadline (0 = none) while side is
// blackholed. A query still running at the watchdog is released by healing
// the proxy, and the time it then needs to return is recorded.
func blackholeTrial(e *env, eng *engine.Engine, side, q string, cold bool, deadline, watchdog time.Duration) bhTrial {
	p := e.proxyOf(side)
	if _, err := runQuery(context.Background(), eng, smallQ); err != nil {
		log.Printf("warm-up failed: %v", err)
	}
	if cold {
		p.cutAll() // pooled connections die; the query must dial anew
		time.Sleep(50 * time.Millisecond)
	}
	base := clientGoroutines()
	p.blackhole()
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if deadline > 0 {
		ctx, cancel = context.WithTimeout(ctx, deadline)
	}
	defer cancel()
	type r struct {
		err error
		d   time.Duration
	}
	done := make(chan r, 1)
	t0 := time.Now()
	go func() {
		_, err := runQuery(ctx, eng, q)
		done <- r{err, time.Since(t0)}
	}()
	var tr bhTrial
	select {
	case x := <-done:
		tr = bhTrial{ReturnedBeforeWatchdog: true, Ms: ms(x.d), Err: errText(x.err)}
	case <-time.After(watchdog):
		tr.StuckGoroutines = clientGoroutines() - base
		tr.Ms = ms(time.Since(t0))
		th := time.Now()
		if err := p.heal(); err != nil {
			log.Fatal(err)
		}
		select {
		case x := <-done:
			tr.ReturnedAfterHeal, tr.MsAfterHeal, tr.ErrAfterHeal = true, ms(time.Since(th)), errText(x.err)
		case <-time.After(10 * time.Second):
			p.cutAll()
			x := <-done
			tr.MsAfterHeal, tr.ErrAfterHeal = ms(time.Since(th)), "returned only after cut: "+errText(x.err)
		}
	}
	e.healAll()
	tr.GoroutineExcess = settle(base, 3*time.Second)
	return tr
}

func summarizeBH(ts []bhTrial, deadline time.Duration) map[string]any {
	var times, heal, stuckG []float64
	var errs, herrs []string
	returned, atDeadline, stuck := 0, 0, 0
	for _, t := range ts {
		if t.ReturnedBeforeWatchdog {
			returned++
			times = append(times, t.Ms)
			errs = append(errs, t.Err)
			if deadline > 0 && t.Ms <= float64(deadline.Milliseconds())+100 {
				atDeadline++
			}
		} else {
			heal = append(heal, t.MsAfterHeal)
			stuckG = append(stuckG, float64(t.StuckGoroutines))
			herrs = append(herrs, t.ErrAfterHeal)
		}
		if t.GoroutineExcess > 0 {
			stuck++
		}
	}
	return map[string]any{
		"trials": len(ts), "returned_before_watchdog": returned, "returned_within_deadline_plus_100ms": atDeadline,
		"hung_until_proxy_healed": len(ts) - returned,
		"time_to_return":          summarize(times), "errors": countErrs(errs),
		"time_to_return_after_heal": summarize(heal), "results_after_heal": countErrs(herrs),
		"client_goroutines_blocked_at_watchdog":          stuckG,
		"trials_with_goroutine_excess_after_heal_and_3s": stuck, "per_trial": ts,
	}
}

func scenarioBlackhole(e *env) (any, error) {
	const deadline, watchdog = 500 * time.Millisecond, 3 * time.Second
	out := map[string]any{"deadline_ms": deadline.Milliseconds(), "watchdog_ms": watchdog.Milliseconds()}
	before := clientGoroutines()
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	for _, side := range []string{"postgres", "mysql"} {
		for _, cold := range []bool{false, true} {
			pool := "warm_pool"
			if cold {
				pool = "cold_pool"
			}
			for _, kind := range []string{"federated", "single_source"} {
				q := smallQ
				if kind == "single_source" {
					q = map[string]string{"postgres": "SELECT id, name FROM postgres.fault_users WHERE id <= 1000", "mysql": "SELECT id, total FROM mysql.fault_orders WHERE id <= 1000"}[side]
				}
				var ts []bhTrial
				for i := 0; i < *trials; i++ {
					ts = append(ts, blackholeTrial(e, eng, side, q, cold, deadline, watchdog))
				}
				key := fmt.Sprintf("%s_%s_%s", side, pool, kind)
				out[key] = summarizeBH(ts, deadline)
				log.Printf("  %s done", key)
			}
		}
		// Without any deadline.
		var ts []bhTrial
		for i := 0; i < 5; i++ {
			ts = append(ts, blackholeTrial(e, eng, side, smallQ, false, 0, watchdog))
		}
		out[side+"_warm_pool_federated_no_deadline"] = summarizeBH(ts, 0)
	}
	// Does the PostgreSQL hang end by itself? Long watchdog, few trials.
	var long []bhTrial
	for i := 0; i < 3; i++ {
		long = append(long, blackholeTrial(e, eng, "postgres", smallQ, false, deadline, 60*time.Second))
	}
	out["postgres_warm_pool_federated_watchdog_60s"] = summarizeBH(long, deadline)
	out["leak_check"] = engineLeak(eng, before)

	// Mitigation for new connections only: lib/pq connect_timeout.
	eng2, err := e.newEngineWith("connect_timeout=1")
	if err != nil {
		return nil, err
	}
	defer eng2.Close()
	var ct []bhTrial
	for i := 0; i < *trials; i++ {
		ct = append(ct, blackholeTrial(e, eng2, "postgres", smallQ, true, deadline, watchdog))
	}
	out["postgres_cold_pool_federated_with_connect_timeout_1s"] = summarizeBH(ct, deadline)
	var wt []bhTrial
	for i := 0; i < 5; i++ {
		wt = append(wt, blackholeTrial(e, eng2, "postgres", smallQ, false, deadline, watchdog))
	}
	out["postgres_warm_pool_federated_with_connect_timeout_1s"] = summarizeBH(wt, deadline)
	return out, nil
}

// stepQueries returns the per-source scans the federation runs for q.
func stepQueries(q string) (map[string]planner.ExecutionStep, error) {
	ast, err := parser.Parse(q)
	if err != nil {
		return nil, err
	}
	plan, err := planner.GeneratePlan(ast)
	if err != nil {
		return nil, err
	}
	out := map[string]planner.ExecutionStep{}
	for _, s := range plan.Steps {
		if s.Type == "SCAN" {
			out[s.Database] = s
		}
	}
	return out, nil
}

func scenarioLatency(e *env) (any, error) {
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	defer eng.Close()
	steps, err := stepQueries(smallQ)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	side := func(name string) (float64, error) {
		s := steps[name]
		db := eng.Sources[name]
		t0 := time.Now()
		res, err := db.Query(ctx, parser.Bind(s.Query, parser.DialectOf(db.Driver())), s.Args...)
		if err != nil {
			return 0, err
		}
		if _, err := drain(res); err != nil {
			return 0, err
		}
		return ms(time.Since(t0)), nil
	}
	configs := []struct{ pg, my int }{{0, 0}, {5, 0}, {50, 0}, {0, 5}, {0, 50}, {50, 50}}
	var results []map[string]any
	for _, c := range configs {
		e.pgP.latency.Store(int64(time.Duration(c.pg) * time.Millisecond))
		e.myP.latency.Store(int64(time.Duration(c.my) * time.Millisecond))
		var fed, pgT, myT []float64
		chunks := map[string]int64{}
		for i := 0; i < *trials+3; i++ {
			c0 := map[string]int64{"postgres": e.pgP.chunks.Load(), "mysql": e.myP.chunks.Load()}
			t0 := time.Now()
			if _, err := runQuery(ctx, eng, smallQ); err != nil {
				return nil, err
			}
			d := ms(time.Since(t0))
			for _, s := range []string{"postgres", "mysql"} {
				chunks[s] = e.proxyOf(s).chunks.Load() - c0[s]
			}
			a, err := side("postgres")
			if err != nil {
				return nil, err
			}
			b, err := side("mysql")
			if err != nil {
				return nil, err
			}
			if i >= 3 { // first three are warm-up
				fed, pgT, myT = append(fed, d), append(pgT, a), append(myT, b)
			}
		}
		results = append(results, map[string]any{
			"added_delay_per_round_trip_ms": map[string]int{"postgres": c.pg, "mysql": c.my},
			"federated":                     summarize(fed), "postgres_scan_alone": summarize(pgT), "mysql_scan_alone": summarize(myT),
			"client_to_server_chunks_per_federated_query": chunks,
		})
	}
	e.healAll()
	return map[string]any{"query": smallQ, "step_queries": steps, "configs": results}, nil
}

// recoveryTrial injects a fault, heals it and counts failed queries before
// the first success, without restarting anything.
type recoveryTrial struct {
	FaultQueryErr  string    `json:"fault_query_err,omitempty"`
	FailuresBefore int       `json:"failures_before_first_success"`
	MsToSuccess    float64   `json:"ms_heal_to_first_success"`
	FailureErrs    []string  `json:"failure_errs,omitempty"`
	NextFiveOK     int       `json:"next_five_ok"`
	Pool           poolStats `json:"pool_after_faulted_side"`
}

func scenarioRecovery(e *env) (any, error) {
	before := clientGoroutines()
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, side := range []string{"postgres", "mysql"} {
		p := e.proxyOf(side)
		for _, fault := range []string{"refused", "cut_idle", "blackhole"} {
			var ts []recoveryTrial
			for i := 0; i < *trials; i++ {
				if _, err := runQuery(context.Background(), eng, smallQ); err != nil {
					log.Printf("warm-up failed: %v", err)
				}
				var tr recoveryTrial
				switch fault {
				case "refused":
					p.refuse()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, err := runQuery(ctx, eng, smallQ)
					cancel()
					tr.FaultQueryErr = errText(err)
				case "cut_idle":
					p.cutAll() // server stays reachable; pooled connections are dead
				case "blackhole":
					p.blackhole()
					done := make(chan error, 1)
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
						defer cancel()
						_, err := runQuery(ctx, eng, smallQ)
						done <- err
					}()
					select {
					case err := <-done:
						tr.FaultQueryErr = errText(err)
					case <-time.After(3 * time.Second):
						tr.FaultQueryErr = "hung past watchdog (3s)"
						if err := p.heal(); err != nil {
							return nil, err
						}
						<-done
					}
				}
				if err := p.heal(); err != nil {
					return nil, err
				}
				th := time.Now()
				for a := 0; a < 50; a++ {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, err := runQuery(ctx, eng, smallQ)
					cancel()
					if err == nil {
						break
					}
					tr.FailuresBefore++
					tr.FailureErrs = append(tr.FailureErrs, normalizeErr(err.Error()))
				}
				tr.MsToSuccess = ms(time.Since(th))
				for k := 0; k < 5; k++ {
					if _, err := runQuery(context.Background(), eng, smallQ); err == nil {
						tr.NextFiveOK++
					}
				}
				tr.Pool = statsOf(eng.Sources[side])
				ts = append(ts, tr)
			}
			var fails []float64
			var times []float64
			hist := map[int]int{}
			var ferrs []string
			nextOK := 0
			for _, t := range ts {
				fails = append(fails, float64(t.FailuresBefore))
				times = append(times, t.MsToSuccess)
				hist[t.FailuresBefore]++
				ferrs = append(ferrs, t.FailureErrs...)
				nextOK += t.NextFiveOK
			}
			out[side+"_"+fault] = map[string]any{
				"trials": len(ts), "failures_before_first_success_histogram": hist,
				"heal_to_first_success": summarize(times), "failure_errors": countErrs(ferrs),
				"subsequent_queries_ok": fmt.Sprintf("%d/%d", nextOK, 5*len(ts)), "per_trial": ts,
			}
		}
	}
	out["leak_check"] = engineLeak(eng, before)
	return out, nil
}

func scenarioBreaker(e *env) (any, error) {
	out := map[string]any{
		"wired_into_api_or_engine": false,
		"code_evidence":            "circuit.CircuitBreaker is only constructed by pool.PoolManager.AddPool (pool/pool.go); PoolManager and ConnectionPool are never used by api/, engine/ or federation/ (api.Connect only attaches pool.StartTuner). The breaker is therefore exercised here directly around api.DB.Query.",
	}
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	defer eng.Close()
	pg := eng.Sources["postgres"]
	const k, open = 5, 1 * time.Second
	call := func(cb *circuit.CircuitBreaker, q string) (error, time.Duration) {
		t0 := time.Now()
		err := cb.Execute(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res, err := pg.Query(ctx, q)
			if err != nil {
				return err
			}
			_, err = drain(res)
			return err
		})
		return err, time.Since(t0)
	}
	q := "SELECT id FROM fault_users WHERE id = 1"
	var seqOK int
	var realMs, rejMs []float64
	var trace []map[string]any
	for i := 0; i < *trials; i++ {
		cb := circuit.NewCircuitBreaker(k, open)
		e.pgP.refuse()
		var seq []string
		for j := 0; j < 10; j++ {
			err, d := call(cb, q)
			switch {
			case errors.Is(err, circuit.ErrCircuitOpen):
				seq = append(seq, "rejected")
				rejMs = append(rejMs, ms(d))
			case err != nil:
				seq = append(seq, "backend_error")
				realMs = append(realMs, ms(d))
			default:
				seq = append(seq, "ok")
			}
		}
		stateOpen := cb.State().String()
		time.Sleep(open + 100*time.Millisecond)
		stateLater := cb.State().String()
		err1, _ := call(cb, q) // half-open trial while still down
		afterFailedProbe := cb.State().String()
		immediate, _ := call(cb, q)
		time.Sleep(open + 100*time.Millisecond)
		if err := e.pgP.heal(); err != nil {
			return nil, err
		}
		err2, _ := call(cb, q) // half-open trial after heal
		afterProbe := cb.State().String()
		good := true
		for j, s := range seq {
			if (j < k && s != "backend_error") || (j >= k && s != "rejected") {
				good = false
			}
		}
		if good && stateOpen == "open" && stateLater == "half-open" && err1 != nil && !errors.Is(err1, circuit.ErrCircuitOpen) &&
			afterFailedProbe == "open" && errors.Is(immediate, circuit.ErrCircuitOpen) && err2 == nil && afterProbe == "closed" {
			seqOK++
		}
		if i == 0 {
			trace = append(trace, map[string]any{"calls_while_down": seq, "state_after_10_calls": stateOpen,
				"state_after_timeout": stateLater, "half_open_trial_while_down": errText(err1), "state_after_failed_trial": afterFailedProbe,
				"call_right_after_failed_trial": errText(immediate), "half_open_trial_after_heal_err": errText(err2), "state_after_successful_trial": afterProbe})
		}
	}
	out["sequence"] = map[string]any{"threshold_k": k, "open_timeout_ms": open.Milliseconds(), "trials": *trials,
		"trials_matching_expected_sequence": seqOK,
		"expected":                          "calls 1..K reach the backend and fail; calls K+1..10 rejected with ErrCircuitOpen; after timeout state reads half-open; failed trial reopens; after heal the trial succeeds and closes",
		"backend_error_latency":             summarize(realMs), "rejected_call_latency": summarize(rejMs), "example_trial": trace}

	// Only one trial call passes while half-open.
	var admitted []float64
	for i := 0; i < *trials; i++ {
		cb := circuit.NewCircuitBreaker(1, 50*time.Millisecond)
		_ = cb.Execute(func() error { return errors.New("fail") })
		time.Sleep(80 * time.Millisecond)
		start := make(chan struct{})
		res := make(chan error, 10)
		for j := 0; j < 10; j++ {
			go func() {
				<-start
				res <- cb.Execute(func() error { time.Sleep(100 * time.Millisecond); return nil })
			}()
		}
		close(start)
		n := 0
		for j := 0; j < 10; j++ {
			if <-res == nil {
				n++
			}
		}
		admitted = append(admitted, float64(n))
	}
	out["half_open_concurrency"] = map[string]any{"concurrent_callers": 10, "admitted_per_trial": admitted}

	// The breaker counts every error, including ones the backend never saw.
	var opened int
	for i := 0; i < *trials; i++ {
		cb := circuit.NewCircuitBreaker(k, open)
		for j := 0; j < k; j++ {
			_, _ = call(cb, "SELECT id FROM fault_users WHERE id = 1 OR 1=1") // blocked by security middleware
		}
		if err, _ := call(cb, q); errors.Is(err, circuit.ErrCircuitOpen) {
			opened++
		}
	}
	out["blocked_queries_open_circuit"] = map[string]any{"trials": *trials, "legit_query_rejected_after_K_blocked_queries": opened,
		"note": "Execute counts any non-nil error (ErrBlockedQuery, SQL errors, caller cancellation) as a backend failure; a breaker wired naively around api.DB.Query would let K injection attempts open it for every caller"}
	return out, nil
}
