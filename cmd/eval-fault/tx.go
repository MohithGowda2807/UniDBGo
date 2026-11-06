package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
)

func (e *env) direct(side string) *sql.DB {
	if side == "postgres" {
		return e.pgDirect
	}
	return e.myDirect
}

// rowCount counts fault_tx rows with the given id, read directly on the server.
func (e *env) rowCount(side string, id int) int {
	var n int
	q := "SELECT COUNT(*) FROM fault_tx WHERE id = " + strconv.Itoa(id)
	if err := e.direct(side).QueryRow(q).Scan(&n); err != nil {
		return -1
	}
	return n
}

func (e *env) tableRows(side string) int {
	var n int
	if err := e.direct(side).QueryRow("SELECT COUNT(*) FROM fault_tx").Scan(&n); err != nil {
		return -1
	}
	return n
}

func ins(id int, note string) string {
	return fmt.Sprintf("INSERT INTO fault_tx VALUES (%d, '%s')", id, note)
}

func scenarioTx(e *env) (any, error) {
	for _, s := range []string{"postgres", "mysql"} {
		if _, err := e.direct(s).Exec("DELETE FROM fault_tx"); err != nil {
			return nil, err
		}
	}
	eng, err := e.newEngine()
	if err != nil {
		return nil, err
	}
	defer eng.Close()
	out := map[string]any{}
	for i, side := range []string{"postgres", "mysql"} {
		base := 1000000 * (i + 1)
		r := map[string]any{}
		r["commit_rollback"] = txCommitRollback(e, eng.Sources[side], side, base)
		r["cut_mid_transaction"] = txCutMid(e, eng.Sources[side], side, base+100000)
		r["cut_during_commit_in_doubt"] = txInDoubt(e, eng.Sources[side], side, base+200000)
		r["security_inside_transaction"] = txSecurity(e, eng.Sources[side], side, base+300000)
		out[side] = r
	}
	out["cross_database_writes"] = txCrossDB(e, eng)
	snap, err := snapshotReads(e, eng)
	if err != nil {
		return nil, err
	}
	out["federated_read_snapshot"] = snap
	return out, nil
}

func txCommitRollback(e *env, db *api.DB, side string, base int) map[string]any {
	ctx := context.Background()
	var commitOK, rollbackOK, isolated int
	var errs []string
	for i := 0; i < *trials; i++ {
		id := base + i
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if _, err := tx.Exec(ctx, ins(id, "commit")); err != nil {
			errs = append(errs, err.Error())
		}
		before := e.rowCount(side, id)
		if err := tx.Commit(); err != nil {
			errs = append(errs, err.Error())
		}
		if before == 0 {
			isolated++
		}
		if e.rowCount(side, id) == 1 {
			commitOK++
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if _, err := tx.Exec(ctx, ins(id+50000, "rollback")); err != nil {
			errs = append(errs, err.Error())
		}
		if err := tx.Rollback(); err != nil {
			errs = append(errs, err.Error())
		}
		if e.rowCount(side, id+50000) == 0 {
			rollbackOK++
		}
	}
	return map[string]any{"trials": *trials, "committed_row_visible": commitOK, "rolled_back_row_absent": rollbackOK,
		"uncommitted_row_invisible_to_other_session": isolated, "errors": countErrs(errs)}
}

func txCutMid(e *env, db *api.DB, side string, base int) map[string]any {
	ctx := context.Background()
	p := e.proxyOf(side)
	var secondErr, commitErr, firstAbsent, secondAbsent int
	var relock []float64
	var errs []string
	for i := 0; i < *trials; i++ {
		a, b := base+2*i, base+2*i+1
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			errs = append(errs, "begin: "+err.Error())
			continue
		}
		if _, err := tx.Exec(ctx, ins(a, "first")); err != nil {
			errs = append(errs, "first insert: "+err.Error())
		}
		p.cutAll()
		_, err = tx.Exec(ctx, ins(b, "second"))
		if err != nil {
			secondErr++
			errs = append(errs, "second insert: "+normalizeErr(err.Error()))
		}
		if err := tx.Commit(); err != nil {
			commitErr++
			errs = append(errs, "commit: "+normalizeErr(err.Error()))
		}
		if e.rowCount(side, a) == 0 {
			firstAbsent++
		}
		if e.rowCount(side, b) == 0 {
			secondAbsent++
		}
		// A lock held by a lingering server-side transaction would block this.
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		t0 := time.Now()
		_, err = e.direct(side).ExecContext(lctx, ins(a, "probe"))
		cancel()
		if err == nil {
			relock = append(relock, ms(time.Since(t0)))
			e.direct(side).Exec("DELETE FROM fault_tx WHERE id = " + strconv.Itoa(a))
		}
	}
	return map[string]any{"trials": *trials, "statement_after_cut_returned_error": secondErr, "commit_returned_error": commitErr,
		"first_insert_absent_on_server": firstAbsent, "second_insert_absent_on_server": secondAbsent,
		"same_key_insertable_by_other_session": len(relock), "other_session_insert_latency": summarize(relock),
		"errors": countErrs(errs)}
}

func txInDoubt(e *env, db *api.DB, side string, base int) map[string]any {
	ctx := context.Background()
	p := e.proxyOf(side)
	var commitErr, committed, errAndCommitted int
	var errs []string
	for i := 0; i < *trials; i++ {
		id := base + i
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			errs = append(errs, "begin: "+err.Error())
			continue
		}
		if _, err := tx.Exec(ctx, ins(id, "in-doubt")); err != nil {
			errs = append(errs, "insert: "+err.Error())
		}
		p.commitTrap.Store(true) // COMMIT reaches the server, its reply is lost
		cerr := tx.Commit()
		time.Sleep(50 * time.Millisecond)
		_ = p.heal()
		c := e.rowCount(side, id) == 1
		if cerr != nil {
			commitErr++
			errs = append(errs, normalizeErr(cerr.Error()))
		}
		if c {
			committed++
		}
		if cerr != nil && c {
			errAndCommitted++
		}
	}
	return map[string]any{"trials": *trials, "commit_returned_error": commitErr, "row_committed_on_server": committed,
		"error_returned_but_committed": errAndCommitted, "commit_errors": countErrs(errs),
		"method": "proxy forwards the COMMIT message to the server, drops every reply, and cuts the connection 200 ms later"}
}

func txSecurity(e *env, db *api.DB, side string, base int) map[string]any {
	ctx := context.Background()
	p := e.proxyOf(side)
	blocked := []string{
		fmt.Sprintf("DELETE FROM fault_tx WHERE id = %d OR 1=1", base),
		fmt.Sprintf("INSERT INTO fault_tx VALUES (%d, 'x'); DROP TABLE fault_tx", base),
		"UPDATE fault_tx SET note = 'pwned' WHERE note = '' OR 'a'='a'",
	}
	var allBlocked, zeroBytes, usableAfter, outcomeOK int
	var errs []string
	for i := 0; i < *trials; i++ {
		d := base + 10*i
		before := e.tableRows(side)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if _, err := tx.Exec(ctx, ins(d, "ok")); err != nil {
			errs = append(errs, err.Error())
		}
		c0 := p.c2s.Load()
		nb := 0
		for _, q := range blocked {
			_, err := tx.Exec(ctx, q)
			if errors.Is(err, api.ErrBlockedQuery) {
				nb++
			}
		}
		if _, err := tx.Query(ctx, "SELECT id FROM fault_tx WHERE id = 1 OR 1=1"); errors.Is(err, api.ErrBlockedQuery) {
			nb++
		}
		if nb == len(blocked)+1 {
			allBlocked++
		}
		if p.c2s.Load() == c0 {
			zeroBytes++
		}
		if _, err := tx.Exec(ctx, ins(d+2, "ok-after-block")); err == nil {
			usableAfter++
		} else {
			errs = append(errs, err.Error())
		}
		if err := tx.Commit(); err != nil {
			errs = append(errs, err.Error())
		}
		if e.tableRows(side) == before+2 && e.rowCount(side, d) == 1 && e.rowCount(side, d+2) == 1 {
			outcomeOK++
		}
	}
	return map[string]any{"trials": *trials, "blocked_statements_per_trial": append(blocked, "SELECT id FROM fault_tx WHERE id = 1 OR 1=1 (tx.Query)"),
		"all_blocked_with_ErrBlockedQuery": allBlocked, "zero_bytes_sent_to_server_for_blocked": zeroBytes,
		"transaction_usable_after_block": usableAfter, "commit_contains_exactly_the_two_allowed_inserts": outcomeOK,
		"errors": countErrs(errs)}
}

func txCrossDB(e *env, eng *engine.Engine) map[string]any {
	ctx := context.Background()
	out := map[string]any{
		"code_evidence": "engine.Engine has no BeginTx; transactions exist only per api.DB (one source). Engine.Exec rejects a write whose plan has more than one step (\"writes must target a single source\"). No two-phase commit, XA or PREPARE TRANSACTION appears anywhere in the repository.",
	}
	// (a) Autocommit writes through Engine.Exec, second source down.
	var firstKept, secondMissing int
	var errs []string
	for i := 0; i < *trials; i++ {
		id := 3000000 + i
		if _, err := eng.Exec(ctx, fmt.Sprintf("INSERT INTO postgres.fault_tx VALUES (%d, 'pair')", id)); err != nil {
			errs = append(errs, "postgres: "+err.Error())
		}
		e.myP.refuse()
		if _, err := eng.Exec(ctx, fmt.Sprintf("INSERT INTO mysql.fault_tx VALUES (%d, 'pair')", id)); err != nil {
			errs = append(errs, "mysql: "+normalizeErr(err.Error()))
		}
		_ = e.myP.heal()
		if e.rowCount("postgres", id) == 1 {
			firstKept++
		}
		if e.rowCount("mysql", id) == 0 {
			secondMissing++
		}
	}
	out["engine_exec_pair_second_down"] = map[string]any{"trials": *trials, "postgres_row_committed": firstKept,
		"mysql_row_missing": secondMissing, "errors": countErrs(errs)}

	// (b) One transaction per source, committed in sequence; the second commit fails.
	firstKept, secondMissing = 0, 0
	errs = nil
	for i := 0; i < *trials; i++ {
		id := 3100000 + i
		tp, err := eng.Sources["postgres"].BeginTx(ctx, nil)
		if err != nil {
			return map[string]any{"harness_error": err.Error()}
		}
		tm, err := eng.Sources["mysql"].BeginTx(ctx, nil)
		if err != nil {
			return map[string]any{"harness_error": err.Error()}
		}
		_, e1 := tp.Exec(ctx, ins(id, "pair"))
		_, e2 := tm.Exec(ctx, ins(id, "pair"))
		if e1 != nil || e2 != nil {
			errs = append(errs, fmt.Sprint("insert: ", e1, e2))
		}
		if err := tp.Commit(); err != nil {
			errs = append(errs, "postgres commit: "+err.Error())
		}
		e.myP.cutAll()
		if err := tm.Commit(); err != nil {
			errs = append(errs, "mysql commit: "+normalizeErr(err.Error()))
		}
		if e.rowCount("postgres", id) == 1 {
			firstKept++
		}
		if e.rowCount("mysql", id) == 0 {
			secondMissing++
		}
	}
	out["two_local_transactions_second_commit_fails"] = map[string]any{"trials": *trials, "postgres_row_committed": firstKept,
		"mysql_row_missing": secondMissing, "errors": countErrs(errs)}

	// (c) Single statements that read one source and write the other.
	var cross []map[string]any
	for _, q := range []string{
		"INSERT INTO mysql.fault_tx SELECT id, note FROM postgres.fault_tx",
		"INSERT INTO postgres.fault_tx SELECT id, status FROM mysql.fault_orders",
		"UPDATE mysql.fault_tx SET note = 'x' WHERE id IN (SELECT id FROM postgres.fault_tx)",
	} {
		r := map[string]any{"statement": q}
		if ast, err := parser.Parse(q); err == nil {
			if plan, err := planner.GeneratePlan(ast); err == nil {
				var steps []string
				for _, s := range plan.Steps {
					steps = append(steps, s.Database+": "+s.Query)
				}
				r["plan_steps"] = steps
			}
		}
		_, err := eng.Exec(ctx, q)
		r["engine_exec_err"] = errText(err)
		cross = append(cross, r)
	}
	out["cross_source_single_statement"] = cross
	return out
}

// snapshotReads runs a federated join while a writer bumps a version
// counter on PostgreSQL and then on MySQL (two commits per step). At every
// instant pg.ver >= my.ver holds, so a result with pg.ver < my.ver shows the
// two scans read the sources at different moments.
func snapshotReads(e *env, eng *engine.Engine) (map[string]any, error) {
	const q = "SELECT p.ver, m.ver FROM postgres.fault_snap p JOIN mysql.fault_snap m ON p.id = m.id"
	ctx := context.Background()
	reads := 10 * *trials
	out := map[string]any{"query": q, "reads_per_config": reads,
		"writer": "loop: UPDATE fault_snap SET ver = v on PostgreSQL (autocommit), then the same on MySQL (autocommit), directly on the servers"}
	for _, lat := range []int{0, 20} {
		for _, s := range []string{"postgres", "mysql"} {
			e.direct(s).Exec("UPDATE fault_snap SET ver = 0 WHERE id = 1")
		}
		e.myP.latency.Store(int64(time.Duration(lat) * time.Millisecond))
		var stop atomic.Bool
		var wg sync.WaitGroup
		var steps atomic.Int64
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := 1; !stop.Load(); v++ {
				e.pgDirect.Exec("UPDATE fault_snap SET ver = $1 WHERE id = 1", v)
				e.myDirect.Exec("UPDATE fault_snap SET ver = ? WHERE id = 1", v)
				steps.Add(1)
			}
		}()
		equal, pgAhead, myAhead, maxGap := 0, 0, 0, 0
		var errs []string
		for i := 0; i < reads; i++ {
			res, _, err := eng.Query(ctx, q)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			for res.Next() {
				var a, b string
				if err := res.Scan(&a, &b); err != nil {
					errs = append(errs, err.Error())
					continue
				}
				pv, _ := strconv.Atoi(a)
				mv, _ := strconv.Atoi(b)
				switch {
				case pv == mv:
					equal++
				case pv > mv:
					pgAhead++
				default:
					myAhead++
				}
				if g := pv - mv; g > maxGap || -g > maxGap {
					maxGap = max(g, -g)
				}
			}
			res.Close()
		}
		stop.Store(true)
		wg.Wait()
		e.myP.latency.Store(0)
		out[fmt.Sprintf("mysql_added_latency_%dms", lat)] = map[string]any{
			"equal_versions": equal, "pg_ahead_existing_intermediate_state": pgAhead,
			"mysql_ahead_never_existing_state": myAhead, "max_abs_version_gap": maxGap,
			"writer_steps": steps.Load(), "errors": countErrs(errs)}
	}
	return out, nil
}
