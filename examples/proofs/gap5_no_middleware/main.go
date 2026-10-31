// ============================================================
// GAP 5 PROOF: database/sql has NO middleware / interceptor
//              pipeline. You CANNOT compose query hooks.
// ============================================================
// WHAT THIS PROVES:
//   In raw Go, there is no official way to intercept every
//   query that goes through *sql.DB and add cross-cutting
//   concerns like security, logging, or metrics.
//   The developer must manually wrap every single db.Query()
//   call in their application code.
//   UniDB-Go introduces a proper Handler + Middleware pattern.
//
// HOW TO RUN:
//   go run ./examples/proofs/gap5_no_middleware
// ============================================================

package main

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"time"
)

// ══════════════════════════════════════════════════════════════
// PART 1: RAW Go — No Middleware Support
// ══════════════════════════════════════════════════════════════

// In raw Go, to add security + logging + metrics to every query,
// you must do this MANUALLY at every single call site.
// There is no db.Use() or middleware chain.

func rawGoWithSecurityAndMetrics(db *sql.DB, query string, args ...any) (*sql.Rows, error) {
	// ─────────────────────────────────────────────────────────
	// PROBLEM: This entire block must be COPY-PASTED everywhere
	// you call db.Query() in your entire application.
	// There is no hook, no interceptor, no middleware.
	// ─────────────────────────────────────────────────────────

	// Manual security check (copy-pasted at every call site)
	fmt.Printf("[RAW GO] Manually checking security for: %s\n", query)
	// ... developer writes injection check here, manually, every time ...

	// Manual metrics (copy-pasted at every call site)
	start := time.Now()
	fmt.Printf("[RAW GO] Manually starting timer for: %s\n", query)

	// Actual query
	rows, err := db.QueryContext(context.Background(), query, args...)

	// Manual metrics end (copy-pasted at every call site)
	elapsed := time.Since(start)
	fmt.Printf("[RAW GO] Manually recording latency: %v for: %s\n", elapsed, query)

	if err != nil {
		// Manual error logging (copy-pasted at every call site)
		fmt.Printf("[RAW GO] Manually logging error: %v\n", err)
	}

	return rows, err
}

// ↑ This function must be manually called instead of db.Query() everywhere.
// If you forget it ONCE, that query has no security check.
// If you add a new concern (e.g., tracing), you must edit EVERY call site.

// ══════════════════════════════════════════════════════════════
// PART 2: UniDB-Go's Middleware Architecture
// ══════════════════════════════════════════════════════════════

// Extracted from UniDB-Go's internal/engine.go and middleware files.
// This is the ACTUAL pattern implemented in the project.

// The base types:
type Result struct{ Rows []map[string]any }
type Handler func(ctx context.Context, query string, args ...any) (Result, error)
type Middleware func(next Handler) Handler

// Composable middleware stack — wired ONCE, applies to ALL queries automatically.

func SecurityMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(ctx context.Context, query string, args ...any) (Result, error) {
			// Runs automatically for EVERY query — developer never has to think about it
			fmt.Printf("[SECURITY MIDDLEWARE] Scanning: %s\n", query)
			if containsInjection(query) {
				return Result{}, fmt.Errorf("query BLOCKED: SQL injection detected")
			}
			fmt.Println("[SECURITY MIDDLEWARE] ✅ Clean — passing to next middleware")
			return next(ctx, query, args...)
		}
	}
}

func MetricsMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(ctx context.Context, query string, args ...any) (Result, error) {
			start := time.Now()
			fmt.Printf("[METRICS MIDDLEWARE] Timer started for: %s\n", query)
			result, err := next(ctx, query, args...)
			elapsed := time.Since(start)
			fmt.Printf("[METRICS MIDDLEWARE] Query took: %v\n", elapsed)
			if elapsed > 500*time.Millisecond {
				fmt.Printf("[METRICS MIDDLEWARE] ⚠️  SLOW QUERY detected: %s\n", query)
			}
			return result, err
		}
	}
}

// The DB struct that composes middlewares:
type UniDB struct {
	middlewares []Middleware
	execute     Handler
}

func (db *UniDB) Use(m Middleware) {
	db.middlewares = append(db.middlewares, m)
}

func (db *UniDB) Query(ctx context.Context, query string, args ...any) (Result, error) {
	// Build the chain: Security → Metrics → Actual Execution
	handler := db.execute
	// Apply middlewares in reverse so Security runs first
	for i := len(db.middlewares) - 1; i >= 0; i-- {
		handler = db.middlewares[i](handler)
	}
	return handler(ctx, query, args...)
}

// Simulated actual execution:
func actualExecution(ctx context.Context, query string, args ...any) (Result, error) {
	fmt.Printf("[EXECUTION] Running query against DB: %s\n", query)
	return Result{}, nil
}

// Simple injection check for demo:
func containsInjection(q string) bool {
	return len(q) > 0 && (contains(q, "OR 1=1") || contains(q, "SLEEP(") || contains(q, "UNION SELECT"))
}
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsAt(s, sub))
}
func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func main() {
	fmt.Println("=== GAP 5: database/sql Has NO Middleware / Interceptor Pipeline ===")
	fmt.Println()

	// ── Demo: Raw Go approach ────────────────────────────────────────────
	fmt.Println("── RAW GO: Manual security + metrics at every call site ─────────────")
	db, _ := sql.Open("postgres", "postgres://user:pass@localhost/db")
	rawGoWithSecurityAndMetrics(db, "SELECT * FROM users WHERE id = 1")
	fmt.Println()
	fmt.Println("[PROOF] In raw Go:")
	fmt.Println("[PROOF]   Every db.Query() call must manually invoke security + metrics.")
	fmt.Println("[PROOF]   Adding a new concern (e.g., tracing) = edit every call site.")
	fmt.Println("[PROOF]   Forgetting to wrap one call = that query has zero protection.")
	fmt.Println()

	// ── Demo: UniDB-Go approach ───────────────────────────────────────────
	fmt.Println("── UNIDB-GO: Middleware wired ONCE, applies to ALL queries ──────────")

	unidb := &UniDB{execute: actualExecution}
	unidb.Use(SecurityMiddleware()) // wired once here
	unidb.Use(MetricsMiddleware())  // wired once here

	fmt.Println()
	fmt.Println("--- Running clean query ---")
	unidb.Query(context.Background(), "SELECT name FROM users WHERE id = 5")

	fmt.Println()
	fmt.Println("--- Running injection query ---")
	_, err := unidb.Query(context.Background(), "SELECT * FROM users WHERE id = 1 OR 1=1")
	if err != nil {
		fmt.Printf("[RESULT] %v\n", err)
	}

	fmt.Println()
	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] database/sql has NO interceptor or middleware hook.")
	fmt.Println("[PROOF] The only extension point is wrapping *sql.DB — manually, everywhere.")
	fmt.Println("[PROOF] UniDB-Go's db.Use() pattern allows composable, reusable middleware:")
	fmt.Println("[PROOF]   db.Use(security.SecurityMiddleware(engine))")
	fmt.Println("[PROOF]   db.Use(metrics.MetricsMiddleware())")
	fmt.Println("[PROOF] Every query automatically flows through the full pipeline.")
	fmt.Println("[PROOF] This is IDENTICAL to how HTTP middleware works (net/http.Handler)")
	fmt.Println("[PROOF] but applied to database queries — a pattern Go's stdlib lacks entirely.")
}
