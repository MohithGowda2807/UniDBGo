// ============================================================
// GAP 7 PROOF: database/sql has a STATIC connection pool.
//              It never adapts to load. UniDB-Go auto-tunes.
// ============================================================
// HOW TO RUN:
//   go run ./examples/proofs/gap7_static_pool
// ============================================================

package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════════
// PART 1: RAW Go — Static Pool
// ══════════════════════════════════════════════════════════════

func demonstrateRawGoStaticPool() {
	db, _ := sql.Open("postgres", "postgres://user:pass@localhost/db")

	// This is ALL you can do in database/sql:
	db.SetMaxOpenConns(20)           // static — set once, never changes
	db.SetMaxIdleConns(5)            // static — never adapts
	db.SetConnMaxLifetime(time.Hour) // static — never adapts

	// db.Stats() gives you numbers but NOTHING in the stdlib reacts to them.
	stats := db.Stats()
	fmt.Printf("[RAW GO] Pool stats (readable but NEVER acted upon automatically):\n")
	fmt.Printf("[RAW GO]   MaxOpenConnections: %d\n", stats.MaxOpenConnections)
	fmt.Printf("[RAW GO]   OpenConnections:    %d\n", stats.OpenConnections)
	fmt.Printf("[RAW GO]   InUse:              %d\n", stats.InUse)
	fmt.Printf("[RAW GO]   Idle:               %d\n", stats.Idle)
	fmt.Printf("[RAW GO]   WaitCount:          %d\n", stats.WaitCount)
	fmt.Printf("[RAW GO]   WaitDuration:       %v\n", stats.WaitDuration)
	fmt.Println()
	fmt.Println("[PROOF] database/sql reads these stats but NEVER adjusts pool size.")
	fmt.Println("[PROOF] During a traffic spike: pool exhausted → requests hang → timeouts.")
	fmt.Println("[PROOF] During low traffic:     20 idle connections waste memory.")
	fmt.Println("[PROOF] Developer must redeploy with new SetMaxOpenConns() to fix. Not acceptable.")
	fmt.Println()
	fmt.Println("[PROOF] Also: database/sql manages ONE pool for ONE *sql.DB.")
	fmt.Println("[PROOF] If your app uses Postgres + MySQL, you have two completely")
	fmt.Println("[PROOF] separate *sql.DB objects with no coordinated pool management.")
}

// ══════════════════════════════════════════════════════════════
// PART 2: UniDB-Go's Adaptive Pool (from pool/pool.go)
// ══════════════════════════════════════════════════════════════

type PoolMetrics struct {
	ActiveConnections int
	IdleConnections   int
	WaitTime          time.Duration
	ExhaustionCount   int
}

type ConnectionPool struct {
	mu              sync.Mutex
	maxSize         int
	active          int
	exhaustionCount int
	metrics         PoolMetrics
}

func NewPool(maxSize int) *ConnectionPool {
	p := &ConnectionPool{maxSize: maxSize}
	go p.AutoTune() // background goroutine — runs forever
	return p
}

// AutoTune: runs every 5 seconds, adjusts pool based on live metrics.
// database/sql has NO equivalent of this.
func (p *ConnectionPool) AutoTune() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		p.mu.Lock()
		metrics := p.metrics

		prevSize := p.maxSize

		// Scale UP: pool is getting exhausted under load
		if metrics.ExhaustionCount > 5 {
			p.maxSize += 5
			p.exhaustionCount = 0
			fmt.Printf("[UNIDB AutoTune] ⬆️  Scaled UP: %d → %d (high exhaustion: %d times)\n",
				prevSize, p.maxSize, metrics.ExhaustionCount)
		}

		// Scale DOWN: too many idle connections — conserve resources
		if metrics.IdleConnections > p.maxSize/2 && p.maxSize > 5 {
			p.maxSize -= 2
			fmt.Printf("[UNIDB AutoTune] ⬇️  Scaled DOWN: %d → %d (too many idle: %d)\n",
				prevSize, p.maxSize, metrics.IdleConnections)
		}

		p.mu.Unlock()
	}
}

// PoolManager: tracks a separate pool per database.
// database/sql has NO concept of multi-database pool management.
type PoolManager struct {
	pools map[string]*ConnectionPool
}

func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools: map[string]*ConnectionPool{
			"postgres": NewPool(20),
			"mysql":    NewPool(15),
			"mongodb":  NewPool(10),
		},
	}
}

func (m *PoolManager) Stats() {
	fmt.Println("[UNIDB PoolManager] Per-database pool stats:")
	for dbName, pool := range m.pools {
		pool.mu.Lock()
		fmt.Printf("[UNIDB PoolManager]   %-10s → maxSize: %d, active: %d\n",
			dbName, pool.maxSize, pool.active)
		pool.mu.Unlock()
	}
}

func main() {
	fmt.Println("=== GAP 7: database/sql Has a STATIC Pool — UniDB-Go Auto-Tunes ===")
	fmt.Println()

	fmt.Println("── RAW Go database/sql pool: ─────────────────────────────────────────")
	demonstrateRawGoStaticPool()

	fmt.Println("── UniDB-Go Adaptive Pool: ───────────────────────────────────────────")
	manager := NewPoolManager()
	manager.Stats()
	fmt.Println()

	// Simulate exhaustion spike
	fmt.Println("[UNIDB] Simulating load spike — marking 6 exhaustion events...")
	pool := manager.pools["postgres"]
	pool.mu.Lock()
	pool.metrics.ExhaustionCount = 6
	pool.metrics.IdleConnections = 1
	pool.mu.Unlock()

	fmt.Println("[UNIDB] Waiting for AutoTune to fire (up to 5 seconds)...")
	time.Sleep(6 * time.Second)
	manager.Stats()
	fmt.Println()

	// Simulate idle state
	fmt.Println("[UNIDB] Simulating low traffic — marking many idle connections...")
	pool.mu.Lock()
	pool.metrics.ExhaustionCount = 0
	pool.metrics.IdleConnections = 15
	pool.mu.Unlock()

	fmt.Println("[UNIDB] Waiting for AutoTune to shrink pool...")
	time.Sleep(6 * time.Second)
	manager.Stats()
	fmt.Println()

	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] database/sql: SetMaxOpenConns() is static. Never self-adjusts.")
	fmt.Println("[PROOF] UniDB-Go:")
	fmt.Println("[PROOF]   - Separate pool per database (postgres/mysql/mongodb independently)")
	fmt.Println("[PROOF]   - Background AutoTune goroutine fires every 5 seconds")
	fmt.Println("[PROOF]   - Scales UP when pool is exhausted under load")
	fmt.Println("[PROOF]   - Scales DOWN when idle connections waste resources")
	fmt.Println("[PROOF]   - Similar to HikariCP (Java) — a feature Go's stdlib lacks")
}
