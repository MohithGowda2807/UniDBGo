// Package metrics records query counts, errors and latency.
package metrics

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/internal"
)

// Bucket upper bounds of the latency histogram.
var Buckets = []time.Duration{
	100 * time.Microsecond, 500 * time.Microsecond, time.Millisecond,
	5 * time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 500 * time.Millisecond, time.Second,
}

// Collector aggregates query metrics. It is safe for concurrent use.
type Collector struct {
	// SlowQuery is the latency above which a query is logged; 0 disables it.
	SlowQuery time.Duration

	mu      sync.Mutex
	queries uint64
	errors  uint64
	total   time.Duration
	max     time.Duration
	buckets []uint64 // len(Buckets)+1, the last one counts slower queries
}

// Snapshot is a point-in-time copy of a Collector.
type Snapshot struct {
	Queries uint64
	Errors  uint64
	Mean    time.Duration
	Max     time.Duration
	// Buckets[i] counts queries with latency <= metrics.Buckets[i]; the
	// extra last element counts the rest.
	Buckets []uint64
}

// NewCollector creates a collector that logs queries slower than 500 ms.
func NewCollector() *Collector {
	return &Collector{SlowQuery: 500 * time.Millisecond, buckets: make([]uint64, len(Buckets)+1)}
}

// Default is the collector used by MetricsMiddleware.
var Default = NewCollector()

// Observe records one query.
func (c *Collector) Observe(query string, d time.Duration, err error) {
	c.mu.Lock()
	c.queries++
	if err != nil {
		c.errors++
	}
	c.total += d
	if d > c.max {
		c.max = d
	}
	i := 0
	for i < len(Buckets) && d > Buckets[i] {
		i++
	}
	c.buckets[i]++
	slow := c.SlowQuery
	c.mu.Unlock()

	if slow > 0 && d > slow {
		log.Printf("unidb: slow query (%v): %s", d, truncate(query, 200))
	}
}

// Snapshot returns the current totals.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{Queries: c.queries, Errors: c.errors, Max: c.max, Buckets: append([]uint64{}, c.buckets...)}
	if c.queries > 0 {
		s.Mean = c.total / time.Duration(c.queries)
	}
	return s
}

// Middleware returns an API middleware that records every query in c.
func (c *Collector) Middleware() api.Middleware {
	return func(next api.Handler) api.Handler {
		return func(ctx context.Context, query string, args ...any) (internal.Result, error) {
			start := time.Now()
			res, err := next(ctx, query, args...)
			c.Observe(query, time.Since(start), err)
			return res, err
		}
	}
}

// MetricsMiddleware creates a middleware that records query metrics in Default.
func MetricsMiddleware() api.Middleware {
	return Default.Middleware()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
