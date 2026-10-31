package pool

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/Dheeran-git/UniDBGo/internal"
)

type nopConn struct{}

func (nopConn) Query(context.Context, string, ...any) (internal.Result, error)    { return nil, nil }
func (nopConn) Exec(context.Context, string, ...any) (internal.ExecResult, error) { return nil, nil }
func (nopConn) BeginTx(context.Context, *internal.TxOptions) (internal.Tx, error) { return nil, nil }
func (nopConn) Close() error                                                      { return nil }

// TestResizeWhileInUse exercises Acquire/Release concurrently with resizing;
// run with -race.
func TestResizeWhileInUse(t *testing.T) {
	p := &ConnectionPool{
		connections: make(chan internal.Connection, 12),
		maxSize:     12,
		createConn:  func() (internal.Connection, error) { return nopConn{}, nil },
		stop:        make(chan struct{}),
	}
	defer p.Close()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if c, err := p.Acquire(); err == nil {
					p.Release(c)
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		p.mu.Lock()
		p.resize(10 + i%5)
		p.mu.Unlock()
	}
	wg.Wait()
	max, active, idle := p.Stats()
	if active > max+8 || idle > max {
		t.Errorf("inconsistent pool: max=%d active=%d idle=%d", max, active, idle)
	}
}

type fakeTunable struct {
	mu    sync.Mutex
	stats sql.DBStats
	limit int
}

func (f *fakeTunable) PoolStats() sql.DBStats { f.mu.Lock(); defer f.mu.Unlock(); return f.stats }
func (f *fakeTunable) SetMaxOpenConns(n int)  { f.mu.Lock(); f.limit = n; f.mu.Unlock() }
func (f *fakeTunable) SetMaxIdleConns(int)    {}

func TestTunerGrowsAndShrinks(t *testing.T) {
	f := &fakeTunable{}
	tu := StartTuner(f, 4, 10, time.Hour) // drive Step manually
	defer tu.Stop()
	if f.limit != 4 {
		t.Fatalf("initial limit %d, want 4", f.limit)
	}
	for i := 0; i < 10; i++ {
		f.mu.Lock()
		f.stats.WaitCount += 3 // acquisitions waited in this window
		f.mu.Unlock()
		tu.Step()
	}
	if tu.Limit() != 10 {
		t.Fatalf("limit after sustained waits = %d, want max 10", tu.Limit())
	}
	f.mu.Lock()
	f.stats.OpenConnections, f.stats.Idle = 10, 9
	f.mu.Unlock()
	for i := 0; i < 20; i++ {
		tu.Step()
	}
	if tu.Limit() != 4 {
		t.Fatalf("limit after idle windows = %d, want min 4", tu.Limit())
	}
}
