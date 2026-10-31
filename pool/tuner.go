package pool

import (
	"database/sql"
	"sync"
	"time"
)

// Tunable is implemented by connections backed by a database/sql pool.
type Tunable interface {
	PoolStats() sql.DBStats
	SetMaxOpenConns(n int)
	SetMaxIdleConns(n int)
}

// Tuner adapts the open-connection limit of a database/sql pool to load.
type Tuner struct {
	target   Tunable
	min, max int
	limit    int
	lastWait int64
	stop     chan struct{}
	once     sync.Once
	mu       sync.Mutex
}

// StartTuner applies min as the initial limit and starts the tuning loop.
func StartTuner(t Tunable, min, max int, interval time.Duration) *Tuner {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	if interval <= 0 {
		interval = time.Second
	}
	tu := &Tuner{target: t, min: min, max: max, limit: min, stop: make(chan struct{})}
	tu.apply()
	tu.lastWait = t.PoolStats().WaitCount
	go tu.loop(interval)
	return tu
}

func (tu *Tuner) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-tu.stop:
			return
		case <-ticker.C:
			tu.Step()
		}
	}
}

// Step runs one tuning decision. The limit grows by a quarter (at least one)
// when any acquisition had to wait during the last window, and shrinks by one
// when nothing waited and more than half of the open connections were idle.
func (tu *Tuner) Step() {
	tu.mu.Lock()
	defer tu.mu.Unlock()

	s := tu.target.PoolStats()
	waited := s.WaitCount - tu.lastWait
	tu.lastWait = s.WaitCount

	switch {
	case waited > 0 && tu.limit < tu.max:
		step := tu.limit / 4
		if step < 1 {
			step = 1
		}
		tu.limit += step
		if tu.limit > tu.max {
			tu.limit = tu.max
		}
		tu.apply()
	case waited == 0 && s.Idle*2 > s.OpenConnections && tu.limit > tu.min:
		tu.limit--
		tu.apply()
	}
}

// Limit returns the current open-connection limit.
func (tu *Tuner) Limit() int {
	tu.mu.Lock()
	defer tu.mu.Unlock()
	return tu.limit
}

func (tu *Tuner) apply() {
	tu.target.SetMaxOpenConns(tu.limit)
	tu.target.SetMaxIdleConns(tu.limit)
}

// Stop ends the tuning loop.
func (tu *Tuner) Stop() { tu.once.Do(func() { close(tu.stop) }) }
