package pool

import (
	"errors"
	"sync"
	"time"

	"github.com/Dheeran-git/UniDBGo/circuit"
	"github.com/Dheeran-git/UniDBGo/internal"
)

var ErrPoolExhausted = errors.New("connection pool exhausted")

// ConnectionPool is a bounded pool of driver connections whose capacity is
// resized by AutoTune. All fields are guarded by mu.
type ConnectionPool struct {
	mu          sync.Mutex
	connections chan internal.Connection
	maxSize     int
	active      int
	exhausted   int
	createConn  func() (internal.Connection, error)
	stop        chan struct{}
	stopOnce    sync.Once
}

func NewConnectionPool(maxSize int, create func() (internal.Connection, error)) *ConnectionPool {
	p := &ConnectionPool{
		connections: make(chan internal.Connection, maxSize),
		maxSize:     maxSize,
		createConn:  create,
		stop:        make(chan struct{}),
	}
	go p.AutoTune(5 * time.Second)
	return p
}

func (p *ConnectionPool) Acquire() (internal.Connection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case conn := <-p.connections:
		return conn, nil
	default:
		if p.active < p.maxSize {
			conn, err := p.createConn()
			if err != nil {
				return nil, err
			}
			p.active++
			return conn, nil
		}
		p.exhausted++
		return nil, ErrPoolExhausted
	}
}

// Release returns a connection to the pool. If the pool shrank while the
// connection was checked out and there is no room for it, it is closed.
func (p *ConnectionPool) Release(conn internal.Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.active <= p.maxSize {
		select {
		case p.connections <- conn:
			return
		default:
		}
	}
	p.active--
	conn.Close()
}

// Stats reports the current capacity, open connections and idle connections.
func (p *ConnectionPool) Stats() (maxSize, active, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxSize, p.active, len(p.connections)
}

// Close stops the tuner and closes all idle connections.
func (p *ConnectionPool) Close() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		select {
		case c := <-p.connections:
			p.active--
			c.Close()
		default:
			return
		}
	}
}

// AutoTune resizes the pool every interval: it grows by 5 when more than 5
// acquisitions failed in the last window, and shrinks by 2 (never below 10)
// when more than 10 connections sat idle.
func (p *ConnectionPool) AutoTune(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		p.tuneOnce()
	}
}

func (p *ConnectionPool) tuneOnce() {
	p.mu.Lock()
	defer p.mu.Unlock()

	exhaustedRate := p.exhausted
	p.exhausted = 0 // reset window
	idleCount := len(p.connections)

	switch {
	case exhaustedRate > 5:
		p.resize(p.maxSize + 5)
	case idleCount > 10 && p.maxSize > 10:
		p.resize(p.maxSize - 2)
	}
}

// resize swaps in a channel of the new capacity, closing idle connections
// that no longer fit. Caller holds mu.
func (p *ConnectionPool) resize(newSize int) {
	newChan := make(chan internal.Connection, newSize)
	for len(p.connections) > 0 {
		c := <-p.connections
		if len(newChan) < newSize {
			newChan <- c
		} else {
			p.active--
			c.Close()
		}
	}
	p.connections = newChan
	p.maxSize = newSize
}

type PoolManager struct {
	pools    map[string]*ConnectionPool
	breakers map[string]*circuit.CircuitBreaker
	mu       sync.RWMutex
}

func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools:    make(map[string]*ConnectionPool),
		breakers: make(map[string]*circuit.CircuitBreaker),
	}
}

func (m *PoolManager) GetPool(dbName string) *ConnectionPool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pools[dbName]
}

func (m *PoolManager) AddPool(dbName string, pool *ConnectionPool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools[dbName] = pool
	// Allocate a circuit breaker per connection pool: 5 failures threshold, 30s open timeout
	m.breakers[dbName] = circuit.NewCircuitBreaker(5, 30*time.Second)
}

// ExecuteWithBreaker executes a database operation guarded by the circuit breaker for that DB.
func (m *PoolManager) ExecuteWithBreaker(dbName string, operation func() error) error {
	m.mu.RLock()
	cb, ok := m.breakers[dbName]
	m.mu.RUnlock()

	if !ok {
		// no breaker defined, fallback to unprotected operation
		return operation()
	}

	return cb.Execute(operation)
}
