// Package circuit implements a circuit breaker for backend calls.
package circuit

import (
	"errors"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker is open due to repeated failures")

// State represents the status of the CircuitBreaker.
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// CircuitBreaker acts as a protective shield against failing backend dependencies.
// After threshold consecutive failures it opens and rejects calls for timeout;
// it then lets a single trial call through (half-open). Success closes the
// circuit, failure opens it again.
type CircuitBreaker struct {
	mu          sync.Mutex
	state       State
	failures    int
	threshold   int
	timeout     time.Duration
	lastFailure time.Time
	probing     bool // a half-open trial call is in flight
	now         func() time.Time
}

// NewCircuitBreaker creates a new circuit breaker mechanism.
func NewCircuitBreaker(failureThreshold int, timeout time.Duration) *CircuitBreaker {
	if failureThreshold < 1 {
		failureThreshold = 1
	}
	return &CircuitBreaker{
		state:     StateClosed,
		threshold: failureThreshold,
		timeout:   timeout,
		now:       time.Now,
	}
}

// State returns the current state.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == StateOpen && cb.now().Sub(cb.lastFailure) > cb.timeout {
		return StateHalfOpen
	}
	return cb.state
}

// Execute runs the given operation through the circuit breaker.
func (cb *CircuitBreaker) Execute(operation func() error) error {
	cb.mu.Lock()
	switch cb.state {
	case StateOpen:
		if cb.now().Sub(cb.lastFailure) <= cb.timeout {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}
		cb.state = StateHalfOpen
		fallthrough
	case StateHalfOpen:
		if cb.probing {
			cb.mu.Unlock()
			return ErrCircuitOpen // only one trial call at a time
		}
		cb.probing = true
	}
	cb.mu.Unlock()

	err := operation()

	cb.mu.Lock()
	defer cb.mu.Unlock()
	wasProbe := cb.probing
	cb.probing = false

	if err != nil {
		cb.failures++
		cb.lastFailure = cb.now()
		if wasProbe || cb.failures >= cb.threshold {
			cb.state = StateOpen
		}
		return err
	}

	// Success resolves the state
	cb.failures = 0
	cb.state = StateClosed
	return nil
}
