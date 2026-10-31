package circuit

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errBackend = errors.New("backend down")

func TestOpensAfterThresholdAndRecovers(t *testing.T) {
	now := time.Unix(0, 0)
	cb := NewCircuitBreaker(3, 10*time.Second)
	cb.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if err := cb.Execute(func() error { return errBackend }); !errors.Is(err, errBackend) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if cb.State() != StateOpen {
		t.Fatalf("state %v, want open", cb.State())
	}
	if err := cb.Execute(func() error { return nil }); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("open circuit let a call through: %v", err)
	}

	now = now.Add(11 * time.Second)
	if cb.State() != StateHalfOpen {
		t.Fatalf("state %v, want half-open", cb.State())
	}
	// A failed trial re-opens immediately.
	cb.Execute(func() error { return errBackend })
	if cb.State() != StateOpen {
		t.Fatalf("failed trial left state %v", cb.State())
	}
	now = now.Add(11 * time.Second)
	if err := cb.Execute(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if cb.State() != StateClosed {
		t.Fatalf("successful trial left state %v", cb.State())
	}
}

func TestHalfOpenAllowsOneTrial(t *testing.T) {
	now := time.Unix(0, 0)
	cb := NewCircuitBreaker(1, time.Second)
	cb.now = func() time.Time { return now }
	cb.Execute(func() error { return errBackend })
	now = now.Add(2 * time.Second)

	release := make(chan struct{})
	var ran, rejected int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cb.Execute(func() error { atomic.AddInt32(&ran, 1); <-release; return nil })
			if errors.Is(err, ErrCircuitOpen) {
				atomic.AddInt32(&rejected, 1)
			}
		}()
	}
	// Nine callers are rejected while the single trial call is blocked.
	for atomic.LoadInt32(&rejected) < 9 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	if ran != 1 {
		t.Fatalf("%d trial calls ran in half-open state, want 1", ran)
	}
}
