package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundedReturnsAtDeadline(t *testing.T) {
	release := make(chan struct{})
	discarded := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := bounded(ctx, func() (int, error) {
		<-release // a driver call that ignores its context
		return 7, nil
	}, func(v int) { discarded <- v })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("returned after %v", d)
	}
	close(release)
	select {
	case v := <-discarded:
		if v != 7 {
			t.Fatalf("discarded %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("late result was not discarded")
	}
}

func TestBoundedWithoutDeadlineRunsInline(t *testing.T) {
	v, err := bounded(context.Background(), func() (int, error) { return 3, nil }, func(int) {})
	if v != 3 || err != nil {
		t.Fatalf("got %d, %v", v, err)
	}
}
