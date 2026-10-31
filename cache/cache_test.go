package cache

import (
	"testing"
	"time"

	"github.com/Dheeran-git/UniDBGo/federation"
)

func TestGetSetExpiry(t *testing.T) {
	e := NewEngine()
	rows := []federation.Row{{"id": 1}}
	e.Set("SELECT 1", nil, rows, time.Hour)
	if got, ok := e.Get("SELECT 1", nil); !ok || len(got) != 1 {
		t.Fatalf("expected a hit, got %v %v", got, ok)
	}
	e.Set("SELECT 2", nil, rows, -time.Second)
	if _, ok := e.Get("SELECT 2", nil); ok {
		t.Fatal("expired entry returned")
	}
}

func TestArgumentTypesDoNotCollide(t *testing.T) {
	e := NewEngine()
	e.Set("q", []any{"1"}, []federation.Row{{"v": "string"}}, time.Hour)
	if _, ok := e.Get("q", []any{1}); ok {
		t.Fatal(`string "1" and int 1 share a cache key`)
	}
	if _, ok := e.Get("q", []any{"1 2"}); ok {
		t.Fatal("different argument lists share a cache key")
	}
}

func TestBounded(t *testing.T) {
	e := NewBoundedEngine(3)
	for i, q := range []string{"a", "b", "c", "d", "e"} {
		e.Set(q, nil, nil, time.Duration(i+1)*time.Minute)
	}
	if e.Len() != 3 {
		t.Fatalf("cache holds %d entries, want 3", e.Len())
	}
	if _, ok := e.Get("e", nil); !ok {
		t.Fatal("newest entry was evicted")
	}
	if _, ok := e.Get("a", nil); ok {
		t.Fatal("entry closest to expiry should have been evicted")
	}
}

func TestInvalidate(t *testing.T) {
	e := NewEngine()
	e.Set("q", nil, nil, time.Hour)
	e.Invalidate()
	if e.Len() != 0 {
		t.Fatal("Invalidate left entries behind")
	}
}
