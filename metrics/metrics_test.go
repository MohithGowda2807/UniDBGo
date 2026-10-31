package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Dheeran-git/UniDBGo/internal"
)

func TestCollector(t *testing.T) {
	c := NewCollector()
	c.SlowQuery = 0
	c.Observe("a", 50*time.Microsecond, nil)
	c.Observe("b", 2*time.Millisecond, errors.New("boom"))
	c.Observe("c", 3*time.Second, nil)
	s := c.Snapshot()
	if s.Queries != 3 || s.Errors != 1 || s.Max != 3*time.Second {
		t.Fatalf("unexpected snapshot %+v", s)
	}
	if s.Buckets[0] != 1 || s.Buckets[3] != 1 || s.Buckets[len(Buckets)] != 1 {
		t.Fatalf("unexpected buckets %v", s.Buckets)
	}
}

func TestMiddlewareRecords(t *testing.T) {
	c := NewCollector()
	h := c.Middleware()(func(context.Context, string, ...any) (internal.Result, error) {
		return nil, errors.New("fail")
	})
	h(context.Background(), "SELECT 1")
	if s := c.Snapshot(); s.Queries != 1 || s.Errors != 1 {
		t.Fatalf("middleware did not record: %+v", s)
	}
}
