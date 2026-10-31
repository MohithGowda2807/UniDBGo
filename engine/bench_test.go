package engine

import (
	"context"
	"testing"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/security"
)

type nopResult struct{}

func (nopResult) Columns() []string { return nil }
func (nopResult) Next() bool        { return false }
func (nopResult) Scan(...any) error { return nil }
func (nopResult) Err() error        { return nil }
func (nopResult) Close() error      { return nil }

type nopConn struct{}

func (nopConn) Query(context.Context, string, ...any) (internal.Result, error) {
	return nopResult{}, nil
}
func (nopConn) Exec(context.Context, string, ...any) (internal.ExecResult, error) {
	return nil, nil
}
func (nopConn) BeginTx(context.Context, *internal.TxOptions) (internal.Tx, error) { return nil, nil }
func (nopConn) Close() error                                                      { return nil }

type nopDriver struct{}

func (nopDriver) Connect(internal.Config) (internal.Connection, error) { return nopConn{}, nil }
func (nopDriver) Capabilities() internal.Capabilities                  { return internal.Capabilities{} }

// BenchmarkPipelineOverhead measures the CPU cost UniDB-Go adds to a cached,
// parameterised point lookup, with a backend that does no work.
func BenchmarkPipelineOverhead(b *testing.B) {
	internal.RegisterDriver("nop", nopDriver{})
	db, err := api.Connect("nop://u:p@h:1/db")
	if err != nil {
		b.Fatal(err)
	}
	e := &Engine{Sources: map[string]*api.DB{"postgres": db}, Default: "postgres", Security: security.NewSecurityEngine()}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		res, _, err := e.Query(ctx, "SELECT id, name, email FROM users WHERE id = $1", i)
		if err != nil {
			b.Fatal(err)
		}
		res.Close()
	}
}
