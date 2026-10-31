package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Dheeran-git/UniDBGo/internal"
)

// recorder is a fake driver connection that records what reaches it.
type recorder struct{ queries []string }

func (r *recorder) Query(_ context.Context, q string, _ ...any) (internal.Result, error) {
	r.queries = append(r.queries, "query:"+q)
	return nil, nil
}
func (r *recorder) Exec(_ context.Context, q string, _ ...any) (internal.ExecResult, error) {
	r.queries = append(r.queries, "exec:"+q)
	return nil, nil
}
func (r *recorder) BeginTx(context.Context, *internal.TxOptions) (internal.Tx, error) {
	return &recTx{r}, nil
}
func (r *recorder) Close() error { return nil }

type recTx struct{ r *recorder }

func (t *recTx) Query(ctx context.Context, q string, a ...any) (internal.Result, error) {
	return t.r.Query(ctx, "tx "+q, a...)
}
func (t *recTx) Exec(ctx context.Context, q string, a ...any) (internal.ExecResult, error) {
	return t.r.Exec(ctx, "tx "+q, a...)
}
func (t *recTx) Commit() error   { return nil }
func (t *recTx) Rollback() error { return nil }

type fakeDriver struct{ conn *recorder }

func (d *fakeDriver) Connect(internal.Config) (internal.Connection, error) { return d.conn, nil }
func (d *fakeDriver) Capabilities() internal.Capabilities                  { return internal.Capabilities{} }

var errDenied = errors.New("denied")

func TestMiddlewareCoversQueryExecAndTx(t *testing.T) {
	rec := &recorder{}
	internal.RegisterDriver("fake", &fakeDriver{rec})
	db, err := Connect("fake://u:p@localhost:1/db")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	var drivers []string
	db.Use(func(next Handler) Handler {
		return func(ctx context.Context, q string, a ...any) (internal.Result, error) {
			order = append(order, "first")
			d, _ := internal.DriverFrom(ctx)
			drivers = append(drivers, d)
			if strings.Contains(q, "DROP") {
				return nil, errDenied
			}
			return next(ctx, q, a...)
		}
	})
	db.Use(func(next Handler) Handler {
		return func(ctx context.Context, q string, a ...any) (internal.Result, error) {
			order = append(order, "second")
			return next(ctx, q, a...)
		}
	})

	ctx := context.Background()
	db.Query(ctx, "SELECT 1")
	db.Exec(ctx, "UPDATE t SET a = 1")
	tx, _ := db.BeginTx(ctx, nil)
	tx.Exec(ctx, "DELETE FROM t")
	if _, err := db.Exec(ctx, "DROP TABLE t"); !errors.Is(err, errDenied) {
		t.Errorf("Exec bypassed the middleware: %v", err)
	}
	if _, err := tx.Query(ctx, "DROP TABLE t"); !errors.Is(err, errDenied) {
		t.Errorf("transaction bypassed the middleware: %v", err)
	}

	want := []string{"query:SELECT 1", "exec:UPDATE t SET a = 1", "exec:tx DELETE FROM t"}
	if strings.Join(rec.queries, "|") != strings.Join(want, "|") {
		t.Errorf("driver saw %v, want %v", rec.queries, want)
	}
	if order[0] != "first" || order[1] != "second" {
		t.Errorf("middleware order %v", order)
	}
	for _, d := range drivers {
		if d != "fake" {
			t.Errorf("middleware did not receive the driver name: %v", drivers)
			break
		}
	}
}

func TestParseConnectionString(t *testing.T) {
	cfg, err := ParseConnectionString("postgresql://app:p%40ss@db:6543/prod?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Driver != "postgres" || cfg.Password != "p@ss" || cfg.Port != 6543 || cfg.Database != "prod" || cfg.Params["sslmode"] != "require" {
		t.Errorf("unexpected config %+v", cfg)
	}
	if cfg, _ := ParseConnectionString("mysql://u@h/db"); cfg.Port != 3306 {
		t.Errorf("default MySQL port: %d", cfg.Port)
	}
	for _, bad := range []string{"localhost:5432", "postgres://h:notaport/db", "::"} {
		if _, err := ParseConnectionString(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if _, err := Connect("nosuchdriver://h/db"); err == nil {
		t.Error("unknown driver accepted")
	}
}
