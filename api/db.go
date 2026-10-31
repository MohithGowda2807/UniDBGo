package api

import (
	"context"

	"github.com/Dheeran-git/UniDBGo/internal"
)

// DB represents the unified database instance.
type DB struct {
	conn       internal.Connection
	config     internal.Config
	middleware []Middleware
	tuner      interface{ Stop() }
}

// chain wraps final with the registered middleware, in reverse order so the
// first added is the first executed.
func (db *DB) chain(final Handler) Handler {
	handler := final
	for i := len(db.middleware) - 1; i >= 0; i-- {
		handler = db.middleware[i](handler)
	}
	return handler
}

// Query executes a query that returns rows, typically a SELECT.
func (db *DB) Query(ctx context.Context, query string, args ...any) (internal.Result, error) {
	return db.chain(db.conn.Query)(db.withDriver(ctx), query, args...)
}

// withDriver tells middleware which driver, and so which SQL dialect, runs the query.
func (db *DB) withDriver(ctx context.Context) context.Context {
	return internal.WithDriver(ctx, db.config.Driver)
}

// Exec executes a query without returning any rows, typically an INSERT,
// UPDATE, or DELETE. It passes through the same middleware chain as Query, so
// security and metrics middleware also see write statements.
func (db *DB) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	return execThrough(db.chain, db.conn.Exec, db.withDriver(ctx), query, args...)
}

// execThrough runs exec at the end of a Query-shaped middleware chain.
func execThrough(chain func(Handler) Handler,
	exec func(context.Context, string, ...any) (internal.ExecResult, error),
	ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	var out internal.ExecResult
	final := func(ctx context.Context, q string, a ...any) (internal.Result, error) {
		r, err := exec(ctx, q, a...)
		out = r
		return nil, err
	}
	if _, err := chain(final)(ctx, query, args...); err != nil {
		return nil, err
	}
	return out, nil
}

// TxOptions configures a transaction; see internal.TxOptions.
type TxOptions = internal.TxOptions

// BeginTx starts a database transaction; opts may be nil. Statements issued
// on the returned transaction pass through the middleware chain.
func (db *DB) BeginTx(ctx context.Context, opts *TxOptions) (internal.Tx, error) {
	tx, err := db.conn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &chainedTx{tx: tx, db: db}, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	if db.tuner != nil {
		db.tuner.Stop()
	}
	return db.conn.Close()
}

// Driver returns the registered driver name ("postgres", "mysql", "mongodb").
func (db *DB) Driver() string { return db.config.Driver }

// Conn exposes the underlying driver connection (e.g. for the federation engine).
func (db *DB) Conn() internal.Connection { return db.conn }

type chainedTx struct {
	tx internal.Tx
	db *DB
}

func (t *chainedTx) Query(ctx context.Context, query string, args ...any) (internal.Result, error) {
	return t.db.chain(t.tx.Query)(t.db.withDriver(ctx), query, args...)
}

func (t *chainedTx) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	return execThrough(t.db.chain, t.tx.Exec, t.db.withDriver(ctx), query, args...)
}

func (t *chainedTx) Commit() error   { return t.tx.Commit() }
func (t *chainedTx) Rollback() error { return t.tx.Rollback() }
