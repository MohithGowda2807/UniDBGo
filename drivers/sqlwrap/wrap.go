// Package sqlwrap adapts database/sql handles to the UniDB-Go interfaces.
package sqlwrap

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/internal"
)

// SQLConnection wraps *sql.DB. Classify, if set, maps driver errors to the
// portable error values in package internal.
type SQLConnection struct {
	DB       *sql.DB
	Classify internal.ErrorClassifier
}

// Open wraps db after verifying that the server is reachable.
func Open(db *sql.DB, classify internal.ErrorClassifier, poolSize int) (*SQLConnection, error) {
	if poolSize > 0 {
		db.SetMaxOpenConns(poolSize)
		db.SetMaxIdleConns(poolSize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLConnection{DB: db, Classify: classify}, nil
}

func (c *SQLConnection) wrap(err error) error { return internal.Classify(c.Classify, err) }

func (c *SQLConnection) Query(ctx context.Context, query string, args ...any) (internal.Result, error) {
	rows, err := c.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, c.wrap(err)
	}
	return &SQLResult{Rows: rows, classify: c.Classify}, nil
}

func (c *SQLConnection) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	res, err := c.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, c.wrap(err)
	}
	return &SQLExecResult{Result: res}, nil
}

func (c *SQLConnection) BeginTx(ctx context.Context, opts *internal.TxOptions) (internal.Tx, error) {
	sqlOpts, err := txOptions(opts)
	if err != nil {
		return nil, err
	}
	tx, err := c.DB.BeginTx(ctx, sqlOpts)
	if err != nil {
		return nil, c.wrap(err)
	}
	return &SQLTx{Tx: tx, classify: c.Classify}, nil
}

func (c *SQLConnection) Close() error {
	return c.DB.Close()
}

// PoolStats exposes database/sql pool statistics for the adaptive tuner.
func (c *SQLConnection) PoolStats() sql.DBStats { return c.DB.Stats() }

func (c *SQLConnection) SetMaxOpenConns(n int) { c.DB.SetMaxOpenConns(n) }

func (c *SQLConnection) SetMaxIdleConns(n int) { c.DB.SetMaxIdleConns(n) }

func txOptions(o *internal.TxOptions) (*sql.TxOptions, error) {
	if o == nil {
		return nil, nil
	}
	levels := map[string]sql.IsolationLevel{
		"":                 sql.LevelDefault,
		"read uncommitted": sql.LevelReadUncommitted,
		"read committed":   sql.LevelReadCommitted,
		"repeatable read":  sql.LevelRepeatableRead,
		"serializable":     sql.LevelSerializable,
	}
	level, ok := levels[strings.ToLower(strings.TrimSpace(o.Isolation))]
	if !ok {
		return nil, fmt.Errorf("unknown isolation level %q", o.Isolation)
	}
	return &sql.TxOptions{Isolation: level, ReadOnly: o.ReadOnly}, nil
}

// SQLResult wraps *sql.Rows
type SQLResult struct {
	Rows     *sql.Rows
	classify internal.ErrorClassifier
}

func (r *SQLResult) Columns() []string {
	cols, _ := r.Rows.Columns()
	return cols
}

func (r *SQLResult) Next() bool {
	return r.Rows.Next()
}

func (r *SQLResult) Scan(dest ...any) error {
	return r.Rows.Scan(dest...)
}

func (r *SQLResult) Err() error {
	return internal.Classify(r.classify, r.Rows.Err())
}

func (r *SQLResult) Close() error {
	return r.Rows.Close()
}

// SQLExecResult wraps sql.Result
type SQLExecResult struct {
	Result sql.Result
}

func (r *SQLExecResult) RowsAffected() int64 {
	v, _ := r.Result.RowsAffected()
	return v
}

func (r *SQLExecResult) LastInsertId() (int64, error) {
	return r.Result.LastInsertId()
}

// SQLTx wraps *sql.Tx
type SQLTx struct {
	Tx       *sql.Tx
	classify internal.ErrorClassifier
}

func (t *SQLTx) Query(ctx context.Context, query string, args ...any) (internal.Result, error) {
	rows, err := t.Tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, internal.Classify(t.classify, err)
	}
	return &SQLResult{Rows: rows, classify: t.classify}, nil
}

func (t *SQLTx) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	res, err := t.Tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, internal.Classify(t.classify, err)
	}
	return &SQLExecResult{Result: res}, nil
}

func (t *SQLTx) Commit() error {
	return internal.Classify(t.classify, t.Tx.Commit())
}

func (t *SQLTx) Rollback() error {
	return t.Tx.Rollback()
}
