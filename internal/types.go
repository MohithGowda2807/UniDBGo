package internal

import (
	"context"
	"time"
)

// Result represents a unified database result. As with database/sql, Err
// must be checked after Next returns false to tell the end of the rows from
// a failure while reading them.
type Result interface {
	Columns() []string
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

// ExecResult represents the result of a non-read query
type ExecResult interface {
	RowsAffected() int64
	LastInsertId() (int64, error)
}

// Tx represents a database transaction
type Tx interface {
	Query(ctx context.Context, query string, args ...any) (Result, error)
	Exec(ctx context.Context, query string, args ...any) (ExecResult, error)

	Commit() error
	Rollback() error
}

// Connection represents a single database connection
type Connection interface {
	Query(ctx context.Context, query string, args ...any) (Result, error)
	Exec(ctx context.Context, query string, args ...any) (ExecResult, error)

	BeginTx(ctx context.Context, opts *TxOptions) (Tx, error)

	Close() error
}

// TxOptions configures a transaction. Isolation is one of "", "read
// uncommitted", "read committed", "repeatable read" or "serializable"
// (case-insensitive); "" uses the database default.
type TxOptions struct {
	Isolation string
	ReadOnly  bool
}

// Capabilities defines what a driver supports
type Capabilities struct {
	SupportsSQL          bool
	SupportsTransactions bool
	SupportsJoins        bool
	SupportsAggregation  bool
}

// Config represents connection configuration
type Config struct {
	Driver   string
	Host     string
	Port     int
	Database string
	Username string
	Password string
	PoolSize int
	// Params holds the query parameters of the connection URI
	// (e.g. sslmode=require, parseTime=true); they are passed to the driver.
	Params map[string]string

	// Adaptive pool bounds; PoolMax > 0 enables the pool tuner.
	PoolMin      int
	PoolMax      int
	TuneInterval time.Duration
}

// Driver is the internal interface all DB drivers MUST implement
type Driver interface {
	Connect(config Config) (Connection, error)
	Capabilities() Capabilities
}

type driverKey struct{}

// WithDriver records in ctx the driver name of the handle executing a query,
// so middleware can apply the right SQL dialect.
func WithDriver(ctx context.Context, driver string) context.Context {
	return context.WithValue(ctx, driverKey{}, driver)
}

// DriverFrom returns the driver name stored by WithDriver.
func DriverFrom(ctx context.Context) (string, bool) {
	d, ok := ctx.Value(driverKey{}).(string)
	return d, ok
}
