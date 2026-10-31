// Package postgres registers the PostgreSQL driver (lib/pq).
package postgres

import (
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/Dheeran-git/UniDBGo/drivers/sqlwrap"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/lib/pq"
)

func init() {
	internal.RegisterDriver("postgres", &PostgresDriver{})
}

type PostgresDriver struct{}

// DSN renders config as a lib/pq connection URI. URI parameters are passed
// through; sslmode defaults to "disable" when not given.
func DSN(config internal.Config) string {
	q := url.Values{}
	for k, v := range config.Params {
		q.Set(k, v)
	}
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "disable")
	}
	u := url.URL{
		Scheme:   "postgres",
		Host:     net.JoinHostPort(config.Host, strconv.Itoa(config.Port)),
		Path:     "/" + config.Database,
		RawQuery: q.Encode(),
	}
	if config.Username != "" {
		u.User = url.UserPassword(config.Username, config.Password)
	}
	return u.String()
}

func (d *PostgresDriver) Connect(config internal.Config) (internal.Connection, error) {
	db, err := sql.Open("postgres", DSN(config))
	if err != nil {
		return nil, err
	}
	return sqlwrap.Open(db, classify, config.PoolSize)
}

// classify maps PostgreSQL SQLSTATE codes to portable errors.
func classify(err error) error {
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case "23505":
		return internal.ErrUniqueViolation
	case "23503":
		return internal.ErrForeignKeyViolation
	case "23502":
		return internal.ErrNotNullViolation
	case "40001", "40P01":
		return internal.ErrDeadlock
	}
	return nil
}

func (d *PostgresDriver) Capabilities() internal.Capabilities {
	return internal.Capabilities{
		SupportsSQL:          true,
		SupportsTransactions: true,
		SupportsJoins:        true,
		SupportsAggregation:  true,
	}
}

// WrapError adds the portable error value (api.ErrUniqueViolation, ...) to a
// lib/pq error; the driver applies it to every error it returns.
func WrapError(err error) error { return internal.Classify(classify, err) }
