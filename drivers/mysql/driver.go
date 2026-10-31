// Package mysql registers the MySQL driver (go-sql-driver/mysql).
package mysql

import (
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/Dheeran-git/UniDBGo/drivers/sqlwrap"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/go-sql-driver/mysql"
)

func init() {
	internal.RegisterDriver("mysql", &MySQLDriver{})
}

type MySQLDriver struct{}

// Config converts config into a go-sql-driver configuration. URI parameters
// (e.g. parseTime=true, tls=true) are applied with the driver's own DSN
// parser, so every parameter it documents is supported.
func Config(config internal.Config) (*mysql.Config, error) {
	base := mysql.NewConfig()
	base.User = config.Username
	base.Passwd = config.Password
	base.Net = "tcp"
	base.Addr = net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	base.DBName = config.Database
	if len(config.Params) == 0 {
		return base, nil
	}
	q := url.Values{}
	for k, v := range config.Params {
		q.Set(k, v)
	}
	// Let the driver parse the parameters, then restore the fields that
	// come from the URI itself (the password may contain any character).
	parsed, err := mysql.ParseDSN("/?" + q.Encode())
	if err != nil {
		return nil, err
	}
	parsed.User, parsed.Passwd, parsed.Net, parsed.Addr, parsed.DBName = base.User, base.Passwd, base.Net, base.Addr, base.DBName
	return parsed, nil
}

func (d *MySQLDriver) Connect(config internal.Config) (internal.Connection, error) {
	cfg, err := Config(config)
	if err != nil {
		return nil, err
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sqlwrap.Open(sql.OpenDB(conn), classify, config.PoolSize)
}

// classify maps MySQL error numbers to portable errors.
func classify(err error) error {
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) {
		return nil
	}
	switch myErr.Number {
	case 1062, 1586:
		return internal.ErrUniqueViolation
	case 1216, 1217, 1451, 1452:
		return internal.ErrForeignKeyViolation
	case 1048, 1364:
		return internal.ErrNotNullViolation
	case 1213:
		return internal.ErrDeadlock
	}
	return nil
}

func (d *MySQLDriver) Capabilities() internal.Capabilities {
	return internal.Capabilities{
		SupportsSQL:          true,
		SupportsTransactions: true,
		SupportsJoins:        true,
		SupportsAggregation:  true,
	}
}

// WrapError adds the portable error value (api.ErrUniqueViolation, ...) to a
// go-sql-driver error; the driver applies it to every error it returns.
func WrapError(err error) error { return internal.Classify(classify, err) }
