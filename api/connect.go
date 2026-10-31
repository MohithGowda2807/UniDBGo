package api

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/pool"

	// Import drivers to run their init() functions
	_ "github.com/Dheeran-git/UniDBGo/drivers/mongodb"
	_ "github.com/Dheeran-git/UniDBGo/drivers/mysql"
	_ "github.com/Dheeran-git/UniDBGo/drivers/postgres"
)

// ParseConnectionString parses a URI into internal.Config
// e.g. postgres://user:pass@localhost:5432/dbname
func ParseConnectionString(connStr string) (internal.Config, error) {
	u, err := url.Parse(connStr)
	if err != nil {
		return internal.Config{}, err
	}

	if u.Scheme == "" || u.Host == "" {
		return internal.Config{}, fmt.Errorf("connection string must look like driver://user:pass@host:port/db, got %q", connStr)
	}
	cfg := internal.Config{
		Driver: u.Scheme,
		Host:   u.Hostname(),
	}
	if cfg.Driver == "postgresql" {
		cfg.Driver = "postgres"
	}

	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return internal.Config{}, fmt.Errorf("invalid port %q", port)
		}
		cfg.Port = p
	} else {
		// Defaults
		switch cfg.Driver {
		case "postgres":
			cfg.Port = 5432
		case "mysql":
			cfg.Port = 3306
		case "mongodb":
			cfg.Port = 27017
		}
	}

	cfg.Database = strings.TrimPrefix(u.Path, "/")
	if q := u.Query(); len(q) > 0 {
		cfg.Params = make(map[string]string, len(q))
		for k, v := range q {
			cfg.Params[k] = v[len(v)-1]
		}
	}

	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}

	return cfg, nil
}

// Connect initializes a new database connection
func Connect(connStr string, opts ...Option) (*DB, error) {
	cfg, err := ParseConnectionString(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	db := &DB{
		config: cfg,
	}

	// Apply options
	for _, opt := range opts {
		opt(db)
	}

	// Get driver
	driver, err := internal.GetDriver(db.config.Driver)
	if err != nil {
		return nil, err
	}

	// Connect
	conn, err := driver.Connect(db.config)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	db.conn = conn

	// Attach the adaptive tuner when the driver exposes a tunable pool.
	if db.config.PoolMax > 0 {
		if t, ok := conn.(pool.Tunable); ok {
			db.tuner = pool.StartTuner(t, db.config.PoolMin, db.config.PoolMax, db.config.TuneInterval)
		}
	}
	return db, nil
}
