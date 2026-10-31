package api

import "time"

// Option allows configuring the DB instance.
type Option func(*DB)

// WithMaxPool returns an Option to configure the connection pool size.
func WithMaxPool(size int) Option {
	return func(db *DB) {
		db.config.PoolSize = size
	}
}

// WithAdaptivePool enables the adaptive pool tuner: the open-connection limit
// starts at min and is adjusted between min and max every interval.
func WithAdaptivePool(min, max int, interval time.Duration) Option {
	return func(db *DB) {
		db.config.PoolSize = min
		db.config.PoolMin = min
		db.config.PoolMax = max
		db.config.TuneInterval = interval
	}
}
