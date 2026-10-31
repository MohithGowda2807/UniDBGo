package api

import (
	"context"
	"github.com/Dheeran-git/UniDBGo/internal"
)

// Handler processes a query and returns a result.
type Handler func(ctx context.Context, query string, args ...any) (internal.Result, error)

// Middleware intercepts or modifies database requests.
type Middleware func(next Handler) Handler

// Use adds a middleware to the database instance.
func (db *DB) Use(m Middleware) {
	db.middleware = append(db.middleware, m)
}
