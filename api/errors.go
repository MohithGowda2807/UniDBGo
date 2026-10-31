package api

import (
	"errors"

	"github.com/Dheeran-git/UniDBGo/internal"
)

var (
	ErrConnectionFailed = errors.New("connection failed")
	ErrBlockedQuery     = errors.New("query blocked by security engine")

	// Portable constraint and concurrency errors. Drivers wrap their native
	// errors so that errors.Is(err, api.ErrUniqueViolation) works for every
	// backend while errors.As still reaches the driver's own error type.
	ErrUniqueViolation     = internal.ErrUniqueViolation
	ErrForeignKeyViolation = internal.ErrForeignKeyViolation
	ErrNotNullViolation    = internal.ErrNotNullViolation
	ErrDeadlock            = internal.ErrDeadlock
)
