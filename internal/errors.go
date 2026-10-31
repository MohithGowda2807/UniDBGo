package internal

import (
	"errors"
	"fmt"
)

// Portable error values. Drivers wrap backend-specific errors so that
// errors.Is works the same way for every database, while errors.As still
// reaches the original driver error.
var (
	ErrUniqueViolation     = errors.New("unique constraint violated")
	ErrForeignKeyViolation = errors.New("foreign key constraint violated")
	ErrNotNullViolation    = errors.New("not null constraint violated")
	ErrDeadlock            = errors.New("deadlock or serialization failure")
)

// ErrorClassifier maps a driver error to one of the portable error values,
// or returns nil if the error has no portable equivalent.
type ErrorClassifier func(error) error

// Classify wraps err with its portable equivalent, keeping err in the chain.
func Classify(c ErrorClassifier, err error) error {
	if err == nil || c == nil {
		return err
	}
	if kind := c(err); kind != nil {
		return fmt.Errorf("%w: %w", kind, err)
	}
	return err
}
