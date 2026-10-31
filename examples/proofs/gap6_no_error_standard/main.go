// ============================================================
// GAP 6 PROOF: database/sql has NO standardized error codes.
//              Every driver throws different types/values.
//              Switching databases = rewriting all error handling.
// ============================================================
// HOW TO RUN:
//   go run ./examples/proofs/gap6_no_error_standard
// ============================================================

package main

import (
	"errors"
	"fmt"

	"github.com/Dheeran-git/UniDBGo/api"
	unimy "github.com/Dheeran-git/UniDBGo/drivers/mysql"
	unipg "github.com/Dheeran-git/UniDBGo/drivers/postgres"
	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// ── UniDB-Go's standardized errors ───────────────────────────────────────
// api.ErrUniqueViolation and friends are defined once; each UniDB-Go driver
// wraps its native errors with them (drivers/postgres, drivers/mysql).

func wrapPostgresError(err error) error { return unipg.WrapError(err) }

func wrapMySQLError(err error) error { return unimy.WrapError(err) }

func main() {
	fmt.Println("=== GAP 6: database/sql Has NO Standardized Error Codes ===")
	fmt.Println()

	// Simulate a duplicate key error from Postgres
	pgRawErr := &pq.Error{Code: "23505", Detail: "Key (email)=(alice@example.com) already exists."}
	// Simulate same error from MySQL
	myRawErr := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'alice@example.com' for key 'email'"}

	// ── Raw Go: Must handle each driver separately ────────────────────────
	fmt.Println("── RAW GO: Handling duplicate key error ─────────────────────────────")
	fmt.Println()

	fmt.Println("[RAW GO] // For Postgres:")
	fmt.Println("[RAW GO] var pgErr *pq.Error")
	fmt.Println("[RAW GO] if errors.As(err, &pgErr) && pgErr.Code == \"23505\" {")
	fmt.Println("[RAW GO]     // handle duplicate — Postgres-specific type and code")
	fmt.Println("[RAW GO] }")
	fmt.Println()
	fmt.Println("[RAW GO] // For MySQL (DIFFERENT package, DIFFERENT type, DIFFERENT number):")
	fmt.Println("[RAW GO] var myErr *mysql.MySQLError")
	fmt.Println("[RAW GO] if errors.As(err, &myErr) && myErr.Number == 1062 {")
	fmt.Println("[RAW GO]     // handle duplicate — MySQL-specific type and number")
	fmt.Println("[RAW GO] }")
	fmt.Println()
	fmt.Println("[PROOF] Both blocks MUST exist in your code.")
	fmt.Println("[PROOF] If you add MongoDB later, you add a THIRD block.")
	fmt.Println("[PROOF] If you switch from Postgres to MySQL: ALL error handling BREAKS.")
	fmt.Println()

	// ── UniDB-Go: Wrap once, use everywhere ──────────────────────────────
	fmt.Println("── UNIDB-GO: Same error, any backend ────────────────────────────────")
	fmt.Println()

	// Wrap both raw errors into unified type
	wrappedPg := wrapPostgresError(pgRawErr)
	wrappedMy := wrapMySQLError(myRawErr)

	fmt.Printf("[UNIDB] Postgres raw error: %v\n", pgRawErr)
	fmt.Printf("[UNIDB] Wrapped:            %v\n", wrappedPg)
	fmt.Printf("[UNIDB] errors.Is(ErrUniqueViolation): %v\n\n", errors.Is(wrappedPg, api.ErrUniqueViolation))

	fmt.Printf("[UNIDB] MySQL raw error:    %v\n", myRawErr)
	fmt.Printf("[UNIDB] Wrapped:            %v\n", wrappedMy)
	fmt.Printf("[UNIDB] errors.Is(ErrUniqueViolation): %v\n\n", errors.Is(wrappedMy, api.ErrUniqueViolation))

	fmt.Println("[UNIDB] Application error handling (works for ALL backends):")
	fmt.Println("[UNIDB]   if errors.Is(err, api.ErrUniqueViolation) {")
	fmt.Println("[UNIDB]       // handle duplicate — same code for Postgres, MySQL, MongoDB")
	fmt.Println("[UNIDB]   }")
	fmt.Println()
	fmt.Println("── CONCLUSION ──────────────────────────────────────────────────────────")
	fmt.Println("[PROOF] database/sql defines no standard error types.")
	fmt.Println("[PROOF] pq.Error, mysql.MySQLError, mongo.WriteException are all DIFFERENT.")
	fmt.Println("[PROOF] Switching databases = rewrite every error handling block.")
	fmt.Println("[PROOF] UniDB-Go wraps constraint and deadlock errors from every SQL driver")
	fmt.Println("[PROOF] into portable values (api.ErrUniqueViolation, ErrForeignKeyViolation,")
	fmt.Println("[PROOF] ErrNotNullViolation, ErrDeadlock); errors.As still reaches the native error.")
}
