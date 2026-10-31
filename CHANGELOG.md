# Changelog

## Unreleased

### Security
- Queries are read with the lexical rules of their target database: PostgreSQL strings, where a backslash does not escape a quote, can no longer smuggle tautologies or stacked statements past the checker. `"identifiers"`, dollar-quoted strings and `#` are handled the PostgreSQL way.
- Single-source queries are sent as written, with only the backend qualifier removed; they are never re-rendered with MySQL escaping. Federated scans quote identifiers and pass every literal as a bind parameter.
- The checker blocks schema-qualified and additional dangerous functions (`pg_sleep_for`, `pg_read_binary_file`, `get_lock`, ...), PostgreSQL `pg_*` catalogs, extraction through sub-queries inside UNION branches, metadata probes outside `WHERE`, and tautologies hidden in `CASE`, `COALESCE`, `IF` or `CAST`.
- Fewer false positives: backend qualifiers such as `mysql.orders`, `owner = CURRENT_USER()`, prose in trailing comments and constant UNIONs inside sub-queries are allowed.
- `Exec` and transactions pass through middleware; federated scans run through each handle's middleware.
- Dashboard: output is HTML-escaped (stored XSS through result rows), request bodies are size-limited, and responses carry security headers.

### Added
- Security decisions are cached per dialect and query text (call `SecurityEngine.ResetCache` after changing its configuration); a cached parameterised query costs about 1 µs of pipeline CPU.
- `engine` package: the end-to-end pipeline with stage timings.
- Portable errors (`api.ErrUniqueViolation`, `ErrForeignKeyViolation`, `ErrNotNullViolation`, `ErrDeadlock`).
- Transaction options (isolation level, read-only); connection URI parameters such as `sslmode` or `parseTime`; `postgresql://` scheme.
- MongoDB SQL-subset translation and raw command documents.
- Adaptive pool tuner (`api.WithAdaptivePool`), metrics collector, bounded result cache.
- Live schema browser, `-addr` flag, graceful shutdown and embedded assets for the dashboard.
- `cmd/unidb-bench` and the evaluation corpora; CI with PostgreSQL and MySQL service containers.

### Fixed
- Errors raised while reading rows are reported (`Result.Err`) instead of silently truncating results.
- Federated joins: case-insensitive column matching, `AS` aliases, NULL keys, mixed driver key types.
- MongoDB: `LIMIT 0`, placeholder numbering, SQL NULL semantics for `<>`/`NOT IN`, `LIKE` escapes.
- Circuit breaker allows a single half-open trial; cache is bounded and keys on argument types.
- Credentials with special characters in connection URIs.

### Changed
- Module path is now `github.com/Dheeran-git/UniDBGo`.
- SQL parsing moved from the unmaintained `xwb1989/sqlparser` (2018) to the Vitess parser (`vitess.io/vitess` v0.24.5, MySQL 8.0 grammar). Constructs the old grammar rejected, such as sub-queries inside `SUBSTRING()`, are now analysed instead of being refused, and blind extraction through a scalar sub-query over a restricted table is blocked by its own rule.
- Go 1.26 or newer is required; the module pins the Go 1.27.3 toolchain. All dependencies are on their latest releases (MongoDB driver v2.9, `go-sql-driver/mysql` 1.10, `lib/pq` 1.12, `golang.org/x/crypto` 0.58, `grpc` 1.85).
- `govulncheck` runs in CI (`make vuln`); it reports no vulnerability reachable from UniDB-Go.
- Repository layout: demos under `examples/`, notes under `docs/`; the committed Windows binary was removed.
