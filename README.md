# UniDB-Go

[![CI](https://github.com/Dheeran-git/UniDBGo/actions/workflows/ci.yml/badge.svg)](https://github.com/Dheeran-git/UniDBGo/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

UniDB-Go is an embeddable database middleware for Go services that keep data in more than one engine. Every statement is parsed into a syntax tree before it reaches a driver; the same tree drives an injection checker, a planner that can join tables living in different databases, and a dialect router.

- **One API for PostgreSQL, MySQL and MongoDB**: `Query`, `Exec` and transactions through a driver registry, with composable middleware (`db.Use`) that covers reads, writes and transactions alike.
- **AST security checker**: blocks tautologies (including hex, `CHAR()`, `CASE` and comment-obfuscated forms), stacked statements, `UNION` extraction from restricted tables or system catalogs, comment truncation, and timing/metadata probes. Queries are read with the lexical rules of the database they target, so PostgreSQL-only tricks such as backslash-quoted strings are seen as PostgreSQL sees them.
- **Cross-database joins**: `SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id` is split into per-source scans with predicate and projection push-down (literals travel as bind parameters), extracted concurrently through each handle's middleware and joined in memory with an FNV-1a hash join. Key normalisation makes `int64` keys from PostgreSQL match the byte-string keys returned by MySQL.
- **Dialect router**: a multinomial Naive Bayes model routes unqualified statements; predictions below a posterior threshold go to a default database instead of a wrong one.
- **Portable errors**: unique, foreign-key and not-null violations from any driver satisfy `errors.Is(err, api.ErrUniqueViolation)` and friends.
- **Operational pieces**: adaptive `database/sql` pool tuning, circuit breaker, bounded TTL result cache, query metrics, and a web dashboard.

## Architecture

```text
application ──► engine.Query / api.DB (middleware)
                 │
                 ├─ 1 parse     Vitess SQL parser, dialect-aware normalisation, AST cache
                 ├─ 2 security  invariants V1–V5 → block / flag / allow
                 ├─ 3 plan      single source, or two scans + join with push-down
                 ├─ 4 route     db qualifier → Naive Bayes (p ≥ θ) → default
                 ├─ 5 execute   driver call, or concurrent scans + hash join
                 └─ 6 drivers   postgres (lib/pq) · mysql (go-sql-driver) · mongodb (SQL subset → find)
```

## Quick start

Requirements: Go 1.26 or newer (the module pins the Go 1.27.3 toolchain, which `go` downloads automatically). PostgreSQL and MySQL are needed only for live execution, the integration test and the benchmarks.

```bash
git clone https://github.com/Dheeran-git/UniDBGo.git
cd UniDBGo
go test ./...
```

### Dashboard

```bash
go run ./cmd/unidb-web                 # demo mode: real parsing, security and planning; sample rows
```

To execute against real databases, name the sources (the first one is the default):

```bash
UNIDB_SOURCES="postgres=postgres://user:pass@localhost:5432/db,mysql=mysql://user:pass@localhost:3306/db" go run ./cmd/unidb-web
```

Then open <http://localhost:8080>. The listen address can be changed with `-addr`.

### Library

```go
pg, _ := api.Connect("postgres://user:pass@localhost:5432/shop")
my, _ := api.Connect("mysql://user:pass@localhost:3306/shop")

e := &engine.Engine{
	Sources:  map[string]*api.DB{"postgres": pg, "mysql": my},
	Default:  "postgres",
	Security: security.NewSecurityEngine("users", "tokens"), // restricted tables
}

rows, trace, err := e.Query(ctx,
	"SELECT u.name, o.total FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id WHERE o.status = 'paid'")
if errors.Is(err, api.ErrBlockedQuery) {
	// rejected by the security checker; trace.Decision says why
}
```

A single database handle can use the same checks as middleware:

```go
db, _ := api.Connect("postgres://user:pass@localhost:5432/shop", api.WithAdaptivePool(4, 64, time.Second))
db.Use(security.SecurityMiddleware(security.NewSecurityEngine()))
db.Use(metrics.MetricsMiddleware())
```

Connection URIs accept the usual query parameters, e.g. `?sslmode=require` for PostgreSQL or `?parseTime=true` for MySQL.

## Testing

```bash
make test          # unit tests
make race          # unit tests with the race detector
make integration   # loads a small dataset and runs the live tests (attacks, errors, transactions, federation)
make vuln          # govulncheck against the Go vulnerability database
```

`make integration` expects PostgreSQL at `postgres://postgres:pass@127.0.0.1:5432/unidb` and MySQL at `mysql://unidb:pass@127.0.0.1:3306/unidb`; override with `make integration PG=... MY=...`. CI runs all of these against PostgreSQL 16 and MySQL 8.0 service containers.

## Benchmarks

`cmd/unidb-bench` runs the evaluation workloads and writes JSON and plot data to `bench/results/`:

```bash
go run ./cmd/unidb-bench security     # injection corpus (verifies payloads against MySQL)
go run ./cmd/unidb-bench router       # routing accuracy and threshold sweep
go run ./cmd/unidb-bench join         # in-memory hash join vs nested loop
go run ./cmd/unidb-bench setup        # load 50,000 users (PostgreSQL) and orders (MySQL)
go run ./cmd/unidb-bench latency      # native driver vs UniDB-Go latency
go run ./cmd/unidb-bench throughput   # throughput and tail latency vs workers
go run ./cmd/unidb-bench fedscale     # live federated join scaling
```

Use `-pg` and `-my` to point at other servers. The security verification step uses a scratch MySQL database (`-secdb`, default `unidb_sec`) that the MySQL user must be allowed to create tables in.

## Project layout

```text
api/            public API: Connect, DB, middleware, options, error values
engine/         end-to-end pipeline (parse → security → plan → route → execute)
parser/         Vitess parsing, dialect normalisation, AST summary
security/       AST invariants and static expression evaluator
planner/        single-source and federated plans
router/         Naive Bayes dialect router
federation/     concurrent extraction and hash join
drivers/        postgres, mysql, mongodb and the shared database/sql wrapper
pool/           adaptive pool tuner and a generic connection pool
cache/ circuit/ metrics/   result cache, circuit breaker, query metrics
web/            dashboard server and static assets (embedded in the binary)
cmd/            unidb-web (dashboard) and unidb-bench (benchmarks)
bench/          evaluation corpora (results go to bench/results/, not tracked)
examples/       basic usage, raw database/sql comparison, gap demos
docs/           design notes and demo guide
```

## Limitations

- The parser is Vitess's MySQL 8.0 grammar. PostgreSQL placeholders, casts, `ILIKE`, quoted identifiers, dollar-quoted and `E''` strings are normalised before analysis (single-source queries are still sent exactly as written), but constructs such as `RETURNING` or `DISTINCT ON` are rejected unless `SecurityEngine.AllowUnparseable` is set.
- Federated queries must not use backslashes in literals, double quotes or `#`, whose meaning differs between the two dialects; they are rejected with an explicit error.
- Federated queries support inner equi-joins of two tables with single-table predicates; bind parameters, multi-way joins, grouping and ordering over the joined result are rejected with an explicit error. The build side of the join must fit in memory.
- MongoDB support covers single-collection `SELECT` with conjunctive predicates, `ORDER BY` and `LIMIT`/`OFFSET`, plus raw command documents; writes are not translated.

## License

MIT; see [LICENSE](LICENSE).
