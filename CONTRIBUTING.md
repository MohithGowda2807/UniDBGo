# Contributing to UniDB-Go

## Development setup

- Go 1.26 or newer (the pinned 1.27.3 toolchain is downloaded automatically).
- PostgreSQL and MySQL for the integration test and the benchmarks (see the README for the expected connection URIs).

## Before opening a pull request

```bash
make fmt          # gofmt every file
make vet
make race         # unit tests with the race detector
make integration  # live PostgreSQL + MySQL test
```

CI runs the same steps; a pull request must pass all of them.

## Guidelines

- Keep changes focused and covered by tests. Security rules need both a blocked attack and an allowed legitimate query in `security/engine_test.go`.
- Never send re-rendered SQL to a database: single-source queries keep the caller's text, and generated queries pass literals as bind parameters.
- If a change affects performance or detection results, re-run the matching `cmd/unidb-bench` sub-command.
- Record user-visible changes in `CHANGELOG.md`.
