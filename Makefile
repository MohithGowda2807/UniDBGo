# Common development tasks. Integration targets expect the databases
# described in README.md (override PG/MY to point elsewhere).
PG ?= postgres://postgres:pass@127.0.0.1:5432/unidb
MY ?= mysql://unidb:pass@127.0.0.1:3306/unidb

.PHONY: all build test race vet vuln fmt fmt-check integration bench web clean

all: fmt-check vet test build

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "unformatted files:"; gofmt -l .; exit 1)

integration:
	go run ./cmd/unidb-bench -pg $(PG) -my $(MY) -rows 1000 setup
	UNIDB_TEST_PG=$(PG) UNIDB_TEST_MY=$(MY) go test -race -run Live -v ./engine/

bench:
	go run ./cmd/unidb-bench security
	go run ./cmd/unidb-bench router
	go run ./cmd/unidb-bench join
	go run ./cmd/unidb-bench -pg $(PG) -my $(MY) setup
	go run ./cmd/unidb-bench -pg $(PG) -my $(MY) latency
	go run ./cmd/unidb-bench -pg $(PG) -my $(MY) throughput
	go run ./cmd/unidb-bench -pg $(PG) -my $(MY) fedscale

web:
	go run ./cmd/unidb-web

clean:
	rm -rf bin
