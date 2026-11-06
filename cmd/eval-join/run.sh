#!/bin/sh
# Runs the three eval-join experiments with their default (paper) settings.
# Run from the repository root on an otherwise idle host, one at a time.
# SMOKE=1 runs tiny sizes into bench/results/revision/smoke instead.
set -eu
BIN=${BIN:-/tmp/eval-join}
go build -o "$BIN" ./cmd/eval-join

if [ "${SMOKE:-0}" = 1 ]; then
	OUT=bench/results/revision/smoke
	"$BIN" -out "$OUT" -sizes 10k,50k -r 2 memory
	"$BIN" -out "$OUT" -memlimit-n 200000 -r 2 memlimit
	"$BIN" -out "$OUT" -sizes 1k,5k -r 2 engines
	exit 0
fi

OUT=bench/results/revision
# 1. Memory per size, each size in a fresh child process (default sizes 10k..1M, r=5).
"$BIN" -out "$OUT" -r 5 memory                 # -> join_memory.json
# 2. 1M x 1M join under GOMEMLIMIT and cgroup hard caps (r=3 joins per child).
"$BIN" -out "$OUT" -memlimit-n 1000000 -r 3 memlimit   # -> join_memlimit.json
# 3. End-to-end federated join vs native PostgreSQL / MySQL joins and DuckDB.
"$BIN" -out "$OUT" -sizes 1k,5k,10k,25k,50k -r 10 -naive-reps 3 engines   # -> join_engines.json
