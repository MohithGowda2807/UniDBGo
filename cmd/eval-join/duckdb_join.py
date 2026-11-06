"""DuckDB federation contestant for eval-join engines.

Usage: python -I -c <this script> PG_ATTACH MY_ATTACH QUERY REPS

Measures (1) a cold run: connect, LOAD both scanner extensions, ATTACH both
live databases, run QUERY and fetch all rows; then (2) REPS warm runs of QUERY
on the same connection (ATTACH done once, outside the timed region), each
fetching every row into Python objects. Prints one JSON object to stdout.
"""
import hashlib
import json
import sys
import time

import duckdb

pg_attach, my_attach, query, reps = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])


def digest(rows):
    lines = sorted(f"{name}|{total:.2f}" for name, total in rows)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


t0 = time.perf_counter()
con = duckdb.connect()
con.execute("LOAD postgres_scanner")
con.execute("LOAD mysql_scanner")
con.execute(f"ATTACH '{pg_attach}' AS pg (TYPE postgres, READ_ONLY)")
con.execute(f"ATTACH '{my_attach}' AS my (TYPE mysql, READ_ONLY)")
t_attach = time.perf_counter()
rows = con.execute(query).fetchall()
t1 = time.perf_counter()

warm = []
nrows = []
for _ in range(reps):
    s = time.perf_counter()
    r = con.execute(query).fetchall()
    warm.append((time.perf_counter() - s) * 1e3)
    nrows.append(len(r))

settings = dict(
    con.execute(
        "SELECT name, value FROM duckdb_settings() WHERE name IN "
        "('threads', 'pg_enable_filter_pushdown', 'mysql_enable_filter_pushdown', "
        "'pg_use_binary_copy', 'pg_connection_limit', 'mysql_pool_size', 'pg_pages_per_task')"
    ).fetchall()
)
explain = "\n".join(r[1] for r in con.execute("EXPLAIN " + query).fetchall())
print(
    json.dumps(
        {
            "version": duckdb.__version__,
            "cold_ms": (t1 - t0) * 1e3,
            "cold_attach_ms": (t_attach - t0) * 1e3,
            "rows": len(rows),
            "warm_rows": nrows,
            "digest": digest(rows),
            "warm_ms": warm,
            "settings": settings,
            "explain": explain,
        }
    )
)
