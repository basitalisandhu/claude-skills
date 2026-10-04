# Reading EXPLAIN output

## PostgreSQL: `EXPLAIN (ANALYZE, BUFFERS)`

- Nodes are indented; the innermost runs first. Each shows `cost=start..total rows=estimate` and, with ANALYZE, `actual time=start..total rows=N loops=L`. Multiply per-loop numbers by `loops` for totals.
- Start at the node with the largest `actual time` difference from its children; that node is the cost.
- `Seq Scan` on a large table with `Rows Removed by Filter` high: missing or unusable index.
- `Index Scan` with `Rows Removed by Filter` high: the index matches part of the predicate; a composite or partial index would help.
- `Index Only Scan` with `Heap Fetches` high: the visibility map is stale; `VACUUM`.
- `Nested Loop` with a large outer `rows` and an inner `Seq Scan`: missing index on the join column, or a misestimate (compare estimated and actual rows).
- `Hash` with `Batches > 1` or `Sort Method: external merge  Disk`: `work_mem` too small for this query, or the input should be filtered earlier.
- Estimate off by 10x or more: stale statistics (`ANALYZE`), correlated columns (`CREATE STATISTICS`), or a predicate the planner cannot estimate.
- `Buffers: shared hit=... read=...`: `read` is disk; a query that reads far more pages than it returns rows is scanning.
- `Limit` above a `Sort` of many rows: no index for the `ORDER BY`; the sort is done then discarded.

Useful: `SHOW work_mem; SHOW random_page_cost; SELECT * FROM pg_stat_user_tables WHERE relname = '...'` (last analyze, dead tuples).

## MySQL / MariaDB: `EXPLAIN ANALYZE` (8.0.18+) or `EXPLAIN FORMAT=JSON`

- `type`: `ALL` is a full table scan; `index` a full index scan; `range`, `ref`, `eq_ref`, `const` are good in that order.
- `key` is the index used; `key_len` tells how many columns of a composite index are used.
- `rows` is the estimate per lookup; `filtered` the percentage kept after the WHERE (low means the index does not cover the predicate).
- `Extra`: `Using filesort` (sort without an index), `Using temporary` (GROUP BY or DISTINCT needing a temp table), `Using index` (covering, good).
- `EXPLAIN ANALYZE` prints a tree with `actual time` and `rows` per node; read it like the PostgreSQL tree.
- Implicit cast between `VARCHAR` and `INT` in a join or predicate disables the index: check column types on both sides.

## SQLite: `EXPLAIN QUERY PLAN`

- `SCAN table` is a full scan; `SEARCH table USING INDEX name (col=?)` uses an index; `USING COVERING INDEX` avoids the table.
- `USE TEMP B-TREE FOR ORDER BY` means no index matched the sort.
- SQLite picks one index per table per query; composite indexes matter more than in other engines.
- `ANALYZE` populates `sqlite_stat1`; without it the planner guesses.

## General reading order

1. Total time and the node that owns most of it.
2. Estimated versus actual rows on that node and its children.
3. Access method (scan versus index) and what was filtered after access.
4. Memory and disk (sorts, hashes, temp tables).
5. Loops: a cheap node run 100,000 times is the problem.
