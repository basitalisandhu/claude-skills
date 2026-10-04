# SQL review checklist

## A. Safety

| # | Check | Severity |
|---|---|---|
| A1 | No SQL built from strings with user input (f-strings, `+`, `format`, template literals); parameters are bound (`$1`, `%s`, `?`, named) | blocker |
| A2 | Identifiers (table or column names from input) are allowlisted, never interpolated | blocker |
| A3 | The connection user has the least privilege the query needs (read-only role for reports) | major |
| A4 | Writes run in a transaction with an explicit scope; no transaction spans a network call or user interaction | major |
| A5 | Destructive statements (`DELETE`, `UPDATE`, `TRUNCATE`) carry a `WHERE` and were checked with a `SELECT COUNT(*)` of the same predicate first | blocker |

## B. Correctness

| # | Check | Notes |
|---|---|---|
| B1 | `= NULL` or `!= NULL` anywhere | Always false; use `IS NULL` |
| B2 | `COUNT(column)` where `COUNT(*)` was meant | `COUNT(column)` skips NULLs |
| B3 | `NOT IN (subquery)` where the subquery can return NULL | Returns no rows; use `NOT EXISTS` |
| B4 | Join fan-out: a one-to-many join before `SUM` or `COUNT` | Aggregate in a subquery first, or use `COUNT(DISTINCT)` deliberately |
| B5 | `DISTINCT` added to "fix" duplicates | Usually hides a join bug (B4) |
| B6 | `GROUP BY` columns match the non-aggregated select list | MySQL without `ONLY_FULL_GROUP_BY` picks arbitrary values |
| B7 | `LIMIT` or pagination without a total `ORDER BY` (including a tie-breaker such as `id`) | Non-deterministic pages |
| B8 | Implicit casts: integer column compared to a string, or string column to a number | Wrong matches (`'1e3'`), index disabled in MySQL |
| B9 | Date handling: `DATE(created_at) = '2026-03-01'` versus a half-open range; time zone of `NOW()` versus stored values | Use `created_at >= '2026-03-01' AND created_at < '2026-03-02'` |
| B10 | Floating point for money | Use `NUMERIC`/`DECIMAL` |
| B11 | `LIKE` with user input not escaped (`%`, `_`) | Escape or use equality |
| B12 | Upserts: `ON CONFLICT` target matches the unique constraint; `INSERT ... SELECT` without a race guard | |
| B13 | Multi-statement migrations that read then write assume no concurrent writers | Use `SELECT ... FOR UPDATE` or constraints |

## C. Performance

| # | Check | Fix |
|---|---|---|
| C1 | Function or cast on the indexed column (`lower(email)`, `date(created_at)`, `id::text`) | Expression index, or rewrite the predicate on the raw column |
| C2 | Leading wildcard `LIKE '%term%'` | Trigram index (`pg_trgm`), full-text search, or a search engine |
| C3 | `OR` across different columns | `UNION ALL` of two indexed queries, or a composite strategy |
| C4 | Composite index column order does not match the predicate (equality columns first, then range, then sort) | Reorder or add an index |
| C5 | `SELECT *` on wide tables, especially with TOAST or BLOB columns | Select needed columns; covering index |
| C6 | Deep `OFFSET` pagination | Keyset pagination: `WHERE (created_at, id) < ($1, $2) ORDER BY created_at DESC, id DESC LIMIT 50` |
| C7 | Correlated subquery in the select list executed per row | Join or lateral join |
| C8 | N+1: the same query with different ids in a loop (visible in query logs) | One query with `WHERE id = ANY($1)` or the ORM's eager loading |
| C9 | Huge `IN (...)` lists (thousands of values) | Temporary table or `= ANY(array)`; batch |
| C10 | `COUNT(*)` to check existence | `EXISTS (SELECT 1 ...)` |
| C11 | Exact `COUNT(*)` over a large table on every page load | Approximate (`pg_class.reltuples`), cached counter, or drop the total |
| C12 | No `LIMIT` on a query whose result goes to a UI or an export in memory | Add a limit or stream with a cursor |
| C13 | Sorting a large set without an index that matches the `ORDER BY` | Index on the sort columns (with the filter columns first) |
| C14 | Missing foreign-key indexes (PostgreSQL does not create them) | Index every FK column that is joined or deleted through |
| C15 | Long transactions holding locks (`idle in transaction`) | Shorten; set `idle_in_transaction_session_timeout` |
| C16 | `SELECT ... FOR UPDATE` on many rows, or lock ordering that differs between code paths | Lock fewer rows; `SKIP LOCKED` for queues; consistent ordering |
| C17 | Stale statistics (estimated rows off by 10x or more) | `ANALYZE table`; raise `default_statistics_target` for skewed columns |
| C18 | Unused or duplicate indexes slowing writes | `pg_stat_user_indexes` with `idx_scan = 0`; drop after confirming |
