# What locks and rewrites (PostgreSQL and MySQL)

## PostgreSQL

| Statement | Lock | Rewrites table? | Notes |
|---|---|---|---|
| `ADD COLUMN` nullable, no default | ACCESS EXCLUSIVE, brief | no | Set `lock_timeout` so it fails rather than queues behind a long transaction |
| `ADD COLUMN ... DEFAULT <constant>` | ACCESS EXCLUSIVE, brief | no (11+) | Volatile defaults (`now()`, `gen_random_uuid()`) still rewrite |
| `SET NOT NULL` | ACCESS EXCLUSIVE, scans table | no | 12+: skipped if a validated CHECK proves it |
| `ADD CONSTRAINT ... NOT VALID` | ACCESS EXCLUSIVE, brief | no | |
| `VALIDATE CONSTRAINT` | SHARE UPDATE EXCLUSIVE | no | Allows reads and writes; scans |
| `ALTER COLUMN TYPE` | ACCESS EXCLUSIVE, rewrites | yes | Except binary-compatible changes |
| `CREATE INDEX` | SHARE (blocks writes) | no | Use CONCURRENTLY |
| `CREATE INDEX CONCURRENTLY` | SHARE UPDATE EXCLUSIVE | no | Two scans; not in a transaction; waits for every transaction that started before it |
| `DROP COLUMN` | ACCESS EXCLUSIVE, brief | no | Space reclaimed by later VACUUM or rewrite |
| `RENAME COLUMN` / `RENAME TABLE` | ACCESS EXCLUSIVE, brief | no | Breaks running code |
| `ADD FOREIGN KEY` (valid) | SHARE ROW EXCLUSIVE on both tables, scans | no | Use NOT VALID then VALIDATE |
| `ALTER TYPE ... ADD VALUE` | brief | no | Not in a transaction before 12; never removable |
| `VACUUM FULL`, `CLUSTER` | ACCESS EXCLUSIVE, rewrites | yes | Use `pg_repack` instead |

Session settings for migrations: `SET lock_timeout = '5s'` (fail fast, then retry), `SET statement_timeout = '15min'`, and check `pg_stat_activity` for `idle in transaction` sessions before an exclusive-lock step.

The queue problem: an `ACCESS EXCLUSIVE` request waits for running queries, and every new query waits behind it, so a brief lock behind a 10-minute report blocks the application for 10 minutes. `lock_timeout` is the fix.

## MySQL (InnoDB, 8.0)

| Statement | Algorithm | Notes |
|---|---|---|
| `ADD COLUMN` (last position) | INSTANT (8.0.12+) | Any position from 8.0.29 |
| `DROP COLUMN` | INSTANT (8.0.29+) else INPLACE rebuild | |
| `MODIFY COLUMN` type change | COPY (rebuild, blocks writes) | Use a new column instead; `gh-ost` or `pt-online-schema-change` for the old way |
| Extend `VARCHAR` within the same byte-length class | INPLACE, no rebuild | The 255 boundary matters |
| `ADD INDEX` | INPLACE, LOCK=NONE | Still reads the whole table; replication lag |
| `ADD UNIQUE INDEX` | INPLACE | Fails on duplicates at the end of the scan |
| `ADD FOREIGN KEY` | INPLACE with `foreign_key_checks=0`, else COPY | |
| `RENAME COLUMN` | INSTANT (8.0) | Still breaks running code |
| `ADD COLUMN ... NOT NULL DEFAULT` | INSTANT | Default applied logically |

Always write `ALGORITHM=INSTANT` or `INPLACE, LOCK=NONE` explicitly so the statement fails instead of silently falling back to a blocking COPY. Watch replica lag during online DDL; large DDL is still replicated as one statement.

## SQLite

Most `ALTER TABLE` operations other than `ADD COLUMN` and `RENAME` need the new-table, copy, drop, rename sequence inside a transaction; the database is locked for its duration. Fine for small embedded databases, not for anything online.
