# Migration patterns (expand, migrate, contract)

| Change | Steps | Notes |
|---|---|---|
| Add nullable column | `ADD COLUMN ... NULL` | Safe; PostgreSQL 11+ also makes `ADD COLUMN ... DEFAULT <constant>` metadata-only |
| Add column with NOT NULL | 1. add nullable (with DEFAULT if constant) 2. backfill in batches 3. `ADD CONSTRAINT ... CHECK (col IS NOT NULL) NOT VALID`, then `VALIDATE CONSTRAINT` 4. `SET NOT NULL` (PostgreSQL 12+ uses the validated check and skips the scan) 5. drop the check | Never `ADD COLUMN ... NOT NULL` without a default on a populated table |
| Rename column | 1. add new column 2. dual write in app; backfill 3. switch reads 4. stop writing old 5. drop old | A bare `RENAME COLUMN` breaks the running old version; only acceptable with stop-the-world deploys |
| Change column type | Same as rename with a new column of the new type; cast during backfill | `ALTER COLUMN TYPE` rewrites the table under an exclusive lock, except widening `varchar(n)` or `varchar` to `text` in PostgreSQL |
| Add index | `CREATE INDEX CONCURRENTLY` (PostgreSQL), `ALGORITHM=INPLACE, LOCK=NONE` (MySQL) | Cannot run inside a transaction in PostgreSQL; a failed concurrent build leaves an INVALID index to drop |
| Add unique constraint | 1. `CREATE UNIQUE INDEX CONCURRENTLY` 2. `ADD CONSTRAINT ... UNIQUE USING INDEX` | Resolve duplicates before step 1 |
| Add foreign key | 1. `ADD CONSTRAINT ... FOREIGN KEY ... NOT VALID` 2. `VALIDATE CONSTRAINT` | Index the referencing column first |
| Add check constraint | `NOT VALID` then `VALIDATE` | Same pattern |
| Drop column | 1. stop reading and writing it in the app (one release) 2. `DROP COLUMN` | Fast in PostgreSQL (marks dropped); MySQL rewrites unless `ALGORITHM=INSTANT` applies (8.0.29+) |
| Drop table | 1. stop using it 2. rename to `_old_<name>` for one release 3. drop | The rename is the cheap undo |
| Split a table | 1. create new table 2. dual write 3. backfill 4. switch reads 5. stop old writes 6. drop old columns | Treat as several column migrations |
| Change primary key type (int to bigint) | 1. add new column 2. trigger or dual write 3. backfill 4. unique index concurrently 5. swap constraint in one short transaction 6. update FKs the same way | Plan weeks ahead; the swap transaction is the only lock |
| Add enum value | PostgreSQL `ALTER TYPE ... ADD VALUE` cannot run in a transaction before 12; values cannot be removed | Prefer a lookup table or a `text` column with a check constraint |
| Rename table | Use a view with the old name for one release, or dual-name in the app | |

## Backfill script shape

```sql
-- resumable, batched, gentle; last_id persisted outside the transaction
UPDATE users SET email_normalized = lower(email)
WHERE id > :last_id AND id <= :last_id + 5000 AND email_normalized IS NULL;
-- commit; sleep 0.1 s; advance last_id; stop when last_id >= max(id)
```

Rules: batch by primary key range (not `LIMIT` with `OFFSET`), commit per batch, pause between batches, make it idempotent (`WHERE new IS NULL`), log progress, run from a job that can be stopped and restarted, watch replication lag.

## Deployment choreography

1. Expand migration runs before the new app version starts.
2. New app version runs with both structures present.
3. Backfill runs while the new version serves traffic.
4. Contract migration runs after every instance of the previous app version is gone and the next app version (which no longer references the old structure) is deployed.

A migration tool that runs all pending migrations at startup must never contain an expand and its contract in the same deploy.
