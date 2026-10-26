# schema-migration-plan

Plan a database schema migration on a live database as an expand and contract sequence of backwards-compatible, reversible steps that work with the running app version: lock and downtime per step, batched backfills for large tables, rollback.

Use it when asked "how do I rename this column safely?", to rename a column or change its type (such as a varchar id to a uuid) without downtime, to add a NOT NULL column with no long lock, or to review a migration PR that drops a column.
Not for query tuning (sql-query-review), version numbers (semver-advisor) or choosing a database.

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/locks.md`](references/locks.md), [`references/patterns.md`](references/patterns.md), and states what it could not check.

## Example requests

- "How do I rename the users.fullname column without taking the app down?"
- "We need to add a NOT NULL column to a 200 million row table. Plan it so there is no long lock"
- "Review this migration PR: it drops a column that the old app version still reads"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
