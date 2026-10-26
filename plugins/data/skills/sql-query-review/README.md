# sql-query-review

Review SQL queries, ORM-generated SQL and query plans for correctness and performance: injection, implicit casts, NULL logic, non-sargable predicates, missing indexes, N+1 patterns, unbounded result sets, lock contention and transaction scope, using a fixed checklist and EXPLAIN reading notes for PostgreSQL, MySQL and SQLite.

Use it when asked "why is this query slow?", to review a query or migration, or to check ORM output.
Not for schema design from scratch (use schema-migration-plan for changes) and not a replacement for a database profiler.

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/checklist.md`](references/checklist.md), [`references/explain.md`](references/explain.md), and states what it could not check.

## Example requests

- "Why is this query slow? Here is the EXPLAIN output from PostgreSQL"
- "Review this SQL for NULL logic mistakes and missing indexes"
- "Check the SQL our ORM generates for N+1 patterns"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
