# Data

Six skills for data and API work: SQL query review, schema migration planning, CSV profiling, JSON Schema inference, regex building with test cases, and OpenAPI 3 contract review.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install data@claude-dev-skills
```

Skills then appear as `/data:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `sql-query-review` | why is this query slow, review this SQL | checklist findings and plan reading with the fix |
| `schema-migration-plan` | add, rename, drop or change a column on a live table | expand, migrate, contract steps with locks and rollback |
| `csv-profiler` | what is in this file, load this CSV | `csv_profiler.py` profile, types, cleaning steps, schema |
| `json-schema-author` | validate this JSON, schema from examples | `json_schema_infer.py` draft, hand-finished schema |
| `regex-builder` | write a regex, why does it not match | `regex_tester.py` case results, backtracking warnings |
| `api-contract-review` | review the OpenAPI spec, client generator fails | `openapi_lint.py` findings, contract review |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.
