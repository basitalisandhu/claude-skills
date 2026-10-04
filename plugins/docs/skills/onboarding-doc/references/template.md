# Onboarding: <service or repository>

_Last verified: <date>, on <OS and versions>, by <name>. If a step fails, fix the document in the same pull request as the fix._

## 1. Setup (clean machine to passing tests)

**Tools:** <runtime and version>, <package manager>, <docker or compose>, <database client>, <cloud CLI>, <editor extensions if the repo relies on them>. Versions from `.tool-versions` / CI.

```bash
git clone <url> && cd <dir>
<install dependencies>
cp .env.example .env            # then fill the keys listed in section 5
<start dependencies, e.g. docker compose up -d db redis>
<run migrations>
<run the test suite>            # expected: N passed in about M seconds
<start the service>             # expected: listening on http://localhost:PORT
curl http://localhost:PORT/health   # expected: {"status":"ok"}
```

**Steps that fail without help:** <the undocumented things found in the clean run, each with its fix>.

## 2. Map of the code

| Directory | What lives here | Owner |
|---|---|---|
| `src/api/` | HTTP handlers, request validation | |
| `src/domain/` | business rules, no I/O | |
| `src/adapters/` | database, queues, external clients | |
| `migrations/` | schema history | |
| `tests/` | unit (fast) and integration (needs docker) | |

**Entry points:** `<file>` (service), `<file>` (worker), `<file>` (CLI).
**One request's path:** `POST /orders` -> `api/orders.py:create` -> `domain/orders.py:place_order` -> `adapters/db.py` and `adapters/billing.py` -> response.
**Data model:** <main tables or types and their relations>.
**External systems:** <name, purpose, client location, sandbox availability>.
**Handle with care:** <untested or complex areas from the tools, with links to the reports>.

## 3. Working loop

| Task | Command |
|---|---|
| One test | `<...>` |
| Whole suite | `<...>` |
| Lint and types | `<...>` |
| Local logs | `<...>` |
| Debugger | `<how to attach; launch config path>` |
| Migrations | `<create>`, `<apply>`, `<rollback>` |
| Reset local data | `<...>` |

## 4. Change path

- Branches: `<convention>`; commits: `<convention>`.
- Pull requests: template at `.github/PULL_REQUEST_TEMPLATE.md`; reviewers from `CODEOWNERS`; the review checklist.
- CI: jobs `<names>`; a failing `<job>` usually means `<common cause>`; logs at `<where>`.
- Deploy: `<how a merge reaches production, how long it takes, where to watch, how to roll back>`.

## 5. Environments and operations

| Environment | URL | Config source | Dashboards | Logs |
|---|---|---|---|---|
| local | | `.env` | | stdout |
| staging | | `<vault path>` | | |
| production | | `<vault path>` | | |

**Configuration keys:** <from `env-diff`: name, purpose, where the value comes from; never the value>.
**On-call:** <rotation, escalation, expectations>. **Runbooks:** <links>.
**Sharp edges:** <flaky test X (#123), slow step Y, platform-specific Z>.

## 6. People and decisions

- Team channel: `<channel>`; code owners: see `CODEOWNERS`.
- Ask about: <area: person>, <area: person>.
- Decisions: `docs/adr/` index; read ADR-<n> (<why the database>), ADR-<n> (<why the queue>), ADR-<n> (<why the API style>) first.

## 7. First tasks

| Issue | Area | Size | Why it is a good start |
|---|---|---|---|
| #<n> | | small | touches the test suite only |
| #<n> | | small | one handler, has a failing test |
| #<n> | | medium | adds a config option end to end |
