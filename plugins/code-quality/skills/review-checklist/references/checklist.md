# The checklist

Cite evidence for each item: a file and line, a command output, or "not applicable: <why>". A section with no evidence is not reviewed.

## 1. Correctness

| # | Question | How to check |
|---|---|---|
| 1.1 | Does the code do what the description says, and only that? | Compare each hunk to the intent sentence; unrelated changes are a finding (split the PR) |
| 1.2 | Boundaries: empty input, one element, maximum size, zero, negative, Unicode, time zones, leap days | Read every loop, index and arithmetic expression |
| 1.3 | Off-by-one in ranges, slices and pagination | Check inclusive versus exclusive ends |
| 1.4 | Null and undefined paths: every optional value is handled where it is read | Trace each `Optional`, `?.`, `null` default |
| 1.5 | Concurrency: shared state, races, idempotency of retried operations | Look for globals, caches, `async` without awaits, database writes without transactions |
| 1.6 | Resource handling: files, sockets, cursors, locks are closed on every path | Context managers, `finally`, `defer`, `using` |

## 2. Tests

| # | Question | How to check |
|---|---|---|
| 2.1 | Every behaviour change has a test that fails without the change | Revert the code mentally; which test breaks? |
| 2.2 | Tests assert outcomes, not implementation details (no asserting on mocks of the thing under test) | Read the assertions |
| 2.3 | The failing case is tested, not only the happy path | Look for `raises`, error status codes, invalid input |
| 2.4 | Tests are deterministic (no real time, randomness, network, ordering assumptions) | Grep for `sleep`, `now()`, `random`, external URLs |
| 2.5 | Deleted or weakened tests are justified in the description | `git diff --stat` on test directories |

## 3. Error handling

| # | Question | How to check |
|---|---|---|
| 3.1 | No bare `except:` / `catch (e) {}` that swallows errors | Grep the diff for `except:`, `catch {`, `pass` in handlers |
| 3.2 | Errors carry context (what was being done, with which input) and are logged once, at the boundary | Follow one error from raise to log |
| 3.3 | External calls (HTTP, DB, queue) have timeouts and bounded retries | Look at every client call |
| 3.4 | User-facing messages do not leak internals (stack traces, SQL, paths) | Check error responses |

## 4. Security

| # | Question | How to check |
|---|---|---|
| 4.1 | Input from outside (request, file, env, CLI) is validated before use | Trace each entry point |
| 4.2 | No string-built SQL, shell commands or HTML with user data | Grep for `f"SELECT`, `subprocess(... shell=True`, `innerHTML`, template `|safe` |
| 4.3 | Authorisation is checked on the new endpoint or action, not only authentication | Compare with a neighbouring endpoint |
| 4.4 | No secrets, tokens or personal data in code, logs, tests or fixtures | Run `secrets-hygiene`; read log statements |
| 4.5 | New dependencies are needed, maintained and pinned | Check the lockfile diff |

## 5. Performance

| # | Question | How to check |
|---|---|---|
| 5.1 | No N+1 queries or network calls inside loops | Look for ORM access or `fetch` inside `for` |
| 5.2 | Work is proportional to input; no accidental quadratic (nested loops over the same collection, `in list` inside loops) | Read the loops |
| 5.3 | Large results are paginated or streamed | Check list endpoints and file reads |
| 5.4 | Caches have a bound and an invalidation story | Any new dict used as a cache |

## 6. Readability and design

| # | Question | How to check |
|---|---|---|
| 6.1 | Names say what things are; functions do one thing; no dead code or commented-out code | Read as a newcomer |
| 6.2 | Duplication with existing code that should have been reused | Search the repository for a similar function |
| 6.3 | Public interface changes are documented (docstring, README, changelog) | Check the docs diff |
| 6.4 | Complexity is proportionate; a `complexity-report` run shows nothing over threshold in the changed files | Run it on the changed paths |

## 7. Compatibility and operations

| # | Question | How to check |
|---|---|---|
| 7.1 | Database migrations are backwards compatible with the running version (add column nullable, backfill, then constrain) | Read the migration |
| 7.2 | API changes are additive, or versioned, or the breaking change is called out | Diff the schema or OpenAPI document |
| 7.3 | Configuration changes have defaults and are documented in `.env.example` | Run `env-diff` |
| 7.4 | Logs and metrics exist for the new code path | Look for log and metric calls |
| 7.5 | Feature flags or rollout plan for risky changes | Description mentions rollout |
