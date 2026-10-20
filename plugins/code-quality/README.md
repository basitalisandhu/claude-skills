# Code Quality

Eight skills for keeping a codebase healthy: a fixed review checklist, refactor planning, dead code and complexity reports, naming and error-handling audits, type coverage for Python and TypeScript, and a test gap finder.

Find this when you search for: tech debt, code smells, cognitive complexity.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install code-quality@claude-dev-skills
```

Skills then appear as `/code-quality:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `review-checklist` | review a PR, diff or branch | findings table with severity and file:line, verdict |
| `refactor-plan` | refactor, split, untangle, clean up | ordered behaviour-preserving steps with tests and rollback |
| `dead-code-finder` | find unused code, shrink the codebase | `dead_code_finder.py` report, confirmed deletion list |
| `complexity-report` | most complex code, where to start, CI threshold | `complexity_report.py` ranking with simplifications |
| `naming-audit` | are these names clear, naming conventions | renames grouped by cost, convention proposals |
| `error-handling-review` | review error handling, silent failures | findings plus an error policy per layer |
| `type-coverage` | how typed is this, where to add types | `type_coverage.py` percentages and a ratchet plan |
| `test-gap-finder` | what is untested, did the PR add tests | `test_gap_finder.py` list of modules without tests, prioritised |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.

## Sample output

`test-gap-finder` on a small package with `shop/cart.py`, `shop/payments.py`, `shop/_mailer.py`, an entry point `shop/main.py`, and `tests/test_cart.py` plus `tests/test_mailer.py`:

```text
$ python3 "${CLAUDE_PLUGIN_ROOT}/skills/test-gap-finder/scripts/test_gap_finder.py" shop
test-gap-finder 0.1.0: 2/3 modules have a test by name or import (66.7%), 2 test files, 1 entry-point or config file(s) not counted
  no test: shop/payments.py
Name and import based. A module listed as covered may still have weak tests; one listed as uncovered may be exercised indirectly.
exit 0
```
