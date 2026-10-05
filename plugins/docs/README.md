# Docs

Six skills for writing documentation that stays accurate: a README author, an ADR writer, a changelog keeper, an onboarding document, API docs extracted from docstrings and JSDoc, and a postmortem writer.

Find this when you search for: incident report, technical writing.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install docs@claude-dev-skills
```

Skills then appear as `/docs:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `readme-author` | no README, stale README, publishing | README in a fixed order with verified commands |
| `adr-writer` | choosing a technology, "why did we do this?" | numbered decision record with options and consequences |
| `changelog-keeper` | changelog line, cut a release, format drift | `changelog.py` check, add, release, show |
| `onboarding-doc` | new team member, service changes hands | docs/ONBOARDING.md verified on a clean machine |
| `api-docs-from-code` | document this package, stale reference | `extract_docs.py` Markdown reference and coverage gate |
| `postmortem-writer` | after an outage or near-miss | blameless postmortem with timeline, causes and actions |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.
