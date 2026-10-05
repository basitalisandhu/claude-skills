# repo-engineering

Twelve skills for repository audits, documentation, release checks, branch clean-up and plan reviews, each with a tested standard-library Python script. Install with `/plugin marketplace add basitalisandhu/repo-engineering-skills` and then `/plugin install repo-engineering@repo-engineering-skills`. Skills appear as `/repo-engineering:<skill>`, and Claude also invokes them on its own when a request matches a skill's description.

| Skill | Script | Use it to |
|---|---|---|
| `docs-truth-check` | `skills/docs-truth-check/scripts/docs_truth_check.py` | verify README, docs/, AGENTS.md and CLAUDE.md claims against the working tree; exit 1 on drift |
| `cited-codebase-audit` | `skills/cited-codebase-audit/scripts/repo_facts.py`, `skills/cited-codebase-audit/scripts/audit_validate.py` | audit a repository from a deterministic inventory, and reject findings whose `path:line` citations do not resolve |
| `agent-context-writer` | `skills/agent-context-writer/scripts/context_lint.py` | write AGENTS.md or CLAUDE.md with only what code cannot say, and lint out what a parser can see |
| `readme-who-what-why` | `skills/readme-who-what-why/scripts/readme_check.py` | score whether a README's first screen says what, who, why, install, example and where to ask |
| `untested-entry-points` | `skills/untested-entry-points/scripts/test_gaps.py` | rank untested public functions and entry points and write characterisation test stubs |
| `repo-onboarding-guide` | `skills/repo-onboarding-guide/scripts/onboarding_facts.py`, `skills/repo-onboarding-guide/scripts/onboarding_lint.py` | extract cited facts, write an onboarding guide only from them, and flag sentences no fact supports |
| `restructure-planner` | `skills/restructure-planner/scripts/restructure_plan.py` | build the import graph, find cycles, coupling and god modules, and print a move plan with `git mv` commands (never run) |
| `adr-miner` | `skills/adr-miner/scripts/adr_mine.py`, `skills/adr-miner/scripts/adr_lint.py` | draft MADR stubs from decision commits, config changes and rationale comments, and lint an ADR folder |
| `repo-hygiene-bundle` | `skills/repo-hygiene-bundle/scripts/hygiene.py` | offline hygiene findings with severities, as a table, JSON or SARIF, with a CI exit code |
| `release-notes-verifier` | `skills/release-notes-verifier/scripts/release_notes_verify.py` | compare release notes with the commits between two tags, and version fields with the tag |
| `stale-branch-sweep` | `skills/stale-branch-sweep/scripts/stale_branch_sweep.py` | report merged, stale, open-PR and protected branches with their last committer, and print `git push --delete` commands for review (never run) |
| `plan-grill` | `skills/plan-grill/scripts/plan_grill.py` | ask a fixed question set about an implementation plan, then check the Markdown for required sections, placeholders, rollback, failure modes, test kinds and unanswered questions |

Requirements: Python 3.11 or newer on `PATH` as `python3`, and git for `adr-miner` and `release-notes-verifier`. No network access (except `release_notes_verify.py --gh`), no third-party packages.

Use it for technical due diligence before taking over or acquiring a codebase (`cited-codebase-audit`), to see a package's internal dependency graph of imports before a split (`restructure-planner`; it does not graph third-party packages), or to record who owns what from CODEOWNERS in an onboarding guide (`repo-onboarding-guide`). No skill measures bus factor from commit history.

Find this when you search for: stale docs, technical due diligence, import dependency graph, ADR backfill, repository hygiene, delete stale branches, merged branches cleanup, review an implementation plan, design review checklist.
