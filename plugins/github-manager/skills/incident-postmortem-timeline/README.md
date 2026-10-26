# incident-postmortem-timeline

Builds a blameless postmortem timeline from the GitHub issue that tracked an incident: label changes, assignments, comments, linked PR merges and the close, ordered by time and each cited to its event id, comment id or PR. Detected, acknowledged, mitigated and resolved are derived by stated rules, disagreeing signals are reported, people appear as roles, and contributing factors are written as questions for the review. For incident commanders and engineering managers preparing a postmortem.

The skill instructions Claude follows are in [SKILL.md](SKILL.md), including the export commands and the phase rules.

## Quick start

```bash
gh issue view 412 --repo OWNER/REPO --json number,title,url,state,author,createdAt,closedAt,body,labels,assignees,comments > export/issue-412.json
gh api repos/OWNER/REPO/issues/412/timeline --paginate --slurp > export/timeline-412.json
python3 scripts/postmortem.py export --issue 412 --redact
python3 scripts/postmortem.py export --issue 412 --check draft.json
```

Optional `prs.json` (or `pr-<N>.json`) with the referenced PRs adds their merges as timeline rows and mitigation signals.

## Sample

Real output on the committed fixture (synthetic data, example handles), from the repository root:

<!-- sample: --lines=30 postmortem tests/fixtures/postmortem --issue 412 --redact -->
```text
# Postmortem: Checkout API returning 502 errors (#412)

Status: draft for the review. Blameless: this document describes what happened and what the systems and processes allowed, not who is at fault. Every timeline row cites the exported event, comment or PR it comes from. Source: fixture-issue-412.json, fixture-prs.json, fixture-timeline-412.json.

## Summary

_To be written at the review, from the timeline below._

## Impact

_To be written from monitoring or support data. This export holds no impact figures, so none are given._

## Phases

| Phase | Time (UTC) | Since detection | Signal | Citation |
|---|---|---|---|---|
| detected | 2026-09-20T08:05:00Z | 0m | Issue opened: Checkout API returning 502 errors | [issue #412 createdAt](https://github.com/example-org/shop/issues/412) |
| acknowledged | 2026-09-20T08:10:00Z | 5m | Assigned to responder-1 | event 9003 |
| mitigated | 2026-09-20T09:02:00Z | 57m | PR #415 merged: Revert connection pool size change | [PR #415 mergedAt, merge commit 415b000](https://github.com/example-org/shop/pull/415) |
| resolved | 2026-09-20T10:55:00Z | 2h50m | Label added: resolved | event 9012 |

Signals that disagree:

- acknowledged: 'Assigned to responder-1' (event 9003, 2026-09-20T08:10:00Z) came 2m before 'Comment: Looking into it. The checkout-api error rate has been elevated since about 07:50.' (comment 5001, 2026-09-20T08:12:00Z); the timeline uses the earlier signal
- mitigated: 'PR #415 merged: Revert connection pool size change' (PR #415 mergedAt, merge commit 415b000, 2026-09-20T09:02:00Z) came 43m before 'Label added: mitigated' (event 9010, 2026-09-20T09:45:00Z); the timeline uses the earlier signal
- resolved: 'Label added: resolved' (event 9012, 2026-09-20T10:55:00Z) came 6m before 'Issue closed (completed)' (event 9015, 2026-09-20T11:01:00Z); the timeline uses the earlier signal

## Timeline

| Time (UTC) | Since detection | What | Who | Citation |
...
```

## Exit codes

0 written with no draft problems, 1 `--check` found draft times that match no exported row, 2 bad input or usage.
