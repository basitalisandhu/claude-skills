# iteration-report

Writes a team-level sprint or iteration report from saved `gh` exports: what shipped, what carried over, what was closed as not planned, what was newly opened, which issues were moved into or out of the milestone during the window, and cycle time (median and p90) and review turnaround (median), each figure followed by the PR or issue numbers it counts. For engineering managers writing a sprint review or a stakeholder update. Team level only: there are no per-person columns.

The skill instructions Claude follows are in [SKILL.md](SKILL.md), including the export commands and the definitions of every figure.

## Quick start

```bash
# prs*.json, issues*.json and milestones.json from the commands in SKILL.md, in ./export
python3 scripts/iteration_report.py export --from 2026-09-14 --to 2026-09-25
python3 scripts/iteration_report.py export --from 2026-09-14 --to 2026-09-25 --milestone "Sprint 38" --json
```

Add `timeline-<N>.json` files for the milestone's issues to list scope added or removed during the window; without them the report says scope changes were not measured.

## Sample

Real output on the committed fixture (synthetic data, example handles), from the repository root:

<!-- sample: --lines=14 iteration-report tests/fixtures/iteration --from 2026-09-14 --to 2026-09-25 -->
```text
## Iteration report: 2026-09-14 to 2026-09-25

Window 2026-09-14T00:00:00Z to 2026-09-26T00:00:00Z (UTC, end exclusive). Source: fixture-issues.json, fixture-milestones.json, fixture-prs.json, fixture-timeline-201.json, fixture-timeline-205.json, fixture-timeline-209.json. Team level only: no per-person counts or rankings.

### Summary

- Shipped 5 PRs (#301, #302, #303, #304, #307), closing 4 issues (#201, #202, #203, #207); shipped PRs that link no issue: 1 (#307).
- Scope: milestone 'Sprint 38' (the one milestone due in the window), 7 issues (#201, #202, #203, #204, #205, #207, #208). Completed 4 (#201, #202, #203, #207), closed as not planned 1 (#208), carried over 2 (#204, #205).
- Scope changes during the window (milestoned and demilestoned events for 'Sprint 38' in the window, from 3 timeline-<N>.json files): added 2 (#205, #209), removed 1 (#209).
- Newly opened in the window: 3 issues (#207, #209, #210), of which 1 in scope (#207).
- Cycle time (first commit to merge, n=5, rows #301, #302, #303, #304, #307): median 2.0d (48.0h), p90 4.0d (96.0h). Start bases used: first commit.
- Review turnaround (PR creation to first review by someone other than the author, n=4, rows #301, #302, #303, #304): median 14.0h. Merged with no such review: 1 (#307).
- Not counted: 2 PRs merged outside the window (#306, #309) and 1 closed without merging (#308).

...
```

## Exit codes

0 report written, 2 bad input or usage (missing files, a window that ends before it starts, an unknown milestone).
