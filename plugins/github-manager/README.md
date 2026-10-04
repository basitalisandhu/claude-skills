# github-manager

Three engineering manager skills that compute from exported GitHub data, each with a tested standard-library Python script. Install with `/plugin marketplace add basitalisandhu/github-manager-skills` and then `/plugin install github-manager@github-manager-skills`. Skills appear as `/github-manager:<skill>`, and Claude also invokes them on its own when a request matches a skill's description.

| Skill | Script | Use it to |
|---|---|---|
| `pr-queue-digest` | `skills/pr-queue-digest/scripts/pr_queue.py` | flag stuck PRs (waiting on review, blocked on one reviewer, changes requested with no new commits, failing checks, conflicts, approved but unmerged, no reviewer, stale drafts), count the review queue per reviewer, and list one next action per PR |
| `iteration-report` | `skills/iteration-report/scripts/iteration_report.py` | report shipped, carried-over and newly opened work for a window, with cycle time (median, p90) and review turnaround (median), every number cited to its rows |
| `incident-postmortem-timeline` | `skills/incident-postmortem-timeline/scripts/postmortem.py` | build a blameless timeline of an incident issue with detected, acknowledged, mitigated and resolved phases, people as roles, questions for the review and a cited postmortem skeleton |

Requirements: Python 3.11 or newer on `PATH` as `python3`, and the gh CLI for the export step. The scripts read saved JSON only: no network access, no third-party packages. Team level only: no per-person scoring.
