# pr-queue-digest

Finds the open pull requests that are stuck and says why: waiting on review, blocked on one reviewer with a long queue, changes requested with no new commits, commits with no re-request, failing checks, conflicts, approved but not merged, no reviewer, or a stale draft. Each PR gets one next action, and the review queue is a count per reviewer (for rebalancing, not a ranking). For tech leads and engineering managers who run a standup or a weekly PR sweep.

The skill instructions Claude follows are in [SKILL.md](SKILL.md), including the `gh` export commands and the minimal token scopes.

## Quick start

```bash
gh pr list --repo OWNER/REPO --state open --limit 500 --json number,title,url,author,isDraft,createdAt,updatedAt,reviewDecision,reviewRequests,reviews,commits,statusCheckRollup,mergeable,mergeStateStatus > export/prs.json
python3 scripts/pr_queue.py export --hours 24
python3 scripts/pr_queue.py export --markdown --redact
```

Optional `timeline-<N>.json` files (one `gh api repos/OWNER/REPO/issues/N/timeline --paginate --slurp` per PR) make waits start at the review request instead of PR creation; `meta.json` fixes the "as of" time.

## Sample

Real output on the committed fixture (synthetic data, example handles), from the repository root:

<!-- sample: --lines=24 pr-queue tests/fixtures/pr_queue -->
```text
PR queue digest for example-org/shop, as of 2026-09-30T12:00:00Z (fixture-meta.json exported_at)
19 open PRs (2 drafts, 1 by bot accounts); 9 flagged; threshold 24h, stale drafts after 14d

blocked-on-reviewer (1)
  #101  only reviewer octocat-r has 9 other pending requests; waiting 5.1d (122.0h) since review requested (timeline)
waiting-on-review (2)
  #101  waiting 5.1d (122.0h) on octocat-r since review requested (timeline)
  #118  waiting 30.0h on octocat-b, octocat-e since review requested (timeline)
no-reviewer (1)
  #116  open 3.1d (75.0h), no review requested and no review
changes-requested-no-new-commits (1)
  #111  octocat-b requested changes at 2026-09-22T15:00:00Z; no commit in the 7.9d (189.0h) since
re-request-needed (1)
  #112  1 commit(s) after octocat-b's changes request at 2026-09-26T10:00:00Z; octocat-b not re-requested
failing-checks (1)
  #102  failing: test (failure)
needs-rebase (1)
  #103  merge conflicts (mergeable=CONFLICTING, mergeStateStatus=DIRTY)
approved-not-merged (1)
  #115  approved at 2026-09-28T09:00:00Z (2.1d (51.0h) ago)
stale-draft (1)
  #113  draft, last updated 2026-08-20T09:00:00Z (41.1d (987.0h) ago)

Review queue (pending requests per reviewer, sorted by name, not a ranking)
...
```

## Exit codes

0 nothing flagged, 1 at least one PR flagged, 2 bad input or usage (the message names the file and row).
