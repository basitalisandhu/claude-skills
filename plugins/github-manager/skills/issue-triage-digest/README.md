# issue-triage-digest

Prepares open-issue triage from a saved `gh issue list` export: unlabelled issues, issues nobody but the author has answered for N days, probable duplicates by title word overlap, stale issues, and issues with many thumbs-up, with a suggested label per issue from the team's own keyword map. For maintainers and leads who run a triage meeting or a weekly backlog sweep.

The skill instructions Claude follows are in [SKILL.md](SKILL.md), including the export command and the keyword map format.

## Quick start

```bash
gh issue list --repo OWNER/REPO --state open --limit 1000 --json number,title,url,author,labels,assignees,createdAt,updatedAt,comments,reactionGroups > export/issues.json
python3 scripts/issue_triage.py export --keywords labels.yaml
python3 scripts/issue_triage.py export --markdown --out triage/
```

## Sample

Real output on the committed fixture (synthetic data, example handles), from the repository root:

<!-- sample: issue-triage tests/fixtures/issue_triage --keywords tests/fixtures/issue_triage/fixture-labels-keywords.json -->
```text
issue triage: example-org/app as of 2026-10-05T09:00:00Z (fixture-meta.json exported_at)
6 open issues, 4 flagged
  unlabelled: 2 (#201, #205)
  unanswered: 2 (#201, #205)
  possible-duplicate: 1 (#204)
  stale: 1 (#203)
  popular: 1 (#201)
#201 App crashes when saving large file: no label; no reply from anyone but the author in 34.0d (threshold 7.0d); 7 thumbs-up; suggest: bug
#203 Docs typo in install guide: no update for 126.0d (threshold 60.0d)
#204 Crashes when saving a large file: title 80% similar to #201
#205 Login button does nothing on Safari: no label; no reply from anyone but the author in 10.0d (threshold 7.0d); suggest: bug
```

## Exit codes

0 nothing flagged, 1 at least one issue flagged, 2 bad input or usage (the message names the file and row).
