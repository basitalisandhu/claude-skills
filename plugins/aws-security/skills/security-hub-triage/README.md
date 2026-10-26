# Security Hub triage

Turns a Security Hub (ASFF) or GuardDuty findings export into an owner-assigned action list offline: drops resolved and suppressed findings, groups the rest by severity, control and resource, assigns owners from rules and orders the actions.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed Security Hub and GuardDuty exports with the example owner rules, first lines, run from the repository root:

````text
$ python3 plugins/aws-security/skills/security-hub-triage/scripts/triage_findings.py tests/fixtures/findings/securityhub-findings.json tests/fixtures/findings/guardduty-findings.json --config tests/fixtures/findings/triage-config.yaml
# Findings triage

15 records: 8 open, 4 not open (archived, resolved, suppressed in the console or passed), 3 suppressed by config.

| Severity | Open |
|---|---|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 1 |
| LOW | 2 |
| INFORMATIONAL | 0 |

## Next actions
````
