# Preventive control mapper

Turns failing Security Hub controls, Prowler checks or a CSV of control ids into the preventive controls that stop the same misconfiguration coming back: an SCP statement, an account or declarative-policy setting, an IaC check, and the AWS Config rule that detects a regression, with a merged SCP draft and its size.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed Security Hub export, first lines (exit 1: one control is not in the table), run from the repository root:

````text
$ python3 plugins/aws-security/skills/preventive-control-mapper/scripts/preventive_map.py --findings tests/fixtures/preventive-map/securityhub-findings.json
# Preventive control map

Read 1 file(s). 12 failing finding(s) across 9 control(s) were kept; skipped: 1 not failed, 2 suppressed or resolved, 1 not active, 1 without a control id.

| Failing controls | With a preventive option | Detective only | Unmapped |
|---|---|---|---|
| 9 | 7 | 1 | 1 |

## S3.8: S3 general purpose buckets should block public access (bucket level)

- Failing findings: 3; accounts: `111122223333`, `444455556666`; regions: `ap-southeast-2`, `us-east-1`
- Sample resources: `arn:aws:s3:::example-public-site`, `arn:aws:s3:::example-reports`, `arn:aws:s3:::example-logs`
````
