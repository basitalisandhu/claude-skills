# AWS account audit

Audits one AWS account offline from a folder of read-only AWS CLI exports: 17 checks covering root MFA and keys, CloudTrail, GuardDuty, S3 public access, open security groups, old access keys, admin policies and encryption, each with severity, evidence and a fix to review.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed insecure account fixture, first lines (exit 1: critical findings), run from the repository root:

````text
$ python3 plugins/aws-security/skills/aws-account-audit/scripts/audit_account.py tests/fixtures/account-audit/insecure --as-of 2026-10-26
AWS account audit (123456789012), as of 2026-10-26

SEVERITY  CHECK                   REGION  RESOURCE                                                     FINDING
CRITICAL  ROOT-ACCESS-KEYS        -       root                                                         Root user has access keys
CRITICAL  ROOT-MFA                -       root                                                         Root user has no MFA device
CRITICAL  SG-OPEN-ALL             -       sg-0aaaabbbbccccdddd (wide-open)                             Security group allows all traffic from the internet
HIGH      CT-MULTI-REGION         -       account                                                      No multi-region CloudTrail trail
HIGH      CT-NOT-LOGGING          -       arn:aws:cloudtrail:us-east-1:123456789012:trail/local-trail  Trail is not logging
HIGH      GD-DISABLED             -       account                                                      GuardDuty is not enabled
HIGH      IAM-ADMIN-POLICY        -       arn:aws:iam::123456789012:policy/LegacyAdmin                 managed policy grants full administrator access
HIGH      IAM-ADMIN-POLICY        -       arn:aws:iam::123456789012:user/alice inline:everything       user inline policy grants full administrator access
HIGH      IAM-CONSOLE-NO-MFA      -       arn:aws:iam::123456789012:user/alice                         IAM user can sign in to the console without MFA
HIGH      S3-ACCOUNT-PAB          -       account                                                      Account-level S3 public access block is missing or partial
HIGH      SG-OPEN-ADMIN           -       sg-0123456789abcdef0 (bastion)                               Security group allows SSH from the internet
````
