# AWS agent session audit

Audits what an AI coding agent did in an AWS account from a saved CloudTrail export filtered to its role session: actions by service, writes versus reads, calls outside a declared allow list, logging tampering, destructive and IAM calls, resources touched and errors, plus the permissions it never used.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed synthetic session, first lines (exit 1), run from the repository root:

````text
$ python3 plugins/aws-security/skills/aws-agent-session-audit/scripts/agent_session_audit.py tests/fixtures/agent-session --session-name agent@operator --allow-list tests/fixtures/agent-session/allow-list.txt --regions ap-southeast-2
## Agent session audit

**Window:** 2026-10-05T09:01:00Z to 2026-10-05T09:07:00Z, 7 events matched (of 8 read).
**Sessions:** AgentRole/agent@operator. **Source IPs:** 203.0.113.10.

### Findings

| Severity | Check | Finding | Evidence |
|---|---|---|---|
| critical | AGENT-LOGGING-TAMPER | Calls that stop or weaken logging or detection | cloudtrail:StopLogging |
| high | AGENT-DESTRUCTIVE | Destructive calls that succeeded | s3:DeleteBucket |
| high | AGENT-IAM-WRITE | IAM changes or role assumption from the agent session | iam:AttachRolePolicy |
| high | AGENT-OUTSIDE-ALLOWLIST | Actions outside the declared allow list | cloudtrail:StopLogging x1, ec2:RunInstances x1 (failed), iam:AttachRolePolicy x1, s3:DeleteBucket x1 |
| low | AGENT-OTHER-REGION | Calls in regions outside the declared list | us-east-1 |
````
