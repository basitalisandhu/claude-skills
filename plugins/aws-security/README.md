# AWS Security

Eleven AWS security skills for Claude Code: a read-only account audit, an SCP guardrail builder and linter, a landing zone blast-radius designer, an IAM least-privilege reviewer, a Security Hub and GuardDuty triage tool, least-privilege access for AI agents with a kill switch, incident response runbooks, spend guardrails, a sandbox OU guardrail pack, an audit of what an AI agent role session did, from CloudTrail, and a mapper from failing Security Hub controls to the preventive controls that stop them coming back.

Use it when you need a quick check against the CIS AWS Foundations benchmark (many of the 17 `aws-account-audit` checks, such as root MFA, CloudTrail, old access keys and open security groups, are CIS controls; the skill does not score the benchmark), when preparing for a Well-Architected security pillar review (account separation with `landing-zone-blast-radius`, detective controls, least privilege), or when an agent role needs a permission boundary (`agent-safe-aws-access`).

## Install

```text
/plugin marketplace add basitalisandhu/aws-security-skills
/plugin install aws-security@aws-security-skills
```

Skills then appear as `/aws-security:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls. The AWS CLI is used only in the collection steps the skills describe, with read-only credentials.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `aws-account-audit` | audit, baseline or health-check one AWS account | `audit_account.py` findings (17 checks) with severity, evidence and a fix command to review |
| `scp-guardrails` | write, review or debug service control policies | `scp_builder.py` SCP documents under the 10,240-character SCP quota; `scp_lint.py` findings |
| `landing-zone-blast-radius` | design an AWS organization, place a workload | `blast_radius.py` OU tree, account names, SCP map, blast-radius table |
| `iam-least-privilege-review` | review or tighten an IAM policy, check escalation | `iam_review.py` ranked findings and a tightened policy template |
| `security-hub-triage` | Security Hub or GuardDuty backlog, weekly review | `triage_findings.py` grouped findings and an owner-assigned action list |
| `agent-safe-aws-access` | AWS access for an AI agent, agent role review, kill switch | `agent_access.py` trust, permission, boundary and SCP documents plus commands; role review findings |
| `aws-incident-response-runbook` | an AWS security incident or a GuardDuty finding that needs a response | `ir_runbook.py` Markdown runbook for one of six scenarios, picked from GuardDuty findings or by name |
| `aws-spend-guardrails` | budget alerts, anomaly detection, sandbox spend limits, cost spikes | `spend_guardrails.py` Budgets and anomaly JSON, spend-deny SCPs, cost review with anomaly flags |
| `sandbox-account-guardrail-pack` | create or tighten a sandbox OU | `sandbox_pack.py` SCPs, baseline checklist, auto-expiry design, budget files and a user README |
| `aws-agent-session-audit` | what an AI agent did in the account, unused agent permissions | `agent_session_audit.py` window, actions by service, resources, 7 checks and a remove-these-permissions proposal |
| `preventive-control-mapper` | how to stop a Security Hub finding coming back, guardrails from findings | `preventive_map.py` per failing control: SCP, account setting, declarative policy, IaC check and Config rule options, a merged SCP draft with its size, unmapped controls |

Find this when you search for: AI agent CloudTrail audit, what did Claude Code do in AWS, agent role session activity, unused permissions of an agent role, least privilege from CloudTrail, how to stop a Security Hub finding coming back, preventive controls from findings, SCP from Security Hub, EC2 declarative policy for IMDSv2.

## Exit codes

Every script uses the same three codes, and each script's `--help` states them for its own subcommands.

| Code | Meaning |
|---|---|
| 0 | Ran cleanly: no finding at or above `--fail-on`, every failing control has a preventive option, or the documents were generated and pass their own lint |
| 1 | Findings at or above `--fail-on` (review them), a failing control the mapper table does not know, or a generated document failed its own lint and nothing was written |
| 2 | Bad input or usage: a missing, empty or wrong-format file, a file that is not the expected CLI output, or a bad option |

## Output samples

Real output from the committed test fixtures, cut to the first lines. Regenerate any of them with the command shown.

`landing-zone-blast-radius`, the start of the blast-radius table:

```text
$ python3 plugins/aws-security/skills/landing-zone-blast-radius/scripts/blast_radius.py tests/fixtures/blast-radius/workloads.yaml
## Blast radius

| Account | Impact if compromised | Can reach | Why | Containment |
|---|---|---|---|---|
| acme-management | critical | every account in the organization | SCPs do not apply to the management account; it can change SCPs, create roles in member accounts through OrganizationAccountAccessRole and close accounts | Keep it empty of workloads; MFA on root; few humans; alert on every console sign-in |
| acme-log-archive | high | all organization logs | Read access to every account's audit trail; tampering is limited by SCPs and S3 Object Lock | Object Lock in compliance mode; protect_log_archive SCP; no human write access |
| acme-security-tooling | high | read-only view of every account; security findings for the organization | Can read configuration everywhere and suppress or archive findings | Read-only audit role only; findings exported to log-archive; alert on suppression rules |
```

`security-hub-triage`, the counts and the first next actions (exit 1: open findings at or above HIGH):

```text
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

| # | Severity | Owner | Action | Resources |
|---|---|---|---|---|
| 1 | CRITICAL | platform-team | Fix EC2.19 (Security groups should not allow unrestricted access to ports with high risk) on 1 resource(s) | arn:aws:ec2:us-east-1:123456789012:security-group/sg-0aaaabbbbccccdddd |
| 2 | CRITICAL | identity-team | Fix IAM.6 (Hardware MFA should be enabled for the root user) on 1 resource(s) | AWS::::Account:123456789012 |
| 3 | HIGH | data-platform-team | Fix S3.8 (S3 general purpose buckets should block public access) on 2 resource(s) | arn:aws:s3:::example-public-site, arn:aws:s3:::example-reports |
```

`scp-guardrails`, the builder on the full spec and the linter on a region deny that would break global services (exit 1):

```text
$ python3 plugins/aws-security/skills/scp-guardrails/scripts/scp_builder.py tests/fixtures/scp/full-spec.yaml
scp-01.json: 4173/10240 chars, guardrails: allowed_regions, deny_disable_security_services, deny_iam_users_outside, deny_leave_organization, deny_public_s3_acls, deny_root_user, require_imdsv2; statements: DenyLeaveOrganization, DenyRootUser, ProtectCloudTrail, ProtectGuardDuty, ProtectSecurityHub, ProtectConfig, DenyOutsideAllowedRegions, DenyIamUsersOutsideIdentityAccount, RequireImdsv2OnLaunch, DenyImdsOptionChanges, DenyImdsv1RoleCredentials, DenyPublicS3CannedAcls, ProtectAccountPublicAccessBlock
Review every document and test it on a non-production OU before attaching it.
$ python3 plugins/aws-security/skills/scp-guardrails/scripts/scp_lint.py tests/fixtures/scp/bad-region-action-star.json
tests/fixtures/scp/bad-region-action-star.json: 179/10240 chars, 2 issue(s)
  error   SCP-REGION-BLOCKS-GLOBAL DenyOtherRegions                   region deny uses Action *: global services (IAM, STS, Organizations, Route 53, CloudFront, Support) are served from us-east-1 and will be denied; use NotAction with the global service list
  info    SCP-NO-EXEMPTION         DenyOtherRegions                   region deny has no aws:PrincipalArn exemption for a break-glass role
```

`aws-agent-session-audit`, the findings table for the committed synthetic session (exit 1):

```text
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
```

`preventive-control-mapper`, selected lines of the report for the committed synthetic Security Hub export: the summary, one declarative policy option and the unmapped control (exit 1: ECR.1 is not in the table):

```text
$ python3 plugins/aws-security/skills/preventive-control-mapper/scripts/preventive_map.py --findings tests/fixtures/preventive-map/securityhub-findings.json
# Preventive control map
| Failing controls | With a preventive option | Detective only | Unmapped |
| 9 | 7 | 1 | 1 |
### EC2.8 option 1: EC2 declarative policy: require IMDSv2 for new instances [declarative-policy]
    "instance_metadata_defaults": {
      "http_tokens": {
        "@@assign": "required"
      "http_tokens_enforced": {
        "@@assign": "enabled"
Size: 1165 characters compact, within the limit of 10240 (the AWS Organizations quota for one SCP).
| ECR.1 | 1 | 111122223333 | arn:aws:ecr:ap-southeast-2:111122223333:repository/example-app |
```
