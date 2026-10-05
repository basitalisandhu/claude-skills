# AWS Security

Ten AWS security skills for Claude Code: a read-only account audit, an SCP guardrail builder and linter, a landing zone blast-radius designer, an IAM least-privilege reviewer, a Security Hub and GuardDuty triage tool, least-privilege access for AI agents with a kill switch, incident response runbooks, spend guardrails, a sandbox OU guardrail pack, and an audit of what an AI agent role session did, from CloudTrail.

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
| `scp-guardrails` | write, review or debug service control policies | `scp_builder.py` SCP documents under 5120 characters; `scp_lint.py` findings |
| `landing-zone-blast-radius` | design an AWS organization, place a workload | `blast_radius.py` OU tree, account names, SCP map, blast-radius table |
| `iam-least-privilege-review` | review or tighten an IAM policy, check escalation | `iam_review.py` ranked findings and a tightened policy template |
| `security-hub-triage` | Security Hub or GuardDuty backlog, weekly review | `triage_findings.py` grouped findings and an owner-assigned action list |
| `agent-safe-aws-access` | AWS access for an AI agent, agent role review, kill switch | `agent_access.py` trust, permission, boundary and SCP documents plus commands; role review findings |
| `aws-incident-response-runbook` | an AWS security incident or a GuardDuty finding that needs a response | `ir_runbook.py` Markdown runbook for one of six scenarios, picked from GuardDuty findings or by name |
| `aws-spend-guardrails` | budget alerts, anomaly detection, sandbox spend limits, cost spikes | `spend_guardrails.py` Budgets and anomaly JSON, spend-deny SCPs, cost review with anomaly flags |
| `sandbox-account-guardrail-pack` | create or tighten a sandbox OU | `sandbox_pack.py` SCPs, baseline checklist, auto-expiry design, budget files and a user README |
| `aws-agent-session-audit` | what an AI agent did in the account, unused agent permissions | `agent_session_audit.py` window, actions by service, resources, 7 checks and a remove-these-permissions proposal |

Find this when you search for: AI agent CloudTrail audit, what did Claude Code do in AWS, agent role session activity, unused permissions of an agent role, least privilege from CloudTrail.
