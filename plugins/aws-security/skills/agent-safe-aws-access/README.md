# Agent-safe AWS access

Plans least-privilege AWS access for an AI coding agent from a short spec (trust policy, task-scoped permissions, a permissions boundary, an SCP backstop, the assume-role command and a kill switch), or reviews an existing agent role in an authorization-details export against the same rules.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for a review of the over-privileged agent role in the committed export, first lines (exit 1), run from the repository root:

````text
$ python3 plugins/aws-security/skills/agent-safe-aws-access/scripts/agent_access.py review --role-json tests/fixtures/agent-access/auth-details.json --role-name agent-claude-code
role agent-claude-code (arn:aws:iam::123456789012:role/agent-claude-code): 17 finding(s)
  evaluated: inline/deploy, managed/agent-extra; boundary: none; max session: unknown
  critical AGENT-ADMIN                    PowerUserAccess                          AWS managed policy PowerUserAccess is attached
  critical AGENT-EFFECTIVE-RISK           billing                                  billing: the role's policies allow aws-portal:ModifyAccount, aws-portal:ModifyBilling, aws-portal:ModifyPaymentMethods, budgets:ModifyBudget and no boundary blocks it
  critical AGENT-EFFECTIVE-RISK           destructive                              destructive: the role's policies allow cloudformation:DeleteStack, dynamodb:DeleteTable, ec2:TerminateInstances, rds:DeleteDBCluster and no boundary blocks it
  critical AGENT-EFFECTIVE-RISK           iam-changes                              iam-changes: the role's policies allow iam:AttachRolePolicy and no boundary blocks it
  critical AGENT-EFFECTIVE-RISK           logging-tampering                        logging-tampering: the role's policies allow cloudtrail:DeleteTrail, cloudtrail:StopLogging, guardduty:CreateIPSet, guardduty:DeleteDetector and no boundary blocks it
  high     AGENT-NO-BOUNDARY              role                                     no permissions boundary: nothing caps what a later policy change grants the agent
````
