# IAM least-privilege review

Reviews IAM policy documents or a get-account-authorization-details export offline for full admin, service and action wildcards, unscoped iam:PassRole, NotAction in Allow statements and known privilege-escalation combinations, ranked by severity with a tightened policy per document.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for a CI deployer policy, the first findings (exit 1), run from the repository root:

````text
$ python3 plugins/aws-security/skills/iam-least-privilege-review/scripts/iam_review.py tests/fixtures/iam/ci-deployer.json
  1. [CRITICAL] IAM-PRIVESC ci-deployer.json (policy): Privilege-escalation path: Create a new version of a managed policy and set it as default
     evidence: iam:CreatePolicyVersion
     suggestion: Remove one action of the path, or scope it to resources that cannot lead to broader permissions (for example a permissions boundary on created roles)
  2. [CRITICAL] IAM-PRIVESC ci-deployer.json (policy): Privilege-escalation path: Create and invoke a Lambda function with a privileged role
     evidence: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
     suggestion: Remove one action of the path, or scope it to resources that cannot lead to broader permissions (for example a permissions boundary on created roles)
  3. [HIGH] IAM-ASSUMEROLE-ANY ci-deployer.json Assume: Can assume any role that trusts this account
     evidence: actions ['sts:AssumeRole'] on ['*']
     suggestion: Resource: the role ARNs this principal needs; add aws:ResourceAccount or aws:ResourceOrgID conditions
````
