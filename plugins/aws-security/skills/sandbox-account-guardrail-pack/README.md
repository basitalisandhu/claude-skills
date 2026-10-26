# Sandbox account guardrail pack

Generates a guardrail pack for a sandbox OU where engineers and AI agents experiment: linted SCPs (region allowlist, IMDSv2, no root, protected logging, spend denies), AWS Budgets, a checklist for new sandbox accounts and a tag-based auto-expiry design. It writes files for review and never deploys or runs a cleanup.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed sandbox spec, run from the repository root:

````text
$ python3 plugins/aws-security/skills/sandbox-account-guardrail-pack/scripts/sandbox_pack.py --spec tests/fixtures/sandbox/sandbox.yaml
scp-01.json: 7416/10240 chars; DenyLeaveOrganization, DenyRootUser, ProtectCloudTrail, ProtectGuardDuty, ProtectSecurityHub, ProtectConfig, DenyOutsideAllowedRegions, RequireImdsv2OnLaunch, DenyImdsOptionChanges, DenyImdsv1RoleCredentials, DenyPublicS3CannedAcls, ProtectAccountPublicAccessBlock, DenyIamUserCreation, RequireOwnerTagOnLaunch, DenyExpensiveInstanceTypes, DenyHighIopsVolumes, DenyProvisionedIopsVolumeTypes, DenySageMakerGpuInstanceTypes, DenyBedrockCustomizationAndThroughput, DenyExpensiveServices, DenyPurchaseCommitments, ProtectBudgetsAndAnomalyMonitors
13 file(s)
Nothing is deployed. Review every file, and test the SCPs on an OU with one account first.
````
