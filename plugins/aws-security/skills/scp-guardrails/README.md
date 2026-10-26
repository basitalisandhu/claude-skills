# SCP guardrails

Builds AWS Organizations service control policies from a short spec (region allowlist, break-glass roles, protected logging, no root user, IMDSv2, no public S3 ACLs) under the SCP size limit, and lints any SCP for Allow statements, region denies that break global services, NotAction misuse and size.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the linter on a region deny that misses global services (exit 0: warnings only), run from the repository root:

````text
$ python3 plugins/aws-security/skills/scp-guardrails/scripts/scp_lint.py tests/fixtures/scp/bad-region-gaps.json
tests/fixtures/scp/bad-region-gaps.json: 196/10240 chars, 2 issue(s)
  warning SCP-REGION-GLOBAL-GAPS   DenyOtherRegions                   region deny NotAction list misses organizations:*, support:*, route53:*, cloudfront:*, budgets:*, health:*
  info    SCP-NO-EXEMPTION         DenyOtherRegions                   region deny has no aws:PrincipalArn exemption for a break-glass role
````
