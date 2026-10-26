# Landing zone blast radius

Turns a list of workloads into an AWS Organizations design with one account per workload and environment: the OU tree, account names and root e-mails, foundation accounts, where SCP guardrails attach, and what a compromise of each account can reach.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the committed workload list, first lines, run from the repository root:

````text
$ python3 plugins/aws-security/skills/landing-zone-blast-radius/scripts/blast_radius.py tests/fixtures/blast-radius/workloads.yaml
# Landing zone design: acme

## OU tree

```text
Root
  acme-management
  Security/
    acme-log-archive
    acme-security-tooling
  Infrastructure/
    acme-shared-services
    acme-network
  Workloads/
    Prod/
      acme-marketing-site-prod
    Prod-Restricted/
      acme-payments-prod
````
