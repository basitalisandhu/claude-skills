# SOC 2 Trust Services Criteria identifiers used in this pack

This file lists criteria identifiers with a short topic written in this repository's own words. It does not
reproduce the criteria text or the points of focus, which are published by the AICPA. Read the criteria in the
AICPA's own publication before relying on any mapping.

Only a licensed CPA firm issues a SOC 2 report. These skills prepare evidence for that firm; they do not test
operating effectiveness over a period, and they do not form an opinion.

| Identifier | Topic (paraphrase, not the AICPA's text) | Exports in these skills that can contribute |
|---|---|---|
| CC1.4 | People with security duties are hired, trained and kept competent | none (HR and training records) |
| CC6.1 | Logical access is controlled with identities, strong sign-in and access rules | AWS root and user MFA, password policy, S3 public access block; Microsoft 365 MFA and legacy authentication; GitHub secret scanning |
| CC6.2 | Accounts are created and removed through an approved process | none (joiner and leaver records) |
| CC6.3 | Access follows roles and least privilege and is reviewed | none (access review records) |
| CC6.6 | Connections from outside the system boundary are restricted | AWS account S3 public access block |
| CC6.8 | Unauthorised or harmful software is prevented or detected | Intune compliance policies |
| CC7.1 | Weaknesses and risky configuration changes are detected | Dependabot alerts and updates; AWS Config recorders |
| CC7.2 | Systems are monitored for signs of attack or failure | CloudTrail, GuardDuty |
| CC8.1 | Changes are approved, tested and recorded before they go live | GitHub branch protection, reviews, status checks, merged pull request reviews, CODEOWNERS, signed commits |
| A1.2 | Backup and recovery capability supports availability commitments | AWS Backup plans |

## Paraphrase rule

- Use the identifier to name a criterion. Write the topic in your own words, in at most 20 words (control_map.py
  rejects longer topics).
- Never paste criteria text or points of focus into a map, a narrative or an issue in this repository.
- A mapping is a judgement. Agree it with your service auditor; the starter map is a place to begin.

## Forbidden phrases

narrative_lint.py refuses any line of more than 25 words that contains a phrase listed here. The list ships empty on
purpose, because this repository does not reproduce criteria text. If you hold a licensed copy, you may add
distinctive phrases from it in a local copy of this file (never in a public fork). Pass the file to the linter with
`--phrases`.

Format: one phrase per line, each line starting with `phrase:` followed by the text.

<!-- Add phrase: lines below this comment in your local copy. -->
