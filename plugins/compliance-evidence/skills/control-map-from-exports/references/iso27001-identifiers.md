# ISO/IEC 27001:2022 Annex A identifiers used in this pack

This file lists control identifiers with a short topic written in this repository's own words. It does not reproduce
the standard's control text, which is copyrighted by ISO and IEC. Read the control itself in your licensed copy of
ISO/IEC 27001:2022 (and the guidance in ISO/IEC 27002:2022) before relying on any mapping.

The paraphrases are deliberately short and loose. They say what kind of evidence an export can contribute, not what
the control requires. A row marked "none" means no export handled by these skills speaks to the control; it needs
documents, records, interviews or sampling, and control_map.py reports it as not assessable.

| Identifier | Topic (paraphrase, not the standard's text) | Exports in these skills that can contribute |
|---|---|---|
| A.5.1 | Security policies exist, are approved and reach the people they apply to | none |
| A.5.15 | Access to systems and data follows defined rules | AWS account S3 public access block |
| A.5.17 | Passwords, keys and other secrets are handled and rotated with care | AWS password policy, access key age; GitHub secret scanning |
| A.5.18 | Access is granted, reviewed and removed on purpose | none (access review records) |
| A.6.3 | People receive security awareness training | none (training records) |
| A.8.1 | Company data on laptops and phones is protected through device management | Intune compliance policies |
| A.8.2 | Administrative access is kept to few people and watched | AWS root access keys and MFA; GitHub admins under branch protection |
| A.8.5 | Sign-in uses strong methods such as multi-factor authentication | AWS root and console user MFA; Microsoft 365 security defaults or Conditional Access |
| A.8.8 | Known software weaknesses are found and fixed in time | Dependabot alerts, security updates and open alert age |
| A.8.9 | System settings are recorded and drift is noticed | AWS Config recorders |
| A.8.12 | Leaks of sensitive data, including credentials, are prevented or caught | GitHub secret scanning and push protection |
| A.8.13 | Copies of data and systems exist and restoring them is tried | AWS Backup plans (restore tests are not visible in exports) |
| A.8.15 | Systems keep a tamper-resistant record of who did what | CloudTrail coverage, logging status, log file validation |
| A.8.16 | Systems are watched for unusual or hostile activity | GuardDuty detectors |
| A.8.25 | Security is part of how software is built | GitHub required status checks |
| A.8.29 | Automated tests run before changes are accepted | GitHub required status checks |
| A.8.32 | Changes go through a reviewed, recorded process | GitHub branch protection, required reviews, merged pull request reviews, CODEOWNERS, signed commits |

## Paraphrase rule

- Use the identifier to name a control. Write the topic in your own words, in at most 20 words (control_map.py
  rejects longer topics).
- Never paste control text, the standard's titles or its guidance into a map, a narrative or an issue in this
  repository.
- A mapping is a judgement. Agree it with your assessor; the starter map is a place to begin.

## Forbidden phrases

narrative_lint.py refuses any line of more than 25 words that contains a phrase listed here. The list ships empty on
purpose, because this repository does not reproduce control text. If your organisation holds a licensed copy, you may
add distinctive phrases from it in a local copy of this file (never in a public fork), so that pasted framework text
is caught before a narrative leaves your hands. Pass the file to the linter with `--phrases`.

Format: one phrase per line, each line starting with `phrase:` followed by the text.

<!-- Add phrase: lines below this comment in your local copy. -->
