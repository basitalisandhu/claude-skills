# AWS incident response runbook

Writes a filled-in incident response runbook for one of six scenarios (leaked access key, compromised EC2 instance, public S3 bucket, suspicious IAM activity, ransomware against S3 or EBS, crypto-mining), with read-only inventory first and containment commands that each need confirmation; `triage` picks the scenario from exported GuardDuty findings.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for triage of the committed GuardDuty export: the scenario mapping before the first runbook (exit 1: a HIGH finding), run from the repository root:

````text
$ python3 plugins/aws-security/skills/aws-incident-response-runbook/scripts/ir_runbook.py triage --guardduty tests/fixtures/incident/guardduty-findings.json --as-of 2026-10-26
8 finding(s), 1 archived
  crypto-mining: HIGH CryptoCurrency:EC2/BitcoinTool.B!DNS, HIGH CryptoCurrency:EC2/BitcoinTool.B
  ransomware-ebs-s3: HIGH Impact:S3/AnomalousBehavior.Delete
  leaked-access-key: MEDIUM UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
  public-s3-bucket: MEDIUM Policy:S3/BucketAnonymousAccessGranted
  compromised-ec2: LOW Recon:EC2/PortProbeUnprotectedPort
  unmapped (no runbook): MEDIUM Execution:Kubernetes/ExecInKubeSystemPod
````
