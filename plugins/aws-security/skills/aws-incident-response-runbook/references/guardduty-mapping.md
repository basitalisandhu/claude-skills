# GuardDuty finding types to runbook scenarios

`ir_runbook.py triage` checks these patterns in order; the first match wins. Patterns use shell-style wildcards on the finding `Type`.

| Pattern | Scenario | Why |
|---|---|---|
| `CryptoCurrency:*` | crypto-mining | Mining software or mining pool traffic |
| `Impact:EC2/BitcoinDomainRequest.Reputation` | crypto-mining | Lookups of mining domains |
| `Impact:Runtime/CryptoMinerExecuted` | crypto-mining | Runtime monitoring saw a miner start |
| `Impact:S3/*` | ransomware-ebs-s3 | Unusual deletes, writes or permission changes on objects |
| `Policy:S3/*` | public-s3-bucket | Public access granted or the public access block turned off |
| `Stealth:S3/ServerAccessLoggingDisabled` | public-s3-bucket | Logging removed from a bucket |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*` | compromised-ec2 | Instance role credentials used elsewhere: start from the instance |
| `Policy:IAMUser/RootCredentialUsage` | suspicious-iam-activity | Root user activity |
| `*:IAMUser/*` | leaked-access-key when the finding names an IAM user's long-term key (`AKIA...`), otherwise suspicious-iam-activity | Credential misuse |
| `Discovery:S3/*`, `Exfiltration:S3/*`, `UnauthorizedAccess:S3/*`, `PenTest:S3/*` | suspicious-iam-activity | Someone's credentials are being used against S3 |
| `*:EC2/*` | compromised-ec2 | Backdoor, trojan, command and control, scanning from or probing of an instance |
| `*:Runtime/*` | compromised-ec2 | Runtime monitoring findings; for ECS and EKS workloads, apply the steps to the task or node |

Everything else (for example Kubernetes audit log, RDS, Lambda network and malware scan findings) is reported as unmapped. Handle those with `security-hub-triage` or by hand, and consider adding a scenario with tests.

Severity follows the GuardDuty bands: 9.0 and above CRITICAL, 7.0 to 8.9 HIGH, 4.0 to 6.9 MEDIUM, below 4.0 LOW. Archived findings are skipped.
