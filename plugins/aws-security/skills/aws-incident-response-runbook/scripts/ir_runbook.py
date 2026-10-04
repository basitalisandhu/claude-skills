#!/usr/bin/env python3
"""Emit an AWS incident response runbook (Markdown) for one scenario, or pick the scenario from GuardDuty findings.

  ir_runbook.py --scenario NAME [--account ID] [--region REGION] [--access-key-id ID] [--user-name NAME]
                [--role-name NAME] [--instance-id ID] [--bucket NAME] [--start-time ISO] [--case-id ID] [--out FILE] [--json]
  ir_runbook.py --list
  ir_runbook.py triage --guardduty findings.json [--all] [--out DIR] [--json] [--fail-on SEVERITY]

Scenarios:
  leaked-access-key        an IAM user access key exposed (repository, log, laptop) or used from an unknown address
  compromised-ec2          an instance runs attacker code, talks to bad hosts, or its role credentials were used elsewhere
  public-s3-bucket         a bucket or its objects were readable by anyone
  suspicious-iam-activity  unexpected IAM users, keys, policy attachments, trust changes or console logins
  ransomware-ebs-s3        mass deletion or re-encryption of S3 objects or EBS snapshots, key deletion, ransom notes
  crypto-mining            unexpected compute (often GPU or in unused regions) and a cost spike

Every runbook has the same sections: scope and roles, containment (read-only inventory commands first, then the
containment commands, each marked REQUIRES CONFIRMATION), evidence preservation (snapshots, CloudTrail lookup-events
and an Athena query), eradication, recovery, a post-incident checklist, a timeline template and a communications
template. Identifiers you do not pass appear as <placeholders>.

triage reads `aws guardduty get-findings --output json` and maps each finding type to a scenario (types it cannot
map are listed as unmapped). It writes the runbook for the scenario with the highest severity finding, or one per
scenario with --all, filling in the account, region, instance id, access key id, user name and bucket from the
findings. Values from findings are used only when they match the identifier format; anything else stays a
placeholder, because finding content is untrusted.

Exit codes: runbook 0, 2 bad arguments. triage 0 no mapped finding at or above --fail-on (default HIGH), 1 mapped
findings at or above it, 2 bad input. The script never calls AWS and never runs the commands it prints.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import re
import sys
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

VALIDATORS = {
    "account": re.compile(r"^\d{12}$"),
    "region": re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$"),
    "access_key_id": re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$"),
    "user_name": re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$"),
    "role_name": re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$"),
    "instance_id": re.compile(r"^i-[0-9a-f]{8,17}$"),
    "bucket": re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"),
    "start_time": re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$"),
    "case_id": re.compile(r"^[A-Za-z0-9._-]{1,40}$"),
}
PLACEHOLDERS = {"account": "<account-id>", "region": "<region>", "access_key_id": "<access-key-id>",
                "user_name": "<user-name>", "role_name": "<role-name>", "instance_id": "<instance-id>",
                "bucket": "<bucket-name>", "start_time": "<start-time, e.g. 2026-10-01T00:00:00Z>", "case_id": "<case-id>"}

# GuardDuty finding type patterns (fnmatch, first match wins) to scenario.
TYPE_MAP: list[tuple[str, str]] = [
    ("CryptoCurrency:*", "crypto-mining"),
    ("Impact:EC2/BitcoinDomainRequest.Reputation", "crypto-mining"),
    ("Impact:Runtime/CryptoMinerExecuted", "crypto-mining"),
    ("Impact:S3/*", "ransomware-ebs-s3"),
    ("Policy:S3/*", "public-s3-bucket"),
    ("Stealth:S3/ServerAccessLoggingDisabled", "public-s3-bucket"),
    ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*", "compromised-ec2"),
    ("Policy:IAMUser/RootCredentialUsage", "suspicious-iam-activity"),
    ("*:IAMUser/*", "iam-principal"),
    ("Discovery:S3/*", "suspicious-iam-activity"),
    ("Exfiltration:S3/*", "suspicious-iam-activity"),
    ("UnauthorizedAccess:S3/*", "suspicious-iam-activity"),
    ("PenTest:S3/*", "suspicious-iam-activity"),
    ("*:EC2/*", "compromised-ec2"),
    ("*:Runtime/*", "compromised-ec2"),
]

COMMON_CHECKLIST = [
    "Root cause written down: how access was gained, and which control would have stopped it.",
    "Every credential the actor could have read is rotated (access keys, database passwords, API tokens, secrets in "
    "Secrets Manager or Parameter Store that the compromised principal could read).",
    "Persistence removed: IAM users, access keys, roles, trust policy changes, Lambda functions, EventBridge rules, "
    "instances and snapshots created by the actor, found from CloudTrail.",
    "Detection gap closed: GuardDuty, CloudTrail (all regions, log file validation) and Security Hub on in every region.",
    "Guardrails added where they would have helped (service control policies, permissions boundaries, budgets).",
    "Evidence archived with hashes and a retention date agreed with legal.",
    "Notification duties checked with legal and privacy (customers, regulators, AWS Support case if AWS contacted you).",
    "Lessons learned review held within two weeks; actions have owners and dates.",
]


def scenario_text(s: str, v: dict) -> dict:
    """Scenario content. v holds identifiers (real values or placeholders)."""
    acct, region, start = v["account"], v["region"], v["start_time"]
    key, user, role, inst, bucket = v["access_key_id"], v["user_name"], v["role_name"], v["instance_id"], v["bucket"]
    revoke_role = (f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions --policy-document "
                   "\"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Deny\\\",\\\"Action\\\":\\\"*\\\","
                   "\\\"Resource\\\":\\\"*\\\",\\\"Condition\\\":{\\\"DateLessThan\\\":{\\\"aws:TokenIssueTime\\\":\\\"$(date -u "
                   "+%Y-%m-%dT%H:%M:%SZ)\\\"}}}]}\"")
    revoke_user = (f"aws iam put-user-policy --user-name {user} --policy-name IRRevokeOlderSessions --policy-document "
                   "\"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Deny\\\",\\\"Action\\\":\\\"*\\\","
                   "\\\"Resource\\\":\\\"*\\\",\\\"Condition\\\":{\\\"DateLessThan\\\":{\\\"aws:TokenIssueTime\\\":\\\"$(date -u "
                   "+%Y-%m-%dT%H:%M:%SZ)\\\"}}}]}\"")
    data = {
        "leaked-access-key": {
            "title": "Leaked IAM access key",
            "signs": "A key id or secret appears in a repository, ticket, log or chat; GuardDuty reports API calls from an "
                     "unusual address with this key; AWS Support or a third party notified you.",
            "inventory": [
                ("Confirm which account owns the key", f"aws sts get-access-key-info --access-key-id {key} --output json"),
                ("Who you are (run as the incident response role)", "aws sts get-caller-identity --output json"),
                ("Last use of the key", f"aws iam get-access-key-last-used --access-key-id {key} --output json"),
                ("All keys of the user", f"aws iam list-access-keys --user-name {user} --output json"),
                ("What the user can do", f"aws iam list-attached-user-policies --user-name {user} --output json"),
                ("Inline policies", f"aws iam list-user-policies --user-name {user} --output json"),
                ("Groups", f"aws iam list-groups-for-user --user-name {user} --output json"),
            ],
            "containment": [
                ("Deactivate the key (reversible; do not delete it yet, the id is evidence)",
                 f"aws iam update-access-key --user-name {user} --access-key-id {key} --status Inactive", False),
                ("Revoke temporary credentials the key already created with GetSessionToken or GetFederationToken",
                 revoke_user, False),
                ("If the console password may also be exposed, remove it (the user cannot sign in until a new one is set)",
                 f"aws iam delete-login-profile --user-name {user}", True),
            ],
            "cloudtrail": [
                ("Every call made with the key, per region it was used in",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=AccessKeyId,AttributeValue={key} "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-key-{region}.json"),
            ],
            "athena": (f"SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, useragent, errorcode\n"
                       f"FROM cloudtrail_logs\nWHERE useridentity.accesskeyid = '{key}'\n  AND eventtime >= '{start}'\n"
                       "ORDER BY eventtime;\n\n-- Credentials and principals the key created (persistence):\n"
                       "SELECT eventtime, eventname, requestparameters, responseelements\nFROM cloudtrail_logs\n"
                       f"WHERE useridentity.accesskeyid = '{key}'\n  AND eventname IN ('CreateUser', 'CreateAccessKey', "
                       "'CreateLoginProfile', 'GetSessionToken', 'GetFederationToken', 'AssumeRole', 'CreateRole',\n"
                       "                    'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy', "
                       "'UpdateAssumeRolePolicy', 'RunInstances', 'CreateFunction');"),
            "snapshots": [],
            "eradication": [
                "Delete everything the actor created (from the persistence query): users, keys, roles, policies, functions, instances.",
                f"After evidence is archived, delete the key: `aws iam delete-access-key --user-name {user} --access-key-id {key}` "
                "(REQUIRES CONFIRMATION).",
                "Remove the secret from where it leaked; for a git repository, rewrite history and treat the key as public anyway.",
                "Rotate every secret the user could read.",
            ],
            "recovery": [
                "Replace long-lived keys with roles: IAM Identity Center for people, OIDC federation for CI, instance or task roles for workloads.",
                "If a key must stay, issue a new one, store it in a secrets manager, and set an alarm on its use from new addresses.",
                "Check the bill for unexpected usage in every region (see the crypto-mining runbook if compute appeared).",
            ],
        },
        "compromised-ec2": {
            "title": "Compromised EC2 instance",
            "signs": "GuardDuty EC2 or Runtime findings (backdoor, trojan, command and control, port scanning from the instance), "
                     "credential exfiltration findings for the instance role, unexpected processes or outbound traffic.",
            "inventory": [
                ("Instance details, network and tags", f"aws ec2 describe-instances --region {region} --instance-ids {inst} --output json"),
                ("Role attached to the instance", f"aws ec2 describe-iam-instance-profile-associations --region {region} "
                                                  f"--filters Name=instance-id,Values={inst} --output json"),
                ("Volumes to snapshot", f"aws ec2 describe-volumes --region {region} "
                                         f"--filters Name=attachment.instance-id,Values={inst} --output json"),
                ("Security groups (from the describe-instances output)",
                 f"aws ec2 describe-security-groups --region {region} --group-ids <sg-id> --output json"),
                ("Console output (may show attacker activity at boot)",
                 f"aws ec2 get-console-output --region {region} --instance-id {inst} --output json"),
                ("Auto Scaling membership", f"aws autoscaling describe-auto-scaling-instances --region {region} --instance-ids {inst} --output json"),
            ],
            "containment": [
                ("Protect the instance from termination so evidence survives",
                 f"aws ec2 modify-instance-attribute --region {region} --instance-id {inst} --disable-api-termination", False),
                ("Detach it from its Auto Scaling group (keeps it running, the group launches a replacement)",
                 f"aws autoscaling detach-instances --region {region} --instance-ids {inst} --auto-scaling-group-name <asg-name> "
                 "--no-should-decrement-desired-capacity", False),
                ("Create an isolation security group with no inbound rules",
                 f"aws ec2 create-security-group --region {region} --group-name ir-isolation-{inst} --description \"IR isolation\" "
                 "--vpc-id <vpc-id> --output json", False),
                ("Remove its default outbound rule",
                 f"aws ec2 revoke-security-group-egress --region {region} --group-id <isolation-sg-id> "
                 "--ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'", False),
                ("Move the instance into it. Tracked connections can survive a security group change; add a network ACL "
                 "deny on the subnet if traffic continues",
                 f"aws ec2 modify-instance-attribute --region {region} --instance-id {inst} --groups <isolation-sg-id>", False),
                ("Revoke the role credentials the instance already handed out (they stay valid until expiry otherwise)",
                 revoke_role, False),
                ("Detach the instance profile (association id from the inventory step)",
                 f"aws ec2 disassociate-iam-instance-profile --region {region} --association-id <association-id>", False),
            ],
            "cloudtrail": [
                ("Calls made with the instance role, from inside or outside AWS",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=ResourceName,AttributeValue={inst} "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-instance-{region}.json"),
            ],
            "athena": ("SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, useragent, errorcode\n"
                       "FROM cloudtrail_logs\n"
                       f"WHERE useridentity.arn LIKE '%:assumed-role/{role}/{inst}'\n  AND eventtime >= '{start}'\n"
                       "ORDER BY eventtime;\n-- Rows whose sourceipaddress is not the instance's address point to stolen credentials."),
            "snapshots": [
                f"aws ec2 create-snapshot --region {region} --volume-id <volume-id> --description \"IR {v['case_id']} {inst}\" "
                f"--tag-specifications 'ResourceType=snapshot,Tags=[{{Key=ir-case,Value={v['case_id']}}}]' --output json",
            ],
            "eradication": [
                "Do not clean the instance in place. Replace it from a known-good image and current patches.",
                "Find how it was reached (open security group, vulnerable application, leaked key pair) and close that path.",
                "Remove anything the role credentials created elsewhere (from the CloudTrail query).",
                "If memory evidence matters, capture it with your forensics tooling before stopping the instance; stopping loses it.",
            ],
            "recovery": [
                "Bring the replacement into service behind the load balancer and watch GuardDuty for repeat findings.",
                "Keep the isolated instance stopped (not terminated) until the evidence retention decision is made.",
                "Require IMDSv2 and narrow the instance role to what the workload needs.",
            ],
        },
        "public-s3-bucket": {
            "title": "Public S3 bucket exposure",
            "signs": "Access Analyzer, Security Hub or GuardDuty reports a public bucket; the account or bucket public access "
                     "block was turned off; a researcher reported readable data.",
            "inventory": [
                ("Bucket public access block", f"aws s3api get-public-access-block --bucket {bucket} --output json"),
                ("Account public access block", f"aws s3control get-public-access-block --account-id {acct} --output json"),
                ("Is the policy public", f"aws s3api get-bucket-policy-status --bucket {bucket} --output json"),
                ("Save the current policy before changing anything",
                 f"aws s3api get-bucket-policy --bucket {bucket} --output json > evidence/bucket-policy.json"),
                ("Save the ACL", f"aws s3api get-bucket-acl --bucket {bucket} --output json > evidence/bucket-acl.json"),
                ("Server access logging (a source of who-read-what)", f"aws s3api get-bucket-logging --bucket {bucket} --output json"),
                ("Versioning", f"aws s3api get-bucket-versioning --bucket {bucket} --output json"),
            ],
            "containment": [
                ("Block public access on the bucket (overrides public policies and ACLs; check that no intended public "
                 "site depends on it)",
                 f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "
                 "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", False),
                ("If no bucket in the account should be public, block it account-wide",
                 f"aws s3control put-public-access-block --account-id {acct} --public-access-block-configuration "
                 "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", False),
            ],
            "cloudtrail": [
                ("Who changed the bucket's policy, ACL or public access block",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=ResourceName,AttributeValue={bucket} "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-bucket.json"),
            ],
            "athena": ("-- Reads need S3 data events in CloudTrail (or server access logs); without them, who read the data "
                       "cannot be known.\n"
                       "SELECT useridentity.type, useridentity.accountid, sourceipaddress, eventname, count(*) AS calls\n"
                       "FROM cloudtrail_logs\nWHERE eventsource = 's3.amazonaws.com'\n"
                       f"  AND json_extract_scalar(requestparameters, '$.bucketName') = '{bucket}'\n"
                       f"  AND eventtime >= '{start}'\nGROUP BY 1, 2, 3, 4\nORDER BY calls DESC;"),
            "snapshots": [],
            "eradication": [
                "Restore the intended bucket policy without the public statement, from the saved copy.",
                "Find and fix the change path that made it public (pipeline, template, manual change) from the CloudTrail result.",
                "Classify what was exposed and for how long; this decides notification duties.",
            ],
            "recovery": [
                "Keep the account-level public access block on; serve public content through CloudFront with origin access control.",
                "Add a preventive control: an SCP that protects the account public access block (see scp-guardrails).",
            ],
        },
        "suspicious-iam-activity": {
            "title": "Suspicious IAM activity",
            "signs": "Unexpected users, access keys, login profiles, policy attachments or trust policy changes; console logins "
                     "from new places; GuardDuty IAMUser findings; root user activity.",
            "inventory": [
                ("Snapshot of all IAM (users, roles, groups, policies) for comparison",
                 "aws iam get-account-authorization-details --output json > evidence/iam-authorization-details.json"),
                ("Credential report: build it, then read it (building changes no configuration)",
                 "aws iam generate-credential-report --output json"),
                ("", "aws iam get-credential-report --output json > evidence/credential-report.json"),
                ("The principal's keys", f"aws iam list-access-keys --user-name {user} --output json"),
                ("The role's trust policy and last use", f"aws iam get-role --role-name {role} --output json"),
            ],
            "containment": [
                ("Block the user from doing anything (AWS managed deny-all policy; reversible)",
                 f"aws iam attach-user-policy --user-name {user} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll", False),
                ("Deactivate the user's keys", f"aws iam update-access-key --user-name {user} --access-key-id {key} --status Inactive", False),
                ("Revoke the role's existing sessions", revoke_role, False),
                ("Block the role from doing anything", f"aws iam attach-role-policy --role-name {role} "
                                                       "--policy-arn arn:aws:iam::aws:policy/AWSDenyAll", False),
                ("If a trust policy was widened, restore the previous version from the snapshot or source control",
                 f"aws iam update-assume-role-policy --role-name {role} --policy-document file://previous-trust.json", False),
            ],
            "cloudtrail": [
                ("IAM events are recorded in us-east-1. Changes made by the principal",
                 f"aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=Username,AttributeValue={user} "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-user.json"),
                ("New users created by anyone",
                 "aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-createuser.json"),
                ("Console logins", "aws cloudtrail lookup-events --region us-east-1 --lookup-attributes "
                                   f"AttributeKey=EventName,AttributeValue=ConsoleLogin --start-time {start} --max-results 50 "
                                   "--output json > evidence/ct-consolelogin.json"),
            ],
            "athena": ("SELECT eventtime, useridentity.arn, eventname, sourceipaddress, requestparameters\n"
                       "FROM cloudtrail_logs\nWHERE eventsource = 'iam.amazonaws.com'\n"
                       "  AND eventname IN ('CreateUser', 'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile', "
                       "'AttachUserPolicy', 'AttachRolePolicy',\n"
                       "                    'PutUserPolicy', 'PutRolePolicy', 'UpdateAssumeRolePolicy', 'CreateRole', "
                       "'AddUserToGroup', 'CreatePolicyVersion', 'SetDefaultPolicyVersion',\n"
                       "                    'DeleteRolePermissionsBoundary', 'DeactivateMFADevice')\n"
                       f"  AND eventtime >= '{start}'\nORDER BY eventtime;"),
            "snapshots": [],
            "eradication": [
                "Remove every user, key, login profile, role, policy version and trust change the actor made, using the "
                "snapshot and the IAM query. Compare with iam-least-privilege-review output from before the incident if you have it.",
                "Investigate how the principal was compromised (leaked key, phished password, missing MFA) and run that runbook.",
            ],
            "recovery": [
                "Detach AWSDenyAll only after the principal's credentials are replaced and MFA is enforced.",
                "Move people to IAM Identity Center; deny IAM user creation outside an identity account with an SCP.",
            ],
        },
        "ransomware-ebs-s3": {
            "title": "Ransomware against S3 or EBS",
            "signs": "Mass DeleteObject or PutObject with customer-provided or foreign KMS keys, a ransom note object, "
                     "lifecycle rules or versioning suspended to purge data, DeleteSnapshot bursts, KMS key deletion scheduled, "
                     "GuardDuty Impact:S3 findings.",
            "inventory": [
                ("Versioning (old versions are the fastest recovery path)", f"aws s3api get-bucket-versioning --bucket {bucket} --output json"),
                ("Object Lock", f"aws s3api get-object-lock-configuration --bucket {bucket} --output json"),
                ("Lifecycle rules the actor may have added",
                 f"aws s3api get-bucket-lifecycle-configuration --bucket {bucket} --output json > evidence/lifecycle.json"),
                ("Recent versions and delete markers",
                 f"aws s3api list-object-versions --bucket {bucket} --max-items 1000 --output json > evidence/object-versions.json"),
                ("Your snapshots", f"aws ec2 describe-snapshots --region {region} --owner-ids self --output json > evidence/snapshots.json"),
                ("KMS keys pending deletion", f"aws kms list-keys --region {region} --output json"),
                ("Backup recovery points", f"aws backup list-recovery-points-by-backup-vault --region {region} "
                                           "--backup-vault-name <vault-name> --output json"),
            ],
            "containment": [
                ("Cut off the actor's credentials first: run the leaked-access-key or suspicious-iam-activity containment "
                 "for the principal seen in CloudTrail", "", False),
                ("Cancel scheduled deletion of any KMS key the data depends on",
                 f"aws kms cancel-key-deletion --region {region} --key-id <key-id>", False),
                ("Remove a lifecycle configuration the actor added (save it first, shown above)",
                 f"aws s3api delete-bucket-lifecycle --bucket {bucket}", False),
                ("Re-enable versioning if it was suspended",
                 f"aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled", False),
                ("Lock the backup vault. In compliance mode this cannot be undone after the grace period; agree it with the "
                 "incident lead and legal",
                 f"aws backup put-backup-vault-lock-configuration --region {region} --backup-vault-name <vault-name> "
                 "--min-retention-days <days>", True),
            ],
            "cloudtrail": [
                ("Key deletion and snapshot deletion",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-kms.json"),
                ("", f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteSnapshot "
                     f"--start-time {start} --max-results 50 --output json > evidence/ct-snapshots.json"),
            ],
            "athena": ("-- Object-level calls need S3 data events in the trail.\n"
                       "SELECT useridentity.arn, eventname, count(*) AS calls, min(eventtime) AS first, max(eventtime) AS last\n"
                       "FROM cloudtrail_logs\nWHERE eventsource IN ('s3.amazonaws.com', 'kms.amazonaws.com', 'ec2.amazonaws.com')\n"
                       "  AND eventname IN ('DeleteObject', 'DeleteObjects', 'PutObject', 'CopyObject', 'PutBucketLifecycle',\n"
                       "                    'PutBucketVersioning', 'ScheduleKeyDeletion', 'DisableKey', 'DeleteSnapshot', "
                       "'ModifySnapshotAttribute')\n"
                       f"  AND eventtime >= '{start}'\nGROUP BY 1, 2\nORDER BY calls DESC;"),
            "snapshots": [
                f"aws ec2 create-snapshot --region {region} --volume-id <volume-id> --description \"IR {v['case_id']} pre-recovery\" --output json",
            ],
            "eradication": [
                "Do not pay or contact the actor without legal advice.",
                "Remove the actor's access everywhere (keys, roles, federation trust) before restoring, or the restore will be hit again.",
                "Remove lifecycle rules, bucket policies and replication rules the actor added.",
            ],
            "recovery": [
                "Restore objects from previous versions or AWS Backup into a clean bucket; restore volumes from snapshots taken "
                "before the first malicious call.",
                "Turn on S3 versioning with Object Lock and a locked backup vault in a separate account for critical data.",
            ],
        },
        "crypto-mining": {
            "title": "Crypto-mining on account compute",
            "signs": "GuardDuty CryptoCurrency findings, a sudden cost spike, GPU or large instances or containers you did not "
                     "launch, often in regions you do not use.",
            "inventory": [
                ("Running instances in every region",
                 "for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do aws ec2 describe-instances "
                 "--region \"$r\" --filters Name=instance-state-name,Values=pending,running --output json > \"evidence/instances-$r.json\"; done"),
                ("Who launched instances",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-runinstances-{region}.json"),
                ("Cost by region and service",
                 "aws ce get-cost-and-usage --time-period Start=<yyyy-mm-dd>,End=<yyyy-mm-dd> --granularity DAILY --metrics UnblendedCost "
                 "--group-by Type=DIMENSION,Key=REGION --output json > evidence/cost-by-region.json"),
                ("Container services that can also mine", f"aws ecs list-clusters --region {region} --output json"),
            ],
            "containment": [
                ("Cut off the credential that launched the compute (from the RunInstances events): run the leaked-access-key "
                 "or suspicious-iam-activity containment", "", False),
                ("Snapshot first (below), then stop the instances. Stopping loses memory evidence; terminate only after "
                 "evidence is saved",
                 f"aws ec2 stop-instances --region {region} --instance-ids {inst}", False),
                ("Scale down Auto Scaling groups or ECS services the actor created",
                 f"aws autoscaling update-auto-scaling-group --region {region} --auto-scaling-group-name <asg-name> "
                 "--min-size 0 --max-size 0 --desired-capacity 0", False),
            ],
            "cloudtrail": [
                ("Every action by the launching principal",
                 f"aws cloudtrail lookup-events --region {region} --lookup-attributes AttributeKey=AccessKeyId,AttributeValue={key} "
                 f"--start-time {start} --max-results 50 --output json > evidence/ct-launcher.json"),
            ],
            "athena": ("SELECT eventtime, awsregion, useridentity.arn, useridentity.accesskeyid, sourceipaddress,\n"
                       "       json_extract_scalar(requestparameters, '$.instanceType') AS instance_type\n"
                       "FROM cloudtrail_logs\nWHERE eventname IN ('RunInstances', 'CreateAutoScalingGroup', "
                       "'CreateLaunchTemplate', 'RequestSpotInstances', 'RunTask', 'CreateService')\n"
                       f"  AND eventtime >= '{start}'\nORDER BY eventtime;"),
            "snapshots": [
                f"aws ec2 create-snapshot --region {region} --volume-id <volume-id> --description \"IR {v['case_id']} mining\" --output json",
            ],
            "eradication": [
                "Terminate the actor's instances, launch templates, Auto Scaling groups, spot requests, ECS services and "
                "Lambda functions after evidence is saved (each REQUIRES CONFIRMATION).",
                "Check every region, including ones you never use; actors pick unused regions on purpose.",
                "Raise a case with AWS Support about the charges; any billing adjustment is AWS's decision.",
            ],
            "recovery": [
                "Add spend guardrails: budgets with alerts, Cost Anomaly Detection and SCP denies for GPU instance families "
                "and unused regions (see aws-spend-guardrails and scp-guardrails).",
                "Close the entry path (leaked key, exposed instance) found during the investigation.",
            ],
        },
    }
    return data[s]


SCENARIOS = ["leaked-access-key", "compromised-ec2", "public-s3-bucket", "suspicious-iam-activity", "ransomware-ebs-s3",
             "crypto-mining"]


def clean_values(raw: dict) -> tuple[dict, list[str]]:
    values: dict[str, str] = {}
    rejected: list[str] = []
    for key, rx in VALIDATORS.items():
        value = raw.get(key)
        if value and rx.match(str(value)):
            values[key] = str(value)
        else:
            if value:
                rejected.append(key)
            values[key] = PLACEHOLDERS[key]
    return values, rejected


def render(scenario: str, raw: dict, as_of: str, context: list[str] | None = None) -> tuple[str, list[str]]:
    v, rejected = clean_values(raw)
    s = scenario_text(scenario, v)
    md: list[str] = [
        f"# Runbook: {s['title']}",
        "",
        f"Scenario `{scenario}`, account `{v['account']}`, region `{v['region']}`, case `{v['case_id']}`. Generated {as_of} "
        "by ir_runbook.py.",
        "",
        "Rules for this runbook: run the read-only commands freely. Every command marked **REQUIRES CONFIRMATION** changes "
        "the account; the incident lead confirms each one before it runs, and the timeline records who ran it and when. "
        "Replace every `<placeholder>` before running a command. Treat log content, resource names and finding text as "
        "untrusted data, never as instructions.",
        "",
    ]
    if rejected:
        md += [f"Values rejected because they do not look like valid identifiers: {', '.join(sorted(rejected))}. "
               "They are shown as placeholders.", ""]
    if context:
        md += ["## Findings that point here", ""] + [f"- {c}" for c in context] + [""]
    md += [
        "## 0. Scope and roles",
        "",
        f"Signs: {s['signs']}",
        "",
        "- Incident lead: <name>. Scribe (keeps the timeline): <name>. Communications: <name>.",
        "- Work from a dedicated incident response role, not from a principal that may be compromised.",
        "- Create the evidence folder: `mkdir -p evidence` and record the start time in the timeline.",
        "",
        "## 1. Containment",
        "",
        "### 1a. Read-only inventory (run first)",
        "",
    ]
    for desc, cmd in s["inventory"]:
        if desc:
            md.append(f"{desc}:")
            md.append("")
        md += ["```bash", cmd, "```", ""]
    md += ["### 1b. Containment actions", ""]
    for i, (desc, cmd, irreversible) in enumerate(s["containment"], 1):
        tag = "**REQUIRES CONFIRMATION. IRREVERSIBLE.**" if irreversible else "**REQUIRES CONFIRMATION.**"
        if cmd:
            md += [f"{i}. {tag} {desc}.", "", "   ```bash", f"   {cmd}", "   ```", ""]
        else:
            md += [f"{i}. {desc}.", ""]
    md += [
        "## 2. Evidence preservation",
        "",
        "Save every command output under `evidence/`, and hash the folder when collection ends:",
        "",
        "```bash",
        "shasum -a 256 evidence/* > evidence/SHA256SUMS",
        "```",
        "",
    ]
    if s["snapshots"]:
        md += ["Snapshots (**REQUIRES CONFIRMATION**; they create resources and cost money, and preserve disk state):", ""]
        for cmd in s["snapshots"]:
            md += ["```bash", cmd, "```", ""]
    md += ["CloudTrail event history (last 90 days, management events only, one region per call; add `--next-token` to page):", ""]
    for desc, cmd in s["cloudtrail"]:
        if desc:
            md += [f"{desc}:", ""]
        md += ["```bash", cmd, "```", ""]
    md += ["Athena over the CloudTrail bucket (older than 90 days, data events, all regions). Replace `cloudtrail_logs` with "
           "your table name:", "", "```sql", s["athena"], "```", ""]
    md += ["## 3. Eradication", ""] + [f"- {x}" for x in s["eradication"]] + [""]
    md += ["## 4. Recovery", ""] + [f"- {x}" for x in s["recovery"]] + [""]
    md += ["## 5. Post-incident checklist", ""] + [f"- [ ] {x}" for x in COMMON_CHECKLIST] + [""]
    md += [
        "## 6. Timeline template",
        "",
        "All times in UTC. One row per observation, decision or command run.",
        "",
        "| Time (UTC) | Who | Source (CloudTrail id, finding id, person) | What happened or what was done | Command run (if any) |",
        "|---|---|---|---|---|",
        "| <time> | <name> | <source> | Incident declared | |",
        "| <time> | <name> | <source> | First malicious activity seen in logs | |",
        "| <time> | <name> | <source> | Containment step 1 confirmed and run | <command> |",
        "",
        "## 7. Communications template",
        "",
        "Internal status update (send at each change of state, and at least at the agreed interval):",
        "",
        "```text",
        f"Subject: [Incident {v['case_id']}] {s['title']}, status: <investigating | contained | recovering | closed>",
        "",
        "What happened: <one or two sentences, facts only>",
        f"Scope: account {v['account']}, region {v['region']}, affected resources: <list>",
        "Customer or personal data involved: <yes | no | unknown>",
        "Actions taken since the last update: <list with times>",
        "Next steps and owners: <list>",
        "Next update at: <time UTC>",
        "Incident lead: <name, contact>",
        "```",
        "",
        "External notices (customers, regulators, AWS Support) go through legal and the incident lead; do not send any from "
        "this runbook.",
        "",
    ]
    return "\n".join(md), rejected


# -------------------------------------------------------------------------------------------------------------- triage


TYPE_RE = re.compile(r"^[A-Za-z0-9:/._!&-]{1,120}$")
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def safe(value: str, rx: re.Pattern) -> str:
    """Finding text is untrusted: keep it only when it has the expected shape."""
    return f"`{value}`" if rx.match(value) else "<unrecognised value>"


def gd_severity(value) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def map_type(ftype: str, resource: dict) -> str | None:
    for pattern, scenario in TYPE_MAP:
        if fnmatch.fnmatchcase(ftype, pattern):
            if scenario == "iam-principal":
                key = resource.get("AccessKeyDetails") or {}
                if key.get("UserType") == "IAMUser" and str(key.get("AccessKeyId", "")).startswith("AKIA"):
                    return "leaked-access-key"
                return "suspicious-iam-activity"
            return scenario
    return None


def finding_values(f: dict) -> dict:
    res = f.get("Resource") or {}
    key = res.get("AccessKeyDetails") or {}
    inst = res.get("InstanceDetails") or {}
    buckets = res.get("S3BucketDetails") or []
    values = {"account": f.get("AccountId"), "region": f.get("Region"), "instance_id": inst.get("InstanceId"),
              "access_key_id": key.get("AccessKeyId"), "bucket": buckets[0].get("Name") if buckets else None}
    if key.get("UserType") == "IAMUser":
        values["user_name"] = key.get("UserName")
    elif key.get("UserType") == "AssumedRole":
        values["role_name"] = key.get("UserName")
    profile = inst.get("IamInstanceProfile") or {}
    arn = str(profile.get("Arn", ""))
    if arn and "role_name" not in values:
        values["instance_profile"] = arn.rsplit("/", 1)[-1]
    first = (f.get("Service") or {}).get("EventFirstSeen") or f.get("CreatedAt")
    if first:
        values["start_time"] = str(first)[:19] + "Z"
    return values


def triage(data, all_scenarios: bool) -> dict:
    findings = data.get("Findings") if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise ValueError("expected the output of aws guardduty get-findings (an object with Findings)")
    mapped: dict[str, list[dict]] = {}
    unmapped: list[dict] = []
    archived = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (f.get("Service") or {}).get("Archived"):
            archived += 1
            continue
        ftype = str(f.get("Type", ""))
        sev = gd_severity(f.get("Severity"))
        scenario = map_type(ftype, f.get("Resource") or {})
        row = {"id": str(f.get("Id", "")), "type": ftype, "severity": sev, "scenario": scenario,
               "values": finding_values(f)}
        (mapped.setdefault(scenario, []) if scenario else unmapped).append(row)
    order = sorted(mapped, key=lambda s: (min(SEVERITIES.index(r["severity"]) for r in mapped[s]), -len(mapped[s]),
                                          SCENARIOS.index(s)))
    chosen = order if all_scenarios else order[:1]
    runbooks = []
    for s in chosen:
        rows = sorted(mapped[s], key=lambda r: SEVERITIES.index(r["severity"]))
        values: dict[str, str] = {}
        for r in rows:
            for k, val in r["values"].items():
                if val and k not in values:
                    values[k] = val
        if s == "compromised-ec2" and "role_name" not in values and values.get("instance_profile"):
            values["role_name"] = values["instance_profile"]
        start = min((r["values"].get("start_time") for r in rows if r["values"].get("start_time")), default=None)
        if start:
            values["start_time"] = start
        context = [f"{r['severity']} {safe(r['type'], TYPE_RE)} ({safe(r['id'], ID_RE)})" for r in rows]
        runbooks.append({"scenario": s, "values": values, "context": context})
    return {"total": len(findings), "archived": archived,
            "by_scenario": {s: [{k: r[k] for k in ("id", "type", "severity")} for r in mapped[s]] for s in order},
            "unmapped": [{k: r[k] for k in ("id", "type", "severity")} for r in unmapped], "runbooks": runbooks}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    today = dt.date.today().isoformat()
    if argv and argv[0] == "triage":
        ap = argparse.ArgumentParser(prog="ir_runbook.py triage", description="Pick runbooks from exported GuardDuty findings.")
        ap.add_argument("--guardduty", required=True, help="output of aws guardduty get-findings --output json")
        ap.add_argument("--all", action="store_true", help="one runbook per matched scenario instead of the top one")
        ap.add_argument("--out", help="directory for runbook-<scenario>.md files")
        ap.add_argument("--case-id", help="case id to put in the runbooks")
        ap.add_argument("--as-of", default=today, help="date printed in the runbook (default today)")
        ap.add_argument("--fail-on", choices=SEVERITIES, default="HIGH", help="exit 1 when a mapped finding is at or above this")
        ap.add_argument("--json", action="store_true", help="print the mapping and runbooks as JSON")
        args = ap.parse_args(argv[1:])
        try:
            result = triage(json.loads(Path(args.guardduty).read_text(encoding="utf-8")), args.all)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for rb in result["runbooks"]:
            if args.case_id:
                rb["values"]["case_id"] = args.case_id
            rb["markdown"], rb["rejected"] = render(rb["scenario"], rb["values"], args.as_of, rb["context"])
            if args.out:
                out = Path(args.out)
                out.mkdir(parents=True, exist_ok=True)
                (out / f"runbook-{rb['scenario']}.md").write_text(rb["markdown"], encoding="utf-8")
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"{result['total']} finding(s), {result['archived']} archived")
            for s, rows in result["by_scenario"].items():
                print(f"  {s}: " + ", ".join(f"{r['severity']} {r['type']}" for r in rows))
            for r in result["unmapped"]:
                print(f"  unmapped (no runbook): {r['severity']} {r['type']}")
            if not result["runbooks"]:
                print("no finding maps to a runbook scenario")
            for rb in result["runbooks"]:
                if args.out:
                    print(f"wrote {Path(args.out) / ('runbook-' + rb['scenario'] + '.md')}")
                else:
                    print()
                    print(rb["markdown"])
        threshold = SEVERITIES.index(args.fail_on)
        hit = any(SEVERITIES.index(r["severity"]) <= threshold for rows in result["by_scenario"].values() for r in rows)
        return 1 if hit else 0

    ap = argparse.ArgumentParser(prog="ir_runbook.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=SCENARIOS, help="scenario to write the runbook for")
    ap.add_argument("--list", action="store_true", help="list the scenarios and exit")
    ap.add_argument("--account", help="12-digit account id")
    ap.add_argument("--region", help="region of the affected resources")
    ap.add_argument("--access-key-id", help="access key id involved")
    ap.add_argument("--user-name", help="IAM user involved")
    ap.add_argument("--role-name", help="IAM role involved")
    ap.add_argument("--instance-id", help="EC2 instance id")
    ap.add_argument("--bucket", help="S3 bucket name")
    ap.add_argument("--start-time", help="start of the window to search, ISO 8601 (UTC)")
    ap.add_argument("--case-id", help="incident case id")
    ap.add_argument("--as-of", default=today, help="date printed in the runbook (default today)")
    ap.add_argument("--out", help="write the Markdown to this file")
    ap.add_argument("--json", action="store_true", help="print JSON with the Markdown and the values used")
    args = ap.parse_args(argv)
    if args.list:
        for s in SCENARIOS:
            print(s)
        return 0
    if not args.scenario:
        ap.error("--scenario is required (or use --list, or the triage subcommand)")
    raw = {k: getattr(args, k) for k in VALIDATORS}
    markdown, rejected = render(args.scenario, raw, args.as_of)
    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
    if args.json:
        print(json.dumps({"scenario": args.scenario, "rejected": rejected, "markdown": markdown}, indent=2))
    elif not args.out:
        print(markdown)
    else:
        print(f"wrote {args.out}")
    if rejected:
        print(f"warning: ignored values that are not valid identifiers: {', '.join(rejected)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
