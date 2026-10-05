#!/usr/bin/env python3
"""Emit a guardrail pack for a sandbox OU where engineers and agents experiment.

  sandbox_pack.py --spec sandbox.yaml [--out DIR] [--json] [--as-of YYYY-MM-DD]

Spec keys:

  sandbox_name: sandbox                    used in names
  allowed_regions: [ap-southeast-2, us-east-1]
  protected_roles: [OrganizationAccountAccessRole, SandboxAdmin]   exempt from the exemptible denies
  log_archive_account: "111122223333"      account that receives the organization CloudTrail
  owner_tag_key: owner                     tag every instance must carry at launch (default owner)
  ttl_tag_key: expires-on                  tag holding the expiry date YYYY-MM-DD (default expires-on)
  default_ttl_days: 14                     applied by the sweeper to resources without the tag
  max_ttl_days: 30                         longer expiry dates are cut back to this
  grace_days: 3                            days between stopping and deleting an expired resource
  sweep_schedule: cron(0 18 * * ? *)       EventBridge Scheduler expression (default daily 18:00)
  sweep_timezone: UTC                      IANA time zone for the schedule
  contacts: {owner: platform@example.com, channel: "#sandbox"}
  budget: {...}                            optional: an aws-spend-guardrails budget spec (monthly_limit, thresholds ...)
  spend: {...}                             aws-spend-guardrails sandbox_scp keys (instance types, IOPS, services ...)

Output (--out):

  scps/scp-NN.json, scps/manifest.json   SCPs built with scp_builder.py (region allowlist, deny leaving the
                                         organization, protect CloudTrail, GuardDuty, Security Hub and Config, deny
                                         the root user, require IMDSv2, deny public S3 ACLs) plus deny IAM user and
                                         access key creation, require the owner tag on new instances, and the spend
                                         denies from spend_guardrails.py; packed under 5120 characters and linted
                                         with scp_lint.py
  baseline-checklist.md                  per-account baseline with read-only verification commands
  auto-expiry/design.md                  tag-based TTL design with the exact EventBridge Scheduler command
  auto-expiry/ttl_sweeper.py             Lambda handler as Python pseudocode (dry run by default; not deployed)
  auto-expiry/sweeper-role-policy.json   permissions the sweeper needs, destructive actions limited to tagged resources
  auto-expiry/scheduler-role-policy.json permission for the schedule to invoke the function
  budget/...                             budget files from spend_guardrails.py when "budget" is set
  README-sandbox-users.md                one page for the people using the sandbox

Exit codes: 0 written, 1 an SCP failed lint, 2 bad spec. Nothing is deployed and AWS is never called.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _scp_builder as scp_builder  # noqa: E402
import _spend_guardrails as spend_guardrails  # noqa: E402
from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402
from _scp_lint import compact, lint_policy  # noqa: E402

SPEC_KEYS = {"sandbox_name", "allowed_regions", "protected_roles", "log_archive_account", "owner_tag_key", "ttl_tag_key",
             "default_ttl_days", "max_ttl_days", "grace_days", "sweep_schedule", "sweep_timezone", "contacts", "budget", "spend"}
TAG_RE = re.compile(r"^[A-Za-z0-9_.:/=+@-]{1,64}$")
SCHEDULE_RE = re.compile(r"^(cron\([0-9*?,/ A-Z#L-]+\)|rate\(\d+ (minute|minutes|hour|hours|day|days)\))$")


class SpecError(Exception):
    pass


def need(cond: bool, message: str) -> None:
    if not cond:
        raise SpecError(message)


def load_spec(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise SpecError(f"{path}: cannot parse: {exc}") from exc
    need(isinstance(data, dict), f"{path}: the spec must be a mapping")
    return data


def validate(spec: dict) -> dict:
    unknown = set(spec) - SPEC_KEYS
    need(not unknown, f"unknown spec keys: {', '.join(sorted(unknown))}")
    name = spec.get("sandbox_name", "sandbox")
    need(isinstance(name, str) and bool(re.match(r"^[a-z0-9][a-z0-9-]{0,30}$", name)), "sandbox_name: lowercase letters, digits, -")
    need(bool(spec.get("allowed_regions")), "allowed_regions is required for a sandbox")
    need(bool(spec.get("protected_roles")), "protected_roles is required: name the admin role that can still fix a sandbox account")
    log_archive = spec.get("log_archive_account")
    need(isinstance(log_archive, str) and bool(re.match(r"^\d{12}$", log_archive)),
         "log_archive_account must be the 12-digit log archive account id (quoted)")
    owner_tag = spec.get("owner_tag_key", "owner")
    ttl_tag = spec.get("ttl_tag_key", "expires-on")
    for key, value in (("owner_tag_key", owner_tag), ("ttl_tag_key", ttl_tag)):
        need(isinstance(value, str) and bool(TAG_RE.match(value)) and not value.lower().startswith("aws:"), f"{key} is not a tag key")
    default_ttl = spec.get("default_ttl_days", 14)
    max_ttl = spec.get("max_ttl_days", 30)
    grace = spec.get("grace_days", 3)
    for key, value in (("default_ttl_days", default_ttl), ("max_ttl_days", max_ttl), ("grace_days", grace)):
        need(isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 365, f"{key} must be a whole number of days, 1 to 365")
    need(default_ttl <= max_ttl, "default_ttl_days must not exceed max_ttl_days")
    schedule = spec.get("sweep_schedule", "cron(0 18 * * ? *)")
    need(isinstance(schedule, str) and bool(SCHEDULE_RE.match(schedule)), "sweep_schedule must be cron(...) or rate(...)")
    tz = spec.get("sweep_timezone", "UTC")
    need(isinstance(tz, str) and bool(re.match(r"^[A-Za-z_]+(/[A-Za-z_+-]+)*$", tz)), "sweep_timezone must be an IANA name")
    contacts = spec.get("contacts") or {}
    need(isinstance(contacts, dict), "contacts must be a mapping")
    if "spend" in spec:
        need(isinstance(spec["spend"], dict), "spend must be a mapping of aws-spend-guardrails sandbox_scp keys")
        need("protected_roles" not in spec["spend"], "spend takes no protected_roles; the pack's protected_roles apply")
    return {"name": name, "regions": spec["allowed_regions"], "roles": spec["protected_roles"], "log_archive": log_archive,
            "owner_tag": owner_tag, "ttl_tag": ttl_tag, "default_ttl": default_ttl, "max_ttl": max_ttl, "grace": grace,
            "schedule": schedule, "tz": tz, "contacts": contacts}


def scp_statements(spec: dict, cfg: dict) -> list[tuple[str, dict]]:
    base = {"allowed_regions": cfg["regions"], "protected_roles": cfg["roles"], "deny_leave_organization": True,
            "deny_disable_security_services": True, "deny_root_user": True, "require_imdsv2": True, "deny_public_s3_acls": True}
    try:
        scp_builder.validate_spec(base)
    except scp_builder.SpecError as exc:
        raise SpecError(str(exc)) from exc
    statements = scp_builder.build_statements(base)
    exempt = scp_builder.exemption(base)
    statements.append(("deny_iam_users", scp_builder.with_condition({
        "Sid": "DenyIamUserCreation", "Effect": "Deny",
        "Action": ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateUser"], "Resource": "*"}, exempt)))
    statements.append(("require_owner_tag", {
        "Sid": "RequireOwnerTagOnLaunch", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "arn:aws:ec2:*:*:instance/*",
        "Condition": {"Null": {f"aws:RequestTag/{cfg['owner_tag']}": "true"}}}))
    if "spend" in spec:
        try:
            statements += spend_guardrails.build_spend_statements(spec["spend"], cfg["roles"])
        except spend_guardrails.SpecError as exc:
            raise SpecError(f"spend: {exc}") from exc
    return statements


def build_scps(spec: dict, cfg: dict) -> tuple[list[dict], dict]:
    statements = scp_statements(spec, cfg)
    try:
        packed = scp_builder.pack(statements, scp_builder.SCP_LIMIT)
    except scp_builder.SpecError as exc:
        raise SpecError(str(exc)) from exc
    docs = [{"Version": "2012-10-17", "Statement": [s for _, s in d]} for d in packed]
    manifest = {"limit": scp_builder.SCP_LIMIT, "documents": [], "warnings": [], "lint": []}
    for i, (doc, items) in enumerate(zip(docs, packed, strict=True), 1):
        name = f"scp-{i:02d}.json"
        manifest["documents"].append({"file": name, "chars_compact": len(compact(doc)),
                                      "guardrails": sorted({g for g, _ in items}), "statements": [s["Sid"] for _, s in items]})
        manifest["lint"] += [{"file": name, **issue} for issue in lint_policy(doc)]
    if len(docs) > scp_builder.MAX_ATTACHED - 1:
        manifest["warnings"].append(f"{len(docs)} documents: an OU takes at most {scp_builder.MAX_ATTACHED} SCPs including "
                                    "FullAWSAccess; attach some to a parent OU")
    return docs, manifest


def checklist(cfg: dict, docs: list[dict]) -> str:
    regions = cfg["regions"]
    lines = [
        f"# Sandbox account baseline: {cfg['name']}",
        "",
        "Check every new sandbox account against this list before handing it over, and again monthly. The commands are",
        "read-only; run them with a read-only role in the sandbox account unless the line says otherwise.",
        "",
        "## Organization level",
        "",
        f"- [ ] The {len(docs)} SCP(s) in `scps/` are attached to the sandbox OU (management account):",
        "",
        "  ```bash",
        "  aws organizations list-policies-for-target --target-id <sandbox-ou-id> --filter SERVICE_CONTROL_POLICY --output json",
        "  ```",
        "",
        f"- [ ] An organization CloudTrail trail delivers to a bucket in the log archive account {cfg['log_archive']}, in all",
        "      regions, with log file validation:",
        "",
        "  ```bash",
        "  aws cloudtrail describe-trails --output json",
        "  aws cloudtrail get-trail-status --name <trail-arn> --output json",
        "  ```",
        "",
        "  Expect `IsOrganizationTrail: true`, `IsMultiRegionTrail: true`, `LogFileValidationEnabled: true`, the S3 bucket",
        f"  owned by {cfg['log_archive']}, and `IsLogging: true`.",
        "",
        "## Per account",
        "",
        "- [ ] GuardDuty has a detector in every allowed region (auto-enabled by the delegated administrator):",
        "",
        "  ```bash",
    ]
    lines += [f"  aws guardduty list-detectors --region {r} --output json" for r in regions]
    lines += [
        "  ```",
        "",
        "- [ ] No default VPC in any allowed region (empty result expected):",
        "",
        "  ```bash",
    ]
    lines += [f"  aws ec2 describe-vpcs --region {r} --filters Name=is-default,Values=true --output json" for r in regions]
    lines += [
        "  ```",
        "",
        "  To remove one (REQUIRES CONFIRMATION; first delete its subnets, detach and delete its internet gateway):",
        "",
        "  ```bash",
        "  aws ec2 delete-subnet --region <region> --subnet-id <subnet-id>",
        "  aws ec2 detach-internet-gateway --region <region> --internet-gateway-id <igw-id> --vpc-id <vpc-id>",
        "  aws ec2 delete-internet-gateway --region <region> --internet-gateway-id <igw-id>",
        "  aws ec2 delete-vpc --region <region> --vpc-id <vpc-id>",
        "  ```",
        "",
        "- [ ] A budget with alerts is attached to the account (see `budget/` or aws-spend-guardrails):",
        "",
        "  ```bash",
        "  aws budgets describe-budgets --account-id <sandbox-account-id> --output json",
        "  ```",
        "",
        "- [ ] Account-level S3 public access block is on:",
        "",
        "  ```bash",
        "  aws s3control get-public-access-block --account-id <sandbox-account-id> --output json",
        "  ```",
        "",
        "- [ ] EBS encryption by default and IMDSv2 by default in each allowed region:",
        "",
        "  ```bash",
    ]
    for r in regions:
        lines += [f"  aws ec2 get-ebs-encryption-by-default --region {r} --output json",
                  f"  aws ec2 get-instance-metadata-defaults --region {r} --output json"]
    lines += [
        "  ```",
        "",
        "- [ ] No IAM users; people sign in through IAM Identity Center:",
        "",
        "  ```bash",
        "  aws iam list-users --output json",
        "  ```",
        "",
        f"- [ ] Expiry is enforced: the TTL sweeper in `auto-expiry/` runs on schedule `{cfg['schedule']}`, or the account is",
        "      reset on a fixed schedule with an account-cleaning tool. Write down which one, and who owns it.",
        "- [ ] The sandbox user README is shared with everyone who gets access.",
        "",
    ]
    return "\n".join(lines)


SWEEPER = '''"""TTL sweeper for sandbox accounts: Lambda handler, Python pseudocode. Generated by sandbox_pack.py.

NOT DEPLOYED. Review, test against a sandbox account with DRY_RUN = True, and read the logs before turning deletion on.
It handles EC2 instances and unattached EBS volumes. Other resource types are reported, never deleted; add them one
at a time with their own tests.

Rules:
  - a resource without the TTL tag gets one: today + DEFAULT_TTL_DAYS
  - an expiry date beyond today + MAX_TTL_DAYS is cut back to that
  - on the expiry date: notify the owner tag and stop the instance
  - GRACE_DAYS after the expiry date: terminate the instance or delete the volume
"""
import datetime
import os

import boto3  # provided by the Lambda runtime

TTL_TAG = "__TTL_TAG__"
OWNER_TAG = "__OWNER_TAG__"
DEFAULT_TTL_DAYS = __DEFAULT_TTL__
MAX_TTL_DAYS = __MAX_TTL__
GRACE_DAYS = __GRACE__
REGIONS = __REGIONS__
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() != "false"


def parse_date(value):
    try:
        return datetime.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def decide(tags, today):
    """Return (action, new_expiry). Pure function: unit-test it before deploying."""
    expiry = parse_date(tags.get(TTL_TAG))
    if expiry is None:
        return "tag", today + datetime.timedelta(days=DEFAULT_TTL_DAYS)
    if expiry > today + datetime.timedelta(days=MAX_TTL_DAYS):
        return "tag", today + datetime.timedelta(days=MAX_TTL_DAYS)
    if today >= expiry + datetime.timedelta(days=GRACE_DAYS):
        return "delete", expiry
    if today >= expiry:
        return "stop", expiry
    return "keep", expiry


def handler(event, context):
    today = datetime.datetime.now(datetime.timezone.utc).date()
    dry_run = DRY_RUN or bool((event or {}).get("dry_run", False))
    report = []
    for region in REGIONS:
        ec2 = boto3.client("ec2", region_name=region)
        for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    action, expiry = decide(tags, today)
                    report.append({"region": region, "id": inst["InstanceId"], "owner": tags.get(OWNER_TAG),
                                   "action": action, "expiry": expiry.isoformat()})
                    if dry_run or action == "keep":
                        continue
                    if action == "tag":
                        ec2.create_tags(Resources=[inst["InstanceId"]], Tags=[{"Key": TTL_TAG, "Value": expiry.isoformat()}])
                    elif action == "stop" and inst["State"]["Name"] in ("pending", "running"):
                        ec2.stop_instances(InstanceIds=[inst["InstanceId"]])
                    elif action == "delete":
                        ec2.terminate_instances(InstanceIds=[inst["InstanceId"]])
        for page in ec2.get_paginator("describe_volumes").paginate(
                Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page["Volumes"]:
                tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                action, expiry = decide(tags, today)
                report.append({"region": region, "id": vol["VolumeId"], "owner": tags.get(OWNER_TAG),
                               "action": action, "expiry": expiry.isoformat()})
                if dry_run or action in ("keep", "stop"):
                    continue
                if action == "tag":
                    ec2.create_tags(Resources=[vol["VolumeId"]], Tags=[{"Key": TTL_TAG, "Value": expiry.isoformat()}])
                elif action == "delete":
                    ec2.delete_volume(VolumeId=vol["VolumeId"])
    # Notify owners of resources that were stopped or are about to be deleted (SNS or chat), then return the report.
    print({"dry_run": dry_run, "today": today.isoformat(), "items": report})
    return {"dry_run": dry_run, "count": len(report)}
'''


def sweeper_code(cfg: dict) -> str:
    return (SWEEPER.replace("__TTL_TAG__", cfg["ttl_tag"]).replace("__OWNER_TAG__", cfg["owner_tag"])
            .replace("__DEFAULT_TTL__", str(cfg["default_ttl"])).replace("__MAX_TTL__", str(cfg["max_ttl"]))
            .replace("__GRACE__", str(cfg["grace"])).replace("__REGIONS__", json.dumps(cfg["regions"])))


def sweeper_policy(cfg: dict) -> dict:
    tagged = {"Null": {f"aws:ResourceTag/{cfg['ttl_tag']}": "false"}}
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "Inventory", "Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes"], "Resource": "*",
         "Condition": {"StringEquals": {"aws:RequestedRegion": cfg["regions"]}}},
        {"Sid": "TagExpiry", "Effect": "Allow", "Action": "ec2:CreateTags",
         "Resource": ["arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:volume/*"],
         "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": [cfg["ttl_tag"]]}}},
        {"Sid": "StopAndDeleteOnlyTagged", "Effect": "Allow",
         "Action": ["ec2:DeleteVolume", "ec2:StopInstances", "ec2:TerminateInstances"],
         "Resource": ["arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:volume/*"], "Condition": tagged},
        {"Sid": "Logs", "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:*:*:log-group:/aws/lambda/{cfg['name']}-ttl-sweeper*"},
    ]}


def scheduler_policy(cfg: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Sid": "InvokeSweeper", "Effect": "Allow", "Action": "lambda:InvokeFunction",
                                                    "Resource": f"arn:aws:lambda:{cfg['regions'][0]}:<sandbox-account-id>:function:"
                                                                f"{cfg['name']}-ttl-sweeper"}]}


def design_md(cfg: dict) -> str:
    fn = f"{cfg['name']}-ttl-sweeper"
    region = cfg["regions"][0]
    target = json.dumps({"Arn": f"arn:aws:lambda:{region}:<sandbox-account-id>:function:{fn}",
                         "RoleArn": f"arn:aws:iam::<sandbox-account-id>:role/{cfg['name']}-ttl-scheduler",
                         "Input": json.dumps({"dry_run": True})}, separators=(",", ":"))
    return "\n".join([
        f"# Auto-expiry design: {cfg['name']}",
        "",
        "Status: design only. Nothing here is deployed. Deploy through your infrastructure-as-code pipeline after review.",
        "",
        "## Tags",
        "",
        f"- `{cfg['owner_tag']}`: who to contact. An SCP denies launching an instance without it.",
        f"- `{cfg['ttl_tag']}`: expiry date `YYYY-MM-DD`. Missing tags get today + {cfg['default_ttl']} days; dates more than "
        f"{cfg['max_ttl']} days ahead are cut back to that.",
        "",
        "## Lifecycle",
        "",
        "| Day | What the sweeper does |",
        "|---|---|",
        "| Before expiry | Nothing; owners extend by editing the tag (up to the maximum). |",
        "| Expiry date | Stops the instance and notifies the owner. Unattached volumes are left alone. |",
        f"| Expiry + {cfg['grace']} days | Terminates the instance or deletes the unattached volume. |",
        "",
        "The sweeper starts in dry run (`DRY_RUN` unset or `true`): it only logs what it would do. Switch it to `false` after",
        "two clean dry-run reports. Other resource types (S3 buckets, databases, clusters) are reported only; delete them by",
        "account reset or by hand, because their data is harder to recover.",
        "",
        "## Schedule (EventBridge Scheduler)",
        "",
        "Create the function from `ttl_sweeper.py` and the two roles from the policy files first. Then (REQUIRES",
        "CONFIRMATION):",
        "",
        "```bash",
        f"aws scheduler create-schedule --region {region} --name {fn} \\",
        f"  --schedule-expression '{cfg['schedule']}' --schedule-expression-timezone '{cfg['tz']}' \\",
        "  --flexible-time-window Mode=OFF \\",
        f"  --target '{target}'",
        "```",
        "",
        "Remove `\"dry_run\": true` from the target input, and set `DRY_RUN=false` on the function, only when deletion is",
        "approved.",
        "",
        "## Permissions",
        "",
        "- `sweeper-role-policy.json`: describe in the allowed regions, add only the TTL tag, and stop, terminate or delete",
        "  only resources that carry the TTL tag.",
        "- `scheduler-role-policy.json`: invoke this one function.",
        "",
        "## Tests to write before deploying",
        "",
        "- `decide()` for: no tag, unparsable tag, date past the maximum, before expiry, on expiry, after the grace period.",
        "- A dry run against a sandbox account with one tagged and one untagged instance; compare the log with the expectation.",
        "",
    ])


def users_readme(cfg: dict, spec: dict, manifest: dict) -> str:
    contacts = cfg["contacts"]
    sids = {s for d in manifest["documents"] for s in d["statements"]}
    spend = spec.get("spend") or {}
    denied = ["Leaving the organization, or turning off CloudTrail, GuardDuty, Security Hub or AWS Config.",
              "Using the root user.", "Creating IAM users, access keys or console passwords: sign in through the access portal.",
              "Launching instances that allow IMDSv1, or without an "
              f"`{cfg['owner_tag']}` tag.", "Public S3 ACLs, or changing the account's S3 public access block."]
    if "DenyExpensiveInstanceTypes" in sids:
        denied.append("Large, GPU, accelerator and bare-metal instance types: " + ", ".join(f"`{t}`" for t in spend["deny_instance_types"]) + ".")
    if "DenyInstanceTypesNotAllowed" in sids:
        denied.append("Any instance type except " + ", ".join(f"`{t}`" for t in spend["allowed_instance_types"]) + ".")
    if "DenyHighIopsVolumes" in sids:
        denied.append(f"EBS volumes above {int(spend['max_volume_iops'])} IOPS.")
    if "DenyProvisionedIopsVolumeTypes" in sids:
        denied.append("EBS volume types " + ", ".join(f"`{t}`" for t in spend["deny_volume_types"]) + ".")
    if "DenySageMakerGpuInstanceTypes" in sids:
        denied.append("SageMaker jobs, notebooks and endpoints on GPU or accelerator instance types.")
    if "DenyBedrockCustomizationAndThroughput" in sids:
        denied.append("Bedrock model customization jobs and provisioned throughput.")
    if "DenyExpensiveServices" in sids:
        denied.append("These services: " + ", ".join(f"`{s}`" for s in sorted(set(spend["deny_services"]))) + ".")
    if "DenyPurchaseCommitments" in sids:
        denied.append("Reserved capacity, Savings Plans and Marketplace subscriptions.")
    if "ProtectBudgetsAndAnomalyMonitors" in sids:
        denied.append("Changing or deleting budgets, budget actions and cost anomaly monitors.")
    budget = spec.get("budget") or {}
    lines = [
        f"# Using the {cfg['name']} accounts",
        "",
        "This account is for experiments. Expect it to be cleaned up. Never put production data, customer data or real",
        "secrets in it.",
        "",
        "## Getting in",
        "",
        "Sign in through the AWS access portal with your own identity. There are no IAM users here, and you cannot create any.",
        "",
        "## Where you can work",
        "",
        "Regions: " + ", ".join(f"`{r}`" for r in cfg["regions"]) + ". Requests to other regions are denied, except for "
        "global services such as IAM.",
        "",
        "## Tag what you create",
        "",
        f"- `{cfg['owner_tag']}`: your email or team. Instances without it cannot be launched.",
        f"- `{cfg['ttl_tag']}`: the date you are done, `YYYY-MM-DD`. If you leave it out you get {cfg['default_ttl']} days; "
        f"the longest allowed is {cfg['max_ttl']} days. Edit the tag to extend.",
        "",
        "On the expiry date your instances are stopped and you are notified. "
        f"{cfg['grace']} days later they are terminated and unattached volumes are deleted. Copy anything you need out first.",
        "",
        "## What is blocked",
        "",
    ]
    lines += [f"- {d}" for d in denied]
    lines += ["", "## Money", ""]
    if budget.get("monthly_limit"):
        lines.append(f"The account has a monthly budget of {budget['monthly_limit']} {budget.get('currency', 'USD')} with alerts. "
                     "Stop or delete what you are not using; cost anomaly alerts go to the platform team.")
    else:
        lines.append("The account has a monthly budget with alerts. Stop or delete what you are not using.")
    lines += ["", "## AI agents", "",
              "Agents run with their own role and session name, never with your personal session. Ask the platform team for",
              "an agent role (see the agent-safe-aws-access skill) rather than handing an agent your credentials.",
              "", "## Help", ""]
    lines.append(f"Platform team: {contacts.get('owner', '<owner contact>')}. Channel: {contacts.get('channel', '<channel>')}.")
    lines.append("If a guardrail blocks something you need, ask; do not work around it.")
    lines.append("")
    return "\n".join(lines)


def build(spec: dict) -> dict:
    cfg = validate(spec)
    docs, manifest = build_scps(spec, cfg)
    files: dict[str, object] = {}
    for meta, doc in zip(manifest["documents"], docs, strict=True):
        files[f"scps/{meta['file']}"] = doc
    files["scps/manifest.json"] = manifest
    files["baseline-checklist.md"] = checklist(cfg, docs)
    files["auto-expiry/design.md"] = design_md(cfg)
    files["auto-expiry/ttl_sweeper.py"] = sweeper_code(cfg)
    files["auto-expiry/sweeper-role-policy.json"] = sweeper_policy(cfg)
    files["auto-expiry/scheduler-role-policy.json"] = scheduler_policy(cfg)
    if spec.get("budget"):
        budget_spec = dict(spec["budget"])
        need("sandbox_scp" not in budget_spec, "budget must not hold sandbox_scp; use the pack's spend key")
        try:
            generated = spend_guardrails.generate(budget_spec)
        except spend_guardrails.SpecError as exc:
            raise SpecError(f"budget: {exc}") from exc
        for name, content in generated["files"].items():
            files[f"budget/{name}"] = content
    files["README-sandbox-users.md"] = users_readme(cfg, spec, manifest)
    return {"files": files, "manifest": manifest, "lint_errors": [i for i in manifest["lint"] if i["level"] == "error"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sandbox_pack.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True, help="YAML or JSON sandbox spec")
    ap.add_argument("--out", help="directory to write the pack into")
    ap.add_argument("--json", action="store_true", help="print the pack as JSON")
    args = ap.parse_args(argv)
    try:
        result = build(load_spec(Path(args.spec)))
    except (SpecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.out and not result["lint_errors"]:
        out = Path(args.out)
        for name, content in result["files"].items():
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content if isinstance(content, str) else json.dumps(content, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for meta in result["manifest"]["documents"]:
            print(f"{meta['file']}: {meta['chars_compact']}/{result['manifest']['limit']} chars; {', '.join(meta['statements'])}")
        for w in result["manifest"]["warnings"]:
            print(f"warning: {w}")
        for issue in result["lint_errors"]:
            print(f"lint error: {issue['file']} {issue['id']} {issue['message']}")
        print(f"{len(result['files'])} file(s)" + (f" written to {args.out}" if args.out and not result["lint_errors"] else ""))
        print("Nothing is deployed. Review every file, and test the SCPs on an OU with one account first.")
    return 1 if result["lint_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
