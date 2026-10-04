#!/usr/bin/env python3
"""Plan or review least-privilege, auditable AWS access for an AI coding agent.

  agent_access.py plan --spec agent.yaml [--out DIR] [--json]
  agent_access.py review --role-json auth-details.json [--role-name NAME] [--get-role role.json] [--json] [--fail-on LEVEL]

plan reads a small YAML or JSON spec (agent name, operators, accounts, regions, session length, tasks) and writes:

  trust-policy-<account>.json   operators' identity-provider-backed roles (IAM Identity Center permission set or
                                listed role ARN patterns) may assume the agent role only with the session tags
                                agent and operator, a source identity, and a session name "<agent>@<operator>"
  permission-policy.json        allow statements built from a vetted allowlist per task type; never Action "*"
  permissions-boundary.json     caps the role: denies IAM, Organizations and account changes, CloudTrail, GuardDuty,
                                Security Hub and Config tampering, billing and purchase commitments, destructive
                                deletes and role chaining; iam:PassRole only for the named execution roles
  sandbox-scp.json              SCP snippet for the sandbox OU: the same denies keyed on the agent role ARN, plus
                                protection of the agent role and its boundary from everyone but the admin roles
  trust-policy-locked.json      trust policy that blocks new sessions (kill switch step 2)
  commands.md                   create commands to review, the aws sts assume-role command per operator, and the
                                kill switch procedure (revoke sessions with an inline deny on aws:TokenIssueTime)

Task types (spec "tasks", each with "type"):
  read-only-inventory  services: [ec2, s3, ...]          metadata reads only (no object, secret or parameter reads)
  deploy-stack         stack_name, execution_role_name   change sets on one CloudFormation stack, PassRole to the
                                                         execution role only; no DeleteStack
  invoke-lambda        function_name                     invoke one function and read its log group
  read-logs            log_group_prefix                  read CloudWatch Logs groups under one prefix
  read-s3-prefix       bucket, prefix                    list and get objects under one prefix

review reads `aws iam get-account-authorization-details --output json` (optionally with `aws iam get-role` output for
MaxSessionDuration) and checks one role against the same rules. Check ids and default severity:

  AGENT-ADMIN                  critical  Action "*" allowed, or AdministratorAccess, PowerUserAccess, IAMFullAccess
                                         or AWSOrganizationsFullAccess attached (evaluated from their main statement)
  AGENT-EFFECTIVE-RISK         critical  the role's policies allow an IAM, Organizations, logging-tampering, billing
                                         or destructive action and no boundary blocks it
  AGENT-TRUST-ANY-PRINCIPAL    critical  trust policy allows Principal "*" (high when a Condition is present)
  AGENT-TRUST-OIDC-NO-SUB      critical  web identity trust without a ":sub" condition
  AGENT-NO-BOUNDARY            high      no permissions boundary
  AGENT-BOUNDARY-GAP           high      the boundary does not block a category (medium for billing and destructive)
  AGENT-SERVICE-WILDCARD       high      Allow "<service>:*"
  AGENT-NOTACTION-ALLOW        high      Allow with NotAction
  AGENT-PASSROLE-ANY           high      iam:PassRole allowed on Resource "*"
  AGENT-WRITE-ON-ANY-RESOURCE  medium    a non-read action allowed on Resource "*"
  AGENT-DATA-READ-ANY          medium    object, secret, parameter, decrypt or table reads allowed on Resource "*"
  AGENT-ROLE-CHAINING          medium    sts:AssumeRole allowed on Resource "*"
  AGENT-LONG-SESSION           medium    MaxSessionDuration above 3600 seconds
  AGENT-TRUST-ACCOUNT-ROOT     medium    trust names an account root with no aws:PrincipalArn condition
  AGENT-TRUST-NO-SESSION-TAGS  medium    trust does not require the agent and operator session tags
  AGENT-TRUST-NO-SOURCE-IDENTITY low     trust does not require a source identity
  AGENT-POLICY-NOT-FOUND       info      an attached policy document is not in the export, so it was not evaluated
  AGENT-SESSION-UNKNOWN        info      MaxSessionDuration not known (pass --get-role)

Conditions are not evaluated: a statement counts as allowing its actions. SCPs and resource policies are not read.
Every generated policy must be reviewed by a human before use. The script never calls AWS.

Exit codes: plan 0 written, 1 the generated set fails its own review, 2 bad spec; review 0 no finding at or above
--fail-on (default high), 1 findings at or above it, 2 bad input.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402

LEVELS = ["critical", "high", "medium", "low", "info"]
MANAGED_POLICY_LIMIT = 6144
SCP_LIMIT = 5120
ROLE_CHAIN_MAX_SECONDS = 3600

# Metadata-only reads per service. Deliberately explicit: no Get* wildcards, which would include object, secret and
# parameter reads. ecs:DescribeTaskDefinition is left out because task definitions can carry environment values.
INVENTORY_ACTIONS: dict[str, list[str]] = {
    "cloudformation": ["cloudformation:DescribeStackEvents", "cloudformation:DescribeStackResources",
                       "cloudformation:DescribeStacks", "cloudformation:ListStackResources", "cloudformation:ListStacks"],
    "cloudwatch": ["cloudwatch:DescribeAlarms", "cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
    "dynamodb": ["dynamodb:DescribeTable", "dynamodb:ListTables", "dynamodb:ListTagsOfResource"],
    "ec2": ["ec2:DescribeAvailabilityZones", "ec2:DescribeImages", "ec2:DescribeInstances", "ec2:DescribeInternetGateways",
            "ec2:DescribeNatGateways", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRegions", "ec2:DescribeRouteTables",
            "ec2:DescribeSecurityGroups", "ec2:DescribeSnapshots", "ec2:DescribeSubnets", "ec2:DescribeTags",
            "ec2:DescribeVolumes", "ec2:DescribeVpcs"],
    "ecs": ["ecs:DescribeClusters", "ecs:DescribeServices", "ecs:ListClusters", "ecs:ListServices", "ecs:ListTaskDefinitions"],
    "eks": ["eks:DescribeCluster", "eks:DescribeNodegroup", "eks:ListClusters", "eks:ListNodegroups"],
    "iam": ["iam:GetPolicy", "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListPolicies", "iam:ListRolePolicies",
            "iam:ListRoles"],
    "lambda": ["lambda:GetFunctionConfiguration", "lambda:ListAliases", "lambda:ListFunctions", "lambda:ListTags",
               "lambda:ListVersionsByFunction"],
    "logs": ["logs:DescribeLogGroups"],
    "rds": ["rds:DescribeDBClusters", "rds:DescribeDBInstances", "rds:DescribeDBSubnetGroups", "rds:ListTagsForResource"],
    "s3": ["s3:GetBucketLocation", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging",
           "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:ListAllMyBuckets"],
    "sns": ["sns:GetTopicAttributes", "sns:ListTopics"],
    "sqs": ["sqs:GetQueueAttributes", "sqs:ListQueues"],
    "tag": ["tag:GetResources", "tag:GetTagKeys"],
}
GLOBAL_SERVICES = {"iam", "s3", "tag"}

IAM_WRITE = ["iam:Add*", "iam:Attach*", "iam:Change*", "iam:Create*", "iam:Deactivate*", "iam:Delete*", "iam:Detach*",
             "iam:Enable*", "iam:Put*", "iam:Remove*", "iam:Reset*", "iam:Resync*", "iam:Set*", "iam:Tag*", "iam:Untag*",
             "iam:Update*", "iam:Upload*"]
ORG_WRITE = ["account:*", "organizations:Accept*", "organizations:Attach*", "organizations:Cancel*", "organizations:Close*",
             "organizations:Create*", "organizations:Decline*", "organizations:Delete*", "organizations:Deregister*",
             "organizations:Detach*", "organizations:Disable*", "organizations:Enable*", "organizations:Invite*",
             "organizations:Leave*", "organizations:Move*", "organizations:Put*", "organizations:Register*",
             "organizations:Remove*", "organizations:Tag*", "organizations:Untag*", "organizations:Update*"]
TAMPERING = ["cloudtrail:DeleteEventDataStore", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors",
             "cloudtrail:PutInsightSelectors", "cloudtrail:StopEventDataStoreIngestion", "cloudtrail:StopLogging",
             "cloudtrail:UpdateEventDataStore", "cloudtrail:UpdateTrail", "config:DeleteConfigurationRecorder",
             "config:DeleteDeliveryChannel", "config:StopConfigurationRecorder", "guardduty:CreateFilter",
             "guardduty:CreateIPSet", "guardduty:DeleteDetector", "guardduty:DeleteMembers",
             "guardduty:DisassociateFromAdministratorAccount", "guardduty:DisassociateFromMasterAccount",
             "guardduty:DisassociateMembers", "guardduty:StopMonitoringMembers", "guardduty:UpdateDetector",
             "guardduty:UpdateFilter", "guardduty:UpdateIPSet", "securityhub:BatchDisableStandards",
             "securityhub:DisableSecurityHub", "securityhub:DisassociateFromAdministratorAccount"]
BILLING = ["aws-marketplace:Subscribe", "aws-portal:*", "billing:*", "budgets:CreateBudgetAction", "budgets:DeleteBudgetAction",
           "budgets:ExecuteBudgetAction", "budgets:ModifyBudget", "budgets:UpdateBudgetAction", "ce:Create*", "ce:Delete*",
           "ce:Update*", "cur:*", "ec2:PurchaseHostReservation", "ec2:PurchaseReservedInstancesOffering", "invoicing:*",
           "payments:*", "purchase-orders:*", "rds:PurchaseReservedDBInstancesOffering", "savingsplans:CreateSavingsPlan",
           "tax:*"]
DESTRUCTIVE = ["backup:DeleteBackupVault", "backup:DeleteRecoveryPoint", "cloudformation:DeleteStack", "dynamodb:DeleteBackup",
               "dynamodb:DeleteTable", "ec2:DeleteSnapshot", "ec2:DeleteVolume", "ec2:TerminateInstances", "ecs:DeleteCluster",
               "ecs:DeleteService", "eks:DeleteCluster", "eks:DeleteNodegroup", "elasticloadbalancing:DeleteLoadBalancer",
               "kms:DisableKey", "kms:ScheduleKeyDeletion", "lambda:DeleteFunction", "logs:DeleteLogGroup",
               "rds:DeleteDBCluster", "rds:DeleteDBClusterSnapshot", "rds:DeleteDBInstance", "rds:DeleteDBSnapshot",
               "route53:DeleteHostedZone", "s3:DeleteBucket"]
PROTECT_ROLE_ACTIONS = ["iam:AttachRolePolicy", "iam:DeleteRole", "iam:DeleteRolePermissionsBoundary", "iam:DeleteRolePolicy",
                        "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary", "iam:PutRolePolicy", "iam:TagRole",
                        "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole"]
PROTECT_POLICY_ACTIONS = ["iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"]

# Representative actions per category, used by review to test whether a policy set or boundary blocks the category.
CATEGORIES: dict[str, tuple[str, list[str]]] = {
    "iam-changes": ("high", ["iam:AttachRolePolicy", "iam:CreateAccessKey", "iam:CreateUser", "iam:DeleteRolePermissionsBoundary",
                             "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"]),
    "organizations-changes": ("high", ["organizations:CreateAccount", "organizations:DetachPolicy",
                                       "organizations:LeaveOrganization", "organizations:MoveAccount"]),
    "logging-tampering": ("high", ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "guardduty:CreateIPSet",
                                   "guardduty:DeleteDetector", "guardduty:UpdateDetector"]),
    "billing": ("medium", ["aws-portal:ModifyAccount", "aws-portal:ModifyBilling", "aws-portal:ModifyPaymentMethods",
                           "budgets:ModifyBudget", "savingsplans:CreateSavingsPlan"]),
    "destructive": ("medium", ["cloudformation:DeleteStack", "dynamodb:DeleteTable", "ec2:TerminateInstances",
                               "rds:DeleteDBCluster", "rds:DeleteDBInstance", "s3:DeleteBucket"]),
}
# Broad AWS managed policies, approximated by their main statement so review can evaluate them without the document.
ADMIN_MANAGED: dict[str, dict] = {
    "AdministratorAccess": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "PowerUserAccess": {"Statement": [{"Effect": "Allow", "NotAction": ["account:*", "iam:*", "organizations:*"], "Resource": "*"}]},
    "IAMFullAccess": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]},
    "AWSOrganizationsFullAccess": {"Statement": [{"Effect": "Allow", "Action": "organizations:*", "Resource": "*"}]},
}
DATA_READS = ["dynamodb:BatchGetItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "kms:Decrypt", "s3:GetObject",
              "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
READ_PREFIXES = ("Describe", "List", "Get", "BatchGet", "Search", "Lookup", "Validate", "Filter")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
OPERATOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+=,.@_-]{1,39}$")
ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
STACK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
FUNCTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
LOG_PREFIX_RE = re.compile(r"^[A-Za-z0-9_./#-]{1,400}$")
S3_PREFIX_RE = re.compile(r"^[A-Za-z0-9!_.'()/-]{1,400}$")
PERMSET_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,32}$")
TASK_TYPES = ("read-only-inventory", "deploy-stack", "invoke-lambda", "read-logs", "read-s3-prefix")
SPEC_KEYS = {"agent_name", "operators", "accounts", "regions", "session_minutes", "trust", "tasks", "role_name",
             "boundary_name", "admin_roles"}


class SpecError(Exception):
    pass


def compact(doc) -> str:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ---------------------------------------------------------------------------------------------------------------- plan


def load_spec(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise SpecError(f"{path}: cannot parse: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError(f"{path}: the spec must be a mapping")
    return data


def need(cond: bool, message: str) -> None:
    if not cond:
        raise SpecError(message)


def validate_spec(spec: dict) -> dict:
    unknown = set(spec) - SPEC_KEYS
    need(not unknown, f"unknown spec keys: {', '.join(sorted(unknown))}")
    agent = spec.get("agent_name")
    need(isinstance(agent, str) and bool(NAME_RE.match(agent)), "agent_name must be lowercase letters, digits and hyphens")
    operators = spec.get("operators")
    need(isinstance(operators, list) and bool(operators), "operators must list the people allowed to start the agent")
    for op in operators:
        need(isinstance(op, str) and bool(OPERATOR_RE.match(op)), f"operator {op!r}: use 2 to 40 of A-Z a-z 0-9 + = , . @ _ -")
        need(len(f"{agent}@{op}") <= 64, f"session name {agent}@{op} is over 64 characters")
    accounts = spec.get("accounts")
    need(isinstance(accounts, list) and bool(accounts), "accounts must list at least one 12-digit account id")
    for acct in accounts:
        need(isinstance(acct, str) and bool(ACCOUNT_RE.match(acct)), f"account {acct!r} is not a 12-digit string (quote it)")
    regions = spec.get("regions")
    need(isinstance(regions, list) and bool(regions), "regions must list at least one region")
    for r in regions:
        need(isinstance(r, str) and bool(REGION_RE.match(r)), f"region {r!r} is not a region name")
    minutes = spec.get("session_minutes", 60)
    need(isinstance(minutes, int) and 15 <= minutes <= 60,
         "session_minutes must be 15 to 60 (a chained role session cannot exceed one hour)")
    trust = spec.get("trust") or {}
    need(isinstance(trust, dict), "trust must be a mapping")
    permset = trust.get("permission_set")
    patterns = trust.get("operator_role_arn_patterns") or []
    need(bool(permset) != bool(patterns), "trust needs exactly one of permission_set or operator_role_arn_patterns")
    if permset:
        need(isinstance(permset, str) and bool(PERMSET_RE.match(permset)), f"permission_set {permset!r} is not a valid name")
    for p in patterns:
        need(isinstance(p, str) and p.startswith("arn:aws:iam::") and ":role/" in p and p.strip() != "arn:aws:iam::*:role/*",
             f"operator_role_arn_patterns entry {p!r} must be a role ARN pattern narrower than every role")
    admins = spec.get("admin_roles")
    need(isinstance(admins, list) and bool(admins),
         "admin_roles must name the admin or break-glass roles that may change or stop the agent role")
    for a in admins:
        need(isinstance(a, str) and bool(re.match(r"^[A-Za-z0-9+=,.@_*-]{1,64}$", a)), f"admin role {a!r} is not a role name")
    for key in ("role_name", "boundary_name"):
        if key in spec:
            need(isinstance(spec[key], str) and bool(ROLE_NAME_RE.match(spec[key])), f"{key} is not a valid IAM name")
    tasks = spec.get("tasks")
    need(isinstance(tasks, list) and bool(tasks), "tasks must list at least one task")
    for i, t in enumerate(tasks):
        need(isinstance(t, dict) and t.get("type") in TASK_TYPES, f"tasks[{i}].type must be one of {', '.join(TASK_TYPES)}")
        kind = t["type"]
        if kind == "read-only-inventory":
            services = t.get("services")
            need(isinstance(services, list) and bool(services), f"tasks[{i}]: services must be a non-empty list")
            for s in services:
                need(s in INVENTORY_ACTIONS, f"tasks[{i}]: no vetted inventory allowlist for service {s!r} "
                                             f"(known: {', '.join(sorted(INVENTORY_ACTIONS))})")
        elif kind == "deploy-stack":
            need(bool(STACK_RE.match(str(t.get("stack_name", "")))), f"tasks[{i}]: stack_name is not a CloudFormation stack name")
            need(bool(ROLE_NAME_RE.match(str(t.get("execution_role_name", "")))),
                 f"tasks[{i}]: execution_role_name must name the CloudFormation service role")
        elif kind == "invoke-lambda":
            need(bool(FUNCTION_RE.match(str(t.get("function_name", "")))), f"tasks[{i}]: function_name is not a function name")
        elif kind == "read-logs":
            prefix = str(t.get("log_group_prefix", ""))
            need(bool(LOG_PREFIX_RE.match(prefix)) and len(prefix.strip("/")) >= 2,
                 f"tasks[{i}]: log_group_prefix must be a specific prefix such as /aws/lambda/example-")
        elif kind == "read-s3-prefix":
            need(bool(BUCKET_RE.match(str(t.get("bucket", "")))), f"tasks[{i}]: bucket is not a bucket name")
            need(bool(S3_PREFIX_RE.match(str(t.get("prefix", "")))), f"tasks[{i}]: prefix must be a non-empty key prefix without *")
    return {
        "agent": agent, "operators": operators, "accounts": accounts, "regions": regions, "minutes": minutes,
        "permission_set": permset, "patterns": patterns, "admins": admins, "tasks": tasks,
        "role": spec.get("role_name", f"agent-{agent}"), "boundary": spec.get("boundary_name", f"agent-{agent}-boundary"),
    }


def regional(cfg: dict) -> dict:
    return {"StringEquals": {"aws:RequestedRegion": cfg["regions"]}}


def task_statements(cfg: dict) -> tuple[list[dict], list[str]]:
    """Allow statements for every task, and the execution role ARNs that iam:PassRole may target."""
    out: list[dict] = []
    pass_roles: list[str] = []
    accts, regions = cfg["accounts"], cfg["regions"]

    def arns(fmt: str) -> list[str]:
        return [fmt.format(a=a, r=r) for a in accts for r in regions]

    for n, t in enumerate(cfg["tasks"], 1):
        kind = t["type"]
        if kind == "read-only-inventory":
            for svc in sorted(set(t["services"])):
                st = {"Sid": f"T{n}Inventory{svc.title().replace('-', '')}", "Effect": "Allow",
                      "Action": INVENTORY_ACTIONS[svc], "Resource": "*"}
                if svc not in GLOBAL_SERVICES:
                    st["Condition"] = regional(cfg)
                out.append(st)
        elif kind == "deploy-stack":
            stack, exec_role = t["stack_name"], t["execution_role_name"]
            out.append({"Sid": f"T{n}DeployStackChangeSets", "Effect": "Allow",
                        "Action": ["cloudformation:CreateChangeSet", "cloudformation:DeleteChangeSet",
                                   "cloudformation:DescribeChangeSet", "cloudformation:DescribeStackEvents",
                                   "cloudformation:DescribeStackResources", "cloudformation:DescribeStacks",
                                   "cloudformation:ExecuteChangeSet", "cloudformation:GetTemplate",
                                   "cloudformation:ListChangeSets"],
                        "Resource": arns("arn:aws:cloudformation:{r}:{a}:stack/" + stack + "/*")
                        + arns("arn:aws:cloudformation:{r}:{a}:changeSet/" + cfg["agent"] + "-*/*")})
            out.append({"Sid": f"T{n}ValidateTemplates", "Effect": "Allow", "Action": "cloudformation:ValidateTemplate",
                        "Resource": "*", "Condition": regional(cfg)})
            role_arns = [f"arn:aws:iam::{a}:role/{exec_role}" for a in accts]
            pass_roles += role_arns
            out.append({"Sid": f"T{n}PassExecutionRoleToCloudFormation", "Effect": "Allow", "Action": "iam:PassRole",
                        "Resource": role_arns,
                        "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}}})
        elif kind == "invoke-lambda":
            fn = t["function_name"]
            out.append({"Sid": f"T{n}InvokeFunction", "Effect": "Allow",
                        "Action": ["lambda:GetFunctionConfiguration", "lambda:InvokeFunction"],
                        "Resource": arns("arn:aws:lambda:{r}:{a}:function:" + fn) + arns("arn:aws:lambda:{r}:{a}:function:" + fn + ":*")})
            out.append({"Sid": f"T{n}ReadFunctionLogs", "Effect": "Allow",
                        "Action": ["logs:DescribeLogStreams", "logs:FilterLogEvents", "logs:GetLogEvents"],
                        "Resource": arns("arn:aws:logs:{r}:{a}:log-group:/aws/lambda/" + fn)
                        + arns("arn:aws:logs:{r}:{a}:log-group:/aws/lambda/" + fn + ":*")})
        elif kind == "read-logs":
            prefix = t["log_group_prefix"]
            out.append({"Sid": f"T{n}ReadLogGroups", "Effect": "Allow",
                        "Action": ["logs:DescribeLogStreams", "logs:FilterLogEvents", "logs:GetLogEvents", "logs:StartQuery"],
                        "Resource": arns("arn:aws:logs:{r}:{a}:log-group:" + prefix + "*")})
            out.append({"Sid": f"T{n}LogQueryResults", "Effect": "Allow",
                        "Action": ["logs:DescribeLogGroups", "logs:GetQueryResults"], "Resource": "*", "Condition": regional(cfg)})
        elif kind == "read-s3-prefix":
            bucket, prefix = t["bucket"], t["prefix"]
            out.append({"Sid": f"T{n}ListPrefix", "Effect": "Allow", "Action": "s3:ListBucket",
                        "Resource": f"arn:aws:s3:::{bucket}", "Condition": {"StringLike": {"s3:prefix": [f"{prefix}*"]}}})
            out.append({"Sid": f"T{n}ReadPrefix", "Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{prefix}*"})
    return out, pass_roles


def trust_policy(cfg: dict, account: str) -> dict:
    if cfg["permission_set"]:
        patterns = [f"arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_{cfg['permission_set']}_*"]
    else:
        patterns = cfg["patterns"]
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "OperatorsStartAgentSessions", "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
        "Condition": {
            "ArnLike": {"aws:PrincipalArn": patterns},
            "StringEquals": {"aws:RequestTag/agent": cfg["agent"], "aws:RequestTag/operator": cfg["operators"],
                             "sts:SourceIdentity": cfg["operators"]},
            "StringLike": {"sts:RoleSessionName": f"{cfg['agent']}@*"},
            "ForAllValues:StringEquals": {"aws:TagKeys": ["agent", "operator"]},
        }}]}


def locked_trust_policy() -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Sid": "KillSwitchNoNewSessions", "Effect": "Deny",
                                                    "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}


def boundary_policy(cfg: dict, permission: dict, pass_roles: list[str]) -> dict:
    services = sorted({a.split(":")[0] for st in permission["Statement"] for a in as_list(st.get("Action"))})
    passrole = {"Sid": "DenyPassRoleExceptExecutionRoles", "Effect": "Deny", "Action": "iam:PassRole"}
    if pass_roles:
        passrole["NotResource"] = pass_roles
    else:
        passrole["Resource"] = "*"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "BoundaryAllowPlannedServices", "Effect": "Allow", "Action": [f"{s}:*" for s in services], "Resource": "*"},
        {"Sid": "DenyIamChanges", "Effect": "Deny", "Action": IAM_WRITE, "Resource": "*"},
        passrole,
        {"Sid": "DenyOrganizationsAndAccountChanges", "Effect": "Deny", "Action": ORG_WRITE, "Resource": "*"},
        {"Sid": "DenyLoggingAndDetectionTampering", "Effect": "Deny", "Action": TAMPERING, "Resource": "*"},
        {"Sid": "DenyBillingAndCommitments", "Effect": "Deny", "Action": BILLING, "Resource": "*"},
        {"Sid": "DenyDestructiveDeletes", "Effect": "Deny", "Action": DESTRUCTIVE, "Resource": "*"},
        {"Sid": "DenyRoleChaining", "Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"},
    ]}


def sandbox_scp(cfg: dict) -> dict:
    agent_arn = f"arn:aws:iam::*:role/{cfg['role']}"
    is_agent = {"ArnLike": {"aws:PrincipalArn": agent_arn}}
    not_admin = {"ArnNotLike": {"aws:PrincipalArn": [f"arn:aws:iam::*:role/{a}" for a in cfg["admins"]]}}
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AgentDenyIamOrgChanges", "Effect": "Deny", "Action": IAM_WRITE + ORG_WRITE, "Resource": "*", "Condition": is_agent},
        {"Sid": "AgentDenyTampering", "Effect": "Deny", "Action": TAMPERING, "Resource": "*", "Condition": is_agent},
        {"Sid": "AgentDenyBilling", "Effect": "Deny", "Action": BILLING, "Resource": "*", "Condition": is_agent},
        {"Sid": "AgentDenyDestructive", "Effect": "Deny", "Action": DESTRUCTIVE, "Resource": "*", "Condition": is_agent},
        {"Sid": "ProtectAgentRole", "Effect": "Deny", "Action": PROTECT_ROLE_ACTIONS, "Resource": agent_arn, "Condition": not_admin},
        {"Sid": "ProtectAgentBoundary", "Effect": "Deny", "Action": PROTECT_POLICY_ACTIONS,
         "Resource": f"arn:aws:iam::*:policy/{cfg['boundary']}", "Condition": not_admin},
    ]}


def commands_md(cfg: dict) -> str:
    role, agent, boundary = cfg["role"], cfg["agent"], cfg["boundary"]
    perm_name = f"agent-{agent}-permissions"
    seconds = cfg["minutes"] * 60
    lines = [
        f"# Agent access for {agent}",
        "",
        "Generated by agent_access.py. A person must review every policy in this folder before anything is created.",
        "None of these commands has been run. Run them yourself, one at a time, from an admin session.",
        "",
        "## 1. Create the role (review first)",
        "",
    ]
    for acct in cfg["accounts"]:
        lines += [
            f"Account {acct}:",
            "",
            "```bash",
            f"aws iam create-policy --policy-name {boundary} --policy-document file://permissions-boundary.json",
            f"aws iam create-policy --policy-name {perm_name} --policy-document file://permission-policy.json",
            f"aws iam create-role --role-name {role} --assume-role-policy-document file://trust-policy-{acct}.json "
            f"--max-session-duration {ROLE_CHAIN_MAX_SECONDS} --permissions-boundary arn:aws:iam::{acct}:policy/{boundary} "
            f"--tags Key=agent,Value={agent}",
            f"aws iam attach-role-policy --role-name {role} --policy-arn arn:aws:iam::{acct}:policy/{perm_name}",
            "```",
            "",
        ]
    lines += [
        "Attach `sandbox-scp.json` to the sandbox OU from the management account only after testing it on an OU with one",
        "account. It denies the same actions to the agent role even if someone later widens the role's policies.",
        "",
        "## 2. Start an agent session",
        "",
        f"The session name is `{agent}@<operator>`, so every CloudTrail event names the agent and the person who started it.",
        "The operator signs in through the identity provider first, then runs:",
        "",
    ]
    for acct in cfg["accounts"]:
        for op in cfg["operators"]:
            lines += [
                "```bash",
                "read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN < <(aws sts assume-role \\",
                f"  --role-arn arn:aws:iam::{acct}:role/{role} \\",
                f"  --role-session-name '{agent}@{op}' \\",
                f"  --source-identity '{op}' \\",
                f"  --tags Key=agent,Value={agent} Key=operator,Value={op} \\",
                f"  --duration-seconds {seconds} \\",
                "  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)",
                "export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
                "aws sts get-caller-identity --output json",
                "```",
                "",
            ]
    lines += [
        f"The caller identity must end in `assumed-role/{role}/{agent}@<operator>`. Start the agent from this shell only, and",
        "do not write the credentials to a file.",
        "",
        "## 3. Kill switch",
        "",
        "Run as one of the admin roles exempted in `sandbox-scp.json`. Step 1 makes every session issued before now fail on",
        "its next call; it is the same policy the IAM console's \"Revoke active sessions\" button writes.",
        "",
        "```bash",
        "NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions --policy-document "
        "\"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Deny\\\",\\\"Action\\\":\\\"*\\\","
        "\\\"Resource\\\":\\\"*\\\",\\\"Condition\\\":{\\\"DateLessThan\\\":{\\\"aws:TokenIssueTime\\\":\\\"$NOW\\\"}}}]}\"",
        "```",
        "",
        "Step 2, block new sessions until the review is done:",
        "",
        "```bash",
        f"aws iam update-assume-role-policy --role-name {role} --policy-document file://trust-policy-locked.json",
        "```",
        "",
        "Step 3, stop the agent process on the operator's machine and confirm the revoke policy is in place:",
        "",
        "```bash",
        f"aws iam get-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions --output json",
        "```",
        "",
        "Step 4, find what the sessions did. CloudTrail Lake or Athena over the trail (replace the table name):",
        "",
        "```sql",
        "SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, errorcode,",
        "       useridentity.sessioncontext.sourceidentity AS operator",
        "FROM cloudtrail_logs",
        f"WHERE useridentity.arn LIKE '%:assumed-role/{role}/{agent}@%'",
        "ORDER BY eventtime",
        "```",
        "",
        "Restore: re-apply `trust-policy-<account>.json` with `update-assume-role-policy`. Delete the",
        f"`AWSRevokeOlderSessions` inline policy only after the maximum session length ({cfg['minutes']} minutes) has passed,",
        "otherwise sessions issued before the revoke work again:",
        "",
        "```bash",
        f"aws iam delete-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions",
        "```",
        "",
    ]
    return "\n".join(lines)


def plan(spec: dict) -> dict:
    cfg = validate_spec(spec)
    statements, pass_roles = task_statements(cfg)
    sids = [s["Sid"] for s in statements]
    need(len(sids) == len(set(sids)), "two tasks produce the same statement id; merge duplicate tasks")
    permission = {"Version": "2012-10-17", "Statement": statements}
    boundary = boundary_policy(cfg, permission, pass_roles)
    trusts = {acct: trust_policy(cfg, acct) for acct in cfg["accounts"]}
    scp = sandbox_scp(cfg)
    warnings: list[str] = []
    sizes = {"permission-policy.json": len(compact(permission)), "permissions-boundary.json": len(compact(boundary)),
             "sandbox-scp.json": len(compact(scp))}
    for name in ("permission-policy.json", "permissions-boundary.json"):
        if sizes[name] > MANAGED_POLICY_LIMIT:
            warnings.append(f"{name} is {sizes[name]} characters compact, over the {MANAGED_POLICY_LIMIT} managed policy "
                            "limit; split the tasks across two policies")
    if sizes["sandbox-scp.json"] > SCP_LIMIT:
        warnings.append(f"sandbox-scp.json is {sizes['sandbox-scp.json']} characters, over the {SCP_LIMIT} SCP limit")
    if any(t["type"] == "deploy-stack" for t in cfg["tasks"]):
        warnings.append("deploy-stack: the execution role decides what the stack can create or delete; scope it, turn on "
                        "termination protection and set DeletionPolicy Retain on stateful resources")
    if any(t["type"] == "read-only-inventory" and "lambda" in t["services"] for t in cfg["tasks"]):
        warnings.append("lambda inventory returns function environment variables; keep secrets out of them")
    findings = review_role(trusts[cfg["accounts"][0]], [("permission-policy", permission)], boundary,
                           ROLE_CHAIN_MAX_SECONDS, [])
    return {"agent": cfg["agent"], "role_name": cfg["role"], "boundary_name": cfg["boundary"],
            "session_name_convention": f"{cfg['agent']}@<operator>", "session_seconds": cfg["minutes"] * 60,
            "files": {**{f"trust-policy-{a}.json": d for a, d in trusts.items()},
                      "permission-policy.json": permission, "permissions-boundary.json": boundary,
                      "sandbox-scp.json": scp, "trust-policy-locked.json": locked_trust_policy()},
            "commands_md": commands_md(cfg), "sizes_compact": sizes, "warnings": warnings, "self_review": findings}


# -------------------------------------------------------------------------------------------------------------- review


def finding(check: str, severity: str, message: str, where: str = "") -> dict:
    return {"id": check, "severity": severity, "where": where, "message": message}


def matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def statement_allows(st: dict, action: str) -> bool:
    if "NotAction" in st:
        return not any(matches(p, action) for p in as_list(st["NotAction"]))
    return any(matches(p, action) for p in as_list(st.get("Action")))


def statements(doc) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def allowed_by(docs: list[dict], action: str) -> bool:
    """Ignoring conditions and resources: some Allow matches and no unconditional Deny on "*" matches."""
    allow = any(s.get("Effect") == "Allow" and statement_allows(s, action) for d in docs for s in statements(d))
    deny = any(s.get("Effect") == "Deny" and statement_allows(s, action) and not s.get("Condition")
               and "*" in as_list(s.get("Resource")) for d in docs for s in statements(d))
    return allow and not deny


def is_read(action: str) -> bool:
    name = action.split(":", 1)[-1]
    return name.startswith(READ_PREFIXES) and "*" not in name


def review_permissions(name: str, doc: dict) -> list[dict]:
    out: list[dict] = []
    for i, st in enumerate(statements(doc)):
        if st.get("Effect") != "Allow":
            continue
        where = f"{name}:{st.get('Sid') or f'#{i}'}"
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = as_list(st.get("Resource"))
        any_resource = "*" in resources
        if "NotAction" in st:
            out.append(finding("AGENT-NOTACTION-ALLOW", "high", "Allow with NotAction allows every action not listed", where))
            continue
        if "*" in actions:
            out.append(finding("AGENT-ADMIN", "critical", "Action \"*\" is allowed: the agent can do anything the boundary "
                                                          "and SCPs do not deny", where))
            continue
        wild = [a for a in actions if a.endswith(":*")]
        if wild:
            out.append(finding("AGENT-SERVICE-WILDCARD", "high", f"service wildcard {', '.join(wild)}: list the actions "
                                                                 "the task needs", where))
        if any_resource:
            if any(matches(a, "iam:PassRole") for a in actions):
                out.append(finding("AGENT-PASSROLE-ANY", "high", "iam:PassRole on any role lets the agent hand any role to a "
                                                                 "service it can create", where))
            if any(matches(a, "sts:AssumeRole") for a in actions):
                out.append(finding("AGENT-ROLE-CHAINING", "medium", "sts:AssumeRole on any role lets the agent hop to roles "
                                                                    "outside this review", where))
            data = sorted({d for d in DATA_READS for a in actions if matches(a, d)})
            if data:
                out.append(finding("AGENT-DATA-READ-ANY", "medium", f"data reads on any resource: {', '.join(data)}", where))
            writes = [a for a in actions if not is_read(a) and not a.endswith(":*")
                      and not matches(a, "iam:PassRole") and not matches(a, "sts:AssumeRole")]
            if writes:
                out.append(finding("AGENT-WRITE-ON-ANY-RESOURCE", "medium",
                                   f"non-read actions on Resource \"*\": {', '.join(writes[:8])}", where))
    return out


def principal_values(st: dict) -> tuple[list[str], list[str]]:
    p = st.get("Principal")
    if p == "*":
        return ["*"], []
    if not isinstance(p, dict):
        return [], []
    return [str(x) for x in as_list(p.get("AWS"))], [str(x) for x in as_list(p.get("Federated"))]


def condition_keys(st: dict) -> set[str]:
    keys: set[str] = set()
    for kv in (st.get("Condition") or {}).values():
        if isinstance(kv, dict):
            keys |= {k.lower() for k in kv}
    return keys


def review_trust(doc: dict) -> list[dict]:
    out: list[dict] = []
    allows = [s for s in statements(doc) if s.get("Effect") == "Allow"]
    tagged = sourced = False
    for i, st in enumerate(allows):
        where = f"trust:{st.get('Sid') or f'#{i}'}"
        aws, federated = principal_values(st)
        keys = condition_keys(st)
        if "*" in aws:
            sev = "high" if st.get("Condition") else "critical"
            out.append(finding("AGENT-TRUST-ANY-PRINCIPAL", sev, "trust allows any AWS principal", where))
        if any(re.match(r"^(arn:aws[a-z-]*:iam::\d{12}:root|\d{12})$", a) for a in aws) and "aws:principalarn" not in keys:
            out.append(finding("AGENT-TRUST-ACCOUNT-ROOT", "medium", "trust names an account root without an aws:PrincipalArn "
                                                                     "condition, so any principal there with sts:AssumeRole "
                                                                     "can start agent sessions", where))
        if any(":oidc-provider/" in f for f in federated) and not any(k.endswith(":sub") for k in keys):
            out.append(finding("AGENT-TRUST-OIDC-NO-SUB", "critical", "web identity trust without a :sub condition lets "
                                                                      "any workload of that provider assume the role", where))
        if {"aws:requesttag/agent", "aws:requesttag/operator"} <= keys:
            tagged = True
        if "sts:sourceidentity" in keys:
            sourced = True
    if allows and not tagged:
        out.append(finding("AGENT-TRUST-NO-SESSION-TAGS", "medium", "trust does not require the agent and operator session "
                                                                    "tags, so sessions are not attributable", "trust"))
    if allows and not sourced:
        out.append(finding("AGENT-TRUST-NO-SOURCE-IDENTITY", "low", "trust does not require a source identity naming the "
                                                                    "operator", "trust"))
    return out


def review_role(trust: dict, policies: list[tuple[str, dict]], boundary: dict | None, max_session: int | None,
                attached_names: list[str]) -> list[dict]:
    out: list[dict] = []
    for name in attached_names:
        if name in ADMIN_MANAGED:
            out.append(finding("AGENT-ADMIN", "critical", f"AWS managed policy {name} is attached", name))
    for name, doc in policies:
        out += review_permissions(name, doc)
    out += review_trust(trust)
    perm_docs = [d for _, d in policies] + [ADMIN_MANAGED[n] for n in attached_names if n in ADMIN_MANAGED]
    for cat, (gap_sev, reps) in CATEGORIES.items():
        can = [a for a in reps if allowed_by(perm_docs, a)]
        blocked = [a for a in reps if boundary is not None and not allowed_by([boundary], a)]
        effective = [a for a in can if a not in blocked]
        if effective:
            out.append(finding("AGENT-EFFECTIVE-RISK", "critical",
                               f"{cat}: the role's policies allow {', '.join(effective[:4])} and no boundary blocks it", cat))
        if boundary is not None and len(blocked) < len(reps):
            missing = [a for a in reps if a not in blocked]
            out.append(finding("AGENT-BOUNDARY-GAP", gap_sev, f"{cat}: the boundary does not block {', '.join(missing[:4])}", cat))
    if boundary is None:
        out.append(finding("AGENT-NO-BOUNDARY", "high", "no permissions boundary: nothing caps what a later policy change "
                                                        "grants the agent", "role"))
    if max_session is None:
        out.append(finding("AGENT-SESSION-UNKNOWN", "info", "MaxSessionDuration not in the export; pass --get-role", "role"))
    elif max_session > ROLE_CHAIN_MAX_SECONDS:
        out.append(finding("AGENT-LONG-SESSION", "medium", f"MaxSessionDuration is {max_session} seconds; keep agent sessions "
                                                           f"at {ROLE_CHAIN_MAX_SECONDS} or less", "role"))
    out.sort(key=lambda f: (LEVELS.index(f["severity"]), f["id"], f["where"]))
    return out


def as_document(value):
    if isinstance(value, str):
        try:
            return json.loads(urllib.parse.unquote(value))
        except json.JSONDecodeError:
            return None
    return value


def review_export(data: dict, role_name: str | None, get_role: dict | None) -> dict:
    roles = data.get("RoleDetailList") if isinstance(data, dict) else None
    if not isinstance(roles, list) or not roles:
        raise ValueError("no RoleDetailList: pass the output of aws iam get-account-authorization-details")
    if role_name:
        picked = [r for r in roles if r.get("RoleName") == role_name]
        if not picked:
            raise ValueError(f"role {role_name!r} is not in the export")
        role = picked[0]
    elif len(roles) == 1:
        role = roles[0]
    else:
        raise ValueError(f"{len(roles)} roles in the export; pass --role-name")
    managed = {}
    for p in data.get("Policies") or []:
        doc = next((as_document(v.get("Document")) for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        managed[p.get("Arn")] = (p.get("PolicyName"), doc)
    findings: list[dict] = []
    policies: list[tuple[str, dict]] = []
    for p in role.get("RolePolicyList") or []:
        doc = as_document(p.get("PolicyDocument"))
        if isinstance(doc, dict):
            policies.append((f"inline/{p.get('PolicyName')}", doc))
    attached_names = []
    for p in role.get("AttachedManagedPolicies") or []:
        arn, name = p.get("PolicyArn"), p.get("PolicyName")
        attached_names.append(name)
        if arn in managed and isinstance(managed[arn][1], dict):
            policies.append((f"managed/{name}", managed[arn][1]))
        elif name not in ADMIN_MANAGED:
            findings.append(finding("AGENT-POLICY-NOT-FOUND", "info", f"document for {arn} is not in the export; add "
                                                                      "--filter LocalManagedPolicy AWSManagedPolicy", name))
    boundary = None
    pb = role.get("PermissionsBoundary") or {}
    if pb.get("PermissionsBoundaryArn"):
        arn = pb["PermissionsBoundaryArn"]
        if arn in managed and isinstance(managed[arn][1], dict):
            boundary = managed[arn][1]
        else:
            findings.append(finding("AGENT-POLICY-NOT-FOUND", "info", f"boundary {arn} is not in the export; it was treated "
                                                                      "as allowing everything", "boundary"))
            boundary = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    max_session = role.get("MaxSessionDuration")
    if get_role:
        max_session = (get_role.get("Role") or {}).get("MaxSessionDuration", max_session)
    trust = as_document(role.get("AssumeRolePolicyDocument")) or {}
    findings += review_role(trust, policies, boundary, max_session, attached_names)
    findings.sort(key=lambda f: (LEVELS.index(f["severity"]), f["id"], f["where"]))
    return {"role": role.get("RoleName"), "arn": role.get("Arn"), "policies_evaluated": [n for n, _ in policies],
            "boundary": pb.get("PermissionsBoundaryArn"), "max_session_seconds": max_session, "findings": findings}


# ---------------------------------------------------------------------------------------------------------------- main


def write_plan(result: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, doc in result["files"].items():
        (out / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (out / "commands.md").write_text(result["commands_md"], encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent_access.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="generate trust, permission, boundary and SCP documents from a spec")
    p.add_argument("--spec", required=True, help="YAML or JSON spec")
    p.add_argument("--out", help="directory to write the documents and commands.md into")
    p.add_argument("--json", action="store_true", help="print everything as JSON")
    r = sub.add_parser("review", help="review an exported agent role against the same rules")
    r.add_argument("--role-json", required=True, help="output of aws iam get-account-authorization-details --output json")
    r.add_argument("--role-name", help="role to review when the export holds several")
    r.add_argument("--get-role", help="output of aws iam get-role --output json, for MaxSessionDuration")
    r.add_argument("--fail-on", choices=LEVELS, default="high", help="exit 1 at or above this severity (default high)")
    r.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)

    if args.cmd == "plan":
        try:
            result = plan(load_spec(Path(args.spec)))
        except (SpecError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.out:
            write_plan(result, Path(args.out))
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"agent {result['agent']}: role {result['role_name']}, boundary {result['boundary_name']}, "
                  f"session name {result['session_name_convention']}, {result['session_seconds']} s sessions")
            for name, size in result["sizes_compact"].items():
                print(f"  {name}: {size} characters compact")
            for w in result["warnings"]:
                print(f"warning: {w}")
            for f in result["self_review"]:
                print(f"self-review {f['severity']}: {f['id']} {f['message']}")
            if args.out:
                print(f"wrote {len(result['files'])} policy files and commands.md to {args.out}")
            print("A person must review every generated policy before it is created or attached.")
        return 1 if any(f["severity"] != "info" for f in result["self_review"]) else 0

    try:
        data = json.loads(Path(args.role_json).read_text(encoding="utf-8"))
        get_role = json.loads(Path(args.get_role).read_text(encoding="utf-8")) if args.get_role else None
        report = review_export(data, args.role_name, get_role)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"role {report['role']} ({report['arn']}): {len(report['findings'])} finding(s)")
        print(f"  evaluated: {', '.join(report['policies_evaluated']) or 'no policy documents'}; "
              f"boundary: {report['boundary'] or 'none'}; max session: {report['max_session_seconds'] or 'unknown'}")
        for f in report["findings"]:
            print(f"  {f['severity']:<8} {f['id']:<30} {f['where']:<40} {f['message']}")
    threshold = LEVELS.index(args.fail_on)
    return 1 if any(LEVELS.index(f["severity"]) <= threshold for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
