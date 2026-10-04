#!/usr/bin/env python3
"""Generate AWS spend guardrails from a budget spec, or review exported Cost Explorer data against it.

  spend_guardrails.py --budget budget.yaml [--out DIR] [--json]
  spend_guardrails.py review --cost-explorer cost.json [cost-page2.json ...] [--budget budget.yaml]
                      [--factor 3] [--window 7] [--min-amount 5] [--fail-on medium] [--json]

Generate writes (each only when its spec key is set):

  budget-cost.json, notifications-cost.json    monthly COST budget with ACTUAL and FORECASTED percentage alerts
  budget-usage-<name>.json, notifications-usage-<name>.json   USAGE budgets (for example EC2 running hours)
  anomaly-monitor.json, anomaly-subscription.json   Cost Anomaly Detection monitor (by service or linked account) and
                                                    an alert subscription with absolute and percentage thresholds
  spend-scp-NN.json, spend-scp-manifest.json    sandbox SCP denies: expensive instance types (deny list or allow
                                                list), EBS IOPS above a ceiling and provisioned IOPS volume types,
                                                SageMaker GPU instance types, Bedrock model customization and
                                                provisioned throughput, whole services (for example redshift),
                                                reserved capacity and Savings Plans purchases, and changes to
                                                budgets, budget actions and anomaly monitors (protected roles exempt)
  commands.md                                   the aws commands that would create them, for review

Budget spec keys: name_prefix, currency (default USD), budget_account (where the budget lives), accounts (linked
account filter, optional), monthly_limit, thresholds (percent, actual), forecast_thresholds (percent), notify_emails,
sns_topic_arn, usage_budgets [{name, usage_type_group, limit, unit}], anomaly {monitor: services | linked-accounts,
threshold_absolute, threshold_percent, frequency: DAILY | WEEKLY | IMMEDIATE}, review {factor, window_days,
min_amount}, sandbox_scp {protected_roles, deny_instance_types | allowed_instance_types, max_volume_iops,
deny_volume_types, sagemaker_instance_types, deny_bedrock_customization, deny_services, deny_commitments,
protect_budgets}.

review reads `aws ce get-cost-and-usage --granularity DAILY --group-by Type=DIMENSION,Key=SERVICE
Type=DIMENSION,Key=LINKED_ACCOUNT --output json` and prints totals by service, account and month, the budget
status, and anomalies. Anomaly rule: a day is flagged when its amount is more than --factor times the median of the
previous --window days for the same service and account (and for the total), and at least --min-amount above it. A
series that was zero for the whole window and now spends at least --min-amount is flagged as new spend. Checks:

  SPEND-ANOMALY      medium   day over factor x median; high when new spend or over 2 x factor x median
  SPEND-OVER-BUDGET  high     month total at or above the monthly limit
  SPEND-THRESHOLD    medium   month total crossed an actual alert threshold
  SPEND-FORECAST     medium   straight-line month-end projection at or above a forecast threshold (rough)

Exit codes: generate 0, 1 lint errors in the generated SCPs, 2 bad spec. review 0 no finding at or above --fail-on
(default medium), 1 findings at or above it, 2 bad input. The script never calls AWS.
"""
from __future__ import annotations

import argparse
import calendar
import datetime as dt
import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parents[1] / "scp-guardrails" / "scripts"))

from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402
from scp_builder import SpecError as BuilderSpecError  # noqa: E402
from scp_builder import exemption, pack, with_condition  # noqa: E402
from scp_lint import compact, lint_policy  # noqa: E402

LEVELS = ["high", "medium", "low"]
SCP_LIMIT = 5120
MAX_NOTIFICATIONS = 5
MAX_EMAIL_SUBSCRIBERS = 10

DEFAULT_DENY_INSTANCE_TYPES = ["dl*", "f*", "g*", "hpc*", "inf*", "p*", "trn*", "u-*", "vt*", "x*", "*.metal*",
                               "*.12xlarge", "*.16xlarge", "*.18xlarge", "*.24xlarge", "*.32xlarge", "*.48xlarge"]
DEFAULT_SAGEMAKER_TYPES = ["ml.g*", "ml.inf*", "ml.p*", "ml.trn*"]
COMMITMENT_ACTIONS = ["aws-marketplace:Subscribe", "ec2:PurchaseHostReservation", "ec2:PurchaseReservedInstancesOffering",
                      "elasticache:PurchaseReservedCacheNodesOffering", "rds:PurchaseReservedDBInstancesOffering",
                      "redshift:PurchaseReservedNodeOffering", "savingsplans:CreateSavingsPlan"]
BUDGET_PROTECT_ACTIONS = ["budgets:DeleteBudgetAction", "budgets:ExecuteBudgetAction", "budgets:ModifyBudget",
                          "budgets:UpdateBudgetAction", "ce:DeleteAnomalyMonitor", "ce:DeleteAnomalySubscription",
                          "ce:UpdateAnomalyMonitor", "ce:UpdateAnomalySubscription"]
SAGEMAKER_CREATE = ["sagemaker:CreateEndpointConfig", "sagemaker:CreateHyperParameterTuningJob", "sagemaker:CreateNotebookInstance",
                    "sagemaker:CreateProcessingJob", "sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"]
BUDGET_KEYS = {"name_prefix", "currency", "budget_account", "accounts", "monthly_limit", "thresholds", "forecast_thresholds",
               "notify_emails", "sns_topic_arn", "usage_budgets", "anomaly", "review", "sandbox_scp"}
SCP_KEYS = {"protected_roles", "deny_instance_types", "allowed_instance_types", "max_volume_iops", "deny_volume_types",
            "sagemaker_instance_types", "deny_bedrock_customization", "deny_services", "deny_commitments", "protect_budgets"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
TYPE_PATTERN_RE = re.compile(r"^[a-z0-9.*-]{1,40}$")
SERVICE_RE = re.compile(r"^[a-z0-9-]{2,40}$")


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


def number(value, name: str, minimum: float = 0) -> float:
    need(isinstance(value, (int, float)) and not isinstance(value, bool) and value > minimum, f"{name} must be a number above {minimum}")
    return float(value)


def fmt_amount(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".") if value != int(value) else str(int(value))


# ------------------------------------------------------------------------------------------------------- SCP statements


def validate_scp_cfg(cfg: dict) -> None:
    need(isinstance(cfg, dict), "sandbox_scp must be a mapping")
    unknown = set(cfg) - SCP_KEYS
    need(not unknown, f"unknown sandbox_scp keys: {', '.join(sorted(unknown))}")
    need(not ("deny_instance_types" in cfg and "allowed_instance_types" in cfg),
         "use deny_instance_types or allowed_instance_types, not both")
    for key in ("deny_instance_types", "allowed_instance_types", "sagemaker_instance_types", "deny_volume_types"):
        if key in cfg:
            need(isinstance(cfg[key], list) and bool(cfg[key]) and all(isinstance(v, str) and TYPE_PATTERN_RE.match(v) for v in cfg[key]),
                 f"sandbox_scp.{key} must be a non-empty list of type names or patterns")
    if "allowed_instance_types" in cfg:
        need("*" not in cfg["allowed_instance_types"], "allowed_instance_types: '*' allows everything")
    if "deny_services" in cfg:
        need(isinstance(cfg["deny_services"], list) and all(isinstance(s, str) and SERVICE_RE.match(s) for s in cfg["deny_services"]),
             "sandbox_scp.deny_services must list IAM service prefixes such as redshift")
        need(not {"iam", "sts", "organizations"} & set(cfg["deny_services"]),
             "sandbox_scp.deny_services must not deny iam, sts or organizations entirely")
    if "max_volume_iops" in cfg:
        number(cfg["max_volume_iops"], "sandbox_scp.max_volume_iops")
    roles = cfg.get("protected_roles", [])
    need(isinstance(roles, list) and all(isinstance(r, str) and r and "/" not in r and ":" not in r for r in roles),
         "sandbox_scp.protected_roles must list role names")


def build_spend_statements(cfg: dict, protected_roles: list[str] | None = None) -> list[tuple[str, dict]]:
    """(guardrail, statement) pairs for the sandbox spend denies. Imported by sandbox_pack.py."""
    validate_scp_cfg(cfg)
    roles = protected_roles if protected_roles is not None else cfg.get("protected_roles", [])
    exempt = exemption({"protected_roles": roles})
    out: list[tuple[str, dict]] = []
    instance = "arn:aws:ec2:*:*:instance/*"
    volume = "arn:aws:ec2:*:*:volume/*"
    if "allowed_instance_types" in cfg:
        out.append(("instance_types", with_condition({
            "Sid": "DenyInstanceTypesNotAllowed", "Effect": "Deny", "Action": ["ec2:RunInstances", "ec2:StartInstances"],
            "Resource": instance, "Condition": {"StringNotLike": {"ec2:InstanceType": cfg["allowed_instance_types"]}}}, exempt)))
    elif "deny_instance_types" in cfg:
        out.append(("instance_types", with_condition({
            "Sid": "DenyExpensiveInstanceTypes", "Effect": "Deny", "Action": ["ec2:RunInstances", "ec2:StartInstances"],
            "Resource": instance, "Condition": {"StringLike": {"ec2:InstanceType": cfg["deny_instance_types"]}}}, exempt)))
    if "max_volume_iops" in cfg:
        out.append(("ebs_iops", with_condition({
            "Sid": "DenyHighIopsVolumes", "Effect": "Deny", "Action": ["ec2:CreateVolume", "ec2:RunInstances"],
            "Resource": volume, "Condition": {"NumericGreaterThan": {"ec2:VolumeIops": str(int(cfg["max_volume_iops"]))}}}, exempt)))
    if "deny_volume_types" in cfg:
        out.append(("ebs_iops", with_condition({
            "Sid": "DenyProvisionedIopsVolumeTypes", "Effect": "Deny", "Action": ["ec2:CreateVolume", "ec2:RunInstances"],
            "Resource": volume, "Condition": {"StringEquals": {"ec2:VolumeType": cfg["deny_volume_types"]}}}, exempt)))
    if "sagemaker_instance_types" in cfg:
        out.append(("sagemaker_gpu", with_condition({
            "Sid": "DenySageMakerGpuInstanceTypes", "Effect": "Deny", "Action": SAGEMAKER_CREATE, "Resource": "*",
            "Condition": {"ForAnyValue:StringLike": {"sagemaker:InstanceTypes": cfg["sagemaker_instance_types"]}}}, exempt)))
    if cfg.get("deny_bedrock_customization"):
        out.append(("bedrock_customization", with_condition({
            "Sid": "DenyBedrockCustomizationAndThroughput", "Effect": "Deny",
            "Action": ["bedrock:CreateModelCustomizationJob", "bedrock:CreateProvisionedModelThroughput"], "Resource": "*"}, exempt)))
    if cfg.get("deny_services"):
        out.append(("deny_services", with_condition({
            "Sid": "DenyExpensiveServices", "Effect": "Deny", "Action": [f"{s}:*" for s in sorted(set(cfg["deny_services"]))],
            "Resource": "*"}, exempt)))
    if cfg.get("deny_commitments"):
        out.append(("commitments", with_condition({
            "Sid": "DenyPurchaseCommitments", "Effect": "Deny", "Action": COMMITMENT_ACTIONS, "Resource": "*"}, exempt)))
    if cfg.get("protect_budgets"):
        out.append(("protect_budgets", with_condition({
            "Sid": "ProtectBudgetsAndAnomalyMonitors", "Effect": "Deny", "Action": BUDGET_PROTECT_ACTIONS, "Resource": "*"}, exempt)))
    return out


def pack_and_lint(statements: list[tuple[str, dict]], prefix: str, limit: int = SCP_LIMIT) -> tuple[list[dict], dict]:
    try:
        packed = pack(statements, limit)
    except BuilderSpecError as exc:
        raise SpecError(str(exc)) from exc
    docs = [{"Version": "2012-10-17", "Statement": [s for _, s in d]} for d in packed]
    manifest = {"limit": limit, "documents": [], "lint": []}
    for i, (doc, items) in enumerate(zip(docs, packed, strict=True), 1):
        name = f"{prefix}-{i:02d}.json"
        manifest["documents"].append({"file": name, "chars_compact": len(compact(doc)),
                                      "guardrails": sorted({g for g, _ in items}), "statements": [s["Sid"] for _, s in items]})
        manifest["lint"] += [{"file": name, **issue} for issue in lint_policy(doc, limit=limit)]
    return docs, manifest


# ----------------------------------------------------------------------------------------------------------- generate


def validate_budget(spec: dict) -> dict:
    unknown = set(spec) - BUDGET_KEYS
    need(not unknown, f"unknown spec keys: {', '.join(sorted(unknown))}")
    prefix = spec.get("name_prefix", "spend")
    need(isinstance(prefix, str) and bool(NAME_RE.match(prefix)), "name_prefix must be letters, digits, - or _")
    currency = spec.get("currency", "USD")
    need(isinstance(currency, str) and bool(re.match(r"^[A-Z]{3}$", currency)), "currency must be a three-letter code")
    for acct in spec.get("accounts", []) or []:
        need(isinstance(acct, str) and bool(ACCOUNT_RE.match(acct)), f"account {acct!r} is not a 12-digit string (quote it)")
    if "budget_account" in spec:
        need(isinstance(spec["budget_account"], str) and bool(ACCOUNT_RE.match(spec["budget_account"])),
             "budget_account must be a 12-digit string")
    emails = spec.get("notify_emails", []) or []
    need(isinstance(emails, list) and all(isinstance(e, str) and EMAIL_RE.match(e) for e in emails), "notify_emails must list addresses")
    need(len(emails) <= MAX_EMAIL_SUBSCRIBERS, f"at most {MAX_EMAIL_SUBSCRIBERS} email subscribers per notification")
    sns = spec.get("sns_topic_arn")
    if sns is not None:
        need(isinstance(sns, str) and sns.startswith("arn:aws:sns:"), "sns_topic_arn must be an SNS topic ARN")
    thresholds = spec.get("thresholds", [])
    forecasts = spec.get("forecast_thresholds", [])
    for name, values in (("thresholds", thresholds), ("forecast_thresholds", forecasts)):
        need(isinstance(values, list) and all(isinstance(v, (int, float)) and 0 < v <= 1000 for v in values),
             f"{name} must list percentages")
    if "monthly_limit" in spec:
        number(spec["monthly_limit"], "monthly_limit")
        need(bool(emails or sns), "a budget needs notify_emails or sns_topic_arn")
        need(bool(thresholds or forecasts), "a budget needs thresholds or forecast_thresholds")
        need(len(thresholds) + len(forecasts) <= MAX_NOTIFICATIONS, f"at most {MAX_NOTIFICATIONS} notifications per budget")
    for i, ub in enumerate(spec.get("usage_budgets", []) or []):
        need(isinstance(ub, dict) and NAME_RE.match(str(ub.get("name", ""))) is not None, f"usage_budgets[{i}].name is required")
        need(isinstance(ub.get("usage_type_group"), str) and bool(ub["usage_type_group"]), f"usage_budgets[{i}].usage_type_group is required")
        number(ub.get("limit"), f"usage_budgets[{i}].limit")
        need(isinstance(ub.get("unit"), str) and bool(ub["unit"]), f"usage_budgets[{i}].unit is required (for example Hrs)")
    anomaly = spec.get("anomaly")
    if anomaly is not None:
        need(isinstance(anomaly, dict), "anomaly must be a mapping")
        need(anomaly.get("monitor", "services") in ("services", "linked-accounts"), "anomaly.monitor is services or linked-accounts")
        if anomaly.get("monitor") == "linked-accounts":
            need(bool(spec.get("accounts")), "anomaly.monitor linked-accounts needs accounts")
        need(anomaly.get("frequency", "DAILY") in ("DAILY", "WEEKLY", "IMMEDIATE"), "anomaly.frequency is DAILY, WEEKLY or IMMEDIATE")
        if anomaly.get("frequency") == "IMMEDIATE":
            need(bool(sns), "anomaly.frequency IMMEDIATE needs sns_topic_arn (email works only for DAILY and WEEKLY)")
        else:
            need(bool(emails or sns), "the anomaly subscription needs notify_emails or sns_topic_arn")
        need("threshold_absolute" in anomaly or "threshold_percent" in anomaly,
             "anomaly needs threshold_absolute, threshold_percent or both")
        for key in ("threshold_absolute", "threshold_percent"):
            if key in anomaly:
                number(anomaly[key], f"anomaly.{key}")
    review = spec.get("review") or {}
    need(isinstance(review, dict) and set(review) <= {"factor", "window_days", "min_amount"}, "review takes factor, window_days, min_amount")
    if "sandbox_scp" in spec:
        validate_scp_cfg(spec["sandbox_scp"])
    return {"prefix": prefix, "currency": currency, "emails": emails, "sns": sns, "thresholds": thresholds, "forecasts": forecasts}


def subscribers(emails: list[str], sns: str | None) -> list[dict]:
    subs = [{"SubscriptionType": "EMAIL", "Address": e} for e in emails]
    if sns:
        subs.append({"SubscriptionType": "SNS", "Address": sns})
    return subs


def notifications(thresholds: list, forecasts: list, subs: list[dict]) -> list[dict]:
    out = []
    for kind, values in (("ACTUAL", thresholds), ("FORECASTED", forecasts)):
        for t in values:
            out.append({"Notification": {"NotificationType": kind, "ComparisonOperator": "GREATER_THAN", "Threshold": t,
                                         "ThresholdType": "PERCENTAGE"}, "Subscribers": subs})
    return out


def generate(spec: dict) -> dict:
    v = validate_budget(spec)
    files: dict[str, object] = {}
    warnings: list[str] = []
    budget_account = spec.get("budget_account") or (spec.get("accounts") or ["<budget-account-id>"])[0]
    subs = subscribers(v["emails"], v["sns"])
    commands = ["# Spend guardrail commands", "", "Generated by spend_guardrails.py. Review every file; none of these has been run.",
                "Budgets that filter on linked accounts must be created in the management (payer) account.", "", "```bash"]
    if "monthly_limit" in spec:
        budget = {"BudgetName": f"{v['prefix']}-monthly-cost", "BudgetType": "COST", "TimeUnit": "MONTHLY",
                  "BudgetLimit": {"Amount": fmt_amount(float(spec["monthly_limit"])), "Unit": v["currency"]}}
        if spec.get("accounts"):
            budget["CostFilters"] = {"LinkedAccount": spec["accounts"]}
        files["budget-cost.json"] = budget
        files["notifications-cost.json"] = notifications(v["thresholds"], v["forecasts"], subs)
        commands.append(f"aws budgets create-budget --account-id {budget_account} --budget file://budget-cost.json "
                        "--notifications-with-subscribers file://notifications-cost.json")
    for ub in spec.get("usage_budgets", []) or []:
        name = ub["name"]
        files[f"budget-usage-{name}.json"] = {
            "BudgetName": f"{v['prefix']}-usage-{name}", "BudgetType": "USAGE", "TimeUnit": "MONTHLY",
            "BudgetLimit": {"Amount": fmt_amount(float(ub["limit"])), "Unit": ub["unit"]},
            "CostFilters": {"UsageTypeGroup": [ub["usage_type_group"]]}}
        files[f"notifications-usage-{name}.json"] = notifications(v["thresholds"] or [100], [], subs)
        commands.append(f"aws budgets create-budget --account-id {budget_account} --budget file://budget-usage-{name}.json "
                        f"--notifications-with-subscribers file://notifications-usage-{name}.json")
    anomaly = spec.get("anomaly")
    if anomaly is not None:
        if anomaly.get("monitor", "services") == "services":
            monitor = {"MonitorName": f"{v['prefix']}-services", "MonitorType": "DIMENSIONAL", "MonitorDimension": "SERVICE"}
        else:
            monitor = {"MonitorName": f"{v['prefix']}-linked-accounts", "MonitorType": "CUSTOM",
                       "MonitorSpecification": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": spec["accounts"]}}}
        exprs = []
        if "threshold_absolute" in anomaly:
            exprs.append({"Dimensions": {"Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "Values": [fmt_amount(float(anomaly["threshold_absolute"]))],
                                         "MatchOptions": ["GREATER_THAN_OR_EQUAL"]}})
        if "threshold_percent" in anomaly:
            exprs.append({"Dimensions": {"Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "Values": [fmt_amount(float(anomaly["threshold_percent"]))],
                                         "MatchOptions": ["GREATER_THAN_OR_EQUAL"]}})
        frequency = anomaly.get("frequency", "DAILY")
        anomaly_subs = [{"Type": "EMAIL", "Address": e} for e in v["emails"]] if frequency != "IMMEDIATE" else []
        if v["sns"]:
            anomaly_subs.append({"Type": "SNS", "Address": v["sns"]})
        files["anomaly-monitor.json"] = monitor
        files["anomaly-subscription.json"] = {
            "SubscriptionName": f"{v['prefix']}-anomaly-alerts", "MonitorArnList": ["<monitor-arn from create-anomaly-monitor>"],
            "Subscribers": anomaly_subs, "Frequency": frequency,
            "ThresholdExpression": exprs[0] if len(exprs) == 1 else {"Or": exprs}}
        commands += ["aws ce create-anomaly-monitor --anomaly-monitor file://anomaly-monitor.json --output json",
                     "# put the MonitorArn from the output into anomaly-subscription.json, then:",
                     "aws ce create-anomaly-subscription --anomaly-subscription file://anomaly-subscription.json --output json"]
    manifest = None
    docs: list[dict] = []
    if "sandbox_scp" in spec:
        statements = build_spend_statements(spec["sandbox_scp"])
        if not statements:
            raise SpecError("sandbox_scp enables no deny")
        docs, manifest = pack_and_lint(statements, "spend-scp")
        for meta, doc in zip(manifest["documents"], docs, strict=True):
            files[meta["file"]] = doc
        files["spend-scp-manifest.json"] = manifest
        if not spec["sandbox_scp"].get("protected_roles"):
            warnings.append("sandbox_scp has no protected_roles: nobody in the sandbox accounts can change budgets or use "
                            "the denied services, including administrators")
        commands += ["# from the management account, after testing on an OU with one account:",
                     "aws organizations create-policy --type SERVICE_CONTROL_POLICY --name spend-guardrails-01 "
                     "--description \"Sandbox spend denies\" --content file://spend-scp-01.json",
                     "aws organizations attach-policy --policy-id <policy-id> --target-id <sandbox-ou-id>"]
    if not files:
        raise SpecError("the spec sets none of monthly_limit, usage_budgets, anomaly or sandbox_scp")
    commands += ["```", ""]
    files["commands.md"] = "\n".join(commands)
    lint_errors = [i for i in (manifest or {}).get("lint", []) if i["level"] == "error"]
    return {"files": files, "warnings": warnings, "lint_errors": lint_errors}


# ------------------------------------------------------------------------------------------------------------- review


def load_cost(paths: list[Path]) -> tuple[dict, list[str], str, int, bool]:
    """Return ({(service, account): {date: amount}}, dates, unit, estimated days, truncated)."""
    series: dict[tuple[str, str], dict[str, float]] = {}
    dates: set[str] = set()
    unit = ""
    estimated: set[str] = set()
    truncated = False
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("ResultsByTime"), list):
            raise ValueError(f"{path}: expected aws ce get-cost-and-usage output with ResultsByTime")
        truncated = truncated or bool(data.get("NextPageToken"))
        dims = [str(g.get("Key", "")).upper() for g in data.get("GroupDefinitions") or []]
        for period in data["ResultsByTime"]:
            day = str((period.get("TimePeriod") or {}).get("Start", ""))
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", day):
                raise ValueError(f"{path}: TimePeriod.Start {day!r} is not a date; use --granularity DAILY")
            dates.add(day)
            if period.get("Estimated"):
                estimated.add(day)
            groups = period.get("Groups") or []
            if not groups and period.get("Total"):
                groups = [{"Keys": [], "Metrics": period["Total"]}]
            for g in groups:
                keys = g.get("Keys") or []
                named = dict(zip(dims, keys, strict=False))
                service = named.get("SERVICE", "all services")
                account = named.get("LINKED_ACCOUNT", "all accounts")
                metrics = g.get("Metrics") or {}
                metric = metrics.get("UnblendedCost") or metrics.get("NetUnblendedCost") or next(iter(metrics.values()), {})
                try:
                    amount = float(metric.get("Amount", 0))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{path}: amount {metric.get('Amount')!r} is not a number") from exc
                unit = unit or str(metric.get("Unit", ""))
                cell = series.setdefault((service, account), {})
                cell[day] = cell.get(day, 0.0) + amount
    if not dates:
        raise ValueError("no days in the export")
    return series, sorted(dates), unit, len(estimated), truncated


def anomalies(name: str, values: list[float], days: list[str], factor: float, window: int, min_amount: float) -> list[dict]:
    out = []
    for i in range(window, len(values)):
        amount = values[i]
        med = statistics.median(values[i - window:i])
        if amount < min_amount or amount - med < min_amount:
            continue
        if med == 0 or amount > factor * med:
            ratio = None if med == 0 else round(amount / med, 2)
            sev = "high" if med == 0 or amount >= 2 * factor * med else "medium"
            out.append({"id": "SPEND-ANOMALY", "severity": sev, "series": name, "date": days[i], "amount": round(amount, 2),
                        "median_prior": round(med, 2), "ratio": ratio,
                        "message": f"{name} on {days[i]}: {amount:.2f} vs prior {window}-day median {med:.2f}"
                                   + (" (new spend)" if med == 0 else f" ({ratio}x)")})
    return out


def review(paths: list[Path], budget: dict | None, factor: float, window: int, min_amount: float) -> dict:
    series, days, unit, estimated, truncated = load_cost(paths)
    accounts_filter = set((budget or {}).get("accounts") or [])
    totals_service: dict[str, float] = {}
    totals_account: dict[str, float] = {}
    total_by_day = {d: 0.0 for d in days}
    for (service, account), cells in series.items():
        if accounts_filter and account != "all accounts" and account not in accounts_filter:
            continue
        for d, amount in cells.items():
            totals_service[service] = totals_service.get(service, 0.0) + amount
            totals_account[account] = totals_account.get(account, 0.0) + amount
            total_by_day[d] += amount
    findings: list[dict] = []
    for (service, account), cells in sorted(series.items()):
        if accounts_filter and account != "all accounts" and account not in accounts_filter:
            continue
        findings += anomalies(f"{service} / {account}", [cells.get(d, 0.0) for d in days], days, factor, window, min_amount)
    findings += anomalies("total", [total_by_day[d] for d in days], days, factor, window, min_amount)
    months: dict[str, dict] = {}
    for d in days:
        m = months.setdefault(d[:7], {"month": d[:7], "total": 0.0, "days": 0, "last_day": d})
        m["total"] += total_by_day[d]
        m["days"] += 1
        m["last_day"] = max(m["last_day"], d)
    limit = float(budget["monthly_limit"]) if budget and "monthly_limit" in budget else None
    for m in months.values():
        m["total"] = round(m["total"], 2)
        if limit is None:
            continue
        year, month = int(m["month"][:4]), int(m["month"][5:])
        length = calendar.monthrange(year, month)[1]
        m["percent_of_limit"] = round(100 * m["total"] / limit, 1)
        last = dt.date.fromisoformat(m["last_day"])
        if last.day < length:
            m["forecast"] = round(m["total"] / m["days"] * length, 2)
        if m["total"] >= limit:
            findings.append({"id": "SPEND-OVER-BUDGET", "severity": "high", "series": "total", "date": m["last_day"],
                             "message": f"{m['month']}: {m['total']:.2f} {unit} is {m['percent_of_limit']}% of the "
                                        f"{limit:.2f} limit"})
        else:
            crossed = [t for t in budget.get("thresholds", []) if m["percent_of_limit"] >= t]
            if crossed:
                findings.append({"id": "SPEND-THRESHOLD", "severity": "medium", "series": "total", "date": m["last_day"],
                                 "message": f"{m['month']}: {m['percent_of_limit']}% of the limit, past the "
                                            f"{max(crossed)}% alert threshold"})
            if "forecast" in m:
                hit = [t for t in budget.get("forecast_thresholds", []) if 100 * m["forecast"] / limit >= t]
                if hit:
                    findings.append({"id": "SPEND-FORECAST", "severity": "medium", "series": "total", "date": m["last_day"],
                                     "message": f"{m['month']}: straight-line projection {m['forecast']:.2f} {unit} reaches "
                                                f"the {max(hit)}% forecast threshold (rough: the daily average of the days "
                                                f"in the export, times the days in the month)"})
    findings.sort(key=lambda f: (LEVELS.index(f["severity"]), f["date"], f["series"]))
    return {"unit": unit, "days": len(days), "first_day": days[0], "last_day": days[-1], "estimated_days": estimated,
            "truncated": truncated, "accounts_filter": sorted(accounts_filter),
            "by_service": [{"service": s, "total": round(t, 2)} for s, t in sorted(totals_service.items(), key=lambda x: -x[1])],
            "by_account": [{"account": a, "total": round(t, 2)} for a, t in sorted(totals_account.items(), key=lambda x: -x[1])],
            "by_month": list(months.values()), "rule": {"factor": factor, "window_days": window, "min_amount": min_amount},
            "findings": findings}


# --------------------------------------------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "review":
        ap = argparse.ArgumentParser(prog="spend_guardrails.py review", description="Review exported Cost Explorer data.")
        ap.add_argument("--cost-explorer", nargs="+", required=True, help="aws ce get-cost-and-usage --output json file(s)")
        ap.add_argument("--budget", help="budget spec (monthly_limit, thresholds, accounts, review defaults)")
        ap.add_argument("--factor", type=float, help="flag a day above factor x the prior median (default 3, or review.factor)")
        ap.add_argument("--window", type=int, help="days in the prior median (default 7, or review.window_days)")
        ap.add_argument("--min-amount", type=float, help="ignore days less than this above the median (default 5)")
        ap.add_argument("--fail-on", choices=LEVELS, default="medium", help="exit 1 at or above this severity (default medium)")
        ap.add_argument("--json", action="store_true", help="print JSON")
        args = ap.parse_args(argv[1:])
        try:
            budget = load_spec(Path(args.budget)) if args.budget else None
            if budget is not None:
                validate_budget(budget)
            defaults = (budget or {}).get("review") or {}
            factor = args.factor if args.factor is not None else float(defaults.get("factor", 3))
            window = args.window if args.window is not None else int(defaults.get("window_days", 7))
            min_amount = args.min_amount if args.min_amount is not None else float(defaults.get("min_amount", 5))
            if factor <= 1 or window < 3 or min_amount < 0:
                raise SpecError("factor must be above 1, window at least 3 days, min-amount not negative")
            report = review([Path(p) for p in args.cost_explorer], budget, factor, window, min_amount)
        except (SpecError, OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"{report['first_day']} to {report['last_day']} ({report['days']} days, {report['unit']}), "
                  f"{report['estimated_days']} estimated day(s)")
            if report["truncated"]:
                print("warning: the export has a NextPageToken; fetch the remaining pages and pass them all")
            print("by service:")
            for row in report["by_service"]:
                print(f"  {row['total']:>12.2f}  {row['service']}")
            print("by account:")
            for row in report["by_account"]:
                print(f"  {row['total']:>12.2f}  {row['account']}")
            for m in report["by_month"]:
                extra = f", {m['percent_of_limit']}% of limit" if "percent_of_limit" in m else ""
                print(f"month {m['month']}: {m['total']:.2f} over {m['days']} day(s){extra}")
            for f in report["findings"]:
                print(f"{f['severity']:<7} {f['id']:<18} {f['message']}")
            if not report["findings"]:
                print("no anomalies or budget findings")
        threshold = LEVELS.index(args.fail_on)
        return 1 if any(LEVELS.index(f["severity"]) <= threshold for f in report["findings"]) else 0

    ap = argparse.ArgumentParser(prog="spend_guardrails.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--budget", required=True, help="YAML or JSON budget spec")
    ap.add_argument("--out", help="directory for the generated files")
    ap.add_argument("--json", action="store_true", help="print the generated files as JSON")
    args = ap.parse_args(argv)
    try:
        result = generate(load_spec(Path(args.budget)))
    except (SpecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.out and not result["lint_errors"]:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for name, content in result["files"].items():
            text = content if isinstance(content, str) else json.dumps(content, indent=2) + "\n"
            (out / name).write_text(text, encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for name in result["files"]:
            print(f"  {name}")
        for w in result["warnings"]:
            print(f"warning: {w}")
        for issue in result["lint_errors"]:
            print(f"lint error: {issue['file']} {issue['id']} {issue['message']}")
        if args.out and not result["lint_errors"]:
            print(f"wrote {len(result['files'])} file(s) to {args.out}")
        print("Review every file before creating budgets or attaching SCPs.")
    return 1 if result["lint_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
