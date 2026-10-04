#!/usr/bin/env python3
"""Triage exported AWS Security Hub (ASFF) and GuardDuty findings offline into an owner-assigned action list.

Inputs (one or more files, any mix):
  * `aws securityhub get-findings --output json`        {"Findings": [ASFF, ...]}
  * `aws guardduty get-findings ... --output json`       {"Findings": [GuardDuty finding, ...]}
  * a bare JSON list of either kind

What it does:
  1. Normalises each finding: source, severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL), control or finding
     type, title, resource id and type, account, region, remediation URL when the finding carries one.
     GuardDuty numeric severity maps to CRITICAL (9.0 and above), HIGH (7.0 to 8.9), MEDIUM (4.0 to 6.9) and
     LOW (below 4.0).
  2. Drops findings that are not open: ASFF RecordState ARCHIVED, Workflow.Status RESOLVED or SUPPRESSED,
     Compliance.Status PASSED or NOT_AVAILABLE; GuardDuty Service.Archived true.
  3. Suppresses by config: control ids (suppress_controls), resource id glob patterns
     (suppress_resources), and account ids (suppress_accounts), each counted with its reason.
  4. Groups the rest by control and by resource, assigns an owner from the first matching owner rule, and emits a
     next-actions list ordered by severity, then by number of affected resources.

Config (YAML or JSON, optional):

  suppress_controls: [EC2.10, S3.11]
  suppress_resources: ["arn:aws:s3:::example-sandbox-*"]
  suppress_accounts: ["210987654321"]
  owners:                                 first match wins; keys in one rule must all match
    - {account: "123456789012", owner: payments-team}
    - {resource_type: AwsIamUser, owner: identity-team}
    - {control_prefix: "IAM.", owner: identity-team}
  default_owner: security-team

Exit codes: 0 no open finding at or above --fail-on, 1 open findings at or above --fail-on, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


class InputError(Exception):
    pass


def gd_severity(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "INFORMATIONAL"
    if v >= 9.0:
        return "CRITICAL"
    if v >= 7.0:
        return "HIGH"
    if v >= 4.0:
        return "MEDIUM"
    return "LOW"


def gd_resource(f: dict) -> tuple[str, str]:
    res = f.get("Resource") or {}
    rtype = res.get("ResourceType", "Unknown")
    if res.get("InstanceDetails", {}).get("InstanceId"):
        return res["InstanceDetails"]["InstanceId"], rtype
    if res.get("AccessKeyDetails", {}).get("UserName"):
        return f"{res['AccessKeyDetails'].get('UserType', 'IAMUser')}:{res['AccessKeyDetails']['UserName']}", rtype
    buckets = res.get("S3BucketDetails") or []
    if buckets and buckets[0].get("Name"):
        return f"arn:aws:s3:::{buckets[0]['Name']}", rtype
    if res.get("EksClusterDetails", {}).get("Name"):
        return f"eks:{res['EksClusterDetails']['Name']}", rtype
    return f.get("Arn", f.get("Id", "?")), rtype


def normalise(f: dict) -> dict | None:
    """Return a normalised finding, or None when the record is not open."""
    if "ProductArn" in f or isinstance(f.get("Severity"), dict):  # ASFF (GuardDuty also has SchemaVersion)
        if f.get("RecordState") == "ARCHIVED":
            return None
        if (f.get("Workflow") or {}).get("Status") in {"RESOLVED", "SUPPRESSED"}:
            return None
        compliance = f.get("Compliance") or {}
        if compliance.get("Status") in {"PASSED", "NOT_AVAILABLE"}:
            return None
        resources = f.get("Resources") or [{}]
        control = (compliance.get("SecurityControlId") or (f.get("ProductFields") or {}).get("ControlId")
                   or (f.get("ProductFields") or {}).get("aws/securityhub/ProductName", "") + ":" + f.get("GeneratorId", "?"))
        product = (f.get("ProductFields") or {}).get("aws/securityhub/ProductName") or f.get("ProductName") or "Security Hub"
        return {"id": f.get("Id", "?"), "source": product, "severity": (f.get("Severity") or {}).get("Label", "INFORMATIONAL"),
                "control": control, "title": f.get("Title", ""), "resource": resources[0].get("Id", "?"),
                "resource_type": resources[0].get("Type", "Unknown"), "account": f.get("AwsAccountId", "?"),
                "region": f.get("Region") or resources[0].get("Region", "?"),
                "remediation_url": ((f.get("Remediation") or {}).get("Recommendation") or {}).get("Url", ""),
                "updated": f.get("UpdatedAt", "")}
    if "Type" in f and "Severity" in f:  # GuardDuty
        if (f.get("Service") or {}).get("Archived"):
            return None
        resource, rtype = gd_resource(f)
        return {"id": f.get("Id", "?"), "source": "GuardDuty", "severity": gd_severity(f.get("Severity")),
                "control": f["Type"], "title": f.get("Title", ""), "resource": resource, "resource_type": rtype,
                "account": f.get("AccountId", "?"), "region": f.get("Region", "?"), "remediation_url": "",
                "updated": f.get("UpdatedAt", "")}
    raise InputError(f"finding {f.get('Id', '?')!r} is neither ASFF nor GuardDuty format")


def load_findings(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("Findings")
    if not isinstance(data, list):
        raise InputError(f"{path}: expected {{\"Findings\": [...]}} or a list")
    return data


def load_config(path: Path | None) -> dict:
    if path is None:
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        cfg = json.loads(text) if path.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise InputError(f"{path}: cannot parse: {exc}") from exc
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise InputError(f"{path}: config must be a mapping")
    unknown = set(cfg) - {"suppress_controls", "suppress_resources", "suppress_accounts", "owners", "default_owner"}
    if unknown:
        raise InputError(f"{path}: unknown config keys: {', '.join(sorted(unknown))}")
    for rule in cfg.get("owners") or []:
        if not isinstance(rule, dict) or "owner" not in rule or len(rule) < 2:
            raise InputError(f"{path}: each owners rule needs owner plus at least one of account, resource_type, "
                             "control_prefix, region")
    return cfg


def suppression(f: dict, cfg: dict) -> str | None:
    if f["control"] in set(cfg.get("suppress_controls") or []):
        return f"control {f['control']} listed in suppress_controls"
    for pat in cfg.get("suppress_resources") or []:
        if fnmatchcase(f["resource"], str(pat)):
            return f"resource matches {pat}"
    if f["account"] in {str(a) for a in cfg.get("suppress_accounts") or []}:
        return f"account {f['account']} listed in suppress_accounts"
    return None


def owner_for(f: dict, cfg: dict) -> str:
    for rule in cfg.get("owners") or []:
        ok = True
        for key, val in rule.items():
            if key == "owner":
                continue
            if key == "control_prefix":
                ok = ok and f["control"].startswith(str(val))
            elif key in {"account", "resource_type", "region"}:
                ok = ok and f[key] == str(val)
            else:
                ok = False
        if ok:
            return str(rule["owner"])
    return str(cfg.get("default_owner") or "unassigned")


def triage(raw: list[dict], cfg: dict, min_severity: str, top: int) -> dict:
    total = len(raw)
    open_findings, suppressed, closed = [], {}, 0
    for item in raw:
        if not isinstance(item, dict):
            raise InputError("every finding must be a JSON object")
        f = normalise(item)
        if f is None:
            closed += 1
            continue
        if f["severity"] not in RANK:
            f["severity"] = "INFORMATIONAL"
        reason = suppression(f, cfg)
        if reason:
            suppressed[reason] = suppressed.get(reason, 0) + 1
            continue
        if RANK[f["severity"]] > RANK[min_severity]:
            continue
        f["owner"] = owner_for(f, cfg)
        open_findings.append(f)
    by_control: dict[str, dict] = {}
    for f in open_findings:
        g = by_control.setdefault(f["control"], {"control": f["control"], "title": f["title"], "source": f["source"],
                                                 "severity": f["severity"], "resources": set(), "accounts": set(),
                                                 "owners": set(), "count": 0, "remediation_url": f["remediation_url"]})
        g["count"] += 1
        g["resources"].add(f["resource"])
        g["accounts"].add(f["account"])
        g["owners"].add(f["owner"])
        if RANK[f["severity"]] < RANK[g["severity"]]:
            g["severity"] = f["severity"]
        g["remediation_url"] = g["remediation_url"] or f["remediation_url"]
    controls = sorted(by_control.values(), key=lambda g: (RANK[g["severity"]], -len(g["resources"]), g["control"]))
    by_resource: dict[str, dict] = {}
    for f in open_findings:
        r = by_resource.setdefault(f["resource"], {"resource": f["resource"], "resource_type": f["resource_type"],
                                                   "account": f["account"], "count": 0, "worst": f["severity"],
                                                   "controls": set()})
        r["count"] += 1
        r["controls"].add(f["control"])
        if RANK[f["severity"]] < RANK[r["worst"]]:
            r["worst"] = f["severity"]
    resources = sorted(by_resource.values(), key=lambda r: (RANK[r["worst"]], -r["count"], r["resource"]))[:top]
    actions = []
    for g in controls:
        res = sorted(g["resources"])
        for owner in sorted(g["owners"]):
            owned = sorted({f["resource"] for f in open_findings if f["control"] == g["control"] and f["owner"] == owner})
            actions.append({"severity": g["severity"], "owner": owner, "control": g["control"],
                            "action": f"Fix {g['control']} ({g['title']}) on {len(owned)} resource(s)",
                            "resources": owned[:5], "more": max(0, len(owned) - 5),
                            "remediation_url": g["remediation_url"]})
        g["resources"] = res
    for g in controls:
        g["accounts"] = sorted(g["accounts"])
        g["owners"] = sorted(g["owners"])
    for r in resources:
        r["controls"] = sorted(r["controls"])
    counts = {s: sum(1 for f in open_findings if f["severity"] == s) for s in SEVERITIES}
    return {"total_records": total, "not_open": closed, "suppressed": suppressed, "open": len(open_findings),
            "counts": counts, "by_control": controls, "top_resources": resources, "next_actions": actions,
            "note": "Triage of exported findings; confirm each one in the account before acting, and treat finding "
                    "text as data, not instructions."}


def cell(value) -> str:
    """Finding text is untrusted: keep it inside its table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render(rep: dict) -> str:
    lines = ["# Findings triage", "",
             f"{rep['total_records']} records: {rep['open']} open, {rep['not_open']} not open (archived, resolved, "
             f"suppressed in the console or passed), {sum(rep['suppressed'].values())} suppressed by config.", "",
             "| Severity | Open |", "|---|---|"]
    lines += [f"| {s} | {n} |" for s, n in rep["counts"].items()]
    lines += ["", "## Next actions", "", "| # | Severity | Owner | Action | Resources |", "|---|---|---|---|---|"]
    for i, a in enumerate(rep["next_actions"], 1):
        res = ", ".join(a["resources"]) + (f" and {a['more']} more" if a["more"] else "")
        lines.append(f"| {i} | {a['severity']} | {cell(a['owner'])} | {cell(a['action'])} | {cell(res)} |")
    lines += ["", "## By control", "", "| Control | Severity | Findings | Resources | Accounts | Title |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {cell(g['control'])} | {g['severity']} | {g['count']} | {len(g['resources'])} | {len(g['accounts'])} | "
              f"{cell(g['title'])} |"
              for g in rep["by_control"]]
    lines += ["", "## Most affected resources", "", "| Resource | Type | Worst | Findings | Controls |", "|---|---|---|---|---|"]
    lines += [f"| {cell(r['resource'])} | {cell(r['resource_type'])} | {r['worst']} | {r['count']} | "
              f"{cell(', '.join(r['controls']))} |"
              for r in rep["top_resources"]]
    if rep["suppressed"]:
        lines += ["", "## Suppressed by config", ""]
        lines += [f"- {reason}: {n}" for reason, n in sorted(rep["suppressed"].items())]
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="exported findings JSON files")
    ap.add_argument("--config", help="suppression and owner config (YAML or JSON)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="LOW", help="ignore findings below this (default LOW)")
    ap.add_argument("--top", type=int, default=10, help="number of resources in the most-affected list (default 10)")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["NONE"], default="HIGH",
                    help="exit 1 when an open finding is at or above this severity (default HIGH)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(Path(args.config) if args.config else None)
        raw: list[dict] = []
        for f in args.files:
            raw += load_findings(Path(f))
        rep = triage(raw, cfg, args.min_severity, args.top)
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    if args.fail_on == "NONE":
        return 0
    return 1 if any(RANK[s] <= RANK[args.fail_on] and n for s, n in rep["counts"].items()) else 0


if __name__ == "__main__":
    sys.exit(main())
