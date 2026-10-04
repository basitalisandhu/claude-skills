#!/usr/bin/env python3
"""Design an AWS Organizations layout with one account per workload and environment, and show the blast radius.

Input: a YAML or JSON file

  organization: acme              short lowercase prefix for account names
  email_domain: example.com       domain for the account root email addresses (default example.com)
  workloads:
    - name: payments              lowercase letters, digits and hyphens
      environment: prod           prod | staging | test | dev | sandbox
      data_classification: confidential   public | internal | confidential | restricted
      internet_facing: true
      depends_on: [identity-api]  optional: other workload names this one calls across accounts (same environment)

Rules the design follows (pure logic, no AWS calls):

  * One account per (workload, environment). Name: <org>-<workload>-<environment>.
  * Foundation accounts: management (billing and Organizations only, no workloads), log-archive, security-tooling
    (delegated administrator for GuardDuty, Security Hub, Config and IAM Access Analyzer), shared-services (CI/CD,
    artifacts, DNS), and network (Transit Gateway, egress, ingress) when any workload is internet-facing.
  * OU tree: Security (log-archive, security-tooling), Infrastructure (shared-services, network), Workloads/Prod,
    Workloads/Prod-Restricted (prod with confidential or restricted data), Workloads/NonProd (staging, test, dev),
    Sandbox, Suspended.
  * SCP attachment uses the guardrail names of the scp-guardrails skill.
  * Blast radius per account: what an attacker with administrator access in that account can reach, from the
    account's own role in the design (foundation accounts) and from declared cross-account dependencies.

Exit codes: 0 design produced, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402

ENVIRONMENTS = ["prod", "staging", "test", "dev", "sandbox"]
CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"]
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
IMPACT = ["low", "medium", "high", "critical"]

SCP_BY_OU = {
    "Root": ["deny_leave_organization", "deny_root_user", "deny_disable_security_services"],
    "Security": ["protect_log_archive (deny s3:DeleteBucket, s3:PutBucketPolicy, s3:PutLifecycleConfiguration on log buckets)"],
    "Infrastructure": ["allowed_regions", "deny_iam_users_outside", "require_imdsv2"],
    "Workloads": ["allowed_regions", "deny_iam_users_outside", "require_imdsv2", "deny_public_s3_acls"],
    "Workloads/Prod": [],
    "Workloads/Prod-Restricted": ["deny_public_s3_acls (already inherited; keep explicit)",
                                  "deny_unencrypted_storage (custom: require encryption on s3:PutObject and RDS/EBS create)"],
    "Workloads/NonProd": [],
    "Sandbox": ["allowed_regions (one region)", "deny_iam_users_outside", "deny_expensive_services (custom)"],
    "Suspended": ["deny_all (Deny * on * with no exemption except the org access role)"],
}


class InputError(Exception):
    pass


def load_input(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise InputError(f"{path}: cannot parse: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path}: expected a mapping with organization and workloads")
    return data


def normalise(data: dict) -> tuple[str, str, list[dict]]:
    org = str(data.get("organization", "")).strip().lower()
    if not NAME_RE.match(org):
        raise InputError("organization must be lowercase letters, digits and hyphens")
    domain = str(data.get("email_domain", "example.com")).strip().lower()
    workloads = data.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        raise InputError("workloads must be a non-empty list")
    seen: set[tuple[str, str]] = set()
    out = []
    for i, w in enumerate(workloads):
        if not isinstance(w, dict):
            raise InputError(f"workloads[{i}] must be a mapping")
        name = str(w.get("name", "")).strip().lower()
        env = str(w.get("environment", "")).strip().lower()
        cls = str(w.get("data_classification", "internal")).strip().lower()
        facing = w.get("internet_facing", False)
        if not NAME_RE.match(name):
            raise InputError(f"workloads[{i}].name {name!r}: use lowercase letters, digits and hyphens")
        if env not in ENVIRONMENTS:
            raise InputError(f"workloads[{i}].environment {env!r}: one of {', '.join(ENVIRONMENTS)}")
        if cls not in CLASSIFICATIONS:
            raise InputError(f"workloads[{i}].data_classification {cls!r}: one of {', '.join(CLASSIFICATIONS)}")
        if isinstance(facing, str):
            facing = facing.strip().lower() in {"yes", "true", "y"}
        if (name, env) in seen:
            raise InputError(f"duplicate workload {name} in {env}")
        seen.add((name, env))
        deps = [str(d).strip().lower() for d in (w.get("depends_on") or [])]
        out.append({"name": name, "environment": env, "data_classification": cls, "internet_facing": bool(facing),
                    "depends_on": deps})
    names_by_env = {(w["name"], w["environment"]) for w in out}
    for w in out:
        for d in w["depends_on"]:
            if (d, w["environment"]) not in names_by_env:
                raise InputError(f"{w['name']} ({w['environment']}) depends on {d!r}, which has no {w['environment']} account")
    return org, domain, out


def ou_for(w: dict) -> str:
    if w["environment"] == "sandbox":
        return "Sandbox"
    if w["environment"] == "prod":
        return "Workloads/Prod-Restricted" if w["data_classification"] in {"confidential", "restricted"} else "Workloads/Prod"
    return "Workloads/NonProd"


def workload_impact(w: dict) -> str:
    """Impact follows data classification, lowered for non-production. Internet exposure changes likelihood, not
    impact, so it is reported in the "why" column instead."""
    score = CLASSIFICATIONS.index(w["data_classification"])  # 0..3
    if w["environment"] != "prod":
        score = max(0, score - 2) if w["environment"] in {"dev", "sandbox"} else max(0, score - 1)
    return IMPACT[score]


def design(data: dict) -> dict:
    org, domain, workloads = normalise(data)
    any_facing = any(w["internet_facing"] for w in workloads)
    accounts: list[dict] = []

    def add(name: str, ou: str, purpose: str, **extra) -> dict:
        acct = {"name": name, "ou": ou, "root_email": f"aws+{name}@{domain}", "purpose": purpose, **extra}
        accounts.append(acct)
        return acct

    add(f"{org}-management", "Root", "Organizations, billing and IAM Identity Center only; no workloads", kind="foundation")
    add(f"{org}-log-archive", "Security", "Organization CloudTrail, Config and VPC flow log buckets (Object Lock)",
        kind="foundation")
    add(f"{org}-security-tooling", "Security",
        "Delegated administrator for GuardDuty, Security Hub, Config and IAM Access Analyzer; read-only audit role "
        "into every account", kind="foundation")
    add(f"{org}-shared-services", "Infrastructure", "CI/CD, artifact registries, shared DNS", kind="foundation")
    if any_facing:
        add(f"{org}-network", "Infrastructure", "Transit Gateway, centralised egress and ingress inspection",
            kind="foundation")
    by_key: dict[tuple[str, str], dict] = {}
    for w in workloads:
        acct = add(f"{org}-{w['name']}-{w['environment']}", ou_for(w),
                   f"{w['name']} {w['environment']} ({w['data_classification']} data"
                   f"{', internet-facing' if w['internet_facing'] else ''})", kind="workload", workload=w)
        by_key[(w["name"], w["environment"])] = acct
    for a in accounts:
        if len(a["name"]) > 50:
            raise InputError(f"account name {a['name']} is over 50 characters; shorten the workload name")

    workload_accounts = [a for a in accounts if a["kind"] == "workload"]
    deployable = [a["name"] for a in workload_accounts if a["workload"]["environment"] != "sandbox"]
    networked = [a["name"] for a in workload_accounts if a["workload"]["environment"] != "sandbox"]
    rows = []
    for a in accounts:
        name = a["name"]
        if name.endswith("-management") and a["kind"] == "foundation":
            rows.append(row(name, "critical", ["every account in the organization"],
                            "SCPs do not apply to the management account; it can change SCPs, create roles in member "
                            "accounts through OrganizationAccountAccessRole and close accounts",
                            "Keep it empty of workloads; MFA on root; few humans; alert on every console sign-in"))
        elif name.endswith("-log-archive"):
            rows.append(row(name, "high", ["all organization logs"],
                            "Read access to every account's audit trail; tampering is limited by SCPs and S3 Object Lock",
                            "Object Lock in compliance mode; protect_log_archive SCP; no human write access"))
        elif name.endswith("-security-tooling"):
            rows.append(row(name, "high", ["read-only view of every account", "security findings for the organization"],
                            "Can read configuration everywhere and suppress or archive findings",
                            "Read-only audit role only; findings exported to log-archive; alert on suppression rules"))
        elif name.endswith("-shared-services"):
            rows.append(row(name, "critical" if deployable else "high", deployable or ["shared DNS and artifacts"],
                            "Pipelines that deploy into workload accounts carry their deployment roles; a poisoned "
                            "artifact reaches every consumer",
                            "One deployment role per target account, scoped by aws:SourceAccount and the pipeline's "
                            "role; separate prod and non-prod pipelines; signed artifacts"))
        elif name.endswith("-network") and a["kind"] == "foundation":
            rows.append(row(name, "high", networked, "Network paths to every attached VPC; can reroute or inspect traffic",
                            "Transit Gateway route tables per environment; no prod to non-prod routes; flow logs to "
                            "log-archive"))
        else:
            w = a["workload"]
            reach = [f"{name} resources and {w['data_classification']} data"]
            reach += [by_key[(d, w["environment"])]["name"] + " (declared dependency)" for d in w["depends_on"]]
            callers = [b["name"] for b in workload_accounts if w["name"] in b["workload"]["depends_on"]
                       and b["workload"]["environment"] == w["environment"]]
            exposure = "internet-facing" if w["internet_facing"] else "internal"
            rows.append(row(name, workload_impact(w), reach,
                            f"{exposure}; cross-account reach only through declared dependencies"
                            + (f"; called by {', '.join(callers)}" if callers else ""),
                            "Resource policies that name the caller's role ARN; no shared credentials; "
                            + ("AWS WAF on the public entry point" if w["internet_facing"] else "no public endpoints")))
    tree: dict[str, list[str]] = {}
    for a in accounts:
        tree.setdefault(a["ou"], []).append(a["name"])
    for ou in SCP_BY_OU:
        tree.setdefault(ou, [])
    scps = {ou: SCP_BY_OU[ou] for ou in SCP_BY_OU}
    return {"organization": org, "accounts": [{k: v for k, v in a.items() if k != "workload"} for a in accounts],
            "ou_tree": tree, "scp_attachments": scps, "blast_radius": rows,
            "note": "A design proposal from declared inputs; review it with the workload owners before creating accounts."}


def row(account: str, impact: str, reach: list[str], why: str, containment: str) -> dict:
    return {"account": account, "impact_if_compromised": impact, "can_reach": reach, "why": why, "containment": containment}


def render(d: dict) -> str:
    out = [f"# Landing zone design: {d['organization']}", "", "## OU tree", "", "```text", "Root"]
    layout = [("Security", 1), ("Infrastructure", 1), ("Workloads", 1), ("Workloads/Prod", 2),
              ("Workloads/Prod-Restricted", 2), ("Workloads/NonProd", 2), ("Sandbox", 1), ("Suspended", 1)]
    out += [f"  {a}" for a in d["ou_tree"].get("Root", [])]
    for ou, depth in layout:
        indent = "  " * depth
        out.append(f"{indent}{ou.split('/')[-1]}/")
        out += [f"{indent}  {a}" for a in d["ou_tree"].get(ou, [])]
    out += ["```", "", "## Accounts", "", "| Account | OU | Root email | Purpose |", "|---|---|---|---|"]
    out += [f"| {a['name']} | {a['ou']} | {a['root_email']} | {a['purpose']} |" for a in d["accounts"]]
    out += ["", "## SCP attachments", "", "| Target | Guardrails |", "|---|---|"]
    out += [f"| {ou} | {', '.join(g) if g else '(inherits)'} |" for ou, g in d["scp_attachments"].items()]
    out += ["", "## Blast radius", "", "| Account | Impact if compromised | Can reach | Why | Containment |",
            "|---|---|---|---|---|"]
    out += [f"| {r['account']} | {r['impact_if_compromised']} | {'; '.join(r['can_reach'])} | {r['why']} | {r['containment']} |"
            for r in d["blast_radius"]]
    out += ["", d["note"]]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="YAML or JSON workload list")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    args = ap.parse_args(argv)
    try:
        d = design(load_input(Path(args.input)))
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(d, indent=2) if args.json else render(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
