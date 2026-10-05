#!/usr/bin/env python3
"""Review Entra ID agent identities, and app registrations that act as agents, from saved Graph exports.

usage: entra_agent_review.py EXPORT_DIR [--as-of YYYY-MM-DD] [--name-pattern REGEX] [--tag TEXT] [--app-id ID]
                             [--include-all] [--fail-on LOW|MEDIUM|HIGH] [--json] [--out FILE] [--redact]

Files read from EXPORT_DIR (entra-service-principals.json is required; the rest add checks):

  entra-service-principals.json     Graph /servicePrincipals with owners expanded
  entra-applications.json           Graph /applications with owners expanded (credentials, redirect URIs, audience)
  entra-agent-identities.json       Graph beta agent identity objects (servicePrincipals cast to agentIdentity)
  entra-agent-blueprints.json       Graph beta agent identity blueprint objects (applications cast to the blueprint)
  entra-oauth2-grants.json          Graph /oauth2PermissionGrants (delegated permissions)
  entra-app-role-assignments.json   Graph appRoleAssignedTo or appRoleAssignments lists (application permissions)
  entra-resource-sps.json           resource service principals with appRoles (names for role ids)
  entra-ca-policies.json            Graph /identity/conditionalAccess/policies
  entra-sign-in-activity.json       Graph beta /reports/servicePrincipalSignInActivities

An identity is reviewed when it is in entra-agent-identities.json, its @odata.type names an agent identity, its
display name matches --name-pattern, a tag contains a --tag value, its appId is given with --app-id, or
--include-all is set. Microsoft first-party service principals are never reviewed.

Rules and severities:
  high-risk-application-permission  HIGH    an application permission on the fixed HIGH_RISK list
  high-risk-delegated-permission    MEDIUM  a delegated permission on the list granted for all users (LOW for one user)
  redirect-uri-insecure             HIGH    an http:// redirect URI that is not localhost
  redirect-uri-wildcard             HIGH    a redirect URI containing *
  no-owner                          MEDIUM  no owner and no sponsor in the export
  credential-expired                LOW     a secret or certificate whose end date has passed (clean it up)
  credential-expiring               MEDIUM  a secret or certificate ending within --expiry-days (30)
  long-lived-secret                 MEDIUM  a client secret valid for more than --max-secret-days (180)
  ca-not-covered                    MEDIUM  no enabled Conditional Access policy targets this service principal
  ca-report-only                    LOW     only report-only policies target it
  dormant                           MEDIUM  last sign-in more than --dormant-days (90) ago, or none recorded
Conditional Access for workload identities applies to single-tenant applications registered in the tenant; other
service principals are reported as not applicable rather than as a gap.

Key ids are shown as their last four characters and secret values are never read. --redact replaces e-mail
addresses with stable tokens.

Exit codes: 0 no finding at or above --fail-on (default MEDIUM), 1 at least one, 2 bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
DEFAULT_NAME_PATTERN = r"(?i)(agent|bot\b|copilot|assistant|mcp|automation)"
SEVERITIES = ("LOW", "MEDIUM", "HIGH")
# Microsoft Graph and Exchange permissions that let an identity read or change data or access across the tenant.
HIGH_RISK = {
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Calendars.ReadWrite",
    "ChannelMessage.Read.All",
    "Chat.Read.All",
    "Chat.ReadWrite.All",
    "Contacts.ReadWrite",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Device.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "Directory.AccessAsUser.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Exchange.ManageAsApp",
    "Files.Read.All",
    "Files.ReadWrite.All",
    "full_access_as_app",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "IdentityRiskyUser.ReadWrite.All",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Policy.ReadWrite.ConditionalAccess",
    "RoleManagement.ReadWrite.Directory",
    "Sites.FullControl.All",
    "Sites.Manage.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class InputError(Exception):
    """Bad input: exit code 2."""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def items(data, *keys: str) -> list[dict]:
    names = ("value", *keys)
    if isinstance(data, dict):
        for k in names:
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
        return []
    out: list[dict] = []
    if isinstance(data, list):
        for x in data:
            if isinstance(x, list):  # gh api --paginate --slurp gives a list of pages
                out += items(x, *keys)
            elif isinstance(x, dict) and any(isinstance(x.get(k), list) for k in names):
                out += items(x, *keys)
            elif isinstance(x, dict):
                out.append(x)
    return out


def optional(folder: Path, name: str) -> list[dict] | None:
    path = folder / name
    return items(load_json(path)) if path.exists() else None


def parse_dt(value) -> datetime | None:
    if value in (None, ""):
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(value).strip().replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def mask(value) -> str:
    text = str(value or "").strip()
    return "****" + text[-4:] if text else "****"


def redact(obj):
    if isinstance(obj, str):
        return EMAIL_RE.sub(
            lambda m: (
                "user-" + hashlib.sha256(m.group(0).lower().encode("utf-8")).hexdigest()[:8] + "@redacted.invalid"
            ),
            obj,
        )
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    return obj


def cell(value) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def who(obj: dict) -> str:
    return str(obj.get("userPrincipalName") or obj.get("mail") or obj.get("displayName") or obj.get("id") or "")


def is_agent_type(obj: dict) -> bool:
    return "agentidentity" in str(obj.get("@odata.type", "")).lower()


# ---- review ------------------------------------------------------------------------------------------------------


def credentials_of(obj: dict, source: str) -> list[dict]:
    out = []
    for kind, field in (("client-secret", "passwordCredentials"), ("certificate", "keyCredentials")):
        for c in obj.get(field) or []:
            if kind == "certificate" and str(c.get("usage", "Verify")).lower() != "verify":
                continue
            out.append(
                {
                    "kind": kind,
                    "on": source,
                    "key_id": mask(c.get("keyId")),
                    "name": c.get("displayName") or "",
                    "start": c.get("startDateTime"),
                    "end": c.get("endDateTime"),
                }
            )
    for c in obj.get("federatedIdentityCredentials") or []:
        out.append(
            {
                "kind": "federated",
                "on": source,
                "key_id": mask(c.get("id") or c.get("name")),
                "name": f"{c.get('issuer', '')} {c.get('subject', '')}".strip(),
                "start": None,
                "end": None,
            }
        )
    return out


def redirect_uris(app: dict) -> list[str]:
    uris: list[str] = []
    for section in ("web", "spa", "publicClient"):
        uris += [str(u) for u in (app.get(section) or {}).get("redirectUris") or []]
    return uris


def ca_status(sp_id: str, single_tenant: bool, is_mi: bool, policies: list[dict] | None) -> tuple[str, list[str]]:
    if policies is None:
        return "unknown (no policy export)", []
    if is_mi:
        return "not applicable (managed identity)", []
    if not single_tenant:
        return "not applicable (not a single-tenant app registered here)", []
    enforced, report_only = [], []
    for p in policies:
        apps = ((p.get("conditions") or {}).get("clientApplications")) or {}
        include = [str(x) for x in apps.get("includeServicePrincipals") or []]
        exclude = [str(x) for x in apps.get("excludeServicePrincipals") or []]
        if sp_id in exclude or not (sp_id in include or "ServicePrincipalsInMyTenant" in include):
            continue
        state = str(p.get("state", ""))
        if state == "enabled":
            enforced.append(str(p.get("displayName") or p.get("id")))
        elif state == "enabledForReportingButNotEnforced":
            report_only.append(str(p.get("displayName") or p.get("id")))
    if enforced:
        return "covered", enforced
    if report_only:
        return "report-only", report_only
    return "not covered", []


def review(folder: Path, args, as_of: datetime) -> dict:
    sps_path = folder / "entra-service-principals.json"
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    if not sps_path.exists():
        raise InputError(f"{folder}: entra-service-principals.json is required")
    try:
        name_re = re.compile(args.name_pattern)
    except re.error as exc:
        raise InputError(f"--name-pattern is not a valid regular expression: {exc}") from exc
    sps = items(load_json(sps_path))
    apps = {str(a.get("appId")): a for a in optional(folder, "entra-applications.json") or []}
    agent_objs = optional(folder, "entra-agent-identities.json") or []
    blueprints = optional(folder, "entra-agent-blueprints.json") or []
    grants = optional(folder, "entra-oauth2-grants.json")
    assignments = optional(folder, "entra-app-role-assignments.json")
    resources = optional(folder, "entra-resource-sps.json") or []
    policies = optional(folder, "entra-ca-policies.json")
    activity_rows = optional(folder, "entra-sign-in-activity.json")
    role_names = {
        (str(r.get("id")), str(ro.get("id"))): ro.get("value") for r in resources for ro in r.get("appRoles") or []
    }
    res_names = {str(r.get("id")): str(r.get("displayName") or r.get("appId")) for r in resources}
    blueprint_by_id = {str(b.get("appId") or b.get("id")): b for b in blueprints}
    for b in blueprints:
        blueprint_by_id[str(b.get("id"))] = b
    last_seen: dict[str, datetime] = {}
    for row in activity_rows or []:
        seen = [
            parse_dt((v or {}).get("lastSignInDateTime"))
            for k, v in row.items()
            if k.endswith("SignInActivity") and isinstance(v, dict)
        ]
        seen = [s for s in seen if s]
        if seen:
            last_seen[str(row.get("appId"))] = max(seen)
    by_object = {str(sp.get("id")): sp for sp in sps}
    for a in agent_objs:
        by_object.setdefault(str(a.get("id")), a)
    agent_ids = {str(a.get("id")) for a in agent_objs}
    tags = [t.lower() for t in (args.tag or ["agent"])]
    reviewed = []
    for obj_id, sp in sorted(by_object.items(), key=lambda kv: str(kv[1].get("displayName", "")).lower()):
        if str(sp.get("appOwnerOrganizationId") or "") in MICROSOFT_TENANTS:
            continue
        app_id = str(sp.get("appId") or "")
        app = apps.get(app_id, {})
        reasons = []
        if obj_id in agent_ids or is_agent_type(sp):
            reasons.append("agent identity object")
        name = str(sp.get("displayName") or app.get("displayName") or app_id)
        if name_re.search(name):
            reasons.append("name pattern")
        all_tags = [str(t) for t in (sp.get("tags") or []) + (app.get("tags") or [])]
        if any(t in tag.lower() for tag in all_tags for t in tags):
            reasons.append("tag")
        if app_id in (args.app_id or []):
            reasons.append("named with --app-id")
        if args.include_all:
            reasons.append("--include-all")
        if not reasons:
            continue
        reviewed.append(
            review_one(
                obj_id,
                sp,
                app,
                reasons,
                blueprint_by_id,
                grants,
                assignments,
                role_names,
                res_names,
                policies,
                last_seen,
                activity_rows is not None,
                args,
                as_of,
            )
        )
    findings = [f for r in reviewed for f in r["findings"]]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {
        "as_of": as_of.date().isoformat(),
        "reviewed": reviewed,
        "summary": {"identities": len(reviewed), "findings": len(findings), "by_severity": counts},
        "inputs": sorted(p.name for p in folder.glob("entra-*.json")),
        "high_risk_list": sorted(HIGH_RISK, key=str.lower),
    }


def review_one(
    obj_id,
    sp,
    app,
    reasons,
    blueprint_by_id,
    grants,
    assignments,
    role_names,
    res_names,
    policies,
    last_seen,
    activity_known,
    args,
    as_of,
) -> dict:
    app_id = str(sp.get("appId") or "")
    findings: list[dict] = []

    def add(rule: str, severity: str, detail: str) -> None:
        findings.append({"rule": rule, "severity": severity, "detail": detail})

    blueprint_ref = str(sp.get("agentIdentityBlueprintId") or "")
    blueprint = blueprint_by_id.get(blueprint_ref) if blueprint_ref else None
    owners = sorted({who(o) for o in (sp.get("owners") or []) + (app.get("owners") or [])} - {""})
    sponsors = sorted({who(o) for o in (sp.get("sponsors") or [])} - {""})
    if not owners and not sponsors:
        add("no-owner", "MEDIUM", "no owner or sponsor recorded")
    app_perms, delegated = [], []
    for a in assignments or []:
        if str(a.get("principalId")) != obj_id:
            continue
        value = role_names.get((str(a.get("resourceId")), str(a.get("appRoleId")))) or str(a.get("appRoleId"))
        resource = a.get("resourceDisplayName") or res_names.get(str(a.get("resourceId"))) or a.get("resourceId")
        risky = value in HIGH_RISK
        app_perms.append({"resource": resource, "permission": value, "high_risk": risky})
        if risky:
            add("high-risk-application-permission", "HIGH", f"{resource}: {value} (application)")
    for g in grants or []:
        if str(g.get("clientId")) != obj_id:
            continue
        everyone = g.get("consentType") == "AllPrincipals"
        resource = res_names.get(str(g.get("resourceId")), str(g.get("resourceId")))
        for scope in str(g.get("scope") or "").split():
            risky = scope in HIGH_RISK
            delegated.append({"resource": resource, "permission": scope, "all_users": everyone, "high_risk": risky})
            if risky:
                consent = "all users" if everyone else "one user"
                add(
                    "high-risk-delegated-permission",
                    "MEDIUM" if everyone else "LOW",
                    f"{resource}: {scope} ({consent})",
                )
    creds = credentials_of(app, "application") + credentials_of(sp, "service principal")
    if blueprint:
        creds += credentials_of(blueprint, "blueprint")
    for c in creds:
        end, start = parse_dt(c["end"]), parse_dt(c["start"])
        c["status"] = "no end date" if not end else "ok"
        if end and end < as_of:
            c["status"] = "expired"
            add("credential-expired", "LOW", f"{c['kind']} {c['key_id']} on the {c['on']} ended {end.date()}")
        elif end and (end - as_of).days <= args.expiry_days:
            c["status"] = "expiring"
            add("credential-expiring", "MEDIUM", f"{c['kind']} {c['key_id']} on the {c['on']} ends {end.date()}")
        if c["kind"] == "client-secret" and start and end and (end - start).days > args.max_secret_days:
            add("long-lived-secret", "MEDIUM", f"secret {c['key_id']} is valid for {(end - start).days} days")
        c.pop("start")
    uris = redirect_uris(app)
    for u in uris:
        if "*" in u:
            add("redirect-uri-wildcard", "HIGH", u)
        if u.lower().startswith("http://") and not re.match(r"(?i)^http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", u):
            add("redirect-uri-insecure", "HIGH", u)
    is_mi = str(sp.get("servicePrincipalType")) == "ManagedIdentity"
    single = str(app.get("signInAudience", "")) == "AzureADMyOrg" or "agent identity object" in reasons
    ca, ca_policies = ca_status(obj_id, single, is_mi, policies)
    if ca == "not covered":
        add("ca-not-covered", "MEDIUM", "no enabled Conditional Access policy includes this service principal")
    elif ca == "report-only":
        add("ca-report-only", "LOW", "only report-only policies: " + ", ".join(ca_policies))
    last = last_seen.get(app_id)
    if activity_known and (not last or (as_of - last).days > args.dormant_days):
        add("dormant", "MEDIUM", f"last sign-in {last.date() if last else 'not recorded'}")
    return {
        "display_name": str(sp.get("displayName") or app.get("displayName") or app_id),
        "app_id": app_id,
        "service_principal_id": obj_id,
        "type": "agent identity" if "agent identity object" in reasons else str(sp.get("servicePrincipalType") or ""),
        "selected_because": reasons,
        "enabled": sp.get("accountEnabled", True) is not False,
        "blueprint": str(blueprint.get("displayName")) if blueprint else (blueprint_ref or None),
        "owners": owners,
        "sponsors": sponsors,
        "application_permissions": app_perms,
        "delegated_permissions": delegated,
        "credentials": creds,
        "redirect_uris": uris,
        "conditional_access": {"status": ca, "policies": ca_policies},
        "last_sign_in": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None,
        "findings": findings,
    }


def render(doc: dict) -> str:
    s = doc["summary"]
    sev = s["by_severity"]
    lines = [
        "# Entra agent identity review",
        "",
        f"As of {doc['as_of']}. {s['identities']} identities reviewed, {s['findings']} findings "
        f"(HIGH {sev['HIGH']}, MEDIUM {sev['MEDIUM']}, LOW {sev['LOW']}). Inputs: {', '.join(doc['inputs'])}.",
        "",
        "| Identity | Selected because | Owners or sponsors | Credentials | Conditional Access | Findings |",
        "|---|---|---|---|---|---|",
    ]
    for r in doc["reviewed"]:
        creds = ", ".join(f"{c['kind']} {c['key_id']} ({c['status']})" for c in r["credentials"]) or "none"
        lines.append(
            f"| {cell(r['display_name'])} | {', '.join(r['selected_because'])} | "
            f"{cell(', '.join(r['owners'] + r['sponsors']))} | {cell(creds)} | {r['conditional_access']['status']} | "
            f"{len(r['findings'])} |"
        )
    for r in doc["reviewed"]:
        lines += ["", f"## {r['display_name']} (`{r['app_id']}`)", ""]
        perms = [
            f"{p['resource']}: {'**' + p['permission'] + '**' if p['high_risk'] else p['permission']} (application)"
            for p in r["application_permissions"]
        ] + [
            f"{p['resource']}: {'**' + p['permission'] + '**' if p['high_risk'] else p['permission']} "
            f"(delegated, {'all users' if p['all_users'] else 'one user'})"
            for p in r["delegated_permissions"]
        ]
        lines.append("- Permissions (high-risk in bold): " + ("; ".join(perms) if perms else "none in the export"))
        lines.append("- Redirect URIs: " + (", ".join(r["redirect_uris"]) or "none"))
        if r["blueprint"]:
            lines.append(f"- Blueprint: {r['blueprint']}")
        lines.append(f"- Last sign-in: {r['last_sign_in'] or 'not recorded'}")
        for f in sorted(r["findings"], key=lambda f: -SEVERITIES.index(f["severity"])):
            lines.append(f"- [{f['severity']}] {f['rule']}: {f['detail']}")
        if r["findings"]:
            lines.append("- Owner decision (keep, reduce, rotate or retire), who and date: ____")
    if not doc["reviewed"]:
        lines += ["", "No identity matched. Widen the selection with --name-pattern, --tag, --app-id or --include-all."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="entra_agent_review.py",
        description="Review Entra agent identities and agent-like app registrations from saved Graph exports.",
        epilog="Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 bad input.",
    )
    ap.add_argument("export_dir", help="folder holding the entra-*.json exports")
    ap.add_argument("--as-of", help="date judged against, YYYY-MM-DD (default today)")
    ap.add_argument("--name-pattern", default=DEFAULT_NAME_PATTERN, help="regex on display names that marks an agent")
    ap.add_argument("--tag", action="append", help="tag text that marks an agent (repeatable, default 'agent')")
    ap.add_argument("--app-id", action="append", help="review this appId as well (repeatable)")
    ap.add_argument("--include-all", action="store_true", help="review every non-Microsoft service principal")
    ap.add_argument("--expiry-days", type=int, default=30, help="days ahead that count as expiring (30)")
    ap.add_argument("--max-secret-days", type=int, default=180, help="longest acceptable secret lifetime (180)")
    ap.add_argument("--dormant-days", type=int, default=90, help="days without sign-in that count as dormant (90)")
    ap.add_argument("--fail-on", default="MEDIUM", choices=SEVERITIES, help="lowest severity that exits 1")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses with stable tokens")
    ap.add_argument("--json", action="store_true", help="print the review as JSON")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        if args.as_of:
            try:
                day = date.fromisoformat(args.as_of)
            except ValueError as exc:
                raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD") from exc
        else:
            day = date.today()
        as_of = datetime.combine(day, datetime.max.time()).replace(microsecond=0, tzinfo=timezone.utc)
        doc = review(Path(args.export_dir), args, as_of)
    except InputError as exc:
        print(f"entra_agent_review.py: {exc}", file=sys.stderr)
        return 2
    if args.redact:
        doc = redact(doc)
    text = json.dumps(doc, indent=2) + "\n" if args.json else render(doc)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    floor = SEVERITIES.index(args.fail_on)
    hit = any(SEVERITIES.index(f["severity"]) >= floor for r in doc["reviewed"] for f in r["findings"])
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
