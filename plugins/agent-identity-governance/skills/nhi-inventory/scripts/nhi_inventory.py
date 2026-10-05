#!/usr/bin/env python3
"""Build one inventory of non-human identities from saved exports, and flag ownerless and unused ones.

usage: nhi_inventory.py EXPORT_DIR [--as-of YYYY-MM-DD] [--dormant-days N] [--json] [--out FILE] [--redact]

Reads every file below that is present in EXPORT_DIR (at least one must be):

  entra-applications.json          Graph /applications with owners expanded (app registrations and their credentials)
  entra-service-principals.json    Graph /servicePrincipals with owners expanded (enterprise apps, managed identities)
  entra-sign-in-activity.json      Graph beta /reports/servicePrincipalSignInActivities (last sign-in per appId)
  entra-app-role-assignments.json  Graph appRoleAssignedTo lists (application permissions held)
  entra-oauth2-grants.json         Graph /oauth2PermissionGrants (delegated permissions granted)
  entra-resource-sps.json          Graph resource service principals with appRoles (turns role ids into names)
  aws-authorization-details.json   aws iam get-account-authorization-details (users, roles, tags, trust, last used)
  aws-access-keys.json             aws iam list-access-keys output, one object or a list of them
  aws-credential-report.csv        aws iam get-credential-report, decoded (key ages and last use)
  github-installations.json        gh api /orgs/ORG/installations
  github-deploy-keys.json          gh api repos/OWNER/REPO/keys, each key carrying a "repository" field
  register.csv                     hand-kept agents, connectors and API keys (id, name, type, owner, purpose, ...)

Rules (each identity gets zero or more flags):
  no-owner     no owner in the export (Entra owners, an "owner" tag, or the register) and none in register.csv
  dormant      last use is more than --dormant-days before --as-of
  never-used   the source records activity, nothing is recorded for this identity, and it is older than
               --dormant-days (or its age is unknown)
  disabled     the identity is switched off (informational; does not change the exit code)

A register.csv row whose id equals an inventory id (for example github-app:deploy-bot) adds its owner, purpose and
permissions to that identity instead of creating a new one. Microsoft first-party service principals are skipped.
AWS service-linked and SSO-reserved roles are skipped unless --include-aws-managed-roles is given.

Redaction: key ids are shown as their last four characters; secret values are never read. --redact replaces e-mail
addresses (owners) with stable tokens.

Exit codes: 0 nothing flagged, 1 at least one identity flagged no-owner, dormant or never-used, 2 bad input.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# Tenants that own Microsoft's own first-party applications; their service principals are not yours to govern.
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
FLAGS_THAT_COUNT = ("no-owner", "dormant", "never-used")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class InputError(Exception):
    """Bad input: exit code 2."""


# ---- shared helpers (each script carries its own copy so a skill folder stands alone) ---------------------------


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def items(data, *keys: str) -> list[dict]:
    """Rows from a Graph page ({"value": [...]}), a list of pages, a bare list, or an object holding one of keys."""
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


def parse_dt(value) -> datetime | None:
    """ISO 8601 text (Z, offset or date only) or epoch milliseconds, as an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000 if value > 10**11 else value, tz=timezone.utc)
    text = str(value).strip()
    if text.lower() in {"n/a", "no_information", "not_supported", "none", "null", "never"}:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00").replace("z", "+00:00"))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def mask(value) -> str:
    """Show only the last four characters of a key id."""
    text = str(value or "").strip()
    return "****" + text[-4:] if text else "****"


def token(value: str) -> str:
    return "user-" + hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:8]


def redact_text(text: str) -> str:
    return EMAIL_RE.sub(lambda m: token(m.group(0)) + "@redacted.invalid", text)


def redact(obj):
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    return obj


def cell(value) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def as_of_arg(value: str | None) -> datetime:
    if not value:
        return datetime.combine(date.today(), datetime.max.time()).replace(microsecond=0, tzinfo=timezone.utc)
    try:
        return datetime.combine(date.fromisoformat(value), datetime.max.time()).replace(
            microsecond=0, tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise InputError(f"--as-of {value!r} is not YYYY-MM-DD") from exc


# ---- identity record ---------------------------------------------------------------------------------------------


def new_identity(ident: str, source: str, kind: str, name: str) -> dict:
    return {
        "id": ident,
        "source": source,
        "type": kind,
        "name": name,
        "owners": [],
        "purpose": "",
        "enabled": True,
        "created": None,
        "last_used": None,
        "activity_recorded": False,
        "credentials": [],
        "assignments": [],
        "trust": [],
        "refs": {},
        "flags": [],
    }


def credential(kind: str, key_id, created, expires, status: str = "Active") -> dict:
    return {
        "kind": kind,
        "key_id": mask(key_id) if key_id else "****",
        "created": iso(parse_dt(created)),
        "expires": iso(parse_dt(expires)),
        "status": status,
    }


def add_owner(identity: dict, owner: str) -> None:
    owner = (owner or "").strip()
    if owner and owner not in identity["owners"]:
        identity["owners"].append(owner)


def owner_of(obj: dict) -> str:
    return str(obj.get("userPrincipalName") or obj.get("mail") or obj.get("displayName") or obj.get("appId") or "")


def tag_owner(tags) -> str:
    for t in tags or []:
        if isinstance(t, dict) and str(t.get("Key", "")).lower() in {"owner", "owner-email", "owneremail"}:
            return str(t.get("Value", ""))
        if isinstance(t, str):
            m = re.match(r"(?i)^owner\s*[:=]\s*(.+)$", t)
            if m:
                return m.group(1).strip()
    return ""


# ---- readers -----------------------------------------------------------------------------------------------------


def read_entra(folder: Path, inv: dict[str, dict], notes: list[str]) -> None:
    apps_path, sps_path = folder / "entra-applications.json", folder / "entra-service-principals.json"
    if not apps_path.exists() and not sps_path.exists():
        return
    sp_by_object: dict[str, str] = {}
    for app in items(load_json(apps_path)) if apps_path.exists() else []:
        app_id = str(app.get("appId") or "")
        if not app_id:
            continue
        ident = inv.setdefault(
            f"entra:{app_id}", new_identity(f"entra:{app_id}", "entra", "entra-app", app.get("displayName") or app_id)
        )
        ident["created"] = iso(parse_dt(app.get("createdDateTime")))
        ident["refs"].update({"app_id": app_id, "application_object_id": app.get("id")})
        for o in app.get("owners") or []:
            add_owner(ident, owner_of(o))
        add_owner(ident, tag_owner(app.get("tags")))
        for c in app.get("passwordCredentials") or []:
            ident["credentials"].append(
                credential("client-secret", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in app.get("keyCredentials") or []:
            ident["credentials"].append(
                credential("certificate", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in app.get("federatedIdentityCredentials") or []:
            ident["credentials"].append(credential("federated", c.get("id") or c.get("name"), None, None))
    for sp in items(load_json(sps_path)) if sps_path.exists() else []:
        app_id = str(sp.get("appId") or "")
        if not app_id or str(sp.get("appOwnerOrganizationId") or "") in MICROSOFT_TENANTS:
            continue
        sp_type = str(sp.get("servicePrincipalType") or "Application")
        kind = "entra-managed-identity" if sp_type == "ManagedIdentity" else "entra-app"
        key = f"entra:{app_id}"
        if key not in inv:
            kind = kind if kind == "entra-managed-identity" else "entra-enterprise-app"
            inv[key] = new_identity(key, "entra", kind, sp.get("displayName") or app_id)
        ident = inv[key]
        ident["refs"].update({"app_id": app_id, "service_principal_id": sp.get("id")})
        if sp.get("accountEnabled") is False:
            ident["enabled"] = False
        for o in sp.get("owners") or []:
            add_owner(ident, owner_of(o))
        add_owner(ident, tag_owner(sp.get("tags")))
        for c in sp.get("passwordCredentials") or []:
            ident["credentials"].append(
                credential("sp-secret", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in sp.get("keyCredentials") or []:
            if str(c.get("usage", "Verify")).lower() == "verify":
                ident["credentials"].append(
                    credential("sp-certificate", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
                )
        if sp.get("id"):
            sp_by_object[str(sp["id"])] = key
    activity = folder / "entra-sign-in-activity.json"
    if activity.exists():
        for ident in inv.values():
            if ident["source"] == "entra":
                ident["activity_recorded"] = True
        for row in items(load_json(activity)):
            key = f"entra:{row.get('appId')}"
            if key not in inv:
                continue
            seen = [
                parse_dt((v or {}).get("lastSignInDateTime"))
                for k, v in row.items()
                if k.endswith("SignInActivity") and isinstance(v, dict)
            ]
            seen = [s for s in seen if s]
            if seen:
                inv[key]["last_used"] = iso(max(seen))
    else:
        notes.append("entra-sign-in-activity.json not found: Entra last use is unknown and not judged")
    role_names: dict[tuple[str, str], str] = {}
    resource_names: dict[str, str] = {}
    scope_resource = folder / "entra-resource-sps.json"
    if scope_resource.exists():
        for res in items(load_json(scope_resource)):
            resource_names[str(res.get("id"))] = str(res.get("displayName") or res.get("appId") or "")
            for role in res.get("appRoles") or []:
                role_names[(str(res.get("id")), str(role.get("id")))] = str(role.get("value") or role.get("id"))
    assignments = folder / "entra-app-role-assignments.json"
    if assignments.exists():
        for a in items(load_json(assignments)):
            key = sp_by_object.get(str(a.get("principalId")))
            if not key:
                continue
            res_id, role_id = str(a.get("resourceId")), str(a.get("appRoleId"))
            name = role_names.get((res_id, role_id), role_id)
            res = a.get("resourceDisplayName") or resource_names.get(res_id) or res_id
            inv[key]["assignments"].append(
                {"kind": "application-permission", "name": f"{res}: {name}", "ref": str(a.get("id") or "")}
            )
    grants = folder / "entra-oauth2-grants.json"
    if grants.exists():
        for g in items(load_json(grants)):
            key = sp_by_object.get(str(g.get("clientId")))
            if not key:
                continue
            res = resource_names.get(str(g.get("resourceId")), str(g.get("resourceId")))
            who = "all users" if g.get("consentType") == "AllPrincipals" else "one user"
            for scope in str(g.get("scope") or "").split():
                inv[key]["assignments"].append(
                    {"kind": "delegated-permission", "name": f"{res}: {scope} ({who})", "ref": str(g.get("id") or "")}
                )


def percent_decode(text: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text.replace("+", " "))


def trust_principals(doc) -> list[str]:
    if isinstance(doc, str):
        text = percent_decode(doc) if doc.lstrip().startswith("%") else doc
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
    out: list[str] = []
    statements = doc.get("Statement", []) if isinstance(doc, dict) else []
    for st in statements if isinstance(statements, list) else [statements]:
        principal = st.get("Principal", {}) if isinstance(st, dict) else {}
        if isinstance(principal, str):
            out.append(f"AWS: {principal}")
            continue
        for kind, vals in principal.items():
            for v in vals if isinstance(vals, list) else [vals]:
                out.append(f"{kind}: {v}")
    return out


def read_aws(folder: Path, inv: dict[str, dict], notes: list[str], include_managed: bool) -> None:
    details_path = folder / "aws-authorization-details.json"
    keys_path = folder / "aws-access-keys.json"
    report_path = folder / "aws-credential-report.csv"
    details = load_json(details_path) if details_path.exists() else {}
    users = {str(u.get("UserName")): u for u in items(details, "UserDetailList")} if details else {}
    keys_by_user: dict[str, list[dict]] = {}
    if keys_path.exists():
        for k in items(load_json(keys_path), "AccessKeyMetadata"):
            keys_by_user.setdefault(str(k.get("UserName")), []).append(k)
    report: dict[str, dict] = {}
    if report_path.exists():
        try:
            with report_path.open(encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, csv.Error) as exc:
            raise InputError(f"{report_path.name}: cannot read: {exc}") from exc
        if rows and "user" not in rows[0]:
            raise InputError(f"{report_path.name}: no 'user' column; is this the decoded credential report?")
        report = {r["user"]: r for r in rows if r.get("user") and r["user"] != "<root_account>"}
    elif users or keys_by_user:
        notes.append("aws-credential-report.csv not found: AWS access key last use is unknown and not judged")
    names = set(keys_by_user)
    for name, row in report.items():
        if any(str(row.get(f"access_key_{n}_active", "")).lower() == "true" for n in (1, 2)):
            names.add(name)
    for name in sorted(names):
        key = f"aws-user:{name}"
        u, row = users.get(name, {}), report.get(name, {})
        ident = inv.setdefault(key, new_identity(key, "aws", "aws-iam-user", name))
        ident["refs"].update({"user_name": name, "arn": u.get("Arn") or row.get("arn")})
        ident["created"] = iso(parse_dt(u.get("CreateDate") or row.get("user_creation_time")))
        add_owner(ident, tag_owner(u.get("Tags")))
        if keys_by_user.get(name):
            for k in keys_by_user[name]:
                ident["credentials"].append(
                    credential("access-key", k.get("AccessKeyId"), k.get("CreateDate"), None, k.get("Status", ""))
                )
        else:
            for n in (1, 2):
                if str(row.get(f"access_key_{n}_active", "")).lower() == "true":
                    c = credential("access-key", None, row.get(f"access_key_{n}_last_rotated"), None)
                    c["key_id"] = f"slot {n}"
                    ident["credentials"].append(c)
        if row:
            ident["activity_recorded"] = True
            used = [parse_dt(row.get(f"access_key_{n}_last_used_date")) for n in (1, 2)]
            used = [d for d in used if d]
            ident["last_used"] = iso(max(used)) if used else None
            if str(row.get("password_enabled", "")).lower() == "true":
                ident["refs"]["console_password"] = True
        for p in u.get("AttachedManagedPolicies") or []:
            ident["assignments"].append(
                {"kind": "managed-policy", "name": p.get("PolicyName"), "ref": p.get("PolicyArn")}
            )
        for p in u.get("UserPolicyList") or []:
            ident["assignments"].append({"kind": "inline-policy", "name": p.get("PolicyName"), "ref": ""})
        for g in u.get("GroupList") or []:
            ident["assignments"].append({"kind": "group", "name": g, "ref": ""})
    for r in items(details, "RoleDetailList") if details else []:
        path = str(r.get("Path") or "/")
        if not include_managed and (path.startswith("/aws-service-role/") or path.startswith("/aws-reserved/")):
            continue
        name = str(r.get("RoleName"))
        key = f"aws-role:{name}"
        ident = inv.setdefault(key, new_identity(key, "aws", "aws-iam-role", name))
        ident["refs"].update({"role_name": name, "arn": r.get("Arn")})
        ident["created"] = iso(parse_dt(r.get("CreateDate")))
        ident["activity_recorded"] = True
        ident["last_used"] = iso(parse_dt((r.get("RoleLastUsed") or {}).get("LastUsedDate")))
        ident["trust"] = trust_principals(r.get("AssumeRolePolicyDocument"))
        add_owner(ident, tag_owner(r.get("Tags")))
        for p in r.get("AttachedManagedPolicies") or []:
            ident["assignments"].append(
                {"kind": "managed-policy", "name": p.get("PolicyName"), "ref": p.get("PolicyArn")}
            )
        for p in r.get("RolePolicyList") or []:
            ident["assignments"].append({"kind": "inline-policy", "name": p.get("PolicyName"), "ref": ""})


def read_github(folder: Path, inv: dict[str, dict]) -> None:
    inst_path, keys_path = folder / "github-installations.json", folder / "github-deploy-keys.json"
    if inst_path.exists():
        for i in items(load_json(inst_path), "installations"):
            slug = str(i.get("app_slug") or i.get("app_id") or i.get("id"))
            key = f"github-app:{slug}"
            ident = inv.setdefault(key, new_identity(key, "github", "github-app", slug))
            ident["refs"].update({"installation_id": i.get("id"), "account": (i.get("account") or {}).get("login")})
            ident["created"] = iso(parse_dt(i.get("created_at")))
            ident["enabled"] = not i.get("suspended_at")
            for perm, level in sorted((i.get("permissions") or {}).items()):
                ident["assignments"].append({"kind": "app-permission", "name": f"{perm}:{level}", "ref": ""})
            ident["assignments"].append(
                {"kind": "repository-selection", "name": str(i.get("repository_selection") or "unknown"), "ref": ""}
            )
    if keys_path.exists():
        data = load_json(keys_path)
        rows = items(data)
        if isinstance(data, dict) and not rows:
            rows = [dict(k, repository=repo) for repo, ks in data.items() if isinstance(ks, list) for k in ks]
        for k in rows:
            repo = str(k.get("repository") or "unknown-repository")
            key = f"github-deploy-key:{repo}#{k.get('id')}"
            ident = inv.setdefault(key, new_identity(key, "github", "github-deploy-key", str(k.get("title") or key)))
            ident["refs"].update({"repository": repo, "deploy_key_id": k.get("id")})
            ident["created"] = iso(parse_dt(k.get("created_at")))
            ident["credentials"].append(credential("deploy-key", k.get("id"), k.get("created_at"), None))
            access = "read-only" if k.get("read_only", True) else "read-write"
            ident["assignments"].append({"kind": "repository-access", "name": f"{repo} ({access})", "ref": ""})
            if "last_used" in k:
                ident["activity_recorded"] = True
                ident["last_used"] = iso(parse_dt(k.get("last_used")))


def read_register(folder: Path, inv: dict[str, dict]) -> None:
    path = folder / "register.csv"
    if not path.exists():
        return
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
    except (OSError, csv.Error) as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    if rows and "id" not in {(h or "").strip().lower() for h in rows[0]}:
        raise InputError(f"{path.name}: needs an 'id' column")
    for n, raw in enumerate(rows, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        rid = row.get("id", "")
        if not rid:
            raise InputError(f"{path.name}: line {n} has no id")
        key = rid if rid in inv else (rid if ":" in rid else f"register:{rid}")
        if key not in inv:
            inv[key] = new_identity(key, "register", row.get("type") or "agent", row.get("name") or rid)
            inv[key]["created"] = iso(parse_dt(row.get("created")))
            if row.get("last_used"):
                inv[key]["activity_recorded"] = True
                inv[key]["last_used"] = iso(parse_dt(row.get("last_used")))
            if row.get("credential_created") or row.get("credential_expires") or row.get("credential_id"):
                inv[key]["credentials"].append(
                    credential(
                        row.get("credential_kind") or "api-key",
                        row.get("credential_id"),
                        row.get("credential_created"),
                        row.get("credential_expires"),
                    )
                )
        ident = inv[key]
        add_owner(ident, row.get("owner", ""))
        ident["purpose"] = ident["purpose"] or row.get("purpose", "")
        ident["refs"]["register_line"] = n
        for p in filter(None, (x.strip() for x in row.get("permissions", "").split(";"))):
            ident["assignments"].append({"kind": "declared-permission", "name": p, "ref": ""})
        if row.get("platform"):
            ident["refs"]["platform"] = row["platform"]
        if row.get("gateway"):
            ident["refs"]["gateway"] = row["gateway"]


# ---- evaluation and output ---------------------------------------------------------------------------------------


def evaluate(inv: dict[str, dict], as_of: datetime, dormant_days: int) -> list[dict]:
    out = []
    for key in sorted(inv):
        ident = inv[key]
        creds = ident["credentials"]
        ages = [(as_of - parse_dt(c["created"])).days for c in creds if parse_dt(c["created"])]
        expiries = sorted(c["expires"] for c in creds if c["expires"])
        ident["credential_count"] = len(creds)
        ident["oldest_credential_age_days"] = max(ages) if ages else None
        ident["next_credential_expiry"] = next((e for e in expiries if parse_dt(e) >= as_of), None)
        flags = []
        if not ident["owners"]:
            flags.append("no-owner")
        last = parse_dt(ident["last_used"])
        created = parse_dt(ident["created"])
        ident["days_since_use"] = (as_of - last).days if last else None
        if last and (as_of - last).days > dormant_days:
            flags.append("dormant")
        elif ident["activity_recorded"] and not last and (not created or (as_of - created).days > dormant_days):
            flags.append("never-used")
        if not ident["enabled"]:
            flags.append("disabled")
        ident["flags"] = flags
        out.append(ident)
    return out


def render(doc: dict) -> str:
    s = doc["summary"]
    lines = [
        "# Non-human identity inventory",
        "",
        f"As of {doc['as_of']}. {s['identities']} identities from {', '.join(doc['sources']) or 'no source'}; "
        f"{s['flagged']} need a person (dormant means no use in {doc['dormant_days']} days).",
        "",
        "| Type | Count |",
        "|---|---|",
    ]
    lines += [f"| {t} | {n} |" for t, n in sorted(s["by_type"].items())]
    lines += [
        "",
        "## Inventory",
        "",
        "| Identity | Type | Owner | Last used | Credentials | Oldest credential (days) | Flags |",
        "|---|---|---|---|---|---|---|",
    ]
    for i in doc["identities"]:
        last = i["last_used"][:10] if i["last_used"] else ("never" if i["activity_recorded"] else "unknown")
        lines.append(
            f"| `{cell(i['id'])}` | {i['type']} | {cell(', '.join(i['owners']))} | {last} | {i['credential_count']} "
            f"| {cell(i['oldest_credential_age_days'])} | {cell(', '.join(i['flags']))} |"
        )
    flagged = [i for i in doc["identities"] if set(i["flags"]) & set(FLAGS_THAT_COUNT)]
    lines += ["", f"## Needs a person ({len(flagged)})", ""]
    for i in flagged:
        lines.append(f"- `{i['id']}` ({i['name']}): {', '.join(f for f in i['flags'] if f in FLAGS_THAT_COUNT)}")
        lines.append("  - Owner to confirm, keep or retire, and date: ____")
    if not flagged:
        lines.append("Nothing flagged. Record the date of this inventory and who reviewed it.")
    if doc["notes"]:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in doc["notes"]]
    return "\n".join(lines) + "\n"


def build(folder: Path, as_of: datetime, dormant_days: int, include_managed: bool) -> dict:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    inv: dict[str, dict] = {}
    notes: list[str] = []
    read_entra(folder, inv, notes)
    read_aws(folder, inv, notes, include_managed)
    read_github(folder, inv)
    read_register(folder, inv)
    known = [p.name for p in sorted(folder.iterdir()) if p.name in KNOWN_FILES]
    if not known:
        raise InputError(f"{folder}: none of the expected export files is present (see --help)")
    identities = evaluate(inv, as_of, dormant_days)
    by_type: dict[str, int] = {}
    for i in identities:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
    flagged = sum(1 for i in identities if set(i["flags"]) & set(FLAGS_THAT_COUNT))
    return {
        "as_of": as_of.date().isoformat(),
        "dormant_days": dormant_days,
        "sources": known,
        "summary": {"identities": len(identities), "flagged": flagged, "by_type": by_type},
        "identities": identities,
        "notes": notes,
    }


KNOWN_FILES = {
    "entra-applications.json",
    "entra-service-principals.json",
    "entra-sign-in-activity.json",
    "entra-app-role-assignments.json",
    "entra-oauth2-grants.json",
    "entra-resource-sps.json",
    "aws-authorization-details.json",
    "aws-access-keys.json",
    "aws-credential-report.csv",
    "github-installations.json",
    "github-deploy-keys.json",
    "register.csv",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="nhi_inventory.py",
        description="One inventory of non-human identities from saved Entra, AWS, GitHub and register exports.",
        epilog="Exit codes: 0 nothing flagged, 1 an identity is ownerless, dormant or never used, 2 bad input.",
    )
    ap.add_argument("export_dir", help="folder holding the export files listed in the module docstring")
    ap.add_argument("--as-of", help="date judged against, YYYY-MM-DD (default today)")
    ap.add_argument("--dormant-days", type=int, default=90, help="days without use that count as dormant (90)")
    ap.add_argument("--include-aws-managed-roles", action="store_true", help="keep service-linked and SSO roles")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses with stable tokens")
    ap.add_argument("--json", action="store_true", help="print the inventory as JSON (the input of other skills)")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        if args.dormant_days < 1:
            raise InputError("--dormant-days must be at least 1")
        doc = build(Path(args.export_dir), as_of_arg(args.as_of), args.dormant_days, args.include_aws_managed_roles)
    except InputError as exc:
        print(f"nhi_inventory.py: {exc}", file=sys.stderr)
        return 2
    if args.redact:
        doc = redact(doc)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n" if args.json else render(doc)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 1 if doc["summary"]["flagged"] else 0


if __name__ == "__main__":
    sys.exit(main())
