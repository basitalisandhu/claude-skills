#!/usr/bin/env python3
"""Incident checklist and hashed evidence folder for a leaked agent credential.

usage: leaked_credential_response.py INVENTORY --identity ID --credential LAST4 --leaked-at TIME
                                     [--match VALUE ...] [--entra-signins FILE] [--entra-audit FILE]
                                     [--cloudtrail FILE] [--github-audit FILE] [--app-log FILE]
                                     [--json] [--out DIR]

INVENTORY is the JSON written by nhi_inventory.py --json. ID is the identity the credential belongs to, LAST4 the
last four characters of the leaked key id (as the inventory shows it), and TIME the earliest moment the credential
could have been exposed (ISO 8601; a date means the start of that day, UTC). The audit exports use the same formats
as agent_action_timeline.py. Events are matched to the identity by the values in its inventory record (app id,
service principal id, user or role name, ARN, name) plus every --match value; give the full access key id or the
GitHub actor name with --match when you have it.

What the script works out:
  reach                 every assignment and trust entry the identity holds in the inventory; entries that can
                        create credentials or grant access are marked escalation-capable
  use after the leak    every matched event at or after TIME, which ones carried the leaked key (CloudTrail), and
                        source IP addresses not seen for this identity before TIME
  new credentials       credentials created at or after TIME: on this identity, and on every identity in the
                        inventory when the identity is escalation-capable
  rotation order        1 the leaked credential, 2 credentials created after TIME, 3 the identity's other
                        credentials, 4 (escalation-capable only) credentials created after TIME on other identities

With --out DIR (which must not exist or be empty) the script writes the evidence folder: inputs/ with a byte-exact
copy of every input file, findings.json, events-after-leak.json, checklist.md, manifest.json (path, size and SHA-256
of every file) and MANIFEST.md. It prints the SHA-256 of manifest.json; record it outside the folder so a rewritten
manifest can be detected. Without --out it prints the checklist.

Key ids are shown as their last four characters; the script never prints a secret value. Copies in inputs/ are
exact, so they hold whatever the exports held: keep the folder access-controlled.

Exit codes: 0 no use after the leak and no new credentials in the exports, 1 use or new credentials found (or the
credential is not in the inventory), 2 bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

TIME_KEYS = ("timestamp", "time", "ts", "@timestamp", "datetime")
ACTION_KEYS = ("action", "event", "tool", "operation", "name")
ID_KEYS = ("agent", "agent_id", "identity", "actor", "principal", "client_id", "user")
ESCALATION_RE = re.compile(
    r"(?i)(Application\.ReadWrite\.All|AppRoleAssignment\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory|"
    r"Directory\.ReadWrite\.All|DelegatedPermissionGrant\.ReadWrite\.All|AdministratorAccess|IAMFullAccess|"
    r"\biam:\*|\biam:Create|\biam:Put|\biam:Attach|administration:write|secrets:write|"
    r"organization_administration:write)"
)


class InputError(Exception):
    """Bad input: exit code 2."""


# ---- event readers (the same code as agent_action_timeline.py, so this skill folder stands alone) ---------------


def parse_dt(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000 if value > 10**11 else value, tz=timezone.utc)
    text = str(value).strip()
    if re.fullmatch(r"\d{10,13}", text):
        return parse_dt(int(text))
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00").replace("z", "+00:00"))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def mask(value) -> str:
    text = str(value or "").strip()
    return "****" + text[-4:] if text else ""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def rows_of(data, *keys: str) -> list[dict]:
    names = ("value", *keys)
    if isinstance(data, dict):
        for k in names:
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
        return []
    out: list[dict] = []
    for x in data if isinstance(data, list) else []:
        if isinstance(x, list):  # gh api --paginate --slurp gives a list of pages
            out += rows_of(x, *keys)
        elif isinstance(x, dict) and any(isinstance(x.get(k), list) for k in names):
            out += rows_of(x, *keys)
        elif isinstance(x, dict):
            out.append(x)
    return out


def event(source, when, action, ids, target="", ip="", failed=False, key_id="", file="", index=0) -> dict | None:
    dt = parse_dt(when)
    if dt is None:
        return None
    return {
        "time": iso(dt),
        "source": source,
        "action": action,
        "ids": sorted({str(i).strip().lower() for i in ids if i}),
        "target": str(target or ""),
        "ip": str(ip or ""),
        "failed": bool(failed),
        "key_id": mask(key_id),
        "file": file,
        "index": index,
    }


def read_entra_signins(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        status = r.get("status") or {}
        out.append(
            event(
                "entra-signin",
                r.get("createdDateTime"),
                f"signin:{r.get('resourceDisplayName') or r.get('resourceId') or 'unknown'}",
                [
                    r.get("appId"),
                    r.get("servicePrincipalId"),
                    r.get("servicePrincipalName"),
                    r.get("userPrincipalName"),
                    r.get("userId"),
                ],
                r.get("resourceDisplayName"),
                r.get("ipAddress"),
                str(status.get("errorCode", 0)) not in ("0", "None"),
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_entra_audit(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        by = r.get("initiatedBy") or {}
        app, user = by.get("app") or {}, by.get("user") or {}
        targets = [t.get("displayName") or t.get("id") for t in r.get("targetResources") or [] if isinstance(t, dict)]
        out.append(
            event(
                "entra-audit",
                r.get("activityDateTime"),
                f"entra:{r.get('activityDisplayName') or 'unknown'}",
                [
                    app.get("appId"),
                    app.get("servicePrincipalId"),
                    app.get("servicePrincipalName"),
                    app.get("displayName"),
                    user.get("id"),
                    user.get("userPrincipalName"),
                ],
                ", ".join(str(t) for t in targets if t),
                user.get("ipAddress"),
                str(r.get("result", "success")).lower() not in ("success", ""),
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_cloudtrail(path: Path) -> list[dict]:
    data = load_json(path)
    records = []
    for r in rows_of(data, "Events", "Records"):
        inner = r.get("CloudTrailEvent")
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}: a CloudTrailEvent is not valid JSON: {exc}") from exc
        if isinstance(inner, dict):
            records.append(inner)
        elif "eventTime" in r or "EventTime" in r:
            records.append(
                {
                    "eventTime": r.get("eventTime") or r.get("EventTime"),
                    "eventSource": r.get("eventSource") or r.get("EventSource"),
                    "eventName": r.get("eventName") or r.get("EventName"),
                    "userIdentity": r.get("userIdentity")
                    or {"userName": r.get("Username"), "accessKeyId": r.get("AccessKeyId")},
                }
            )
    out = []
    for n, r in enumerate(records):
        who = r.get("userIdentity") or {}
        issuer = ((who.get("sessionContext") or {}).get("sessionIssuer")) or {}
        arn = str(who.get("arn") or "")
        role = arn.split("/")[1] if ":assumed-role/" in arn and arn.count("/") >= 2 else ""
        service = str(r.get("eventSource") or "unknown").split(".")[0]
        resources = [x.get("ARN") or x.get("arn") for x in r.get("resources") or [] if isinstance(x, dict)]
        out.append(
            event(
                "cloudtrail",
                r.get("eventTime"),
                f"{service}:{r.get('eventName') or 'unknown'}",
                [
                    arn,
                    who.get("principalId"),
                    who.get("accessKeyId"),
                    who.get("userName"),
                    issuer.get("arn"),
                    issuer.get("userName"),
                    role,
                ],
                ", ".join(str(x) for x in resources if x),
                r.get("sourceIPAddress"),
                bool(r.get("errorCode")),
                who.get("accessKeyId"),
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_github_audit(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        out.append(
            event(
                "github-audit",
                r.get("@timestamp") or r.get("created_at"),
                f"github:{r.get('action') or 'unknown'}",
                [r.get("actor"), r.get("user"), r.get("oauth_application_name"), r.get("integration")],
                r.get("repo") or r.get("repository") or r.get("org"),
                r.get("actor_ip"),
                False,
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_app_log(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path.name}: line {n} is not JSON: {exc}") from exc
        if not isinstance(r, dict):
            raise InputError(f"{path.name}: line {n} is not a JSON object")
        when = next((r[k] for k in TIME_KEYS if r.get(k) not in (None, "")), None)
        action = next((r[k] for k in ACTION_KEYS if r.get(k) not in (None, "")), "unknown")
        level = str(r.get("level") or r.get("status") or "").lower()
        e = event(
            "app-log",
            when,
            f"app:{action}",
            [r.get(k) for k in ID_KEYS],
            r.get("target") or r.get("resource"),
            r.get("ip"),
            level in ("error", "failed", "failure", "denied"),
            "",
            path.name,
            n,
        )
        if e:
            out.append(e)
    return out


READERS = {
    "entra_signins": read_entra_signins,
    "entra_audit": read_entra_audit,
    "cloudtrail": read_cloudtrail,
    "github_audit": read_github_audit,
    "app_log": read_app_log,
}


def load_inventory(path: Path) -> list[dict]:
    data = load_json(path)
    rows = data.get("identities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise InputError(f"{path.name}: expected nhi_inventory.py JSON with an identities list")
    return [r for r in rows if isinstance(r, dict)]


def match_values(ident: dict, extra: list[str]) -> set[str]:
    refs = ident.get("refs") or {}
    values = [ident.get("name"), ident["id"].split(":", 1)[-1], *extra]
    values += [refs.get(k) for k in ("app_id", "service_principal_id", "user_name", "role_name", "arn", "account")]
    return {str(v).strip().lower() for v in values if v not in (None, "")}


def analyse(args) -> tuple[dict, list[Path]]:
    inventory_path = Path(args.inventory)
    identities = load_inventory(inventory_path)
    ident = next((r for r in identities if r.get("id") == args.identity), None)
    if ident is None:
        raise InputError(f"identity {args.identity!r} is not in the inventory")
    leaked_at = parse_dt(args.leaked_at)
    if leaked_at is None:
        raise InputError(f"--leaked-at {args.leaked_at!r} is not a date or time")
    last4 = args.credential.strip().replace("*", "")[-4:]
    if not last4:
        raise InputError("--credential must give the last characters of the key id")
    creds = ident.get("credentials") or []
    leaked = [c for c in creds if str(c.get("key_id", "")).endswith(last4)]
    files = [inventory_path]
    events: list[dict] = []
    for option, reader in READERS.items():
        for f in getattr(args, option) or []:
            files.append(Path(f))
            events += reader(Path(f))
    wanted = match_values(ident, args.match or [])
    events = sorted((e for e in events if wanted & set(e["ids"])), key=lambda e: (e["time"], e["source"], e["action"]))
    for e in events:
        e.pop("ids")
    before = [e for e in events if parse_dt(e["time"]) < leaked_at]
    after = [e for e in events if parse_dt(e["time"]) >= leaked_at]
    known_ips = {e["ip"] for e in before if e["ip"]}
    for e in after:
        e["flags"] = []
        if e["key_id"] and e["key_id"].endswith(last4):
            e["flags"].append("leaked-key")
        if e["ip"] and e["ip"] not in known_ips:
            e["flags"].append("new-source-ip")
        if e["failed"]:
            e["flags"].append("failed")
    reach = [
        {
            "what": f"{a.get('kind')}: {a.get('name')}",
            "escalation_capable": bool(ESCALATION_RE.search(str(a.get("name")))),
        }
        for a in ident.get("assignments") or []
    ] + [{"what": f"trusted by {t}", "escalation_capable": False} for t in ident.get("trust") or []]
    escalation = any(r["escalation_capable"] for r in reach)

    def created_after(c: dict) -> bool:
        dt = parse_dt(c.get("created"))
        return bool(dt and dt >= leaked_at)

    new_here = [dict(c, identity=ident["id"]) for c in creds if created_after(c)]
    new_elsewhere = [
        dict(c, identity=r["id"])
        for r in identities
        if escalation and r is not ident
        for c in r.get("credentials") or []
        if created_after(c)
    ]
    order = []
    for c in leaked or [{"kind": "credential", "key_id": "****" + last4}]:
        order.append(
            {
                "step": "revoke or deactivate the leaked credential now",
                "identity": ident["id"],
                "credential": f"{c.get('kind')} {c.get('key_id')}",
            }
        )
    for c in new_here:
        order.append(
            {
                "step": "remove: created after the leak time, so it may be the intruder's",
                "identity": ident["id"],
                "credential": f"{c.get('kind')} {c.get('key_id')}",
            }
        )
    for c in creds:
        if c not in leaked and not created_after(c):
            order.append(
                {
                    "step": "rotate: same identity, same exposure",
                    "identity": ident["id"],
                    "credential": f"{c.get('kind')} {c.get('key_id')}",
                }
            )
    for c in new_elsewhere:
        order.append(
            {
                "step": "check with its owner, then remove or rotate: created after the leak by an identity "
                "this credential could have used",
                "identity": c["identity"],
                "credential": f"{c.get('kind')} {c.get('key_id')}",
            }
        )
    doc = {
        "identity": ident["id"],
        "identity_type": ident.get("type"),
        "owners": ident.get("owners") or [],
        "credential": [{k: c.get(k) for k in ("kind", "key_id", "created", "expires")} for c in leaked]
        or [{"kind": "unknown", "key_id": "****" + last4, "note": "not found in the inventory record"}],
        "credential_in_inventory": bool(leaked),
        "leaked_at": iso(leaked_at),
        "reach": reach,
        "escalation_capable": escalation,
        "events_matched": len(events),
        "events_before_leak": len(before),
        "events_after_leak": after,
        "used_leaked_key": sum(1 for e in after if "leaked-key" in e["flags"]),
        "new_source_ips": sorted({e["ip"] for e in after if "new-source-ip" in e["flags"]}),
        "credentials_created_after_leak": new_here + new_elsewhere,
        "rotation_order": order,
    }
    return doc, files


def checklist(doc: dict) -> str:
    lines = [
        f"# Leaked credential response: {doc['identity']}",
        "",
        f"Credential {', '.join(c['kind'] + ' ' + c['key_id'] for c in doc['credential'])} of `{doc['identity']}` "
        f"({doc['identity_type']}), owners {', '.join(doc['owners']) or 'none recorded'}, exposed from "
        f"{doc['leaked_at']}."
        + ("" if doc["credential_in_inventory"] else " This key is NOT in the inventory record."),
        "",
        "## 1. Contain",
        "",
        "- [ ] Revoke or deactivate the leaked credential (first line of the rotation order). Time and by whom: ____",
        "- [ ] Remove the leaked value from where it appeared (commit, transcript, log, ticket) and record where: ____",
        "- [ ] If the agent must keep running, issue a new credential through the normal process, not by copying.",
        "",
        "## 2. Scope: what it could reach",
        "",
    ]
    lines += [f"- {r['what']}" + (" (escalation-capable)" if r["escalation_capable"] else "") for r in doc["reach"]]
    if not doc["reach"]:
        lines.append("- Nothing recorded in the inventory; find its access before closing this incident.")
    lines += [
        "",
        "## 3. Use after the leak",
        "",
        f"{doc['events_matched']} events matched the identity: {doc['events_before_leak']} before the leak time, "
        f"{len(doc['events_after_leak'])} at or after it; {doc['used_leaked_key']} carried the leaked key. New source "
        f"IP addresses: {', '.join(doc['new_source_ips']) or 'none'}.",
        "",
    ]
    if doc["events_after_leak"]:
        lines += ["| Time (UTC) | Source | Action | Target | IP | Flags |", "|---|---|---|---|---|---|"]
        lines += [
            f"| {e['time']} | {e['source']} | {e['action']} | {e['target'] or '-'} | {e['ip'] or '-'} | "
            f"{', '.join(e['flags']) or '-'} |"
            for e in doc["events_after_leak"]
        ]
    else:
        lines.append(
            "No event after the leak time in these exports. Absence here is only as good as the exports given."
        )
    lines += ["", "## 4. Rotate, in this order", ""]
    lines += [
        f"{n}. [ ] {o['identity']}: {o['credential']}: {o['step']}" for n, o in enumerate(doc["rotation_order"], 1)
    ]
    lines += [
        "",
        "## 5. Prove no further use",
        "",
        "- [ ] Export the audit logs again after the rotation and re-run this script; nothing should succeed with the "
        "old credential.",
        "- [ ] Every new-source-IP and escalation-capable action above has an explanation: ____",
        "",
        "## 6. Record",
        "",
        "- [ ] Evidence folder path and the SHA-256 of manifest.json, kept outside the folder: ____",
        "- [ ] Incident reference, notification decision (and who made it) and closing date: ____",
    ]
    return "\n".join(lines) + "\n"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def write_evidence(out: Path, doc: dict, files: list[Path], text: str) -> str:
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise InputError(f"{out}: already exists and is not empty; evidence folders are never overwritten")
    (out / "inputs").mkdir(parents=True, exist_ok=True)
    for n, src in enumerate(files, start=1):
        dst = out / "inputs" / f"{n:02d}-{src.name}"
        try:
            dst.write_bytes(src.read_bytes())
        except OSError as exc:
            raise InputError(f"{src}: cannot copy: {exc}") from exc
        if sha256_file(dst) != sha256_file(src):
            raise InputError(f"{src.name}: the copy does not match the source; the file changed while copying")
    (out / "findings.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (out / "events-after-leak.json").write_text(json.dumps(doc["events_after_leak"], indent=2) + "\n", encoding="utf-8")
    (out / "checklist.md").write_text(text, encoding="utf-8")
    entries = [
        {"path": p.relative_to(out).as_posix(), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
        for p in sorted(out.rglob("*"))
        if p.is_file()
    ]
    manifest = {"identity": doc["identity"], "leaked_at": doc["leaked_at"], "files": entries}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    md = [
        "# Evidence manifest",
        "",
        f"Leaked credential of `{doc['identity']}`, exposed from {doc['leaked_at']}.",
        "",
        "| File | Bytes | SHA-256 |",
        "|---|---|---|",
    ]
    md += [f"| {e['path']} | {e['bytes']} | `{e['sha256']}` |" for e in entries]
    md += ["", "manifest.json lists the same hashes; its own hash is recorded outside this folder."]
    (out / "MANIFEST.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return sha256_file(out / "manifest.json")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="leaked_credential_response.py",
        description="Checklist, rotation order and hashed evidence folder for a leaked agent credential.",
        epilog="Exit codes: 0 no use after the leak in the exports, 1 use or new credentials found, 2 bad input.",
    )
    ap.add_argument("inventory", help="inventory JSON from nhi_inventory.py --json")
    ap.add_argument("--identity", required=True, help="identity id the credential belongs to")
    ap.add_argument("--credential", required=True, help="last four characters of the leaked key id")
    ap.add_argument("--leaked-at", required=True, help="earliest possible exposure time, ISO 8601 (UTC if no offset)")
    ap.add_argument("--match", action="append", help="another value the identity appears as in the logs (repeatable)")
    ap.add_argument("--entra-signins", action="append", help="Graph sign-in log export (repeatable)")
    ap.add_argument("--entra-audit", action="append", help="Graph directory audit export (repeatable)")
    ap.add_argument("--cloudtrail", action="append", help="CloudTrail lookup-events output or log file (repeatable)")
    ap.add_argument("--github-audit", action="append", help="GitHub organisation audit log export (repeatable)")
    ap.add_argument("--app-log", action="append", help="application log in JSON lines (repeatable)")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    ap.add_argument("--out", help="evidence folder to create (must not exist or be empty)")
    args = ap.parse_args(argv)
    try:
        doc, files = analyse(args)
        text = checklist(doc)
        manifest_hash = write_evidence(Path(args.out), doc, files, text) if args.out else None
    except InputError as exc:
        print(f"leaked_credential_response.py: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.write(json.dumps(dict(doc, manifest_sha256=manifest_hash), indent=2) + "\n")
    elif args.out:
        sys.stdout.write(
            f"Evidence folder: {args.out}\nSHA-256 of manifest.json: {manifest_hash}\n"
            "Record this value outside the folder (for example in the incident ticket).\n\n" + text
        )
    else:
        sys.stdout.write(text)
    needs = doc["events_after_leak"] or doc["credentials_created_after_leak"] or not doc["credential_in_inventory"]
    return 1 if needs else 0


if __name__ == "__main__":
    sys.exit(main())
