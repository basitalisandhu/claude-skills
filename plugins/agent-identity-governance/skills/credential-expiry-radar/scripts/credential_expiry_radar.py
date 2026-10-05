#!/usr/bin/env python3
"""Bucket expiring and expired secrets, certificates, access keys and tokens, and write an action list per owner.

usage: credential_expiry_radar.py EXPORT_DIR [--as-of YYYY-MM-DD] [--max-key-age N] [--fail-within N]
                                  [--json] [--out FILE] [--redact]

Files read from EXPORT_DIR (at least one must be present):

  entra-applications.json          Graph /applications with owners expanded: passwordCredentials, keyCredentials
  entra-service-principals.json    Graph /servicePrincipals with owners expanded: SAML signing and other credentials
  aws-access-keys.json             aws iam list-access-keys output, one object or a list of them
  aws-credential-report.csv        aws iam get-credential-report, decoded (used when aws-access-keys.json is absent)
  aws-authorization-details.json   aws iam get-account-authorization-details (owner tags on IAM users)
  github-fine-grained-tokens.json  gh api /orgs/ORG/personal-access-tokens (fine-grained tokens with org access)
  other-keys.csv                   any other key: name, system, owner, key_id, created, expires

Due date: the end date where the system has one. AWS access keys have none, so a key is due --max-key-age days
(90) after it was created; the basis is printed with every row. A row with neither end date nor creation date is
bucketed as no-expiry.

Buckets by days from --as-of to the due date: expired (< 0), 7, 30, 90, later, no-expiry.

Key ids are shown as their last four characters; secret and token values are never read. --redact replaces e-mail
addresses with stable tokens.

Exit codes: 0 nothing expired or due within --fail-within days (30), 1 something is, 2 bad input.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

BUCKETS = ("expired", "7", "30", "90", "later", "no-expiry")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
KNOWN = (
    "entra-applications.json",
    "entra-service-principals.json",
    "aws-access-keys.json",
    "aws-credential-report.csv",
    "aws-authorization-details.json",
    "github-fine-grained-tokens.json",
    "other-keys.csv",
)


class InputError(Exception):
    """Bad input: exit code 2."""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def load_csv(path: Path) -> list[dict[str, str]]:
    try:
        rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
    except (OSError, csv.Error) as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in rows]


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


def parse_dt(value) -> datetime | None:
    if value in (None, "") or str(value).strip().lower() in {"n/a", "none", "null", "never", "no_information"}:
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
        return {redact(k): redact(v) for k, v in obj.items()}  # owner e-mail addresses are keys in by_owner
    return obj


def owners_of(obj: dict) -> list[str]:
    out = []
    for o in obj.get("owners") or []:
        name = str(o.get("userPrincipalName") or o.get("mail") or o.get("displayName") or o.get("id") or "")
        if name and name not in out:
            out.append(name)
    return out


def row(identity: str, system: str, kind: str, key_id, owners: list[str], due, basis: str) -> dict:
    return {
        "identity": identity,
        "system": system,
        "kind": kind,
        "key_id": key_id if str(key_id).startswith(("****", "slot ")) else mask(key_id),
        "owners": owners,
        "due": due.date().isoformat() if due else None,
        "basis": basis,
    }


def collect(folder: Path, max_key_age: int) -> tuple[list[dict], list[str]]:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    present = [n for n in KNOWN if (folder / n).exists()]
    if not present:
        raise InputError(f"{folder}: none of the expected export files is present (see --help)")
    rows: list[dict] = []
    for name, system in (("entra-applications.json", "entra"), ("entra-service-principals.json", "entra")):
        path = folder / name
        if not path.exists():
            continue
        for obj in items(load_json(path)):
            ident = f"{obj.get('displayName') or obj.get('appId')} ({obj.get('appId')})"
            where = "app registration" if name.startswith("entra-app") else "service principal"
            for field, kind in (("passwordCredentials", "client secret"), ("keyCredentials", "certificate")):
                for c in obj.get(field) or []:
                    rows.append(
                        row(
                            ident,
                            system,
                            f"{kind} on {where}",
                            c.get("keyId"),
                            owners_of(obj),
                            parse_dt(c.get("endDateTime")),
                            "end date",
                        )
                    )
    tag_owner: dict[str, str] = {}
    details = folder / "aws-authorization-details.json"
    if details.exists():
        for u in items(load_json(details), "UserDetailList"):
            for t in u.get("Tags") or []:
                if str(t.get("Key", "")).lower() == "owner":
                    tag_owner[str(u.get("UserName"))] = str(t.get("Value"))
    keys = folder / "aws-access-keys.json"
    report = folder / "aws-credential-report.csv"
    rule = f"rotation due {max_key_age} days after creation"
    if keys.exists():
        for k in items(load_json(keys), "AccessKeyMetadata"):
            if str(k.get("Status", "Active")) != "Active":
                continue
            user = str(k.get("UserName"))
            created = parse_dt(k.get("CreateDate"))
            due = created + timedelta(days=max_key_age) if created else None
            owner = [tag_owner[user]] if user in tag_owner else []
            rows.append(row(f"IAM user {user}", "aws", "access key", k.get("AccessKeyId"), owner, due, rule))
    elif report.exists():
        for r in load_csv(report):
            if "user" not in r:
                raise InputError(f"{report.name}: no 'user' column; is this the decoded credential report?")
            for n in (1, 2):
                if r.get(f"access_key_{n}_active", "").lower() != "true":
                    continue
                created = parse_dt(r.get(f"access_key_{n}_last_rotated"))
                due = created + timedelta(days=max_key_age) if created else None
                owner = [tag_owner[r["user"]]] if r["user"] in tag_owner else []
                rows.append(row(f"IAM user {r['user']}", "aws", "access key", f"slot {n}", owner, due, rule))
    tokens = folder / "github-fine-grained-tokens.json"
    if tokens.exists():
        for t in items(load_json(tokens)):
            login = str((t.get("owner") or {}).get("login") or "")
            name = t.get("token_name") or f"token {t.get('token_id') or t.get('id')}"
            rows.append(
                row(
                    f"{name} ({login})",
                    "github",
                    "fine-grained token",
                    t.get("token_id") or t.get("id"),
                    [login] if login else [],
                    parse_dt(t.get("token_expires_at")),
                    "end date",
                )
            )
    other = folder / "other-keys.csv"
    if other.exists():
        data = load_csv(other)
        if data and "name" not in data[0]:
            raise InputError(f"{other.name}: needs a name column")
        for n, r in enumerate(data, start=2):
            if r.get("expires") and not parse_dt(r["expires"]):
                raise InputError(f"{other.name}: line {n}: expires {r['expires']!r} is not a date")
            expires = parse_dt(r.get("expires"))
            rows.append(
                row(
                    r["name"],
                    r.get("system") or "other",
                    r.get("kind") or "key",
                    r.get("key_id"),
                    [o.strip() for o in r.get("owner", "").split(";") if o.strip()],
                    expires,
                    "end date" if expires else "no end date recorded",
                )
            )
    return rows, present


def bucket(days: int | None) -> str:
    if days is None:
        return "no-expiry"
    if days < 0:
        return "expired"
    for limit in (7, 30, 90):
        if days <= limit:
            return str(limit)
    return "later"


def action(r: dict) -> str:
    if r["bucket"] == "expired":
        return "remove it, or replace it if something still depends on it"
    if r["bucket"] == "no-expiry":
        return "set an expiry or a rotation date, or record why it has none"
    if r["bucket"] in ("7", "30"):
        return f"rotate before {r['due']} and confirm the consumer picked up the new one"
    return f"plan the rotation before {r['due']}"


def build(folder: Path, as_of: date, max_key_age: int, fail_within: int) -> dict:
    rows, present = collect(folder, max_key_age)
    for r in rows:
        r["days_left"] = (date.fromisoformat(r["due"]) - as_of).days if r["due"] else None
        r["bucket"] = bucket(r["days_left"])
        r["action"] = action(r)
    rows.sort(key=lambda r: (r["days_left"] is None, r["days_left"] or 0, r["identity"], r["key_id"]))
    owners: dict[str, list[dict]] = {}
    for r in rows:
        if r["bucket"] == "later":
            continue
        for o in r["owners"] or ["(no owner recorded)"]:
            owners.setdefault(o, []).append(r)
    due = [r for r in rows if r["days_left"] is not None and r["days_left"] <= fail_within]
    return {
        "as_of": as_of.isoformat(),
        "inputs": present,
        "max_key_age_days": max_key_age,
        "fail_within_days": fail_within,
        "counts": {b: sum(1 for r in rows if r["bucket"] == b) for b in BUCKETS},
        "credentials": rows,
        "by_owner": {o: owners[o] for o in sorted(owners, key=lambda o: (o.startswith("("), o.lower()))},
        "needs_action": len(due),
    }


def render(doc: dict) -> str:
    c = doc["counts"]
    lines = [
        "# Credential expiry radar",
        "",
        f"As of {doc['as_of']}. {len(doc['credentials'])} credentials from {', '.join(doc['inputs'])}. AWS access keys "
        f"are due {doc['max_key_age_days']} days after creation.",
        "",
        "| Expired | Within 7 days | Within 30 days | Within 90 days | Later | No expiry |",
        "|---|---|---|---|---|---|",
        f"| {c['expired']} | {c['7']} | {c['30']} | {c['90']} | {c['later']} | {c['no-expiry']} |",
        "",
        "## Actions by owner",
    ]
    for owner, rows in doc["by_owner"].items():
        lines += ["", f"### {owner}", ""]
        for r in rows:
            when = f"due {r['due']} ({r['days_left']} days)" if r["due"] else "no due date"
            lines.append(f"- [{r['bucket']}] {r['identity']}: {r['kind']} {r['key_id']}, {when}: {r['action']}")
    if not doc["by_owner"]:
        lines += ["", "Nothing is expired, undated or due within 90 days."]
    lines += [
        "",
        "## All credentials",
        "",
        "| Bucket | Identity | System | Kind | Key | Due | Basis | Owners |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in doc["credentials"]:
        lines.append(
            f"| {r['bucket']} | {r['identity']} | {r['system']} | {r['kind']} | {r['key_id']} | {r['due'] or '-'} "
            f"| {r['basis']} | {', '.join(r['owners']) or '-'} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="credential_expiry_radar.py",
        description="Expired and expiring secrets, certificates, access keys and tokens, grouped by owner.",
        epilog="Exit codes: 0 nothing expired or due within --fail-within days, 1 something is, 2 bad input.",
    )
    ap.add_argument("export_dir", help="folder holding the export files listed in the module docstring")
    ap.add_argument("--as-of", help="date judged against, YYYY-MM-DD (default today)")
    ap.add_argument("--max-key-age", type=int, default=90, help="days after creation an AWS access key is due (90)")
    ap.add_argument("--fail-within", type=int, default=30, help="exit 1 when anything is due within N days (30)")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses with stable tokens")
    ap.add_argument("--json", action="store_true", help="print the radar as JSON")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        try:
            as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
        except ValueError as exc:
            raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD") from exc
        if args.max_key_age < 1 or args.fail_within < 0:
            raise InputError("--max-key-age must be at least 1 and --fail-within at least 0")
        doc = build(Path(args.export_dir), as_of, args.max_key_age, args.fail_within)
    except InputError as exc:
        print(f"credential_expiry_radar.py: {exc}", file=sys.stderr)
        return 2
    if args.redact:
        doc = redact(doc)
    text = json.dumps(doc, indent=2) + "\n" if args.json else render(doc)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 1 if doc["needs_action"] else 0


if __name__ == "__main__":
    sys.exit(main())
