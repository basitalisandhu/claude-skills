#!/usr/bin/env python3
"""Build a quarterly recertification pack for agent and workload identities: per-owner sheets and a tracking CSV.

usage: agent_recertification.py INVENTORY [--attestations CSV] [--users FILE] [--previous-inventory FILE]
                                [--as-of YYYY-MM-DD] [--quarter LABEL] [--max-age N] [--json] [--out DIR]

INVENTORY is the JSON written by nhi_inventory.py --json (or a CSV with id, name, type, owner, last_used and an
optional permissions column separated by semicolons). The previous attestation CSV has one row per decision:
identity_id, owner, decision (keep, reduce, remove), attested_on (YYYY-MM-DD) and attested_by; the latest row per
identity counts. The users export is Graph /users (userPrincipalName, mail, accountEnabled) as JSON, or a CSV with
userPrincipalName or mail and accountEnabled. The previous inventory is last quarter's nhi_inventory.py JSON.

Rules (exit 1 when any identity has one):
  never-attested      no attestation row for the identity
  attestation-stale   the latest attestation is older than --max-age days (90)
  owner-left          an owner is missing from the users export or the account is disabled (only with --users)
  no-owner            the inventory names no owner
  removal-not-done    the latest decision was remove (or retire) and the identity is still in the inventory
Changes since last quarter (new identity, owner, credentials, permissions) are listed on the sheets for the owner
to read; they do not change the exit code.

Each identity goes on the sheet of its first owner; identities with no owner, or whose owners all left, go on
review-unassigned.md. With --out DIR the script writes review-<owner>.md per owner and tracking.csv into DIR (and
nothing else); without it, it prints the summary and every sheet to standard output.

Exit codes: 0 nothing flagged, 1 at least one identity needs a person, 2 bad input.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import date
from pathlib import Path

FLAG_RULES = ("never-attested", "attestation-stale", "owner-left", "no-owner", "removal-not-done")
TRACKING_COLUMNS = (
    "quarter",
    "identity_id",
    "name",
    "type",
    "owner",
    "owner_status",
    "last_used",
    "last_attested",
    "attestation_age_days",
    "flags",
    "changes",
    "decision",
    "decided_by",
    "decided_on",
    "notes",
)


class InputError(Exception):
    """Bad input: exit code 2."""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc


def read_csv(path: Path) -> list[dict[str, str]]:
    try:
        rows = list(csv.DictReader(io.StringIO(read_text(path))))
    except csv.Error as exc:
        raise InputError(f"{path.name}: not a readable CSV: {exc}") from exc
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in rows]


def read_json(path: Path):
    try:
        return json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def parse_day(value: str) -> date | None:
    try:
        return date.fromisoformat(str(value or "").strip()[:10])
    except ValueError:
        return None


def load_inventory(path: Path) -> dict[str, dict]:
    if path.suffix.lower() == ".csv":
        rows = read_csv(path)
        if rows and "id" not in rows[0]:
            raise InputError(f"{path.name}: needs an id column")
        out = {}
        for r in rows:
            perms = [p.strip() for p in r.get("permissions", "").split(";") if p.strip()]
            out[r["id"]] = {
                "id": r["id"],
                "name": r.get("name") or r["id"],
                "type": r.get("type", ""),
                "owners": [o.strip() for o in re.split(r"[;,]", r.get("owner", "")) if o.strip()],
                "last_used": r.get("last_used") or None,
                "credentials": [],
                "assignments": [{"kind": "permission", "name": p} for p in perms],
                "trust": [],
            }
        return out
    data = read_json(path)
    rows = data.get("identities") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise InputError(f"{path.name}: expected nhi_inventory.py JSON with an identities list")
    out = {}
    for r in rows:
        if not isinstance(r, dict) or not r.get("id"):
            raise InputError(f"{path.name}: every identity needs an id")
        out[str(r["id"])] = r
    return out


def load_attestations(path: Path | None) -> dict[str, dict]:
    if not path:
        return {}
    rows = read_csv(path)
    if rows and not ({"identity_id", "id"} & set(rows[0])):
        raise InputError(f"{path.name}: needs an identity_id column")
    latest: dict[str, dict] = {}
    for n, r in enumerate(rows, start=2):
        ident = r.get("identity_id") or r.get("id", "")
        day = parse_day(r.get("attested_on", ""))
        if not ident:
            continue
        if r.get("attested_on") and not day:
            raise InputError(f"{path.name}: line {n}: attested_on {r['attested_on']!r} is not YYYY-MM-DD")
        r["_day"] = day
        r["_line"] = n
        prev = latest.get(ident)
        if prev is None or (day and (prev["_day"] is None or day >= prev["_day"])):
            latest[ident] = r
    return latest


def load_users(path: Path | None) -> dict[str, bool] | None:
    if not path:
        return None
    if path.suffix.lower() == ".csv":
        rows = read_csv(path)
    else:
        data = read_json(path)
        rows = data.get("value") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise InputError(f"{path.name}: expected a Graph users list")
        rows = [{str(k).lower(): v for k, v in r.items()} for r in rows if isinstance(r, dict)]
    users: dict[str, bool] = {}
    for r in rows:
        enabled = str(r.get("accountenabled", "true")).strip().lower() not in {"false", "0", "no"}
        for key in ("userprincipalname", "mail", "email", "upn"):
            if r.get(key):
                users[str(r[key]).strip().lower()] = enabled
    return users


def describe(identity: dict) -> list[str]:
    caps = [f"{a.get('kind', 'permission')}: {a.get('name')}" for a in identity.get("assignments") or []]
    caps += [f"trusted by {t}" for t in identity.get("trust") or []]
    return caps


def changes(current: dict, previous: dict | None) -> list[str]:
    if previous is None:
        return ["new since last quarter"]
    out = []
    if sorted(current.get("owners") or []) != sorted(previous.get("owners") or []):
        before = ", ".join(previous.get("owners") or []) or "none"
        after = ", ".join(current.get("owners") or []) or "none"
        out.append(f"owner {before} -> {after}")
    now = {c.get("key_id") for c in current.get("credentials") or []}
    then = {c.get("key_id") for c in previous.get("credentials") or []}
    out += [f"credential added {k}" for k in sorted(now - then)]
    out += [f"credential removed {k}" for k in sorted(then - now)]
    now_caps, then_caps = set(describe(current)), set(describe(previous))
    out += [f"gained {c}" for c in sorted(now_caps - then_caps)]
    out += [f"lost {c}" for c in sorted(then_caps - now_caps)]
    return out


def slug(owner: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", owner.lower()).strip("-") or "unassigned"


def build(args) -> dict:
    as_of = date.today()
    if args.as_of:
        parsed = parse_day(args.as_of)
        if parsed is None:
            raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD")
        as_of = parsed
    inventory = load_inventory(Path(args.inventory))
    attest = load_attestations(Path(args.attestations) if args.attestations else None)
    users = load_users(Path(args.users) if args.users else None)
    previous = load_inventory(Path(args.previous_inventory)) if args.previous_inventory else None
    quarter = args.quarter or f"{as_of.year}-Q{(as_of.month - 1) // 3 + 1}"
    rows = []
    for ident_id in sorted(inventory):
        ident = inventory[ident_id]
        owners = list(ident.get("owners") or [])
        flags = []
        owner_status = "not checked"
        left = []
        if not owners:
            flags.append("no-owner")
            owner_status = "none"
        elif users is not None:
            left = [o for o in owners if users.get(o.lower()) is not True]
            owner_status = "left: " + ", ".join(left) if left else "active"
            if left:
                flags.append("owner-left")
        att = attest.get(ident_id)
        age = None
        if att is None:
            flags.append("never-attested")
        else:
            age = (as_of - att["_day"]).days if att["_day"] else None
            if age is None or age > args.max_age:
                flags.append("attestation-stale")
            if att.get("decision", "").lower() in {"remove", "retire", "revoke"}:
                flags.append("removal-not-done")
        active = [o for o in owners if o not in left]
        sheet_owner = active[0] if active else "unassigned"
        rows.append(
            {
                "identity_id": ident_id,
                "name": ident.get("name") or ident_id,
                "type": ident.get("type", ""),
                "owners": owners,
                "sheet": sheet_owner,
                "owner_status": owner_status,
                "last_used": ident.get("last_used"),
                "can_do": describe(ident),
                "last_attested": att["_day"].isoformat() if att and att["_day"] else None,
                "last_decision": att.get("decision", "") if att else None,
                "attestation_age_days": age,
                "changes": changes(ident, previous.get(ident_id)) if previous is not None else [],
                "flags": flags,
            }
        )
    gone = sorted(set(previous) - set(inventory)) if previous is not None else []
    return {
        "quarter": quarter,
        "as_of": as_of.isoformat(),
        "max_age_days": args.max_age,
        "users_checked": users is not None,
        "identities": rows,
        "removed_since_last_quarter": gone,
        "summary": {
            "identities": len(rows),
            "needs_a_person": sum(1 for r in rows if r["flags"]),
            "by_flag": {f: sum(1 for r in rows if f in r["flags"]) for f in FLAG_RULES},
            "sheets": sorted({r["sheet"] for r in rows}),
        },
    }


def sheet_markdown(doc: dict, owner: str) -> str:
    rows = [r for r in doc["identities"] if r["sheet"] == owner]
    title = "Unassigned identities (no current owner)" if owner == "unassigned" else owner
    lines = [
        f"# Recertification {doc['quarter']}: {title}",
        "",
        f"Prepared {doc['as_of']}. For each identity, confirm it is still needed, that what it can do matches its "
        "job, and record a decision: keep, reduce (say what) or remove.",
    ]
    for r in rows:
        lines += [
            "",
            f"## {r['name']} (`{r['identity_id']}`)",
            "",
            f"- Type: {r['type'] or 'not recorded'}; owners: {', '.join(r['owners']) or 'none'} ({r['owner_status']})",
            f"- Last acted: {r['last_used'] or 'not recorded'}",
            f"- Last attestation: {r['last_attested'] or 'never'}"
            + (f" (decision: {r['last_decision']})" if r["last_decision"] else ""),
            "- What it can do: " + ("; ".join(r["can_do"]) if r["can_do"] else "nothing recorded in the inventory"),
        ]
        if r["changes"]:
            lines.append("- Changed since last quarter: " + "; ".join(r["changes"]))
        if r["flags"]:
            lines.append("- Flags: " + ", ".join(r["flags"]))
        lines.append("- Decision (keep, reduce, remove), by whom and date: ____")
    return "\n".join(lines) + "\n"


def summary_markdown(doc: dict) -> str:
    s = doc["summary"]
    lines = [
        f"# Agent and workload identity recertification {doc['quarter']}",
        "",
        f"As of {doc['as_of']}. {s['identities']} identities on {len(s['sheets'])} sheet(s); {s['needs_a_person']} "
        f"flagged. Attestations older than {doc['max_age_days']} days are stale."
        + ("" if doc["users_checked"] else " Owners were not checked against a users export."),
        "",
        "| Flag | Identities |",
        "|---|---|",
    ]
    lines += [f"| {f} | {n} |" for f, n in s["by_flag"].items()]
    lines += ["", "| Identity | Sheet | Last attested | Flags |", "|---|---|---|---|"]
    for r in doc["identities"]:
        lines.append(
            f"| `{r['identity_id']}` | {r['sheet']} | {r['last_attested'] or 'never'} | "
            f"{', '.join(r['flags']) or '-'} |"
        )
    if doc["removed_since_last_quarter"]:
        lines += ["", "Gone since last quarter: " + ", ".join(f"`{x}`" for x in doc["removed_since_last_quarter"])]
    return "\n".join(lines) + "\n"


def tracking_csv(doc: dict) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=TRACKING_COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in doc["identities"]:
        w.writerow(
            {
                "quarter": doc["quarter"],
                "identity_id": r["identity_id"],
                "name": r["name"],
                "type": r["type"],
                "owner": r["sheet"],
                "owner_status": r["owner_status"],
                "last_used": r["last_used"] or "",
                "last_attested": r["last_attested"] or "",
                "attestation_age_days": "" if r["attestation_age_days"] is None else r["attestation_age_days"],
                "flags": ";".join(r["flags"]),
                "changes": ";".join(r["changes"]),
            }
        )
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agent_recertification.py",
        description="Quarterly recertification sheets per owner and a tracking CSV for agent and workload identities.",
        epilog="Exit codes: 0 nothing flagged, 1 at least one identity needs a person, 2 bad input.",
    )
    ap.add_argument("inventory", help="nhi_inventory.py JSON, or a CSV with id, name, type, owner, last_used")
    ap.add_argument("--attestations", help="previous attestation CSV (identity_id, owner, decision, attested_on, ...)")
    ap.add_argument("--users", help="Graph users export (JSON) or CSV, to find owners who left")
    ap.add_argument("--previous-inventory", help="last quarter's inventory JSON, to list what changed")
    ap.add_argument("--as-of", help="date judged against, YYYY-MM-DD (default today)")
    ap.add_argument("--quarter", help="label for this round, for example 2026-Q4 (default from --as-of)")
    ap.add_argument("--max-age", type=int, default=90, help="days after which an attestation is stale (90)")
    ap.add_argument("--json", action="store_true", help="print the computed pack as JSON")
    ap.add_argument("--out", help="folder to write review-<owner>.md sheets and tracking.csv into")
    args = ap.parse_args(argv)
    try:
        doc = build(args)
    except InputError as exc:
        print(f"agent_recertification.py: {exc}", file=sys.stderr)
        return 2
    sheets = {owner: sheet_markdown(doc, owner) for owner in doc["summary"]["sheets"]}
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for owner, text in sheets.items():
            (out / f"review-{slug(owner)}.md").write_text(text, encoding="utf-8")
        (out / "tracking.csv").write_text(tracking_csv(doc), encoding="utf-8")
    if args.json:
        sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    elif args.out:
        sys.stdout.write(summary_markdown(doc) + f"\nWrote {len(sheets)} sheet(s) and tracking.csv to {args.out}\n")
    else:
        sys.stdout.write(summary_markdown(doc) + "".join("\n---\n\n" + t for t in sheets.values()))
    return 1 if doc["summary"]["needs_a_person"] else 0


if __name__ == "__main__":
    sys.exit(main())
