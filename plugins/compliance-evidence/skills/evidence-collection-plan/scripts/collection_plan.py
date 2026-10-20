#!/usr/bin/env python3
"""Plan which evidence to collect for each in-scope control, from which system, how, how often and by when, as an
auditor-style PBC (prepared by client) request list, and on later runs show which requests an evidence pack already
meets with a fresh file, which are stale and which are missing or overdue.

The script never connects to a system. It reads the scope file, the request catalogue and, optionally, the manifest of
an evidence pack, and prints a plan.

Inputs:
  --scope FILE       JSON: {"organisation": "Example Pty Ltd", "framework": "iso27001-2022" or "soc2",
                     "period": {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD"}, "controls": ["A.8.15", ...],
                     "systems": [{"kind": "aws", "owner": "Cloud platform lead"}, ...]}
                     systems is the inventory of what the organisation uses (aws, m365, entra, github, google-workspace,
                     hr-system, endpoint-mdm, ticketing, ...) with an owner role for each. The kind "document" (policies
                     and records kept as documents) is always available.
  --catalogue FILE   optional JSON in the bundled catalogue's format (references/request-catalogue.json). Its requests
                     are added to the bundled ones; a request with the same id replaces the bundled one. Its
                     control_topics are added too.
  --manifest FILE    optional manifest.json of an evidence pack (evidence-pack-builder). Each file entry is matched to a
                     request by the entry's optional "request_id", or by the request's match.path_glob patterns on the
                     entry's path (case-insensitive). The collection day is collected_at, else file_mtime.
  --as-of DATE       the day to evaluate on (YYYY-MM-DD, default today); pin it to reproduce a report
  --format FORMAT    markdown (default), json or csv; csv is the PBC spreadsheet to paste into a tracker. --json is
                     the same as --format json.
  --out FILE         write the report to FILE instead of stdout
  --redact           replace e-mail addresses and the owner names in the inventory with stable tokens; secret-shaped
                     strings are always masked

Rows. Each selected request gets one row per slot of the audit period: once-per-period and population-sample requests
one row (due on the period end), quarterly requests one row per three months from the period start, monthly requests one
row per month. A request whose system is not in the inventory is listed as not applicable unless the system is added; it
is never dropped silently. A control that no request in the catalogue covers is listed as a gap.

Status of a row on --as-of:
  met      a matching file was collected inside the row's slot (and the audit period) and within the request's
           freshness window, counted back from the earlier of --as-of and the due date
  stale    a matching file was collected inside the slot but is older than the freshness window
  missing  no matching file yet and the due date has not passed
  overdue  no matching file in the slot and the due date has passed
A control takes the worst status of its rows (met, then missing, stale, overdue). A population-sample file may be
collected after the period ends, because the whole population is only known then. Dates are calendar days and
timezone-naive.

Statuses describe collection only. This script never marks a control supported, contradicted or not assessable: a met
request means a fresh file exists, not that the control works. Use control-map-from-exports for that. Every output is
preparation for a human assessor, not an audit opinion or an attestation.

Exit codes: 0 every in-scope control has requests and none is stale or overdue, 1 any stale or overdue row or any control
without an applicable request, 2 bad input or usage (missing file, invalid JSON, unknown framework, bad dates, period end
before start, malformed scope, manifest or catalogue). Standard library only. Reads files only; no network.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import fnmatch
import hashlib
import io
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

FRAMEWORKS = ("iso27001-2022", "soc2")
FREQUENCIES = ("once-per-period", "quarterly", "monthly", "population-sample")
STATUSES = ("met", "missing", "stale", "overdue")  # best to worst
SEVERITY = {s: i for i, s in enumerate(STATUSES)}
ALWAYS_AVAILABLE = "document"
MAX_PERIOD_DAYS = 1096
MAX_FRESHNESS_DAYS = 1100
MAX_TITLE = 120
MAX_HOW = 400
DISCLAIMER = (
    "Preparation for a human assessor: this is a collection plan, not an audit opinion, an attestation or a statement that any "
    "control works. The catalogue is a starting set; the assessor decides what evidence is sufficient."
)
BUNDLED = Path(__file__).resolve().parents[1] / "references" / "request-catalogue.json"
ID_RE = re.compile(r"^[A-Z0-9][A-Za-z0-9._-]{1,30}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CONTROL_RES = {
    "iso27001-2022": re.compile(r"^A\.[5-8]\.\d{1,2}$"),
    "soc2": re.compile(r"^(CC[1-9]\.\d{1,2}|A1\.\d{1,2}|C1\.\d{1,2}|PI1\.\d{1,2}|P[1-8]\.\d{1,2})$"),
}
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def parse_day(value: object, what: str) -> date:
    if not isinstance(value, str) or not DAY_RE.match(value.strip()):
        raise InputError(f"{what}: {value!r} is not a date in YYYY-MM-DD form")
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        raise InputError(f"{what}: {value!r} is not a real calendar date") from None


def add_months(d: date, months: int) -> date:
    index = d.year * 12 + (d.month - 1) + months
    year, month = divmod(index, 12)
    return date(year, month + 1, min(d.day, calendar.monthrange(year, month + 1)[1]))


def read_json(path: str, what: str) -> object:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise InputError(f"{what} file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read {what} file {path}: {exc}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{what} file {path} is not valid JSON: {exc}") from None


def text_field(obj: dict, key: str, what: str, limit: int, required: bool = True) -> str:
    value = obj.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise InputError(f"{what}: '{key}' must be a non-empty string")
    if len(value) > limit:
        raise InputError(f"{what}: '{key}' is longer than {limit} characters")
    return value.strip()


def normalise_control(value: object, framework: str, what: str) -> str:
    if not isinstance(value, str):
        raise InputError(f"{what}: control ids must be strings, got {value!r}")
    cid = value.strip().upper()
    if not CONTROL_RES[framework].match(cid):
        raise InputError(f"{what}: {value!r} is not a {framework} control identifier")
    return cid


def validate_catalogue(doc: object, what: str) -> tuple[list[dict], dict[str, str]]:
    if not isinstance(doc, dict) or not isinstance(doc.get("requests"), list):
        raise InputError(f"{what}: expected an object with a 'requests' list")
    topics_in = doc.get("control_topics", {})
    if not isinstance(topics_in, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in topics_in.items()):
        raise InputError(f"{what}: control_topics must map identifiers to text")
    requests: list[dict] = []
    seen: set[str] = set()
    for n, raw in enumerate(doc["requests"], 1):
        where = f"{what}: request {n}"
        if not isinstance(raw, dict):
            raise InputError(f"{where} is not an object")
        rid = text_field(raw, "id", where, 31)
        if not ID_RE.match(rid):
            raise InputError(f"{where}: id {rid!r} must be letters, digits, '.', '_' or '-' (2 to 31 characters)")
        if rid in seen:
            raise InputError(f"{what}: duplicate request id {rid}")
        seen.add(rid)
        where = f"{what}: request {rid}"
        controls_in = raw.get("controls")
        if not isinstance(controls_in, dict):
            raise InputError(f"{where}: 'controls' must map a framework to a list of identifiers")
        controls: dict[str, list[str]] = {}
        for fw, ids in controls_in.items():
            if fw not in FRAMEWORKS:
                raise InputError(f"{where}: unknown framework {fw!r} in controls")
            if not isinstance(ids, list):
                raise InputError(f"{where}: controls.{fw} must be a list")
            controls[fw] = sorted({normalise_control(i, fw, where) for i in ids}, key=control_sort_key)
        if not any(controls.values()):
            raise InputError(f"{where}: no control identifiers")
        system = text_field(raw, "system", where, 41)
        if not SLUG_RE.match(system):
            raise InputError(f"{where}: system {system!r} must be a lower-case slug such as aws or google-workspace")
        freq = raw.get("frequency")
        if freq not in FREQUENCIES:
            raise InputError(f"{where}: frequency must be one of {', '.join(FREQUENCIES)}")
        fresh = raw.get("freshness_days")
        if isinstance(fresh, bool) or not isinstance(fresh, int) or not 1 <= fresh <= MAX_FRESHNESS_DAYS:
            raise InputError(f"{where}: freshness_days must be a whole number from 1 to {MAX_FRESHNESS_DAYS}")
        consumers = raw.get("consumers", [])
        if not isinstance(consumers, list) or not all(isinstance(c, str) and c.strip() for c in consumers):
            raise InputError(f"{where}: consumers must be a list of skill names")
        match = raw.get("match", {})
        globs = match.get("path_glob", []) if isinstance(match, dict) else None
        if globs is None or not isinstance(globs, list) or not all(isinstance(g, str) and g.strip() for g in globs):
            raise InputError(f"{where}: match.path_glob must be a list of patterns")
        requests.append(
            {
                "id": rid,
                "title": text_field(raw, "title", where, MAX_TITLE),
                "controls": controls,
                "system": system,
                "how": text_field(raw, "how", where, MAX_HOW),
                "frequency": freq,
                "freshness_days": fresh,
                "owner_role": text_field(raw, "owner_role", where, 80),
                "consumers": [c.strip() for c in consumers],
                "path_glob": [g.strip() for g in globs],
            }
        )
    return requests, dict(topics_in)


def control_sort_key(cid: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"(\d+)", cid) if p)


def load_catalogue(custom: str | None) -> tuple[list[dict], dict[str, str], int]:
    requests, topics = validate_catalogue(read_json(str(BUNDLED), "bundled catalogue"), "bundled catalogue")
    overridden = 0
    if custom:
        extra, extra_topics = validate_catalogue(read_json(custom, "catalogue"), f"catalogue {custom}")
        by_id = {r["id"]: r for r in requests}
        for r in extra:
            overridden += r["id"] in by_id
            by_id[r["id"]] = r
        requests = list(by_id.values())
        topics.update(extra_topics)
    return requests, topics, overridden


def load_scope(path: str) -> dict:
    doc = read_json(path, "scope")
    if not isinstance(doc, dict):
        raise InputError("scope: expected a JSON object")
    framework = doc.get("framework")
    if framework not in FRAMEWORKS:
        raise InputError(f"scope: unknown framework {framework!r}; use one of {', '.join(FRAMEWORKS)}")
    period = doc.get("period")
    if not isinstance(period, dict):
        raise InputError("scope: 'period' must be an object with start and end")
    start, end = parse_day(period.get("start"), "scope period.start"), parse_day(period.get("end"), "scope period.end")
    if end < start:
        raise InputError(f"scope: period end {end} is before the start {start}")
    if (end - start).days + 1 > MAX_PERIOD_DAYS:
        raise InputError(f"scope: the period is longer than {MAX_PERIOD_DAYS} days")
    controls_in = doc.get("controls")
    if not isinstance(controls_in, list) or not controls_in:
        raise InputError("scope: 'controls' must be a non-empty list of control identifiers")
    if len(controls_in) > 500:
        raise InputError("scope: more than 500 controls")
    controls = sorted({normalise_control(c, framework, "scope") for c in controls_in}, key=control_sort_key)
    systems_in = doc.get("systems", [])
    if not isinstance(systems_in, list):
        raise InputError("scope: 'systems' must be a list of {kind, owner}")
    systems: dict[str, str] = {}
    for item in systems_in:
        if not isinstance(item, dict) or not isinstance(item.get("kind"), str):
            raise InputError("scope: each system needs a 'kind' string")
        kind = item["kind"].strip().lower()
        if not SLUG_RE.match(kind):
            raise InputError(f"scope: system kind {item['kind']!r} must be a slug such as aws or google-workspace")
        if kind in systems:
            raise InputError(f"scope: system {kind} is listed twice")
        owner = item.get("owner", "")
        if not isinstance(owner, str) or len(owner) > 80:
            raise InputError(f"scope: owner of {kind} must be a string of at most 80 characters")
        systems[kind] = owner.strip()
    org = doc.get("organisation", "")
    if not isinstance(org, str) or len(org) > 120:
        raise InputError("scope: organisation must be a string of at most 120 characters")
    return {"organisation": org.strip(), "framework": framework, "start": start, "end": end, "controls": controls, "systems": systems}


def load_manifest(path: str) -> list[dict]:
    doc = read_json(path, "manifest")
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
        raise InputError("manifest: expected an evidence pack manifest object with a 'files' list")
    schema = doc.get("schema")
    if schema is not None and not (isinstance(schema, str) and schema.startswith("compliance-evidence-pack/")):
        raise InputError(f"manifest: unrecognised schema {schema!r}")
    files: list[dict] = []
    for n, entry in enumerate(doc["files"], 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"].strip():
            raise InputError(f"manifest: file entry {n} has no path")
        stamp = entry.get("collected_at") or entry.get("file_mtime")
        if not isinstance(stamp, str) or not stamp.strip():
            raise InputError(f"manifest: {entry['path']} has no collected_at or file_mtime")
        day = parse_day(stamp.strip()[:10], f"manifest: {entry['path']} collected_at")
        rid = entry.get("request_id")
        if rid is not None and not isinstance(rid, str):
            raise InputError(f"manifest: {entry['path']} request_id must be a string")
        path_norm = entry["path"].strip().replace("\\", "/")
        while path_norm.startswith("./"):
            path_norm = path_norm[2:]
        files.append({"path": path_norm, "date": day, "request_id": (rid or "").strip()})
    return files


def slots(freq: str, start: date, end: date) -> list[tuple[str, date, date]]:
    """The slots of the period for a frequency as (label, slot start, due date)."""
    if freq in ("once-per-period", "population-sample"):
        return [("period" if freq == "once-per-period" else "population", start, end)]
    step, tag = (3, "Q") if freq == "quarterly" else (1, "M")
    out = []
    i = 0
    while True:
        s = add_months(start, step * i)
        if s > end:
            break
        due = min(add_months(start, step * (i + 1)) - timedelta(days=1), end)
        out.append((f"{tag}{i + 1:02d}" if tag == "M" else f"{tag}{i + 1}", s, due))
        i += 1
    return out


def file_matches(f: dict, req: dict) -> bool:
    if f["request_id"] and f["request_id"].upper() == req["id"].upper():
        return True
    path = f["path"].lower()
    return any(fnmatch.fnmatchcase(path, g.lower()) for g in req["path_glob"])


def classify(req: dict, label: str, slot_start: date, due: date, files: list[dict], as_of: date) -> dict:
    matched = sorted((f for f in files if file_matches(f, req)), key=lambda f: (f["date"], f["path"]))
    usable = [f for f in matched if f["date"] <= as_of]
    population = req["frequency"] == "population-sample"
    in_slot = [f for f in usable if f["date"] >= slot_start and (population or f["date"] <= due)]
    ref = min(as_of, due)
    row = {
        "request_id": req["id"],
        "slot": label,
        "slot_start": slot_start.isoformat(),
        "due": due.isoformat(),
        "evidence_file": "",
        "collected_at": "",
        "note": "",
    }
    if in_slot:
        best = in_slot[-1]
        age = (ref - best["date"]).days
        row["evidence_file"], row["collected_at"] = best["path"], best["date"].isoformat()
        if age <= req["freshness_days"]:
            row["status"] = "met"
        else:
            row["status"] = "stale"
            row["note"] = f"collected {age} days before {ref.isoformat()}; the freshness window is {req['freshness_days']} days"
        return row
    after = [f for f in usable if f["date"] > due]
    before = [f for f in usable if f["date"] < slot_start]
    if due < as_of:
        row["status"] = "overdue"
        if after:
            row["note"] = f"{after[-1]['path']} was collected on {after[-1]['date'].isoformat()}, after the due date"
        elif before:
            row["note"] = f"latest matching file {before[-1]['path']} is from {before[-1]['date'].isoformat()}, before this slot"
        return row
    row["status"] = "missing"
    if before:
        age = (as_of - before[-1]["date"]).days
        row["note"] = (
            f"latest matching file {before[-1]['path']} is from {before[-1]['date'].isoformat()} ({age} days ago), before this slot; "
            f"collect a new one by {due.isoformat()}"
        )
    elif len(matched) > len(usable):
        row["note"] = "a matching file is dated after --as-of and was ignored"
    return row


def evaluate(args: argparse.Namespace) -> dict:
    scope = load_scope(args.scope)
    as_of = parse_day(args.as_of, "--as-of") if args.as_of else date.today()
    requests, topics, overridden = load_catalogue(args.catalogue)
    files = load_manifest(args.manifest) if args.manifest else None
    framework = scope["framework"]
    in_scope = set(scope["controls"])

    selected = [r for r in requests if in_scope & set(r["controls"].get(framework, []))]
    rows: list[dict] = []
    not_applicable: list[dict] = []
    for req in selected:
        mine = sorted(in_scope & set(req["controls"][framework]), key=control_sort_key)
        kind = req["system"]
        if kind != ALWAYS_AVAILABLE and kind not in scope["systems"]:
            not_applicable.append(
                {
                    "request_id": req["id"],
                    "title": req["title"],
                    "system": kind,
                    "controls": mine,
                    "note": f"applies if {kind} is added to the inventory, otherwise evidence these controls another way",
                }
            )
            continue
        owner = scope["systems"].get(kind, "") or req["owner_role"]
        for label, s, due in slots(req["frequency"], scope["start"], scope["end"]):
            if files is None:
                row = {
                    "request_id": req["id"],
                    "slot": label,
                    "slot_start": s.isoformat(),
                    "due": due.isoformat(),
                    "evidence_file": "",
                    "collected_at": "",
                    "note": "",
                    "status": "overdue" if due < as_of else "missing",
                }
            else:
                row = classify(req, label, s, due, files, as_of)
            row.update(
                {
                    "title": req["title"],
                    "controls": mine,
                    "system": kind,
                    "owner": owner,
                    "how": req["how"],
                    "frequency": req["frequency"],
                    "freshness_days": req["freshness_days"],
                    "consumers": req["consumers"],
                }
            )
            rows.append(row)
    rows.sort(key=lambda r: (r["due"], r["request_id"], r["slot"]))

    controls: list[dict] = []
    gaps: list[dict] = []
    for cid in scope["controls"]:
        covering = [r for r in requests if cid in r["controls"].get(framework, [])]
        mine_rows = [r for r in rows if cid in r["controls"]]
        topic = topics.get(cid, "")
        entry = {"id": cid, "topic": topic, "requests": sorted({r["request_id"] for r in mine_rows}), "rows": len(mine_rows)}
        if not covering:
            entry["status"] = "gap"
            entry["note"] = "no request in the catalogue"
            gaps.append({"control": cid, "topic": topic, "reason": "no request in the catalogue"})
        elif not mine_rows:
            systems = sorted({r["system"] for r in covering})
            entry["status"] = "gap"
            entry["note"] = f"requests exist only for systems not in the inventory ({', '.join(systems)})"
            gaps.append({"control": cid, "topic": topic, "reason": entry["note"]})
        else:
            entry["status"] = max((r["status"] for r in mine_rows), key=SEVERITY.__getitem__)
            entry["note"] = ""
        controls.append(entry)

    row_counts = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
    ctl_counts = {s: sum(c["status"] == s for c in controls) for s in (*STATUSES, "gap")}
    unmatched: list[str] = []
    if files is not None:
        unmatched = sorted({f["path"] for f in files if not any(file_matches(f, r) for r in selected)})
    summary = {
        "controls": len(controls),
        "controls_by_status": ctl_counts,
        "requests_selected": len(selected),
        "requests_not_applicable": len(not_applicable),
        "rows": len(rows),
        "rows_by_status": row_counts,
        "gaps": len(gaps),
    }
    return {
        "organisation": scope["organisation"],
        "framework": framework,
        "period": {"start": scope["start"].isoformat(), "end": scope["end"].isoformat()},
        "as_of": as_of.isoformat(),
        "manifest_checked": files is not None,
        "catalogue_overrides": overridden,
        "inventory": [{"kind": k, "owner": v} for k, v in scope["systems"].items()],
        "summary": summary,
        "controls": controls,
        "requests": rows,
        "not_applicable": not_applicable,
        "gaps": gaps,
        "unmatched_manifest_files": unmatched,
        "disclaimer": DISCLAIMER,
    }


def exit_code(rep: dict) -> int:
    s = rep["summary"]
    return 1 if s["gaps"] or s["rows_by_status"]["stale"] or s["rows_by_status"]["overdue"] else 0


def scrub(text: str, owners: list[str], redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8] + "@redacted.invalid", text)
        for o in sorted({o for o in owners if o and "@" not in o}, key=len, reverse=True):
            text = text.replace(o, "owner-" + hashlib.sha256(o.lower().encode()).hexdigest()[:8])
    return text


def cell(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def csv_cell(v: object) -> str:
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render(rep: dict) -> str:
    s = rep["summary"]
    rb, cb = s["rows_by_status"], s["controls_by_status"]
    title = f"## Evidence collection plan: {cell(rep['organisation'] or 'unnamed organisation')}"
    lines = [
        title,
        "",
        f"Framework {rep['framework']}, audit period {rep['period']['start']} to {rep['period']['end']}, evaluated as of {rep['as_of']}. "
        + ("Evidence statuses come from the manifest." if rep["manifest_checked"] else "No manifest was given, so nothing counts as collected yet."),
        "",
        f"{s['controls']} controls in scope: {cb['met']} met, {cb['missing']} missing, {cb['stale']} stale, {cb['overdue']} overdue, "
        f"{cb['gap']} without an applicable request.",
        f"{s['requests_selected']} requests selected, {s['rows']} request rows: {rb['met']} met, {rb['missing']} missing, {rb['stale']} stale, "
        f"{rb['overdue']} overdue. {s['requests_not_applicable']} requests are not applicable unless their system is added.",
        "",
        "### Controls",
        "",
        "| Control | Topic (paraphrase) | Status | Requests |",
        "|---|---|---|---|",
    ]
    for c in rep["controls"]:
        reqs = ", ".join(c["requests"]) if c["requests"] else "none"
        status = c["status"] if not c["note"] else f"gap: {c['note']}"
        lines.append(f"| {c['id']} | {cell(c['topic'])} | {cell(status)} | {cell(reqs)} |")
    lines += [
        "",
        "A control takes the worst status of its rows (met, then missing, stale, overdue). A status says whether a file was collected in "
        "time, not whether the control works.",
        "",
        "### PBC request list",
        "",
        "| Request | Slot | Due | Item | Controls | System | Owner | Status | Evidence file | Collected |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rep["requests"]:
        lines.append(
            f"| {r['request_id']} | {r['slot']} | {r['due']} | {cell(r['title'])} | {cell(' '.join(r['controls']))} | {cell(r['system'])} | "
            f"{cell(r['owner'])} | {r['status']} | {cell(r['evidence_file'])} | {r['collected_at']} |"
        )
    notes = [r for r in rep["requests"] if r["note"]]
    if notes:
        lines += ["", "Notes:", ""]
        lines += [f"- {r['request_id']} {r['slot']}: {cell(r['note'])}" for r in notes]
    lines += ["", "### How to obtain each item", ""]
    seen: set[str] = set()
    for r in rep["requests"]:
        if r["request_id"] in seen:
            continue
        seen.add(r["request_id"])
        users = ", ".join(r["consumers"]) or "none listed"
        lines.append(
            f"- {r['request_id']} ({r['frequency']}, fresh within {r['freshness_days']} days, owner {cell(r['owner'])}): {cell(r['how'])}. "
            f"Used by: {cell(users)}."
        )
    if rep["not_applicable"]:
        lines += ["", "### Not applicable unless the system is added", ""]
        lines += [
            f"- {n['request_id']} {cell(n['title'])} (system {cell(n['system'])}, controls {cell(' '.join(n['controls']))}): {cell(n['note'])}."
            for n in rep["not_applicable"]
        ]
    lines += ["", "### Gaps", ""]
    if rep["gaps"]:
        lines += [f"- {g['control']}{(' ' + cell(g['topic'])) if g['topic'] else ''}: {cell(g['reason'])}." for g in rep["gaps"]]
    else:
        lines.append("None: every in-scope control has at least one applicable request.")
    if rep["manifest_checked"] and rep["unmatched_manifest_files"]:
        shown = rep["unmatched_manifest_files"]
        lines += [
            "",
            f"Manifest files matching no selected request ({len(shown)}): {cell(', '.join(shown[:10]))}{' and more' if len(shown) > 10 else ''}.",
        ]
    lines += ["", rep["disclaimer"]]
    return "\n".join(lines)


CSV_COLUMNS = [
    "request_id", "title", "controls", "system", "owner", "how_to_obtain", "frequency", "slot", "due_date", "freshness_days", "status",
    "evidence_file", "collected_at", "used_by", "note",
]  # fmt: skip


def to_csv(rep: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)

    def put(**fields: object) -> None:
        w.writerow([csv_cell(fields.get(col, "")) for col in CSV_COLUMNS])

    for r in rep["requests"]:
        put(
            request_id=r["request_id"],
            title=r["title"],
            controls=" ".join(r["controls"]),
            system=r["system"],
            owner=r["owner"],
            how_to_obtain=r["how"],
            frequency=r["frequency"],
            slot=r["slot"],
            due_date=r["due"],
            freshness_days=r["freshness_days"],
            status=r["status"],
            evidence_file=r["evidence_file"],
            collected_at=r["collected_at"],
            used_by="; ".join(r["consumers"]),
            note=r["note"],
        )
    for n in rep["not_applicable"]:
        put(
            request_id=n["request_id"],
            title=n["title"],
            controls=" ".join(n["controls"]),
            system=n["system"],
            status="not applicable",
            note=n["note"],
        )
    for g in rep["gaps"]:
        title = f"Control {g['control']}" + (f": {g['topic']}" if g["topic"] else "")
        put(title=title, controls=g["control"], status="no request", note=g["reason"])
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", required=True, help="scope JSON: framework, audit period, control ids, system inventory")
    ap.add_argument("--catalogue", help="extra or overriding requests, in the format of references/request-catalogue.json")
    ap.add_argument("--manifest", help="manifest.json of an evidence pack, to show which requests are met, stale, missing or overdue")
    ap.add_argument("--as-of", help="evaluate on this day (YYYY-MM-DD, default today)")
    ap.add_argument("--format", choices=("markdown", "json", "csv"), default="markdown", help="output format (csv is the PBC spreadsheet)")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses and inventory owner names with stable tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    fmt = "json" if args.json else args.format
    try:
        rep = evaluate(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if fmt == "json":
        body = json.dumps(rep, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        body = to_csv(rep)
    else:
        body = render(rep)
    text = scrub(body, [i["owner"] for i in rep["inventory"]], args.redact)
    try:
        if args.out:
            Path(args.out).write_text(text if fmt == "csv" else text + "\n", encoding="utf-8", newline="")
        else:
            sys.stdout.write(text if fmt == "csv" else text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return exit_code(rep)


if __name__ == "__main__":
    sys.exit(main())
