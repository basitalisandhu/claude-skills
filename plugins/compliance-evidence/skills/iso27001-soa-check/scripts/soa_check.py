#!/usr/bin/env python3
"""Lint an ISO/IEC 27001:2022 Statement of Applicability (SoA) exported as CSV or JSON.

The script reads the SoA you already have, row by row, and reports what an assessor would ask about: Annex A
controls that are missing, identifiers that are unknown, duplicated or still in the 2013 numbering, applicability
that is not a clear yes or no, inclusions and exclusions without a justification, included controls with no
implementation status, implemented controls with no evidence reference, evidence files that do not exist, missing
owners and reviews older than --max-age-days. With --risk-register it also lists risks whose treatment names a
control the SoA excludes, and included controls that no risk, requirement or justification refers to.

Annex A of ISO/IEC 27001:2022 has 93 controls: 5.1 to 5.37 (organisational), 6.1 to 6.8 (people), 7.1 to 7.14
(physical) and 8.1 to 8.34 (technological). The script knows these identifiers only. It ships no control titles or
text (they are ISO and IEC copyright); titles in your file are passed through as you wrote them.

Inputs:
  SOA                 a CSV file (comma, semicolon or tab separated; UTF-8 or UTF-16 with a byte order mark, as
                      spreadsheet programs save "CSV UTF-8" and "Unicode Text"), or a JSON list of row objects (or
                      {"rows": [...]}). Columns are found by header name; see --map.
  --map FIELD=HEADER  use this header for a field (repeatable). Fields: control, title, applicable, justification,
                      inclusion_justification, exclusion_justification, status, evidence, owner, reviewed, risks
  --evidence-root DIR check that evidence references that look like file paths exist under DIR
  --risk-register CSV a risk register with a treatment (or controls) column naming Annex A identifiers
  --risk-map F=HEADER header overrides for the risk register (fields: risk, treatment)
  --as-of DATE        the day review ages are measured to (YYYY-MM-DD, default today)
  --max-age-days N    a review older than this is reported (default 365)
  --fail-on LEVEL     error (default) or warning: the lowest severity that makes the exit code 1
  --format FORMAT     markdown (default) or json; --json is the same as --format json
  --out FILE          write the report to FILE instead of stdout
  --redact            replace e-mail addresses and owner names with stable tokens; secret-shaped strings are always
                      masked

Applicability values read as yes: yes, y, true, 1, x, applicable, included, include, in scope, selected. As no: no,
n, false, 0, not applicable, n/a, na, excluded, exclude, out of scope, not selected. Anything else is unclear.

Exit codes: 0 nothing at or above --fail-on, 1 findings, 2 bad input or usage (missing or unreadable file, not UTF-8
or UTF-16, an .xlsx workbook, no header row, no control column, invalid JSON, bad --map, bad dates). Standard
library only. Reads files only; no network. Every output is preparation for a human assessor, not an audit opinion
or an attestation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path, PurePosixPath

PROG = "soa_check.py"
THEMES = (
    ("5", "Organisational", 37),
    ("6", "People", 8),
    ("7", "Physical", 14),
    ("8", "Technological", 34),
)
ANNEX_A = [f"A.{clause}.{n}" for clause, _, count in THEMES for n in range(1, count + 1)]
ANNEX_SET = set(ANNEX_A)
THEME_NAME = {clause: name for clause, name, _ in THEMES}
DISCLAIMER = (
    "Preparation for a human assessor: this is a check of the Statement of Applicability's content, not an audit "
    "opinion, an attestation or a statement that any control works."
)

FIELDS = ("control", "title", "applicable", "justification", "inclusion_justification", "exclusion_justification",
          "status", "evidence", "owner", "reviewed", "risks")
ALIASES: dict[str, tuple[str, ...]] = {
    "control": ("control", "control id", "control ref", "control reference", "control no", "control number", "id",
                "ref", "reference", "annex a", "annex a control", "annex a ref", "annex a reference", "iso control",
                "iso 27001 control", "clause", "number", "no"),
    "title": ("title", "control title", "control name", "name", "description", "control description"),
    "applicable": ("applicable", "applicability", "applies", "included", "include", "in scope", "selected",
                   "applicable yes no", "is applicable", "inclusion", "status applicable"),
    "justification": ("justification", "reason", "rationale", "justification for inclusion or exclusion",
                      "justification for inclusion exclusion", "reason for inclusion or exclusion",
                      "inclusion exclusion justification", "justification reason"),
    "inclusion_justification": ("inclusion justification", "justification for inclusion", "reason for inclusion",
                                "reason included"),
    "exclusion_justification": ("exclusion justification", "justification for exclusion", "reason for exclusion",
                                "reason excluded"),
    "status": ("implementation status", "status", "implemented", "implementation", "implementation state",
               "control status", "state"),
    "evidence": ("evidence", "evidence reference", "evidence references", "evidence ref", "evidence refs",
                 "evidence location", "evidence link", "references", "reference documents", "documents"),
    "owner": ("owner", "control owner", "responsible", "accountable", "responsible person", "owner role"),
    "reviewed": ("last reviewed", "review date", "reviewed", "last review", "date reviewed", "last review date",
                 "reviewed on"),
    "risks": ("risks", "risk", "risk ids", "risk references", "risk refs", "linked risks", "risk id"),
}
RISK_ALIASES = {
    "risk": ("risk id", "id", "risk", "ref", "risk ref", "reference", "risk no", "risk number"),
    "treatment": ("treatment", "treatment plan", "risk treatment", "controls", "annex a controls", "control",
                  "mitigating controls", "treatment controls", "selected controls", "annex a"),
}
YES = {"yes", "y", "true", "1", "x", "applicable", "included", "include", "in scope", "selected", "\u2713", "\u2714"}
NO = {"no", "n", "false", "0", "not applicable", "n/a", "na", "excluded", "exclude", "out of scope", "not selected",
      "not included"}
IMPLEMENTED = {"implemented", "fully implemented", "in place", "done", "complete", "completed", "operational",
               "operating", "yes", "verified", "effective"}
NOT_IMPLEMENTED = {"partially implemented", "partial", "partly implemented", "in progress", "planned",
                   "not started", "not implemented", "no", "to do", "todo", "under implementation", "not yet"}
NOT_APPLICABLE_STATUS = {"not applicable", "n/a", "na", "excluded"}
REQUIREMENT_WORDS = re.compile(r"\b(legal|law|laws|regulat\w*|statut\w*|contract\w*|customer|client|act|gdpr|privacy|"
                               r"requirement\w*|obligation\w*|licen[cs]e\w*|policy|standard|framework|tender|"
                               r"insurance|business need|risk\w*)\b", re.I)
RISK_ID_RE = re.compile(r"\b[A-Z]{1,4}-?\d{1,4}\b")
ID_RE = re.compile(r"^\s*(?:annex\s*)?a?[\s.:-]*(\d{1,2})\s*\.\s*(\d{1,2})(?:\s*\.\s*(\d{1,2}))?\s*$", re.I)
TREATMENT_ID_RE = re.compile(r"(?<![\w.])(?:A\s?\.?\s?)?([5-8])\.(\d{1,2})(?!\.?\d)", re.I)
DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%d.%m.%Y", "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y")
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
PATHLIKE_RE = re.compile(r"[/\\]|\.[A-Za-z0-9]{1,5}$")
SEVERITY = {"error": 0, "warning": 1, "note": 2}


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


# ---------------------------------------------------------------- reading

def norm_header(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower().replace("&", " and ")).split())


def decode(data: bytes, what: str) -> str:
    if data.startswith(b"PK\x03\x04"):
        raise InputError(f"{what} is an .xlsx workbook; save it as CSV UTF-8 first")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise InputError(f"{what} is not valid UTF-16") from exc
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError(f"{what} is not UTF-8; save it as CSV UTF-8") from exc


def read_file(path: str, what: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"{what} not found: {path}")
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {what} {path}: {exc.strerror or exc}") from exc
    text = decode(data, f"{what} {path}")
    if not text.strip():
        raise InputError(f"{what} {path} is empty")
    return text


def read_rows(path: str, what: str) -> tuple[list[str], list[dict[str, str]], list[int]]:
    """(headers, rows, line numbers) from a CSV or JSON table."""
    text = read_file(path, what)
    stripped = text.lstrip()
    if path.lower().endswith(".json") or stripped.startswith(("[", "{")):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"{what} {path} is not valid JSON (line {exc.lineno}: {exc.msg})") from exc
        if isinstance(doc, dict) and isinstance(doc.get("rows"), list):
            doc = doc["rows"]
        if not isinstance(doc, list) or not doc or not all(isinstance(r, dict) for r in doc):
            raise InputError(f"{what} {path} must be a non-empty JSON list of row objects (or {{\"rows\": [...]}})")
        headers: list[str] = []
        for r in doc:
            for k in r:
                if str(k) not in headers:
                    headers.append(str(k))
        rows = [{str(k): "" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else str(v))
                 for k, v in r.items()} for r in doc]
        return headers, rows, list(range(1, len(rows) + 1))
    first = text.splitlines()[0]
    delimiter = max((",", ";", "\t"), key=first.count)
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        table = list(reader)
    except csv.Error as exc:
        raise InputError(f"{what} {path} is not readable CSV ({exc})") from exc
    while table and not any(c.strip() for c in table[0]):
        table.pop(0)
    if len(table) < 2:
        raise InputError(f"{what} {path} needs a header row and at least one data row")
    headers = [h.strip() for h in table[0]]
    rows, lines = [], []
    line = 1
    for raw in table[1:]:
        line += 1
        if not any(c.strip() for c in raw):
            continue
        rows.append({headers[i] if i < len(headers) else f"column {i + 1}": raw[i].strip() for i in range(len(raw))})
        lines.append(line)
    if not rows:
        raise InputError(f"{what} {path} has a header row but no data rows")
    return headers, rows, lines


def resolve_columns(headers: list[str], aliases: dict[str, tuple[str, ...]], overrides: dict[str, str],
                    what: str) -> dict[str, str]:
    by_norm = {norm_header(h): h for h in headers if h}
    found: dict[str, str] = {}
    for field, header in overrides.items():
        if header not in headers and norm_header(header) not in by_norm:
            raise InputError(f"{what}: --map {field}={header}: no column with that header")
        found[field] = header if header in headers else by_norm[norm_header(header)]
    used = set(found.values())
    for field, names in aliases.items():
        if field in found:
            continue
        for name in names:
            h = by_norm.get(name)
            if h and h not in used:
                found[field] = h
                used.add(h)
                break
    return found


def parse_map(values: list[str] | None, allowed: tuple[str, ...], flag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise InputError(f"{flag} {item!r}: use FIELD=HEADER")
        field, header = (s.strip() for s in item.split("=", 1))
        if field not in allowed or not header:
            raise InputError(f"{flag} {item!r}: field must be one of {', '.join(allowed)}")
        out[field] = header
    return out


# ---------------------------------------------------------------- values

def normalise_id(raw: str) -> tuple[str, str | None]:
    """(kind, id): kind is 2022, 2013, unknown or blank."""
    if not raw.strip():
        return "blank", None
    m = ID_RE.match(raw)
    if not m:
        return "unknown", None
    clause, num, sub = int(m.group(1)), int(m.group(2)), m.group(3)
    if sub is not None:
        return "2013", f"A.{clause}.{num}.{int(sub)}"
    if 9 <= clause <= 18:
        return "2013", f"A.{clause}.{num}"
    cid = f"A.{clause}.{num}"
    return ("2022", cid) if cid in ANNEX_SET else ("unknown", cid)


def applicability(value: str) -> str:
    v = " ".join(value.strip().lower().replace("-", " ").split())
    if v in YES:
        return "yes"
    if v in NO or v.replace(" ", "") in {"n/a", "na"}:
        return "no"
    return "unclear"


def status_kind(value: str) -> str:
    v = " ".join(value.strip().lower().replace("-", " ").replace("_", " ").split())
    if not v:
        return "blank"
    if v in IMPLEMENTED:
        return "implemented"
    if v in NOT_APPLICABLE_STATUS:
        return "not-applicable"
    if v in NOT_IMPLEMENTED:
        return "not-implemented"
    return "other"


def parse_day(value: str) -> date | None:
    v = value.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}T", v):
        v = v[:10]
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(v, fmt).date()
        except ValueError:
            continue
    return None


def split_refs(value: str) -> list[str]:
    return [p.strip() for p in re.split(r"[;\n|]+|,\s+", value) if p.strip()]


def check_evidence_ref(ref: str, root: Path) -> str:
    """ok, missing, outside, url or not-a-path."""
    if re.match(r"^[a-z][a-z0-9+.-]*://", ref, re.I):
        return "url"
    clean = ref.split("#", 1)[0]
    clean = re.sub(r":\d+(-\d+)?$", "", clean).strip().strip("\"'")
    if not clean or not PATHLIKE_RE.search(clean):
        return "not-a-path"
    posix = PurePosixPath(clean.replace("\\", "/"))
    if posix.is_absolute() or re.match(r"^[A-Za-z]:", clean) or ".." in posix.parts:
        return "outside"
    target = root.joinpath(*posix.parts)
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return "outside"
    return "ok" if target.exists() else "missing"


# ---------------------------------------------------------------- checks

class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, severity: str, rule: str, control: str | None, line: int | None, detail: str) -> None:
        self.items.append({"severity": severity, "rule": rule, "control": control, "line": line, "detail": detail})


def evaluate(args: argparse.Namespace) -> dict:
    as_of = date.today()
    if args.as_of:
        parsed = parse_day(args.as_of) if re.match(r"^\d{4}-\d{2}-\d{2}$", args.as_of) else None
        if parsed is None:
            raise InputError(f"--as-of {args.as_of!r} is not a YYYY-MM-DD date")
        as_of = parsed
    if args.max_age_days < 1:
        raise InputError("--max-age-days must be 1 or more")
    root: Path | None = None
    if args.evidence_root:
        root = Path(args.evidence_root)
        if not root.is_dir():
            raise InputError(f"--evidence-root is not a folder: {args.evidence_root}")
    headers, rows, lines = read_rows(args.soa, "SoA")
    cols = resolve_columns(headers, ALIASES, parse_map(args.map, FIELDS, "--map"), "SoA")
    if "control" not in cols:
        raise InputError("SoA has no control identifier column; name it with --map control=HEADER "
                         f"(headers seen: {', '.join(h for h in headers if h) or 'none'})")
    f = Findings()
    seen: dict[str, int] = {}
    entries: dict[str, dict] = {}
    other_rows: list[dict] = []
    owners: list[str] = []
    evidence_counts = {"checked": 0, "found": 0, "missing": 0, "not_checked": 0}
    for column in ("applicable", "owner", "status"):
        if column not in cols:
            f.add("error", f"no-{column}-column", None, 1, f"no {column} column found (map one with --map "
                  f"{column}=HEADER); every row is treated as missing it")
    if "reviewed" not in cols:
        f.add("warning", "no-review-column", None, 1, "no review date column; review ages were not checked")
    if not ({"justification", "inclusion_justification", "exclusion_justification"} & set(cols)):
        f.add("error", "no-justification-column", None, 1, "no justification column; the SoA must justify every "
              "inclusion and exclusion")

    def get(row: dict[str, str], field: str) -> str:
        return row.get(cols[field], "").strip() if field in cols else ""

    for row, line in zip(rows, lines, strict=True):
        raw_id = get(row, "control")
        kind, cid = normalise_id(raw_id)
        if kind == "blank":
            f.add("error", "no-control-id", None, line, "row has no control identifier")
            continue
        if kind == "2013":
            f.add("error", "id-2013", cid, line, f"{raw_id!r} is an ISO/IEC 27001:2013 identifier; the SoA needs the "
                  "2022 Annex A numbering (transition to the 2022 controls)")
            other_rows.append({"id": raw_id, "kind": kind, "line": line})
            continue
        if kind == "unknown":
            f.add("error", "unknown-id", cid, line, f"{raw_id!r} is not an ISO/IEC 27001:2022 Annex A control; it is "
                  "kept out of the theme counts")
            other_rows.append({"id": raw_id, "kind": kind, "line": line})
            continue
        if cid in seen:
            f.add("error", "duplicate-id", cid, line, f"{cid} appears again (first on line {seen[cid]})")
            continue
        seen[cid] = line
        applic = applicability(get(row, "applicable")) if "applicable" in cols else "unclear"
        status_raw = get(row, "status")
        status = status_kind(status_raw)
        owner = get(row, "owner")
        if owner:
            owners.append(owner)
        entry = {"id": cid, "line": line, "title": get(row, "title"), "applicable": applic,
                 "status": status_raw, "status_kind": status, "owner": owner, "reviewed": get(row, "reviewed"),
                 "evidence": split_refs(get(row, "evidence")), "risks": get(row, "risks")}
        entries[cid] = entry
        general = get(row, "justification")
        if applic == "unclear" and "applicable" in cols:
            shown = get(row, "applicable")
            f.add("error", "applicability-unclear", cid, line, f"applicability {shown!r} is not a clear yes or no"
                  if shown else "applicability is blank")
        if applic == "no":
            just = get(row, "exclusion_justification") or general
            entry["justification"] = just
            if not just:
                f.add("error", "excluded-no-justification", cid, line, "excluded with no justification for the "
                      "exclusion")
            if status == "implemented":
                f.add("warning", "excluded-but-implemented", cid, line, f"excluded, but the status says "
                      f"{status_raw!r}; one of the two is wrong")
            continue
        if applic != "yes":
            continue
        just = get(row, "inclusion_justification") or general
        entry["justification"] = just
        if not just and ({"justification", "inclusion_justification", "exclusion_justification"} & set(cols)):
            f.add("error", "included-no-justification", cid, line, "included with no justification; the standard "
                  "asks for a justification for inclusions as well as exclusions")
        if "status" in cols and status == "blank":
            f.add("error", "included-no-status", cid, line, "included with no implementation status")
        elif status == "not-applicable":
            f.add("error", "status-contradicts-applicability", cid, line, f"included, but the status says "
                  f"{status_raw!r}")
        elif status == "other":
            f.add("warning", "status-unrecognised", cid, line, f"implementation status {status_raw!r} is not one the "
                  "script knows; read it by hand")
        if status == "implemented" and not entry["evidence"]:
            f.add("error", "implemented-no-evidence", cid, line, f"status {status_raw!r} with no evidence reference")
        if root is not None:
            for ref in entry["evidence"]:
                state = check_evidence_ref(ref, root)
                if state == "ok":
                    evidence_counts["checked"] += 1
                    evidence_counts["found"] += 1
                elif state == "missing":
                    evidence_counts["checked"] += 1
                    evidence_counts["missing"] += 1
                    f.add("error", "evidence-not-found", cid, line, f"evidence {ref!r} does not exist under "
                          f"{root.as_posix()}")
                elif state == "outside":
                    f.add("error", "evidence-outside-root", cid, line, f"evidence {ref!r} points outside "
                          "--evidence-root; give a path inside it")
                else:
                    evidence_counts["not_checked"] += 1
        if "owner" in cols and not owner:
            f.add("error", "owner-missing", cid, line, "included with no owner")
        if "reviewed" in cols:
            reviewed = entry["reviewed"]
            day = parse_day(reviewed) if reviewed else None
            if not reviewed:
                f.add("error", "review-missing", cid, line, "included with no review date")
            elif day is None:
                f.add("error", "review-date-unreadable", cid, line, f"review date {reviewed!r} is not a date the "
                      "script reads (use YYYY-MM-DD)")
            elif day > as_of:
                f.add("warning", "review-in-future", cid, line, f"review date {day.isoformat()} is after "
                      f"{as_of.isoformat()}")
            elif (as_of - day).days > args.max_age_days:
                f.add("error", "review-overdue", cid, line, f"last reviewed {day.isoformat()}, "
                      f"{(as_of - day).days} days before {as_of.isoformat()} (limit {args.max_age_days})")
    missing = [c for c in ANNEX_A if c not in entries]
    for clause, name, _ in THEMES:
        ids = [c for c in missing if c.split(".")[1] == clause]
        if ids:
            f.add("error", "missing-controls", None, None, f"{name} ({clause}.x): {len(ids)} control(s) not in the "
                  f"SoA: {', '.join(ids)}")
    risks = check_risks(args, f, entries) if args.risk_register else None
    themes = []
    for clause, name, count in THEMES:
        mine = [e for e in entries.values() if e["id"].split(".")[1] == clause]
        themes.append({
            "theme": name, "clause": clause, "annex_a_controls": count, "in_soa": len(mine),
            "included": sum(e["applicable"] == "yes" for e in mine),
            "excluded": sum(e["applicable"] == "no" for e in mine),
            "unclear": sum(e["applicable"] == "unclear" for e in mine),
            "implemented": sum(e["applicable"] == "yes" and e["status_kind"] == "implemented" for e in mine),
            "findings": sum(1 for x in f.items if x["control"] and x["control"].startswith(f"A.{clause}.")
                            and x["control"] in entries),
        })
    for x in f.items:  # the user's own title, passed through as written
        x["title"] = entries[x["control"]]["title"] if x["control"] in entries else ""
    f.items.sort(key=lambda x: (SEVERITY[x["severity"]], x["line"] or 0, x["rule"]))
    counts = {s: sum(1 for x in f.items if x["severity"] == s) for s in SEVERITY}
    return {
        "soa": Path(args.soa).as_posix(), "as_of": as_of.isoformat(), "columns": cols,
        "rows": len(rows), "annex_a_rows": len(entries), "other_rows": other_rows,
        "themes": themes, "evidence": evidence_counts if root is not None else None,
        "risk_register": risks, "findings": f.items, "counts": counts, "owners": owners,
        "disclaimer": DISCLAIMER,
    }


def check_risks(args: argparse.Namespace, f: Findings, entries: dict[str, dict]) -> dict:
    headers, rows, lines = read_rows(args.risk_register, "risk register")
    cols = resolve_columns(headers, RISK_ALIASES, parse_map(args.risk_map, ("risk", "treatment"), "--risk-map"),
                           "risk register")
    if "treatment" not in cols:
        raise InputError("risk register has no treatment or controls column; name it with --risk-map "
                         "treatment=HEADER")
    referenced: dict[str, list[str]] = {}
    risk_ids: set[str] = set()
    for row, line in zip(rows, lines, strict=True):
        rid = row.get(cols["risk"], "").strip() if "risk" in cols else ""
        rid = rid or f"line {line}"
        risk_ids.add(rid)
        text = row.get(cols["treatment"], "")
        for m in TREATMENT_ID_RE.finditer(text):
            cid = f"A.{int(m.group(1))}.{int(m.group(2))}"
            if cid not in ANNEX_SET:
                f.add("warning", "risk-unknown-control", None, None, f"risk {rid} (risk register line {line}) names "
                      f"{m.group(0).strip()!r}, which is not an Annex A 2022 control")
                continue
            referenced.setdefault(cid, []).append(rid)
            e = entries.get(cid)
            if e and e["applicable"] == "no":
                f.add("error", "risk-treats-excluded", cid, e["line"], f"risk {rid} is treated with {cid}, which the "
                      "SoA excludes")
            elif e is None:
                f.add("warning", "risk-control-not-in-soa", cid, None, f"risk {rid} is treated with {cid}, which is not "
                      "in the SoA")
    for cid, e in entries.items():
        if e["applicable"] != "yes" or cid in referenced:
            continue
        linked = e.get("risks", "")
        if linked and any(r in linked for r in risk_ids):
            continue
        if REQUIREMENT_WORDS.search(e.get("justification", "") or ""):
            continue
        f.add("warning", "included-unreferenced", cid, e["line"], "included, but no risk treatment names it and the "
              "justification names no legal, contractual or other requirement")
    return {"file": Path(args.risk_register).as_posix(), "risks": len(rows),
            "controls_referenced": sorted(referenced, key=sort_key)}


def sort_key(cid: str) -> tuple:
    parts = cid.split(".")
    return tuple(int(p) for p in parts[1:])


# ---------------------------------------------------------------- output

def cell(v: object) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def render(rep: dict) -> str:
    c = rep["counts"]
    out = [f"## Statement of Applicability check: {rep['soa']}", "",
           f"{rep['rows']} rows, {rep['annex_a_rows']} of the 93 ISO/IEC 27001:2022 Annex A controls, "
           f"{len(rep['other_rows'])} row(s) with other identifiers. Reviews measured to {rep['as_of']}.",
           f"{c['error']} error(s), {c['warning']} warning(s).", "",
           "### By theme", "",
           "| Theme | Annex A | In SoA | Included | Excluded | Unclear | Implemented | Findings |",
           "|---|---|---|---|---|---|---|---|"]
    for t in rep["themes"]:
        out.append(f"| {t['theme']} ({t['clause']}.x) | {t['annex_a_controls']} | {t['in_soa']} | {t['included']} | "
                   f"{t['excluded']} | {t['unclear']} | {t['implemented']} | {t['findings']} |")
    out.append("")
    out.append("Rows with 2013 or unknown identifiers are not counted in any theme.")
    if rep["evidence"] is not None:
        e = rep["evidence"]
        out += ["", f"Evidence references: {e['checked']} file path(s) checked, {e['found']} found, {e['missing']} not "
                f"found, {e['not_checked']} not a file path (URLs and document names are not checked)."]
    if rep["risk_register"] is not None:
        r = rep["risk_register"]
        out += ["", f"Risk register {r['file']}: {r['risks']} risk(s) naming {len(r['controls_referenced'])} Annex A "
                "control(s)."]
    out += ["", "### Findings", ""]
    if rep["findings"]:
        out += ["| Severity | Rule | Control | Line | Detail |", "|---|---|---|---|---|"]
        for x in rep["findings"]:
            title = x.get("title") or ""
            name = f"{x['control']} ({title[:40]})" if x["control"] and title else x["control"]
            out.append(f"| {x['severity']} | {x['rule']} | {cell(name)} | {cell(x['line'])} | "
                       f"{cell(x['detail'])} |")
    else:
        out.append("No findings.")
    out += ["", rep["disclaimer"]]
    return "\n".join(out) + "\n"


def scrub(text: str, owners: list[str], redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8]
                            + "@redacted.invalid", text)
        for o in sorted({o for o in owners if o and "@" not in o and len(o) > 2}, key=len, reverse=True):
            text = text.replace(o, "owner-" + hashlib.sha256(o.lower().encode()).hexdigest()[:8])
    return text


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to a legacy code page
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog=PROG, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("soa", help="the Statement of Applicability as CSV or JSON")
    ap.add_argument("--map", action="append", metavar="FIELD=HEADER", help="header to use for a field (repeatable)")
    ap.add_argument("--evidence-root", help="folder that evidence file references are relative to")
    ap.add_argument("--risk-register", help="risk register CSV or JSON with a treatment or controls column")
    ap.add_argument("--risk-map", action="append", metavar="FIELD=HEADER", help="risk register header overrides")
    ap.add_argument("--as-of", help="day review ages are measured to (YYYY-MM-DD, default today)")
    ap.add_argument("--max-age-days", type=int, default=365, help="oldest acceptable review in days (default 365)")
    ap.add_argument("--fail-on", choices=("error", "warning"), default="error",
                    help="lowest severity that makes the exit code 1 (default error)")
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown", help="output format")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses and owner names with stable tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    try:
        rep = evaluate(args)
    except InputError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2
    owners = rep.pop("owners")
    body = json.dumps(rep, indent=2, ensure_ascii=False) + "\n" if args.json or args.format == "json" else render(rep)
    text = scrub(body, owners, args.redact)
    try:
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    except OSError as exc:
        print(f"{PROG}: cannot write output: {exc.strerror or exc}", file=sys.stderr)
        return 2
    levels = ("error",) if args.fail_on == "error" else ("error", "warning")
    return 1 if any(x["severity"] in levels for x in rep["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
