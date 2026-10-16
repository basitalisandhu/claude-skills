#!/usr/bin/env python3
"""Digest a register of vendor attestations (SOC 2 reports, ISO 27001 certificates, bridge letters, penetration test
summaries) against the vendor list, and list what each vendor owner has to do: expired or expiring documents, gaps
after a SOC 2 period, qualified opinions, noted exceptions, services outside the report scope, complementary user
entity controls nobody reviewed, and fields that were never extracted.

Inputs:
  --register      the attestations, as CSV or JSON (a list of objects, or {"attestations": [...]}), one row per
                  document, with the fields taken by hand (or with PDF tooling) from the document itself:
                    vendor, type            type is soc2-type2, soc2-type1, iso27001-certificate, bridge-letter,
                                            pentest-summary or other
                    issuer                  the service auditor, certification body or tester
                    period_start, period_end  SOC 2 reports (period_start is needed for Type 2 only)
                    valid_from, valid_to    certificates and bridge letters (pentest-summary and other take
                                            valid_to or period_end)
                    opinion                 SOC 2: unqualified, qualified, adverse, disclaimer or unknown
                    exceptions              SOC 2: number of exceptions noted in the tests of controls (0 or more)
                    scope_services          SOC 2 and certificates: services in scope, separated by ";"
                    cuecs                   SOC 2: complementary user entity controls, separated by ";", or "none"
                    cuecs_reviewed          yes, no or blank
                    source_file, source_page  the document and the page each field was read from
                  Dates are YYYY-MM-DD. A blank or unreadable field is never guessed: the row is not assessable.
  --vendors       CSV with vendor, services_used (";" list), criticality (high, medium or low) and owner
  --docs          optional folder holding the source documents: each source_file found there is hashed (SHA-256);
                  a source_file that is not there is reported as source-unverified
  --as-of         the day to evaluate on (YYYY-MM-DD); required so that the output can be reproduced

Policy options (this skill's defaults, not a rule of any standard; agree your own with the assessor):
  --max-report-age-months 12   a SOC 2 report (or a summary with only a period_end) counts as expired this many
                               months after period_end
  --bridge-max-months 3        a gap between period_end and --as-of longer than this needs a bridge letter
  --expiring-days 60           warn this many days before a document expires

Findings: no-attestation, expired, expiring, coverage-gap, bridge-letter-expired, type1-only, opinion-not-unqualified,
exceptions-noted, scope-mismatch, cuecs-not-reviewed, missing-field, source-unverified. Only the latest document of
each kind per vendor raises findings; older ones are listed as superseded.

Result states (per document and per vendor):
  supported       the document is current on --as-of, its fields are complete, its source is found (with --docs)
                  and the opinion is unqualified
  contradicted    the register shows a problem: expired, a gap no bridge letter covers, an expired bridge letter,
                  an opinion other than unqualified, or (per vendor) a used service outside every report's scope
  not assessable  a field is missing or unreadable, the source file is not found, or nothing is on file

The script does not read PDFs and does not judge whether a report is good enough: it checks the fields recorded in
the register. Every output is preparation for a human assessor, not a vendor risk decision, an audit opinion or an
attestation.

Output: Markdown (default) or --json, to stdout or --out; --csv writes one row per finding. --redact replaces owner
names and e-mail addresses with stable tokens; secret-shaped strings are always masked.

Exit codes: 0 no findings, 1 findings for an owner to act on, 2 bad input or usage. Standard library only. Reads files
only; no network.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import hashlib
import io
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

SUPPORTED, CONTRADICTED, NOT_ASSESSABLE = "supported", "contradicted", "not assessable"
STATE_ORDER = {SUPPORTED: 0, NOT_ASSESSABLE: 1, CONTRADICTED: 2}
DISCLAIMER = (
    "Preparation for a human assessor: this is not a vendor risk decision, an audit opinion or an attestation. "
    "Every value comes from the register; check it against the cited page."
)
TYPES = ("soc2-type2", "soc2-type1", "iso27001-certificate", "bridge-letter", "pentest-summary", "other")
SOC2 = ("soc2-type2", "soc2-type1")
OPINIONS = ("unqualified", "qualified", "adverse", "disclaimer", "unknown")
CRITICALITY = ("high", "medium", "low")
CRIT_ORDER = {"high": 0, "medium": 1, "low": 2, "not in vendor list": 3}
COUNTED = ("soc2-type2", "soc2-type1", "iso27001-certificate", "other")  # what counts as an attestation on file
CONTRA_CODES = {"expired", "coverage-gap", "bridge-letter-expired", "opinion-not-unqualified"}
NA_CODES = {"missing-field", "source-unverified"}
FINDINGS = (
    "no-attestation",
    "expired",
    "expiring",
    "coverage-gap",
    "bridge-letter-expired",
    "type1-only",
    "opinion-not-unqualified",
    "exceptions-noted",
    "scope-mismatch",
    "cuecs-not-reviewed",
    "missing-field",
    "source-unverified",
)
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def parse_day(value: str) -> date | None:
    try:
        return date.fromisoformat(value.strip()) if value and len(value.strip()) == 10 else None
    except ValueError:
        return None


def add_months(d: date, months: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))


def split_list(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(";") if x.strip()]


def norm(value: str) -> str:
    return " ".join(value.lower().split())


def read_rows(path: Path, what: str) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    if not text.strip():
        raise InputError(f"{path.name}: empty {what} file")
    if path.suffix.lower() == ".json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path.name}: invalid JSON: {exc}") from exc
        if isinstance(doc, dict) and isinstance(doc.get("attestations"), list):
            doc = doc["attestations"]
        if not isinstance(doc, list) or not all(isinstance(r, dict) for r in doc):
            raise InputError(f"{path.name}: expected a list of {what} objects")
        rows = []
        for r in doc:
            row = {}
            for k, v in r.items():
                if isinstance(v, (dict, list)) and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                    raise InputError(f"{path.name}: field {k!r} must be a string, a number or a list of strings")
                row[str(k).strip().lower()] = "; ".join(v) if isinstance(v, list) else ("" if v is None else str(v)).strip()
            rows.append(row)
        return rows
    try:
        reader = csv.DictReader(io.StringIO(text))
        return [{str(k).strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in reader]
    except csv.Error as exc:
        raise InputError(f"{path.name}: cannot read CSV: {exc}") from exc


def load_register(path: Path) -> list[dict]:
    rows = read_rows(path, "register")
    if not rows:
        raise InputError(f"{path.name}: the register has no rows")
    out = []
    for n, r in enumerate(rows, 1):
        if not r.get("vendor"):
            raise InputError(f"{path.name}: row {n} has no vendor")
        t = r.get("type", "").lower()
        if t not in TYPES:
            raise InputError(f"{path.name}: row {n}: type must be one of {', '.join(TYPES)}, not {r.get('type', '')!r}")
        op = r.get("opinion", "").lower()
        if op and op not in OPINIONS:
            raise InputError(f"{path.name}: row {n}: opinion must be one of {', '.join(OPINIONS)}, not {op!r}")
        exc = r.get("exceptions", "")
        if exc and not re.fullmatch(r"\d+", exc):
            raise InputError(f"{path.name}: row {n}: exceptions must be a whole number of noted exceptions, not {exc!r}")
        rev = r.get("cuecs_reviewed", "").lower()
        if rev not in ("", "yes", "no"):
            raise InputError(f"{path.name}: row {n}: cuecs_reviewed must be yes, no or blank, not {rev!r}")
        out.append(dict(r, row=n, type=t, opinion=op, cuecs_reviewed=rev))
    return out


def load_vendors(path: Path) -> dict[str, dict]:
    rows = read_rows(path, "vendor")
    if not rows:
        raise InputError(f"{path.name}: the vendor list has no rows")
    vendors: dict[str, dict] = {}
    for n, r in enumerate(rows, 1):
        name = r.get("vendor", "")
        crit = r.get("criticality", "").lower()
        if not name:
            raise InputError(f"{path.name}: row {n} has no vendor")
        if crit not in CRITICALITY:
            raise InputError(f"{path.name}: row {n} ({name}): criticality must be high, medium or low, not {crit!r}")
        if norm(name) in vendors:
            raise InputError(f"{path.name}: vendor {name!r} is listed twice")
        vendors[norm(name)] = {
            "vendor": name,
            "criticality": crit,
            "owner": r.get("owner", ""),
            "services_used": split_list(r.get("services_used", "")),
        }
    return vendors


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def finding(code: str, message: str, action: str, att: dict | None = None, field: str = "") -> dict:
    f = {"code": code, "message": message, "action": action}
    if att is not None:
        f["register_row"] = att["row"]
        f["field"] = field
        f["citation"] = cite(att, field)
    return f


def cite(att: dict, field: str = "") -> str:
    src = att.get("source_file") or "no source file"
    page = f" p.{att['source_page']}" if att.get("source_page") else ""
    return f"[register row {att['row']}{'#' + field if field else ''}; source: {src}{page}]"


def check_fields(att: dict) -> list[str]:
    """Names of required fields that are blank or unreadable for this document type."""
    t = att["type"]
    need = ["issuer", "source_file", "source_page"]
    dates: list[str] = []
    if t in SOC2:
        dates = ["period_end"] + (["period_start"] if t == "soc2-type2" else [])
        need += ["opinion", "exceptions", "scope_services", "cuecs"]
    elif t in ("iso27001-certificate", "bridge-letter"):
        dates = ["valid_from", "valid_to"]
        if t == "iso27001-certificate":
            need.append("scope_services")
    missing = [f for f in need if not att.get(f)]
    if t in SOC2 and att.get("opinion") == "unknown":
        missing.append("opinion")
    for f in dates:
        if parse_day(att.get(f, "")) is None:
            missing.append(f)
    if t in ("pentest-summary", "other") and parse_day(att.get("valid_to", "")) is None and parse_day(att.get("period_end", "")) is None:
        missing.append("valid_to or period_end")
    return missing


def end_of_validity(att: dict, max_age: int) -> date | None:
    """The last day the document counts as current."""
    if parse_day(att.get("valid_to", "")):
        return parse_day(att["valid_to"])
    if parse_day(att.get("period_end", "")):
        return add_months(parse_day(att["period_end"]), max_age)
    return None


def key_date(att: dict) -> date | None:
    return parse_day(att.get("period_end", "")) or parse_day(att.get("valid_to", ""))


def family(att: dict) -> str:
    return "soc2" if att["type"] in SOC2 else att["type"]


def evaluate_document(att: dict, ctx: dict, bridges: list[dict]) -> tuple[list[dict], list[str]]:
    """Findings and notes for one document (vendor-level findings are added elsewhere)."""
    as_of, max_age, bridge_m, exp_days = ctx["as_of"], ctx["max_age"], ctx["bridge"], ctx["expiring"]
    vendor, t = att["vendor"], att["type"]
    out: list[dict] = []
    notes: list[str] = []
    for f in check_fields(att):
        page = f" (page {att['source_page']})" if att.get("source_page") else ""
        out.append(
            finding(
                "missing-field",
                f"{f} is blank or unreadable in the register",
                f"Take {f} from {att.get('source_file') or 'the source document'}{page} and record it; until then this row is not assessable.",
                att,
                f,
            )
        )
    if ctx["docs"] is not None and att.get("source_file"):
        root = ctx["docs"].resolve()
        p = (root / att["source_file"]).resolve()
        if root in p.parents and p.is_file():
            att["source_sha256"] = sha256(p)
        else:
            out.append(
                finding(
                    "source-unverified",
                    f"{att['source_file']} is not in the --docs folder, so the register cannot be checked against it",
                    f"Put {att['source_file']} in the documents folder or correct the file name, then run again.",
                    att,
                    "source_file",
                )
            )
    if t == "iso27001-certificate" and parse_day(att.get("valid_from", "")) and parse_day(att["valid_from"]) > as_of:
        notes.append(f"valid_from {att['valid_from']} is after {as_of}: the certificate is not yet in force")
        att["not_yet_valid"] = True
    end = end_of_validity(att, max_age)
    if t == "bridge-letter":
        return out, notes  # judged against the SOC 2 report it bridges, in evaluate_vendor
    if end is not None:
        if end < as_of:
            basis = "valid_to" if parse_day(att.get("valid_to", "")) else f"period_end plus {max_age} months"
            out.append(
                finding(
                    "expired",
                    f"{t} from {att.get('issuer') or 'unknown issuer'} counted until {end} ({basis}), before {as_of}",
                    f"Request the current {t} from {vendor}.",
                    att,
                    "valid_to" if parse_day(att.get("valid_to", "")) else "period_end",
                )
            )
        elif (end - as_of).days <= exp_days:
            out.append(
                finding(
                    "expiring",
                    f"{t} counts until {end}, {(end - as_of).days} days after {as_of}",
                    f"Request the next {t} from {vendor} before {end}.",
                    att,
                    "valid_to" if parse_day(att.get("valid_to", "")) else "period_end",
                )
            )
    if t in SOC2 and end is not None and end >= as_of:
        pe = parse_day(att["period_end"])
        window = add_months(pe, bridge_m)
        if as_of > window:
            later = [b for b in bridges if parse_day(b.get("valid_to", "")) and parse_day(b["valid_to"]) > pe]
            covering = [
                b for b in later if parse_day(b.get("valid_from", "")) and parse_day(b["valid_from"]) <= pe + timedelta(days=1)
            ]
            current = [b for b in covering if parse_day(b["valid_to"]) >= as_of]
            if current:
                b = max(current, key=lambda x: parse_day(x["valid_to"]))
                att["bridged_by"] = b["row"]
                notes.append(f"the gap after {pe} is covered by the bridge letter in register row {b['row']} until {b['valid_to']}")
            elif covering:
                b = max(covering, key=lambda x: parse_day(x["valid_to"]))
                out.append(
                    finding(
                        "bridge-letter-expired",
                        f"the bridge letter after this report ran to {b['valid_to']}, before {as_of}",
                        f"Request a new bridge letter or the next SOC 2 report from {vendor}.",
                        b,
                        "valid_to",
                    )
                )
            else:
                out.append(
                    finding(
                        "coverage-gap",
                        f"{(as_of - pe).days} days from period_end {pe} to {as_of}, more than the {bridge_m}-month bridge window, "
                        "and no bridge letter covers it",
                        f"Request a bridge letter from {vendor} covering {pe + timedelta(days=1)} to {as_of}, or a newer report.",
                        att,
                        "period_end",
                    )
                )
    if t in SOC2 and att.get("opinion") in ("qualified", "adverse", "disclaimer"):
        out.append(
            finding(
                "opinion-not-unqualified",
                f"the service auditor's opinion is {att['opinion']}",
                "Read the opinion section, record the reason and whether it affects the services you use, and decide with the owner.",
                att,
                "opinion",
            )
        )
    if t in SOC2 and att.get("exceptions", "").isdigit() and int(att["exceptions"]) > 0:
        n = int(att["exceptions"])
        out.append(
            finding(
                "exceptions-noted",
                f"{n} exception{'s' if n != 1 else ''} noted in the tests of controls",
                "Read each exception and the vendor's response, and record whether it affects the services you use.",
                att,
                "exceptions",
            )
        )
    cuecs = [c for c in split_list(att.get("cuecs", "")) if c.lower() != "none"]
    if cuecs and att.get("cuecs_reviewed") != "yes":
        out.append(
            finding(
                "cuecs-not-reviewed",
                f"{len(cuecs)} complementary user entity control{'s' if len(cuecs) != 1 else ''} not marked as reviewed: {'; '.join(cuecs)}",
                "Record, for each complementary user entity control, the control of ours that meets it, then set cuecs_reviewed to yes.",
                att,
                "cuecs_reviewed",
            )
        )
    return out, notes


def period_text(att: dict) -> str:
    start, end = att.get("period_start", ""), att.get("period_end", "")
    if start and end:
        return f"{start} to {end}"
    return f"as of {end}" if end else ""


def doc_state(findings: list[dict], att: dict) -> str:
    codes = {f["code"] for f in findings}
    if codes & CONTRA_CODES:
        return CONTRADICTED
    if codes & NA_CODES or att.get("not_yet_valid"):
        return NOT_ASSESSABLE
    return SUPPORTED


def evaluate_vendor(name: str, info: dict, docs: list[dict], ctx: dict) -> dict:
    bridges = [d for d in docs if d["type"] == "bridge-letter"]
    latest: dict[str, date] = {}
    for d in docs:
        k = key_date(d)
        if k and d["type"] != "bridge-letter":
            latest[family(d)] = max(latest.get(family(d), k), k)
    documents, findings = [], []
    soc2_latest = None
    for d in docs:
        k = key_date(d)
        superseded = d["type"] != "bridge-letter" and k is not None and k < latest.get(family(d), k)
        fs, notes = evaluate_document(d, ctx, bridges)
        state = doc_state(fs, d)
        if d["type"] in SOC2 and not superseded and k is not None:
            soc2_latest = d
        documents.append(
            {
                "register_row": d["row"],
                "type": d["type"],
                "issuer": d.get("issuer", ""),
                "period": period_text(d),
                "valid": f"{d.get('valid_from', '')} to {d.get('valid_to', '')}" if d.get("valid_from") or d.get("valid_to") else "",
                "opinion": d.get("opinion", ""),
                "exceptions": d.get("exceptions", ""),
                "scope_services": split_list(d.get("scope_services", "")),
                "state": state,
                "superseded": superseded,
                "source_file": d.get("source_file", ""),
                "source_page": d.get("source_page", ""),
                "source_sha256": d.get("source_sha256"),
                "citation": cite(d),
                "notes": notes,
            }
        )
        if not superseded:
            findings += fs
    # Bridge letters are judged with the report they bridge; one without any SOC 2 report is not assessable.
    for doc in documents:
        if doc["type"] == "bridge-letter":
            if soc2_latest is None:
                doc["state"] = NOT_ASSESSABLE
                doc["notes"].append("no SOC 2 report in the register for this bridge letter to bridge")
            elif any(f["code"] == "bridge-letter-expired" and f.get("register_row") == doc["register_row"] for f in findings):
                doc["state"] = CONTRADICTED
    # Findings for a bridge letter row are carried on that row; drop duplicates.
    seen, unique = set(), []
    for f in findings:
        key = (f["code"], f.get("register_row"), f.get("field"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique
    crit = info["criticality"] if info else "not in vendor list"
    counted = [doc for doc in documents if doc["type"] in COUNTED and not doc["superseded"]]
    if info and not counted and crit in ("high", "medium"):
        findings.insert(
            0,
            finding(
                "no-attestation",
                f"no SOC 2 report, ISO 27001 certificate or other attestation in the register for a {crit}-criticality vendor",
                f"Request a current SOC 2 Type 2 report or ISO 27001 certificate from {info['vendor']}, or record why none is needed.",
            ),
        )
    if info and crit == "high" and soc2_latest is not None and soc2_latest["type"] == "soc2-type1":
        findings.append(
            finding(
                "type1-only",
                "the latest SOC 2 report is Type 1 (design at a point in time, no testing over a period)",
                f"Ask {info['vendor']} for a SOC 2 Type 2 report, or record why a Type 1 is accepted for a high-criticality vendor.",
                soc2_latest,
                "type",
            )
        )
    if info and counted:
        scoped = [doc for doc in counted if doc["scope_services"]]
        in_scope = {norm(s) for doc in scoped for s in doc["scope_services"]}
        if scoped:
            for svc in info["services_used"]:
                if norm(svc) not in in_scope:
                    rows = ", ".join(str(doc["register_row"]) for doc in scoped)
                    findings.append(
                        {
                            "code": "scope-mismatch",
                            "message": f"service {svc!r} is used but is not in scope_services of register row(s) {rows}",
                            "action": f"Confirm with {info['vendor']} whether {svc} is covered by another report, or request one that includes it.",
                            "field": "scope_services",
                            "citation": f"[vendors#services_used; register rows {rows}#scope_services]",
                        }
                    )
    codes = {f["code"] for f in findings}
    if not counted:
        state = NOT_ASSESSABLE
    elif "scope-mismatch" in codes:
        state = CONTRADICTED
    elif any(doc["state"] == SUPPORTED for doc in counted):
        state = SUPPORTED
    elif any(doc["state"] == CONTRADICTED for doc in counted):
        state = CONTRADICTED
    else:
        state = NOT_ASSESSABLE
    return {
        "vendor": info["vendor"] if info else docs[0]["vendor"],
        "criticality": crit,
        "owner": info["owner"] if info else "",
        "services_used": info["services_used"] if info else [],
        "state": state,
        "documents": documents,
        "findings": sorted(findings, key=lambda f: FINDINGS.index(f["code"])),
    }


def evaluate(args) -> dict:
    as_of = parse_day(args.as_of or "")
    if as_of is None:
        raise InputError(f"--as-of: cannot parse {args.as_of!r}; use YYYY-MM-DD")
    for opt, val, low in (
        ("--max-report-age-months", args.max_report_age_months, 1),
        ("--bridge-max-months", args.bridge_max_months, 0),
        ("--expiring-days", args.expiring_days, 0),
    ):
        if val < low:
            raise InputError(f"{opt} must be {low} or more")
    docs_dir = Path(args.docs) if args.docs else None
    if docs_dir is not None and not docs_dir.is_dir():
        raise InputError(f"--docs: {docs_dir} is not a folder")
    register = load_register(Path(args.register))
    vendors = load_vendors(Path(args.vendors))
    ctx = {"as_of": as_of, "max_age": args.max_report_age_months, "bridge": args.bridge_max_months, "expiring": args.expiring_days, "docs": docs_dir}
    by_vendor: dict[str, list[dict]] = {}
    for att in register:
        by_vendor.setdefault(norm(att["vendor"]), []).append(att)
    results = [evaluate_vendor(k, v, by_vendor.get(k, []), ctx) for k, v in vendors.items()]
    results += [evaluate_vendor(k, {}, docs, ctx) for k, docs in by_vendor.items() if k not in vendors]
    results.sort(key=lambda r: (CRIT_ORDER[r["criticality"]], r["vendor"].lower()))
    counts = {c: sum(1 for r in results for f in r["findings"] if f["code"] == c) for c in FINDINGS}
    return {
        "tool": "vendor_attestations",
        "register": Path(args.register).name,
        "vendors_file": Path(args.vendors).name,
        "as_of": as_of.isoformat(),
        "policy": {
            "max_report_age_months": args.max_report_age_months,
            "bridge_max_months": args.bridge_max_months,
            "expiring_days": args.expiring_days,
            "note": "skill defaults unless changed on the command line; not a requirement of any standard",
        },
        "sources_checked": docs_dir is not None,
        "summary": {
            "vendors": len(results),
            "documents": len(register),
            "findings": sum(counts.values()),
            "by_code": {k: v for k, v in counts.items() if v},
            "states": {s: sum(1 for r in results if r["state"] == s) for s in (SUPPORTED, CONTRADICTED, NOT_ASSESSABLE)},
        },
        "vendors": results,
        "disclaimer": DISCLAIMER,
    }


def scrub(text: str, owners: list[str], redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8] + "@redacted.invalid", text)
        for o in sorted({o for o in owners if o and "@" not in o}, key=len, reverse=True):
            text = text.replace(o, "owner-" + hashlib.sha256(o.lower().encode()).hexdigest()[:8])
    return text


def cell(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(rep: dict) -> str:
    s = rep["summary"]
    pol = rep["policy"]
    lines = [
        f"## Vendor attestation digest: {cell(rep['register'])}",
        "",
        f"Evaluated as of {rep['as_of']} with this skill's default policy unless changed: report counts for "
        f"{pol['max_report_age_months']} months after its period, bridge letter needed after {pol['bridge_max_months']} months, "
        f"expiry warning {pol['expiring_days']} days ahead.",
        f"{s['vendors']} vendors, {s['documents']} documents, {s['findings']} findings. "
        + ("Source documents were hashed from --docs." if rep["sources_checked"] else "Source documents were not checked (no --docs)."),
        "",
        "| Vendor | Criticality | Owner | State | Findings |",
        "|---|---|---|---|---|",
    ]
    for v in rep["vendors"]:
        codes = ", ".join(sorted({f["code"] for f in v["findings"]}, key=FINDINGS.index)) or "none"
        lines.append(f"| {cell(v['vendor'])} | {v['criticality']} | {cell(v['owner'])} | {v['state']} | {codes} |")
    lines += ["", f"States: `{SUPPORTED}`, `{CONTRADICTED}`, `{NOT_ASSESSABLE}`. Vendors are ordered by criticality."]
    for v in rep["vendors"]:
        lines += ["", f"### {cell(v['vendor'])} ({v['criticality']}, {v['state']})", ""]
        if v["services_used"]:
            lines.append(f"Services used: {cell('; '.join(v['services_used']))}.")
            lines.append("")
        if v["documents"]:
            lines += ["| Row | Type | Issuer | Period or validity | Opinion | Exceptions | State | Source |", "|---|---|---|---|---|---|---|---|"]
            for d in v["documents"]:
                when = d["period"] or d["valid"]
                state = d["state"] + (" (superseded)" if d["superseded"] else "")
                src = d["source_file"] + (f" p.{d['source_page']}" if d["source_page"] else "")
                if d["source_sha256"]:
                    src += f" sha256 {d['source_sha256'][:12]}"
                lines.append(
                    f"| {d['register_row']} | {d['type']} | {cell(d['issuer'])} | {cell(when)} | {cell(d['opinion'])} | "
                    f"{cell(d['exceptions'])} | {state} | {cell(src)} |"
                )
            notes = [(d["register_row"], n) for d in v["documents"] for n in d["notes"]]
            if notes:
                lines.append("")
            lines += [f"- Row {row}: {cell(n)}" for row, n in notes]
        else:
            lines.append("No documents in the register.")
        if v["findings"]:
            lines += ["", "Actions for the owner:", ""]
            for f in v["findings"]:
                lines.append(f"- `{f['code']}`: {cell(f['message'])}. {cell(f['action'])} {cell(f.get('citation', ''))}".rstrip())
    lines += ["", rep["disclaimer"]]
    return "\n".join(lines)


def to_csv(rep: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["vendor", "criticality", "owner", "vendor_state", "finding", "register_row", "field", "message", "action", "citation"])
    for v in rep["vendors"]:
        for f in v["findings"] or [{}]:
            w.writerow(
                [
                    v["vendor"],
                    v["criticality"],
                    v["owner"],
                    v["state"],
                    f.get("code", ""),
                    f.get("register_row", ""),
                    f.get("field", ""),
                    f.get("message", ""),
                    f.get("action", ""),
                    f.get("citation", ""),
                ]
            )
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--register", required=True, help="attestation register (CSV or JSON)")
    ap.add_argument("--vendors", required=True, help="vendor list CSV: vendor, services_used, criticality, owner")
    ap.add_argument("--docs", help="folder with the source documents, to hash each source_file")
    ap.add_argument("--as-of", required=True, help="evaluate on this day (YYYY-MM-DD)")
    ap.add_argument("--max-report-age-months", type=int, default=12, help="skill default 12: a report counts this many months after its period")
    ap.add_argument("--bridge-max-months", type=int, default=3, help="skill default 3: longer gaps after a SOC 2 period need a bridge letter")
    ap.add_argument("--expiring-days", type=int, default=60, help="skill default 60: warn this many days before a document expires")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace owner names and e-mail addresses with stable tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    ap.add_argument("--csv", help="also write one row per finding as CSV to this path")
    args = ap.parse_args(argv)
    try:
        rep = evaluate(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    owners = [v["owner"] for v in rep["vendors"]]
    text = scrub(json.dumps(rep, indent=2, ensure_ascii=False) if args.json else render(rep), owners, args.redact)
    try:
        if args.csv:
            Path(args.csv).write_text(scrub(to_csv(rep), owners, args.redact), encoding="utf-8", newline="")
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return 1 if rep["summary"]["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
