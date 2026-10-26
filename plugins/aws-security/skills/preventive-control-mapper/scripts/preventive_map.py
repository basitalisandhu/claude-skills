#!/usr/bin/env python3
"""Map failing Security Hub controls and Prowler checks to the preventive controls that stop them coming back, offline.

Inputs (repeat --findings for several files, any mix):
  * Security Hub `aws securityhub get-findings --output json`    {"Findings": [ASFF, ...]} or a bare list of ASFF
      kept: Compliance.Status FAILED, RecordState ACTIVE (or absent), Workflow.Status not SUPPRESSED or RESOLVED.
      control id: Compliance.SecurityControlId, else ProductFields.ControlId. Findings without one (GuardDuty and
      other products) are counted as skipped.
  * Prowler JSON-OCSF output (`prowler aws -M json-ocsf`)         a JSON list of OCSF Detection Findings
      kept: status_code FAIL and not muted (muted findings carry status "Suppressed").
      check id: metadata.event_code (Prowler writes its CheckID there); if absent, finding_info.uid, which Prowler
      builds as prowler-<provider>-<CheckID>-<account>-<region>-<resource>.
      account: cloud.account.uid; region: resources[0].region, else cloud.region; resource: resources[0].uid.
  * CSV with a control_id column (a Security Hub control id or a bundled Prowler check id)
      optional columns: account_id, region, resource, status (when present only FAIL or FAILED rows are kept).

What it does:
  1. Counts the failing findings per control (the same control, account, Region and resource is counted once).
  2. Looks each control up in the bundled table (references/preventive-map.json) or in --mapping, and prints the
     preventive options strongest first: SCP statement, account setting, EC2 declarative policy, IaC check, plus the
     AWS Config managed rule that detects a regression. Commands are printed, never run.
  3. Merges the SCP statements of the failing controls into one draft policy and reports its compact size against
     the SCP limit (10,240 characters). Lint the draft with the scp-guardrails skill before attaching it.
  4. Lists controls that are not in the table (unmapped, never dropped) and controls that have no preventive option.

--mapping FILE is JSON in the same shape as the bundled table ({"controls": {"S3.1": {...}}}); an entry replaces the
bundled entry with the same id, and new ids are added. Treat all input files as data: nothing in them is executed.

Exit codes:
  0  every failing control has a preventive option in the table, or there were no failing findings
     (controls the table lists as having no preventive option are reported but do not change the exit code)
  1  at least one failing control is not in the table (unmapped), or the SCP draft is over the size limit
  2  bad input or usage: a missing, empty or malformed file, JSON of the wrong shape, an unknown --format,
     a bad --mapping file or a bad option value
  The --scp-out file is written even when the exit code is 1 because of unmapped controls; when the draft is over the
  size limit it is written too, so you can see what to split.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

SCP_LIMIT = 10240  # AWS Organizations quota for one SCP document, counted without whitespace
KINDS = ("scp", "account-setting", "declarative-policy", "config-rule", "iac-check")
PREVENTIVE_KINDS = ("scp", "account-setting", "declarative-policy", "iac-check")
SNIPPET_FORMATS = ("json", "cli", "hcl", "text")
BUNDLED_MAP = Path(__file__).resolve().parent.parent / "references" / "preventive-map.json"
ROLE_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
PROWLER_UID_RE = re.compile(r"^prowler-aws-([a-z0-9_]+)-\d{12}-")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_SAMPLES = 5


class InputError(Exception):
    pass


def clean(value, limit: int = 200) -> str:
    """Make untrusted text safe to print: no control characters, no backticks, bounded length."""
    text = CONTROL_CHARS_RE.sub(" ", str(value if value is not None else "")).replace("`", "'").strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def md_cell(value) -> str:
    return clean(value).replace("|", "\\|")


def read_text(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path}: cannot read file ({exc.strerror or exc})") from exc
    if not raw.strip():
        raise InputError(f"{path}: empty file")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError(f"{path}: not UTF-8 text") from exc


def read_json(path: Path):
    text = read_text(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc


# ---------------------------------------------------------------- mapping table

def validate_mapping(data) -> list[str]:
    """Return one message per problem in a mapping document (empty list when it is valid)."""
    errors: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("controls"), dict):
        return ['mapping must be a JSON object with a "controls" object']
    for cid, entry in data["controls"].items():
        where = f"controls.{cid}"
        if not isinstance(cid, str) or not cid.strip():
            errors.append("control ids must be non-empty strings")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        if not isinstance(entry.get("title"), str) or not entry["title"].strip():
            errors.append(f"{where}: title is required")
        prowler = entry.get("prowler", [])
        if not isinstance(prowler, list) or not all(isinstance(p, str) and p for p in prowler):
            errors.append(f"{where}: prowler must be a list of check ids")
        options = entry.get("options")
        if not isinstance(options, list):
            errors.append(f"{where}: options must be a list (it may be empty)")
            continue
        scp_options = 0
        for i, opt in enumerate(options):
            errors += _validate_option(f"{where}.options[{i}]", opt)
            if isinstance(opt, dict) and opt.get("kind") == "scp":
                scp_options += 1
        if scp_options > 1:
            errors.append(f"{where}: at most one scp option per control")
        if not options and not entry.get("note"):
            errors.append(f"{where}: a control with no options needs a note saying what to do instead")
    return errors


def _validate_option(where: str, opt) -> list[str]:
    errors: list[str] = []
    if not isinstance(opt, dict):
        return [f"{where}: must be an object"]
    kind = opt.get("kind")
    if kind not in KINDS:
        errors.append(f"{where}: kind must be one of {', '.join(KINDS)}")
    for key in ("name", "prevents"):
        if not isinstance(opt.get(key), str) or not opt[key].strip():
            errors.append(f"{where}: {key} is required")
    doc = opt.get("doc")
    if not isinstance(doc, str) or not doc.startswith("https://"):
        errors.append(f"{where}: doc must be an https URL")
    caveats = opt.get("caveats", [])
    if not isinstance(caveats, list) or not all(isinstance(c, str) for c in caveats):
        errors.append(f"{where}: caveats must be a list of strings")
    if opt.get("snippet_format") not in SNIPPET_FORMATS:
        errors.append(f"{where}: snippet_format must be one of {', '.join(SNIPPET_FORMATS)}")
    if "snippet" not in opt or opt["snippet"] in (None, "", [], {}):
        errors.append(f"{where}: snippet is required")
    elif kind == "scp":
        statements = opt["snippet"]
        if not isinstance(statements, list) or not statements:
            errors.append(f"{where}: an scp snippet must be a non-empty list of statements")
        else:
            for j, st in enumerate(statements):
                if not isinstance(st, dict) or st.get("Effect") != "Deny":
                    errors.append(f"{where}: statement {j} must be an object with Effect Deny")
                elif not isinstance(st.get("Sid"), str) or not re.fullmatch(r"[A-Za-z0-9]+", st["Sid"]) \
                        or not (st.get("Action") or st.get("NotAction")) or "Resource" not in st:
                    errors.append(f"{where}: statement {j} needs an alphanumeric Sid, Action or NotAction, and Resource")
    elif kind in ("account-setting", "iac-check") and not isinstance(opt["snippet"], str):
        errors.append(f"{where}: snippet must be a string")
    elif kind == "declarative-policy" and not isinstance(opt["snippet"], dict):
        errors.append(f"{where}: a declarative-policy snippet must be a JSON object")
    elif kind == "config-rule":
        rule = opt.get("config_rule")
        if not isinstance(rule, dict) or not all(isinstance(rule.get(k), str) and rule[k] for k in ("name", "identifier")):
            errors.append(f"{where}: config-rule options need config_rule.name and config_rule.identifier")
    return errors


def load_mapping(extra: Path | None) -> dict[str, dict]:
    try:
        bundled = json.loads(BUNDLED_MAP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"bundled mapping {BUNDLED_MAP} is unreadable ({exc})") from exc
    controls = dict(bundled["controls"])
    if extra is not None:
        data = read_json(extra)
        problems = validate_mapping(data)
        if problems:
            raise InputError(f"{extra}: bad mapping: " + "; ".join(problems[:5]) + (f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""))
        controls.update(data["controls"])
    return controls


def build_lookup(controls: dict[str, dict]) -> dict[str, str]:
    """Lower-cased control id or Prowler check id -> control id."""
    lookup: dict[str, str] = {}
    for cid, entry in controls.items():
        for p in entry.get("prowler", []):
            lookup.setdefault(p.lower(), cid)
    for cid in controls:
        lookup[cid.lower()] = cid
    return lookup


# ---------------------------------------------------------------- finding parsers

def _text(value) -> str:
    return value if isinstance(value, str) else ""


def parse_asff(items: list, stats: dict) -> list[dict]:
    out = []
    for f in items:
        if not isinstance(f, dict):
            raise InputError("a Findings entry is not an object")
        comp = f.get("Compliance") if isinstance(f.get("Compliance"), dict) else {}
        fields = f.get("ProductFields") if isinstance(f.get("ProductFields"), dict) else {}
        cid = _text(comp.get("SecurityControlId")) or _text(fields.get("ControlId"))
        if not cid:
            stats["no_control_id"] += 1
            continue
        if _text(f.get("RecordState")) not in ("", "ACTIVE"):
            stats["not_active"] += 1
            continue
        workflow = f.get("Workflow") if isinstance(f.get("Workflow"), dict) else {}
        if _text(workflow.get("Status")) in ("SUPPRESSED", "RESOLVED"):
            stats["suppressed_or_resolved"] += 1
            continue
        if _text(comp.get("Status")) != "FAILED":
            stats["not_failed"] += 1
            continue
        resources = f.get("Resources") if isinstance(f.get("Resources"), list) else []
        first = resources[0] if resources and isinstance(resources[0], dict) else {}
        out.append({"key": cid, "account": _text(f.get("AwsAccountId")), "region": _text(f.get("Region")), "resource": _text(first.get("Id"))})
    return out


def parse_ocsf(items: list, stats: dict) -> list[dict]:
    out = []
    for f in items:
        if not isinstance(f, dict):
            raise InputError("a finding entry is not an object")
        meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
        info = f.get("finding_info") if isinstance(f.get("finding_info"), dict) else {}
        check = _text(meta.get("event_code"))
        if not check:
            m = PROWLER_UID_RE.match(_text(info.get("uid")))
            check = m.group(1) if m else ""
        if not check:
            stats["no_control_id"] += 1
            continue
        if _text(f.get("status")).lower() == "suppressed":
            stats["suppressed_or_resolved"] += 1
            continue
        if _text(f.get("status_code")).upper() != "FAIL":
            stats["not_failed"] += 1
            continue
        cloud = f.get("cloud") if isinstance(f.get("cloud"), dict) else {}
        account = cloud.get("account") if isinstance(cloud.get("account"), dict) else {}
        resources = f.get("resources") if isinstance(f.get("resources"), list) else []
        first = resources[0] if resources and isinstance(resources[0], dict) else {}
        out.append({"key": check, "account": _text(account.get("uid")), "region": _text(first.get("region")) or _text(cloud.get("region")),
                    "resource": _text(first.get("uid"))})
    return out


def parse_csv(text: str, path: Path, stats: dict) -> list[dict]:
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        header = reader.fieldnames or []
    except csv.Error as exc:
        raise InputError(f"{path}: invalid CSV ({exc})") from exc
    if "control_id" not in header:
        raise InputError(f"{path}: CSV needs a control_id column")
    out = []
    for row in rows:
        cid = (row.get("control_id") or "").strip()
        if not cid:
            stats["no_control_id"] += 1
            continue
        status = (row.get("status") or "").strip().upper()
        if "status" in row and status not in ("FAIL", "FAILED"):
            stats["not_failed"] += 1
            continue
        out.append({"key": cid, "account": (row.get("account_id") or "").strip(), "region": (row.get("region") or "").strip(),
                    "resource": (row.get("resource") or "").strip()})
    return out


def is_ocsf(x) -> bool:
    return isinstance(x, dict) and "status_code" in x and isinstance(x.get("metadata"), dict)


def is_asff(x) -> bool:
    return isinstance(x, dict) and ("Compliance" in x or "AwsAccountId" in x or "SchemaVersion" in x)


def load_findings(path: Path, stats: dict) -> list[dict]:
    text = read_text(path)
    if path.suffix.lower() == ".csv":
        return parse_csv(text, path, stats)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    try:
        if isinstance(data, dict) and "Findings" in data:
            if not isinstance(data["Findings"], list):
                raise InputError("Findings is not a list")
            return parse_asff(data["Findings"], stats)
        if isinstance(data, list):
            if not data:
                return []
            if all(is_ocsf(x) for x in data):
                return parse_ocsf(data, stats)
            if all(is_asff(x) for x in data):
                return parse_asff(data, stats)
            raise InputError("a list must hold Security Hub findings or Prowler JSON-OCSF findings")
        raise InputError('expected a Security Hub export ({"Findings": [...]}) or a Prowler JSON-OCSF list')
    except InputError as exc:
        raise InputError(f"{path}: {exc}") from exc


# ---------------------------------------------------------------- analysis

def aggregate(records: list[dict], lookup: dict[str, str]) -> dict[str, dict]:
    """Group failing findings by control id (or by the raw id when the table does not know it)."""
    groups: dict[str, dict] = {}
    seen: set[tuple] = set()
    for r in records:
        control = lookup.get(r["key"].lower())
        key = control or r["key"]
        ident = (key, r["account"], r["region"], r["resource"])
        if r["resource"] and ident in seen:
            continue
        seen.add(ident)
        g = groups.setdefault(key, {"id": key, "mapped": control is not None, "count": 0, "accounts": set(), "regions": set(),
                                    "resources": [], "raw_ids": set()})
        g["count"] += 1
        g["raw_ids"].add(r["key"])
        if r["account"]:
            g["accounts"].add(r["account"])
        if r["region"]:
            g["regions"].add(r["region"])
        if r["resource"] and r["resource"] not in g["resources"]:
            g["resources"].append(r["resource"])
    return groups


def exempt_condition(roles: list[str]) -> dict:
    return {"ArnNotLike": {"aws:PrincipalArn": [f"arn:aws:iam::*:role/{r}" for r in roles]}}


def with_exemption(statement: dict, roles: list[str]) -> dict:
    st = json.loads(json.dumps(statement))
    cond = st.setdefault("Condition", {})
    for op, kv in exempt_condition(roles).items():
        existing = cond.setdefault(op, {})
        for k, v in kv.items():
            old = existing.get(k, [])
            old = [old] if isinstance(old, str) else list(old)
            existing[k] = old + [x for x in v if x not in old]
    return st


def compact(doc: dict) -> str:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def scp_draft(failing: list[dict], controls: dict[str, dict], roles: list[str], limit: int) -> dict:
    statements: list[dict] = []
    sources: dict[str, list[str]] = {}
    by_sid: dict[str, str] = {}
    notes: list[str] = []
    for g in failing:
        for opt in controls[g["id"]]["options"]:
            if opt["kind"] != "scp" or opt.get("draft", True) is False:
                continue
            for st in opt["snippet"]:
                final = with_exemption(st, roles) if roles and opt.get("exemptable") else st
                sid = final["Sid"]
                dumped = compact(final)
                if sid in by_sid and by_sid[sid] != dumped:
                    n = 2
                    while f"{sid}{n}" in by_sid:
                        n += 1
                    notes.append(f"Two options use the Sid {sid} with different content; the second was renamed {sid}{n}.")
                    final = {**final, "Sid": f"{sid}{n}"}
                    sid, dumped = final["Sid"], compact(final)
                if sid in by_sid:
                    sources[sid].append(g["id"])
                    continue
                by_sid[sid] = dumped
                statements.append(final)
                sources[sid] = [g["id"]]
    document = {"Version": "2012-10-17", "Statement": statements}
    chars = len(compact(document)) if statements else 0
    open_statements = []
    if not roles:
        for g in failing:
            for o in controls[g["id"]]["options"]:
                if o["kind"] == "scp" and o.get("exemptable") and o.get("draft", True):
                    open_statements += [s["Sid"] for s in o["snippet"]]
    return {"document": document if statements else None, "chars": chars, "limit": limit, "over_limit": chars > limit,
            "statements": [s["Sid"] for s in statements], "sources": sources, "notes": notes, "no_exemption_for": sorted(set(open_statements))}


def analyse(records: list[dict], controls: dict[str, dict], roles: list[str], limit: int, stats: dict, files: list[str]) -> dict:
    groups = aggregate(records, build_lookup(controls))
    order = sorted(groups.values(), key=lambda g: (-g["count"], g["id"]))
    mapped = [g for g in order if g["mapped"]]
    unmapped = [g for g in order if not g["mapped"]]
    with_options = [g for g in mapped if any(o["kind"] in PREVENTIVE_KINDS for o in controls[g["id"]]["options"])]
    detective_only = [g for g in mapped if g not in with_options]
    draft = scp_draft(with_options, controls, roles, limit)
    failing_total = sum(g["count"] for g in order)
    return {"files": files, "skipped": stats, "failing_findings": failing_total, "controls": order, "mapped": mapped, "with_options": with_options,
            "detective_only": detective_only, "unmapped": unmapped, "draft": draft, "table": controls}


# ---------------------------------------------------------------- rendering

def fence(body: str, lang: str = "") -> list[str]:
    ticks = "```"
    while ticks in body:
        ticks += "`"
    return [f"{ticks}{lang}", body, ticks]


def snippet_text(opt: dict) -> tuple[str, str]:
    fmt = opt["snippet_format"]
    snip = opt["snippet"]
    if fmt == "json" and not isinstance(snip, str):
        return json.dumps(snip, indent=2), "json"
    return str(snip), {"json": "json", "cli": "bash", "hcl": "hcl", "text": "text"}[fmt]


def group_view(g: dict) -> dict:
    return {"control": g["id"], "findings": g["count"], "accounts": sorted(g["accounts"]), "regions": sorted(g["regions"]),
            "sample_resources": [clean(r) for r in g["resources"][:MAX_SAMPLES]]}


def render_markdown(rep: dict) -> str:
    controls, draft = rep["table"], rep["draft"]
    sk = rep["skipped"]
    L: list[str] = ["# Preventive control map", ""]
    L.append(f"Read {len(rep['files'])} file(s). {rep['failing_findings']} failing finding(s) across {len(rep['controls'])} control(s) were kept; "
             f"skipped: {sk['not_failed']} not failed, {sk['suppressed_or_resolved']} suppressed or resolved, {sk['not_active']} not active, "
             f"{sk['no_control_id']} without a control id.")
    L += ["", "| Failing controls | With a preventive option | Detective only | Unmapped |", "|---|---|---|---|",
          f"| {len(rep['controls'])} | {len(rep['with_options'])} | {len(rep['detective_only'])} | {len(rep['unmapped'])} |", ""]
    if not rep["controls"]:
        L += ["No failing findings: nothing to map.", ""]
    for g in rep["with_options"]:
        entry = controls[g["id"]]
        L += [f"## {g['id']}: {clean(entry['title'])}", ""]
        v = group_view(g)
        L.append(f"- Failing findings: {g['count']}; accounts: {', '.join(f'`{clean(a)}`' for a in v['accounts']) or 'not given'}; "
                 f"regions: {', '.join(f'`{clean(r)}`' for r in v['regions']) or 'not given'}")
        if v["sample_resources"]:
            L.append("- Sample resources: " + ", ".join(f"`{r}`" for r in v["sample_resources"]))
        L.append(f"- Control page: {entry.get('doc', 'not given')}")
        if entry.get("note"):
            L.append(f"- Note: {clean(entry['note'], 600)}")
        L.append("")
        for n, opt in enumerate(entry["options"], 1):
            kind = opt["kind"]
            label = kind + (" (detects, does not prevent)" if kind == "config-rule" else "")
            L += [f"### {g['id']} option {n}: {clean(opt['name'])} [{label}]", "", f"Prevents: {clean(opt['prevents'], 600)}", ""]
            if kind == "config-rule":
                rule = opt["config_rule"]
                trigger = f", trigger: {clean(rule['trigger'])}" if rule.get("trigger") else ""
                L.append(f"Managed rule `{clean(rule['name'])}`, identifier `{clean(rule['identifier'])}`{trigger}.")
                L.append("")
            body, lang = snippet_text(opt)
            L += fence(body, lang)
            L.append("")
            if opt.get("caveats"):
                L += [f"- Caveat: {clean(c, 600)}" for c in opt["caveats"]]
            L += [f"- Source: {clean(opt['doc'], 300)}", ""]
    if rep["detective_only"]:
        L += ["## Controls with no preventive option", ""]
        for g in rep["detective_only"]:
            entry = controls[g["id"]]
            v = group_view(g)
            fallback = "No preventive control is known; keep the detective control and route the finding to its owner (security-hub-triage)."
            L.append(f"- **{g['id']}** {clean(entry['title'])}: {g['count']} finding(s). {clean(entry.get('note') or fallback, 600)} "
                     f"Sample: {', '.join(f'`{r}`' for r in v['sample_resources']) or 'none'}.")
            for opt in entry["options"]:
                if opt["kind"] == "config-rule":
                    rule = opt["config_rule"]
                    L.append(f"  - Continuous detection: managed rule `{clean(rule['name'])}` (`{clean(rule['identifier'])}`).")
        L.append("")
    L += ["## SCP draft", ""]
    if draft["document"] is None:
        L += ["No failing control has an SCP option, so there is no draft.", ""]
    else:
        L += fence(json.dumps(draft["document"], indent=2), "json")
        status = "OVER the limit" if draft["over_limit"] else "within the limit"
        L += ["", f"Size: {draft['chars']} characters compact, {status} of {draft['limit']} (the AWS Organizations quota for one SCP).",
              "The console does not count whitespace, but the AWS CLI and SDKs keep what you send, so upload the compact form.",
              f"Statements: {', '.join(draft['statements'])}."]
        if draft["over_limit"]:
            L.append("Split the statements into two SCPs or drop the ones you do not need.")
        for note in draft["notes"]:
            L.append(f"Note: {note}")
        if draft["no_exemption_for"]:
            L.append(f"Warning: no --break-glass-role was given, so {', '.join(draft['no_exemption_for'])} apply to every principal in scope. "
                     "Pass --break-glass-role NAME so one role can still change those settings.")
        L += ["", "Lint it with the scp-guardrails skill before attaching it (scp_lint.py) and attach it to a sandbox OU first. "
                  "SCPs do not apply to the management account or to service-linked roles.", ""]
    L += ["## Unmapped controls", ""]
    if rep["unmapped"]:
        L += ["These failing controls are not in the table. They are not dropped: map them by hand or extend the table with --mapping.", "",
              "| Id | Findings | Accounts | Sample resources |", "|---|---|---|---|"]
        for g in rep["unmapped"]:
            v = group_view(g)
            L.append(f"| {md_cell(g['id'])} | {g['count']} | {md_cell(', '.join(v['accounts']))} | {md_cell(', '.join(v['sample_resources']))} |")
    else:
        L.append("None.")
    L.append("")
    return "\n".join(L)


def render_json(rep: dict) -> str:
    controls = rep["table"]

    def opt_view(opt: dict) -> dict:
        return {k: opt[k] for k in ("kind", "name", "prevents", "snippet_format", "snippet", "caveats", "doc", "config_rule") if k in opt}

    def full(g: dict) -> dict:
        entry = controls[g["id"]]
        return {**group_view(g), "title": entry["title"], "note": entry.get("note"), "options": [opt_view(o) for o in entry["options"]]}

    d = rep["draft"]
    out = {
        "files": rep["files"], "skipped": rep["skipped"], "failing_findings": rep["failing_findings"],
        "summary": {"failing_controls": len(rep["controls"]), "with_preventive_option": len(rep["with_options"]),
                    "detective_only": len(rep["detective_only"]), "unmapped": len(rep["unmapped"])},
        "controls": [full(g) for g in rep["with_options"]],
        "detective_only": [full(g) for g in rep["detective_only"]],
        "scp_draft": {"document": d["document"], "chars": d["chars"], "limit": d["limit"], "over_limit": d["over_limit"],
                      "statements": d["statements"], "notes": d["notes"],
                      "no_exemption_for": d["no_exemption_for"], "lint_with": "scp-guardrails (scp_lint.py)"},
        "unmapped": [{**group_view(g), "raw_ids": sorted(clean(x) for x in g["raw_ids"])} for g in rep["unmapped"]],
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- command line

def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", required=True, metavar="FILE",
                    help="Security Hub get-findings JSON, Prowler JSON-OCSF, or CSV with a control_id column (repeatable)")
    ap.add_argument("--mapping", metavar="FILE", help="JSON table that extends or overrides the bundled references/preventive-map.json")
    ap.add_argument("--format", default="markdown", help="markdown (default) or json")
    ap.add_argument("--json", action="store_true", help="shorthand for --format json")
    ap.add_argument("--out", metavar="FILE", help="write the report here instead of printing it")
    ap.add_argument("--scp-out", metavar="FILE", help="write the merged SCP draft here as compact JSON (ready for scp_lint.py)")
    ap.add_argument("--break-glass-role", action="append", default=[], metavar="NAME",
                    help="role name exempted (aws:PrincipalArn) from SCP statements that restrict settings; repeatable")
    ap.add_argument("--scp-limit", type=int, default=SCP_LIMIT, metavar="N", help=f"SCP size limit in characters (default {SCP_LIMIT})")
    args = ap.parse_args(argv)

    fmt = "json" if args.json else args.format
    try:
        if fmt not in ("markdown", "json"):
            raise InputError(f"unknown --format {fmt!r} (use markdown or json)")
        if args.scp_limit < 1:
            raise InputError("--scp-limit must be at least 1")
        for role in args.break_glass_role:
            if not ROLE_RE.match(role):
                raise InputError(f"--break-glass-role {role!r} is not an IAM role name")
        inputs = {Path(p).resolve() for p in args.findings + ([args.mapping] if args.mapping else [])}
        for flag, target in (("--out", args.out), ("--scp-out", args.scp_out)):
            if target and Path(target).resolve() in inputs:
                raise InputError(f"{flag} would overwrite an input file")
        controls = load_mapping(Path(args.mapping) if args.mapping else None)
        stats = {"not_failed": 0, "suppressed_or_resolved": 0, "not_active": 0, "no_control_id": 0}
        records: list[dict] = []
        for f in args.findings:
            records += load_findings(Path(f), stats)
        rep = analyse(records, controls, args.break_glass_role, args.scp_limit, stats, [Path(f).name for f in args.findings])
        text = render_json(rep) if fmt == "json" else render_markdown(rep)
        if args.scp_out:
            if rep["draft"]["document"] is None:
                print("note: no SCP statements to write, so --scp-out wrote nothing", file=sys.stderr)
            else:
                Path(args.scp_out).write_text(compact(rep["draft"]["document"]) + "\n", encoding="utf-8")
        if args.out:
            Path(args.out).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {args.out}" if args.out else text)
    return 1 if rep["unmapped"] or rep["draft"]["over_limit"] else 0


def main(argv: list[str] | None = None) -> int:
    """Run the script; a value of the wrong type or shape anywhere in the input exits 2 with a message, not a traceback."""
    try:
        return _main(argv)
    except (TypeError, AttributeError, KeyError, IndexError, RecursionError) as exc:
        print(f"error: the input has a value of an unexpected type or shape ({type(exc).__name__}: {exc}); "
              "check that it is the unmodified export or spec the skill describes", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
