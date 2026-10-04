#!/usr/bin/env python3
"""Map the exports in an evidence pack to ISO/IEC 27001:2022 Annex A or SOC 2 control identifiers with a mapping file.

Usage:
  control_map.py <pack> --framework iso27001|soc2 --map <map.yaml> [--out control-map.json] [--max-age-days N]

<pack> is a folder built by evidence_pack.py (manifest.json plus evidence/). Every file a check reads is first
re-hashed and compared with the manifest; a file that does not match is not assessable, never supported.

Mapping file (YAML or JSON; the starter map is references/starter-map.yaml). Control topics are the map owner's own
short paraphrases, never the standard's text:
  controls:
    iso27001: {A.8.32: "Changes go through a reviewed, recorded process"}
    soc2: {CC8.1: "Changes are authorised, tested and approved before release"}
  checks:
    - id: github-required-reviews
      iso27001: [A.8.32]
      soc2: [CC8.1]
      evidence: github/branch-protection.json      path (glob allowed) of a file inside the pack
      field: required_pull_request_reviews.required_approving_review_count
      expect: {gte: 1}
      absent_when: ["Branch not protected"]       error messages that mean "configured off", not "cannot tell"
      on_fail: not assessable                     optional: a failed condition is a gap, not a contradiction
      describes: "Merges to the protected branch need at least one approving review"

  field: dotted path; "name[]" fans out over a list, "[]" alone is the top-level list (a CSV file is a list of rows).
  where: optional {subpath: condition} filter applied to each fanned-out object before expect.
  expect: one condition. Value conditions: equals, not_equals, in, gte, lte, contains, not_contains, exists,
    not_empty (with "match: any" a fanned-out field needs only one value to pass; default all). Count conditions on
    the entries left after where: count_gte, count_lte.
  any_of: instead of evidence/field/expect, a list of alternatives; supported when one alternative is supported.

States (only these three):
  supported       every value the check reads meets the condition, from a file whose hash matches the manifest
  contradicted    a value read from a verified file does not meet the condition (or an error listed in absent_when)
  not assessable  the file is missing, empty, an error response (403 and similar), fails its hash check, is older than
                  --max-age-days, or the field is absent
A control is supported only when every check mapped to it is supported; any contradicted check makes it
contradicted; otherwise it is not assessable. A control listed in the map with no checks is not assessable.

File types: .json (an empty file or a saved API error body is not assessable), .csv (list of rows), .http (output of
`gh api -i`: status line and headers; 401 and 403 are not assessable). An AWS export's stderr saved next to it as
<name>.err (same folder, same stem) is read as the export's error when it is not empty.

Output: Markdown (default) or JSON (--json) per control: state, citations (file, field, value, sha256), gaps, and the
pack files no check read. --out writes the JSON to a file for narrative.py.

Exit codes: 0 report built, 1 a control matched --fail-on, 2 bad input or bad map. Nothing calls any API.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    CONTRADICTED,
    DISCLAIMER,
    NOT_ASSESSABLE,
    SUPPORTED,
    InputError,
    add_common_args,
    as_of_datetime,
    cell,
    cite_text,
    days_between,
    dumps,
    error_body,
    fail_exit,
    is_denied,
    load_json,
    load_yaml_or_json,
    redact,
    resolve_path,
    sha256_file,
    state_counts,
    worst_state,
)

FRAMEWORKS = ("iso27001", "soc2")
VALUE_OPS = {"equals", "not_equals", "in", "gte", "lte", "contains", "not_contains", "exists", "not_empty"}
COUNT_OPS = {"count_gte", "count_lte"}
CHECK_KEYS = {"id", "iso27001", "soc2", "evidence", "field", "where", "expect", "match", "absent_when", "on_fail", "describes", "any_of"}
ALT_KEYS = {"evidence", "field", "where", "expect", "match", "absent_when", "on_fail"}
MAX_TOPIC_WORDS = 20


# ---- map loading ------------------------------------------------------------------------------------------------

def _check_condition(cond, where: str, allow_count: bool) -> None:
    if not isinstance(cond, dict) or len(cond) != 1:
        raise InputError(f"{where}: a condition is a mapping with exactly one operator, for example {{gte: 1}}")
    op = next(iter(cond))
    allowed = VALUE_OPS | (COUNT_OPS if allow_count else set())
    if op not in allowed:
        raise InputError(f"{where}: unknown operator {op!r}; use one of {', '.join(sorted(allowed))}")
    if op == "in" and not isinstance(cond[op], list):
        raise InputError(f"{where}: 'in' needs a list")
    if op in COUNT_OPS | {"gte", "lte"} and (isinstance(cond[op], bool) or not isinstance(cond[op], int | float)):
        raise InputError(f"{where}: {op} needs a number")


def _check_alternative(alt: dict, where: str) -> None:
    unknown = set(alt) - ALT_KEYS
    if unknown:
        raise InputError(f"{where}: unknown keys {', '.join(sorted(unknown))}")
    for key in ("evidence", "field", "expect"):
        if key not in alt:
            raise InputError(f"{where}: needs {key}")
    if not isinstance(alt["evidence"], str) or not alt["evidence"] or PurePosixPath(alt["evidence"]).is_absolute() or ".." in alt["evidence"]:
        raise InputError(f"{where}: evidence must be a relative path inside the pack")
    if not isinstance(alt["field"], str):
        raise InputError(f"{where}: field must be a string")
    _check_condition(alt["expect"], f"{where}.expect", allow_count=True)
    if alt.get("match", "all") not in ("all", "any"):
        raise InputError(f"{where}: match must be all or any")
    where_clause = alt.get("where", {})
    if not isinstance(where_clause, dict):
        raise InputError(f"{where}: where must be a mapping of subpath to condition")
    for sub, cond in where_clause.items():
        _check_condition(cond, f"{where}.where.{sub}", allow_count=False)
    if where_clause and "[]" not in alt["field"]:
        raise InputError(f"{where}: where needs a field that fans out over a list (ends in [])")
    if alt.get("on_fail", CONTRADICTED) not in (CONTRADICTED, NOT_ASSESSABLE):
        raise InputError(f"{where}: on_fail must be 'contradicted' or 'not assessable'")
    absent = alt.get("absent_when", [])
    if not isinstance(absent, list) or not all(isinstance(a, str) and a for a in absent):
        raise InputError(f"{where}: absent_when must be a list of message fragments")


def load_map(path: str) -> dict:
    data = load_yaml_or_json(path)
    if not isinstance(data, dict):
        raise InputError(f"{path}: the map must be a mapping with controls and checks")
    unknown = set(data) - {"version", "notes", "controls", "checks"}
    if unknown:
        raise InputError(f"{path}: unknown top-level keys {', '.join(sorted(unknown))}")
    controls = data.get("controls") or {}
    if not isinstance(controls, dict) or set(controls) - set(FRAMEWORKS):
        raise InputError(f"{path}: controls must map iso27001 and/or soc2 to {{identifier: paraphrase}}")
    for fw, entries in controls.items():
        if not isinstance(entries, dict):
            raise InputError(f"{path}: controls.{fw} must map identifiers to paraphrases")
        for cid, topic in entries.items():
            if not isinstance(topic, str) or not topic.strip():
                raise InputError(f"{path}: controls.{fw}.{cid} needs a short paraphrase")
            if len(topic.split()) > MAX_TOPIC_WORDS:
                raise InputError(f"{path}: controls.{fw}.{cid} paraphrase is over {MAX_TOPIC_WORDS} words; "
                                 "write a short topic in your own words, never the standard's text")
    checks = data.get("checks") or []
    if not isinstance(checks, list):
        raise InputError(f"{path}: checks must be a list")
    seen = set()
    for i, chk in enumerate(checks):
        where = f"{path}: checks[{i}]"
        if not isinstance(chk, dict):
            raise InputError(f"{where}: must be a mapping")
        unknown = set(chk) - CHECK_KEYS
        if unknown:
            raise InputError(f"{where}: unknown keys {', '.join(sorted(unknown))}")
        cid = chk.get("id")
        if not cid or not isinstance(cid, str):
            raise InputError(f"{where}: needs an id")
        if cid in seen:
            raise InputError(f"{where}: duplicate id {cid}")
        seen.add(cid)
        for fw in FRAMEWORKS:
            ids = chk.get(fw, [])
            if not isinstance(ids, list):
                raise InputError(f"{where} ({cid}): {fw} must be a list of identifiers")
            for ident in ids:
                if ident not in (controls.get(fw) or {}):
                    raise InputError(f"{where} ({cid}): {fw} identifier {ident} has no paraphrase under controls.{fw}")
        if "any_of" in chk:
            if not isinstance(chk["any_of"], list) or not chk["any_of"]:
                raise InputError(f"{where} ({cid}): any_of must be a non-empty list")
            if set(chk) & {"evidence", "field", "expect", "where"}:
                raise InputError(f"{where} ({cid}): use either any_of or evidence/field/expect, not both")
            for j, alt in enumerate(chk["any_of"]):
                if not isinstance(alt, dict):
                    raise InputError(f"{where} ({cid}).any_of[{j}]: must be a mapping")
                _check_alternative(alt, f"{where} ({cid}).any_of[{j}]")
        else:
            _check_alternative({k: v for k, v in chk.items() if k in ALT_KEYS}, f"{where} ({cid})")
    return {"controls": controls, "checks": checks}


# ---- pack access ------------------------------------------------------------------------------------------------

class Pack:
    def __init__(self, folder: str, as_of: datetime, max_age_days: int | None):
        self.folder = Path(folder)
        mpath = self.folder / "manifest.json"
        if not mpath.is_file():
            raise InputError(f"{self.folder}: no manifest.json; build the pack with evidence_pack.py first")
        m = load_json(mpath)
        if not isinstance(m, dict) or not isinstance(m.get("files"), list):
            raise InputError(f"{mpath}: not an evidence pack manifest")
        self.manifest = m
        self.root = Path(m["source_root"]) if m.get("mode") == "reference" and m.get("source_root") else self.folder / "evidence"
        self.files = {f["path"]: f for f in m["files"] if isinstance(f, dict) and f.get("path")}
        self.as_of = as_of
        self.max_age_days = max_age_days
        self.read: set[str] = set()
        self._verified: dict[str, bool] = {}

    def match(self, pattern: str) -> list[str]:
        return sorted(p for p in self.files if fnmatch.fnmatchcase(p, pattern))

    def verified(self, rel: str) -> bool:
        if rel not in self._verified:
            p = self.root / rel
            self._verified[rel] = p.is_file() and sha256_file(p) == self.files[rel].get("sha256")
        return self._verified[rel]

    def age_gap(self, rel: str) -> str | None:
        if self.max_age_days is None:
            return None
        f = self.files[rel]
        when = f.get("collected_at") or f.get("file_mtime")
        age = days_between(when, self.as_of)
        if age is None:
            return f"{rel}: no collection date, so its age cannot be checked against --max-age-days"
        if age > self.max_age_days:
            return f"{rel}: collected {age} days before {self.as_of:%Y-%m-%d}, over the {self.max_age_days}-day limit"
        return None

    def stderr_of(self, rel: str) -> tuple[str, str] | None:
        """Return (err file, text) for a non-empty <stem>.err saved next to rel in the pack."""
        err_rel = str(PurePosixPath(rel).with_suffix(".err"))
        if err_rel == rel or err_rel not in self.files:
            return None
        self.read.add(err_rel)
        if not self.verified(err_rel):
            return (err_rel, "")
        text = (self.root / err_rel).read_text(encoding="utf-8", errors="replace").strip()
        return (err_rel, text) if text else None

    def load(self, rel: str):
        """Return (data, error dict or None). Errors carry status and message."""
        self.read.add(rel)
        p = self.root / rel
        if rel.endswith(".csv"):
            text = p.read_text(encoding="utf-8-sig", errors="replace")
            if not text.strip():
                return None, None
            return list(csv.DictReader(io.StringIO(text))), None
        if rel.endswith(".http"):
            return parse_http(p.read_text(encoding="utf-8", errors="replace"))
        data = load_json(p)
        return data, error_body(data)


def parse_http(text: str):
    """Parse `gh api -i` output: the status line and headers (the body is ignored)."""
    lines = text.splitlines()
    if not lines or not lines[0].upper().startswith("HTTP/"):
        return None, None
    parts = lines[0].split()
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        return None, None
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    data = {"status": status, "headers": headers}
    if status in (401, 403):
        return data, {"status": str(status), "message": f"HTTP {status}"}
    return data, None


# ---- evaluation -------------------------------------------------------------------------------------------------

def _num(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float):
        return v
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def value_ok(value, cond: dict) -> bool:
    op, arg = next(iter(cond.items()))
    if op == "equals":
        if isinstance(value, bool) != isinstance(arg, bool):
            return False
        return value == arg or (isinstance(value, str) and isinstance(arg, str) and value.lower() == arg.lower())
    if op == "not_equals":
        return not value_ok(value, {"equals": arg})
    if op == "in":
        return any(value_ok(value, {"equals": a}) for a in arg)
    if op in ("gte", "lte"):
        n = _num(value)
        if n is None:
            return False
        return n >= arg if op == "gte" else n <= arg
    if op == "contains":
        if isinstance(value, list):
            return any(value_ok(v, {"equals": arg}) for v in value)
        return isinstance(value, str) and str(arg).lower() in value.lower()
    if op == "not_contains":
        return not value_ok(value, {"contains": arg})
    if op == "exists":
        return (value is not None) == bool(arg)
    if op == "not_empty":
        return bool(value) == bool(arg)
    raise InputError(f"unknown operator {op}")


def describe(cond: dict) -> str:
    op, arg = next(iter(cond.items()))
    return f"{op} {json.dumps(arg, sort_keys=True)}"


def eval_file(pack: Pack, rel: str, alt: dict, check_id: str) -> dict:
    """Evaluate one alternative against one pack file. Returns {state, citations, gaps}."""
    field = alt["field"]
    cites, gaps = [], []
    if not pack.verified(rel):
        return {"state": NOT_ASSESSABLE, "citations": [],
                "gaps": [f"{rel}: missing or its SHA-256 does not match manifest.json; run evidence_pack.py verify"]}
    stale = pack.age_gap(rel)
    if stale:
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [stale]}
    digest = pack.files[rel].get("sha256")
    stderr = pack.stderr_of(rel)
    if stderr is not None and stderr[1] == "":
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [f"{stderr[0]}: fails its hash check"]}
    data, err = pack.load(rel)
    err_file = rel
    if stderr is not None:
        err, err_file = {"status": "", "message": stderr[1]}, stderr[0]
        digest = pack.files[err_file].get("sha256")
    if err:
        msg = f"{err.get('status', '')} {err.get('message', '')}".strip()
        for frag in alt.get("absent_when", []):
            if frag.lower() in msg.lower() and not is_denied(err):
                c = {"file": err_file, "field": "error", "value": msg[:200], "sha256": digest, "check": check_id}
                return {"state": CONTRADICTED, "citations": [c], "gaps": []}
        why = "the export could not see this data (permissions, plan or licence)" if is_denied(err) else "the export is an error response"
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [f"{err_file}: {why}: {msg[:200]}"]}
    if data is None:
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [f"{rel}: empty export"]}
    resolved = resolve_path(data, field)
    where_clause = alt.get("where") or {}
    cond = alt["expect"]
    op = next(iter(cond))
    if not resolved and not (op in ("count_gte", "count_lte") and field.endswith("[]") and _list_exists(data, field)):
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [f"{rel}: field {field} not found in the export"]}
    if where_clause:
        kept = []
        for path, obj in resolved:
            if all(_sub_ok(obj, sub, c) for sub, c in where_clause.items()):
                kept.append((path, obj))
    else:
        kept = resolved
    if op in ("count_gte", "count_lte"):
        n = len(kept)
        ok = n >= cond[op] if op == "count_gte" else n <= cond[op]
        value = f"{n} of {len(resolved)} entries match" + (f" ({', '.join(p for p, _ in kept[:5])})" if kept else "")
    else:
        values = [v for _, v in kept]
        results = [value_ok(v, cond) for v in values]
        ok = (any(results) if alt.get("match") == "any" else all(results)) if results else False
        value = values[0] if len(values) == 1 else values
    expected = describe(cond)
    if where_clause:
        expected += " where " + ", ".join(f"{k} {describe(v)}" for k, v in where_clause.items())
    cites.append({"file": rel, "field": field, "value": value, "sha256": digest, "check": check_id, "expected": expected})
    if not ok and alt.get("on_fail") == NOT_ASSESSABLE:
        gaps.append(f"{rel}: {field} does not meet {describe(cond)}, but the map says this absence does not contradict the "
                    "control on its own; other evidence is needed")
        return {"state": NOT_ASSESSABLE, "citations": cites, "gaps": gaps}
    return {"state": SUPPORTED if ok else CONTRADICTED, "citations": cites, "gaps": gaps}


def _list_exists(data, field: str) -> bool:
    base = field[:-2]
    if base == "":
        return isinstance(data, list)
    return any(isinstance(v, list) for _, v in resolve_path(data, base))


def _sub_ok(obj, sub: str, cond: dict) -> bool:
    found = resolve_path(obj, sub)
    if not found:
        return value_ok(None, cond) if next(iter(cond)) in ("exists", "not_equals", "not_contains") else False
    return all(value_ok(v, cond) for _, v in found)


def eval_alternative(pack: Pack, alt: dict, check_id: str) -> dict:
    files = pack.match(alt["evidence"])
    if not files:
        return {"state": NOT_ASSESSABLE, "citations": [], "gaps": [f"{alt['evidence']}: not in the pack"]}
    parts = [eval_file(pack, rel, alt, check_id) for rel in files]
    return {"state": worst_state(p["state"] for p in parts),
            "citations": [c for p in parts for c in p["citations"]], "gaps": [g for p in parts for g in p["gaps"]]}


def eval_check(pack: Pack, chk: dict) -> dict:
    if "any_of" in chk:
        parts = [eval_alternative(pack, alt, chk["id"]) for alt in chk["any_of"]]
        supported = [p for p in parts if p["state"] == SUPPORTED]
        if supported:
            state, cites, gaps = SUPPORTED, supported[0]["citations"], []
        elif all(p["state"] == CONTRADICTED for p in parts):
            state, cites, gaps = CONTRADICTED, [c for p in parts for c in p["citations"]], []
        else:
            state = NOT_ASSESSABLE
            cites = [c for p in parts for c in p["citations"]]
            gaps = [g for p in parts for g in p["gaps"]] or ["no alternative was supported and not all were contradicted"]
    else:
        r = eval_alternative(pack, chk, chk["id"])
        state, cites, gaps = r["state"], r["citations"], r["gaps"]
    return {"id": chk["id"], "describes": chk.get("describes", ""), "state": state, "citations": cites, "gaps": gaps}


def build(pack: Pack, mapping: dict, framework: str) -> dict:
    topics = mapping["controls"].get(framework) or {}
    checks = [c for c in mapping["checks"] if c.get(framework)]
    results = {c["id"]: eval_check(pack, c) for c in checks}
    controls = []
    for cid, topic in topics.items():
        mine = [results[c["id"]] for c in checks if cid in c.get(framework, [])]
        if not mine:
            controls.append({"id": cid, "topic": topic, "state": NOT_ASSESSABLE, "checks": [], "citations": [],
                             "gaps": ["no check in the map reads an export for this control; "
                                      "it needs other evidence (documents, interviews, samples)"]})
            continue
        state = worst_state(r["state"] for r in mine)
        controls.append({"id": cid, "topic": topic, "state": state, "checks": mine,
                         "citations": [c for r in mine for c in r["citations"]],
                         "gaps": [f"{r['id']}: {g}" for r in mine for g in r["gaps"]]})
    unread = sorted(set(pack.files) - pack.read)
    return {
        "framework": framework,
        "as_of": pack.as_of.strftime("%Y-%m-%d"),
        "pack": str(pack.folder),
        "pack_built_at": pack.manifest.get("built_at"),
        "rule": ("A control is supported only when every mapped check is supported; any contradicted check makes it "
                 "contradicted; otherwise not assessable."),
        "summary": state_counts(controls),
        "controls": controls,
        "unmapped_files": unread,
        "disclaimer": DISCLAIMER,
    }


def render(report: dict) -> str:
    label = {"iso27001": "ISO/IEC 27001:2022 Annex A", "soc2": "SOC 2 Trust Services Criteria"}[report["framework"]]
    s = report["summary"]
    lines = [f"# Control map: {label} identifiers", "", f"> {DISCLAIMER}", "",
             f"Pack: {cell(report['pack'])} (built {report['pack_built_at']}). Evaluated as of {report['as_of']}.",
             f"Controls: {s[SUPPORTED]} supported, {s[CONTRADICTED]} contradicted, {s[NOT_ASSESSABLE]} not assessable.",
             f"Rule: {report['rule']}", "",
             "| Control | Topic (paraphrase) | State | Evidence (file#field = value) | Gaps |", "|---|---|---|---|---|"]
    for c in report["controls"]:
        ev = "<br>".join(cell(cite_text(x)) for x in c["citations"]) or "none"
        gaps = "<br>".join(cell(g) for g in c["gaps"])
        lines.append(f"| {c['id']} | {cell(c['topic'])} | {c['state']} | {ev} | {gaps} |")
    lines += ["", "## Pack files no check read", ""]
    lines += [f"- {cell(f)}" for f in report["unmapped_files"]] or ["- None."]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="control_map.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pack", help="evidence pack folder (with manifest.json)")
    ap.add_argument("--framework", choices=FRAMEWORKS, required=True)
    ap.add_argument("--map", required=True, help="mapping file (YAML or JSON)")
    ap.add_argument("--out", help="also write the JSON report to this file")
    ap.add_argument("--max-age-days", type=int, help="treat evidence collected more than N days before --as-of as not assessable")
    add_common_args(ap)
    args = ap.parse_args(argv)
    try:
        as_of = as_of_datetime(args.as_of) if args.as_of else datetime.now(UTC)
        mapping = load_map(args.map)
        report = build(Pack(args.pack, as_of, args.max_age_days), mapping, args.framework)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.redact:
        report = redact(report)
        report["redacted"] = True
    if args.out:
        Path(args.out).write_text(dumps(report) + "\n", encoding="utf-8")
    print(dumps(report) if args.json else render(report))
    return fail_exit(report["controls"], args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
