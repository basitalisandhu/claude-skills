#!/usr/bin/env python3
"""Map the test results of a Maester run (Microsoft 365 and Entra ID security tests) to ISO 27001:2022 Annex A and
SOC 2 control identifiers through a mapping you own, and report per control supported, contradicted or not assessable,
with the tests behind each state. Also writes the test list with control columns added (--annotated-csv).

Inputs:
  results         the JSON file written by Invoke-Maester -OutputJsonFile: an object with Result, ExecutedAt,
                  TenantId, TenantName, the counts and a Tests list. Each test has Index, Id (for example MT.1001,
                  CIS.M365.1.1.1, EIDSCA.AF01, MS.AAD.3.1), Title, Name ("Id: Title"), HelpUrl, Severity, Tag,
                  Result (Passed, Failed, Skipped, NotRun, Error or Investigate), Block and ResultDetail. A test
                  without Id takes the part of Name before the first colon.
  --map           CSV with columns match, framework, control and note. match is an exact test id, an id prefix
                  ending in "*" (CIS.M365.1.1.*), or tag:<Tag> (tag:MFA). framework is iso27001 or soc2; control
                  must be an identifier in references/iso27001-identifiers.md or references/soc2-identifiers.md
                  (add more with --identifiers). references/example-map.csv is an example to review, not an
                  authoritative mapping.
  --identifiers   extra identifier list(s) in the same Markdown table format, for identifiers your own licensed
                  copy of the standard supports and the bundled lists do not carry

Result states (per control, from the tests mapped to it):
  supported       at least one mapped test Passed and none Failed or needs human review
  contradicted    at least one mapped test Failed
  not assessable  only Skipped, NotRun or Error results, or a mapped test returned Investigate (needs human review)
                  and none Failed, or no mapped test is in the results file
Skipped, NotRun, Error and Investigate never count as support: a skipped Conditional Access test says nothing about
the policy, and Investigate means Maester could not decide.

The results file's SHA-256 and ExecutedAt are reported. The run is stale when ExecutedAt is more than --max-age-days
(default 30) before --as-of (default today), or when ExecutedAt is missing or unreadable.

Every output is preparation for a human assessor, not an audit opinion or attestation. A mapping is a judgement to
agree with the assessor; the script only applies it.

Output: Markdown (default) or --json, to stdout or --out. --annotated-csv writes one row per test with iso27001 and
soc2 columns. --redact tokenises TenantName, TenantId and e-mail addresses; secret-shaped strings are always masked.

Exit codes: 0 nothing contradicted and the run is not stale, 1 a control is contradicted or the run is stale,
2 bad input or usage. Standard library only. Reads files only; no network.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc  # noqa: UP017 (keeps Python 3.10 working)
SUPPORTED, CONTRADICTED, NOT_ASSESSABLE = "supported", "contradicted", "not assessable"
RESULTS = ("Passed", "Failed", "Skipped", "NotRun", "Error", "Investigate")
FRAMEWORKS = ("iso27001", "soc2")
DISCLAIMER = (
    "Preparation for a human assessor: this is not an audit opinion or an attestation. "
    "The mapping is a judgement to agree with the assessor; Maester results are a point in time."
)
REFS = Path(__file__).resolve().parent.parent / "references"
ID_FILES = {"iso27001": REFS / "iso27001-identifiers.md", "soc2": REFS / "soc2-identifiers.md"}
ID_ROW_RE = re.compile(r"^\| ((?:A|CC|PI|C|P)\d*(?:\.\d+)+) \| ([^|]+) \|", re.M)
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def parse_dt(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    m = re.fullmatch(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/", s)  # Windows PowerShell 5.1 ConvertTo-Json
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
    s = s[:-1] + "+00:00" if s.endswith("Z") else s
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # .NET writes seven fractional digits
    try:
        dt = datetime.fromisoformat(s if "T" in s else s + "T00:00:00+00:00")
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def load_identifiers(extra: list[str]) -> dict[str, dict[str, str]]:
    ids: dict[str, dict[str, str]] = {fw: {} for fw in FRAMEWORKS}
    for fw, path in ID_FILES.items():
        for m in ID_ROW_RE.finditer(path.read_text(encoding="utf-8")):
            ids[fw][m.group(1)] = m.group(2).strip()
    for e in extra:
        p = Path(e)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"--identifiers {p}: cannot read: {exc}") from exc
        found = ID_ROW_RE.findall(text)
        if not found:
            raise InputError(f"--identifiers {p.name}: no '| identifier | topic |' table rows found")
        for cid, topic in found:
            if len(topic.split()) > 20:
                raise InputError(f"--identifiers {p.name}: topic for {cid} is over 20 words; write a short paraphrase, never the standard's text")
            ids["iso27001" if re.fullmatch(r"A\.\d+\.\d+", cid) else "soc2"][cid] = topic.strip()
    return ids


def load_results(path: Path) -> tuple[dict, list[dict], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    if not raw.strip():
        raise InputError(f"{path.name}: empty file")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("Tests"), list):
        raise InputError(f"{path.name}: expected a Maester results object with a Tests list (Invoke-Maester -OutputJsonFile)")
    tests = []
    for i, t in enumerate(doc["Tests"]):
        if not isinstance(t, dict):
            raise InputError(f"{path.name}: Tests[{i}] is not an object")
        tid = t.get("Id")
        if not isinstance(tid, str) or not tid.strip():
            name = t.get("Name")
            if not isinstance(name, str) or not name.strip():
                raise InputError(f"{path.name}: Tests[{i}] has neither Id nor Name")
            tid = name.split(":", 1)[0]
        result = t.get("Result")
        if result == "Inconclusive":  # older runs; Maester itself reports Pester's Inconclusive as Skipped
            result = "Skipped"
        if result not in RESULTS:
            raise InputError(f"{path.name}: Tests[{i}] ({tid.strip()}): Result must be one of {', '.join(RESULTS)}, not {result!r}")
        tags = t.get("Tag") or []
        if isinstance(tags, str):
            tags = [tags]
        if not isinstance(tags, list) or not all(isinstance(x, str) for x in tags):
            raise InputError(f"{path.name}: Tests[{i}] ({tid.strip()}): Tag must be a list of strings")
        title = t.get("Title")
        if not isinstance(title, str) or not title:
            name = t.get("Name") if isinstance(t.get("Name"), str) else ""
            title = name.split(":", 1)[1].strip() if ":" in name else name
        detail = t.get("ResultDetail") if isinstance(t.get("ResultDetail"), dict) else {}
        tests.append(
            {
                "position": i,
                "index": t.get("Index", i + 1),
                "id": tid.strip(),
                "title": title,
                "result": result,
                "severity": t.get("Severity") or detail.get("Severity") or "",
                "tags": tags,
                "block": t.get("Block") or "",
                "help_url": t.get("HelpUrl") or "",
                "skipped_reason": detail.get("SkippedReason") or "",
            }
        )
    return doc, tests, hashlib.sha256(raw).hexdigest()


def load_map(path: Path | None, ids: dict[str, dict[str, str]]) -> list[dict]:
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    if not text.strip():
        raise InputError(f"{path.name}: empty mapping file")
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = [{str(k).strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in reader]
    except csv.Error as exc:
        raise InputError(f"{path.name}: cannot read CSV: {exc}") from exc
    if not {"match", "framework", "control"} <= {f.strip().lower() for f in reader.fieldnames or []}:
        raise InputError(f"{path.name}: needs the columns match, framework, control (and optionally note)")
    for n, r in enumerate(rows, 2):
        if not r.get("match") or not r.get("framework") or not r.get("control"):
            raise InputError(f"{path.name}: line {n}: match, framework and control are required")
        r["framework"] = r["framework"].lower()
        if r["framework"] not in FRAMEWORKS:
            raise InputError(f"{path.name}: line {n}: framework must be iso27001 or soc2, not {r['framework']!r}")
        if r["control"] not in ids[r["framework"]]:
            raise InputError(
                f"{path.name}: line {n}: {r['control']!r} is not in the {r['framework']} identifier list; "
                "check the identifier or pass a list that carries it with --identifiers"
            )
        if r["match"].lower().startswith("tag:") and not r["match"][4:].strip():
            raise InputError(f"{path.name}: line {n}: tag: needs a tag name")
        r["line"] = n
    return rows


def matches(rule: str, test: dict) -> bool:
    if rule.lower().startswith("tag:"):
        want = rule[4:].strip().lower()
        return any(t.lower() == want for t in test["tags"])
    if rule.endswith("*"):
        return test["id"].startswith(rule[:-1])
    return test["id"] == rule


def control_state(counts: dict[str, int]) -> str:
    if counts["Failed"]:
        return CONTRADICTED
    if counts["Investigate"]:
        return NOT_ASSESSABLE
    if counts["Passed"]:
        return SUPPORTED
    return NOT_ASSESSABLE


def evaluate(args) -> dict:
    ids = load_identifiers(args.identifiers or [])
    results_path = Path(args.results)
    doc, tests, digest = load_results(results_path)
    rows = load_map(Path(args.map) if args.map else None, ids)
    as_of = parse_dt(args.as_of) if args.as_of else datetime.now(UTC)
    if as_of is None:
        raise InputError(f"--as-of: cannot parse {args.as_of!r}; use YYYY-MM-DD")
    if args.max_age_days < 0:
        raise InputError("--max-age-days must be 0 or more")
    executed = parse_dt(doc.get("ExecutedAt") if isinstance(doc.get("ExecutedAt"), str) else None)
    if executed is None:
        freshness = {"stale": True, "reason": "ExecutedAt is missing or unreadable, so the age of the run cannot be shown"}
    else:
        age = (as_of - executed).days
        stale = age > args.max_age_days
        freshness = {
            "stale": stale,
            "age_days": age,
            "reason": f"run is {age} days old on {as_of.strftime('%Y-%m-%d')}, over the {args.max_age_days}-day limit"
            if stale
            else f"run is {age} days old on {as_of.strftime('%Y-%m-%d')}",
        }
    rule_hits: dict[int, int] = {}
    per_test: dict[int, dict[str, set]] = {t["position"]: {fw: set() for fw in FRAMEWORKS} for t in tests}
    controls: dict[tuple[str, str], dict] = {}
    for r in rows:
        key = (r["framework"], r["control"])
        topic = ids[r["framework"]][r["control"]]
        c = controls.setdefault(key, {"framework": r["framework"], "control": r["control"], "topic": topic, "rules": [], "tests": {}})
        c["rules"].append({"match": r["match"], "note": r.get("note", ""), "line": r["line"]})
        for t in tests:
            if matches(r["match"], t):
                rule_hits[r["line"]] = rule_hits.get(r["line"], 0) + 1
                c["tests"][t["position"]] = t
                per_test[t["position"]][r["framework"]].add(r["control"])
    out_controls = []
    for (fw, cid), c in sorted(controls.items(), key=lambda kv: (FRAMEWORKS.index(kv[0][0]), kv[0][1])):
        mapped = sorted(c["tests"].values(), key=lambda t: t["position"])
        counts = {res: sum(1 for t in mapped if t["result"] == res) for res in RESULTS}
        state = control_state(counts)
        out_controls.append(
            {
                "framework": fw,
                "control": cid,
                "topic": c["topic"],
                "state": state,
                "counts": counts,
                "rules": c["rules"],
                "tests": [
                    {
                        "id": t["id"],
                        "title": t["title"],
                        "result": t["result"],
                        "citation": f"[evidence: {results_path.name}#Tests[{t['position']}].Result]",
                    }
                    for t in mapped
                ],
                "needs_human_review": [t["id"] for t in mapped if t["result"] == "Investigate"],
                "gap": "" if mapped else "no test in the results file matched this control's map rows",
            }
        )
    annotated = [
        dict(t, iso27001=sorted(per_test[t["position"]]["iso27001"]), soc2=sorted(per_test[t["position"]]["soc2"])) for t in tests
    ]
    declared = {k: doc.get(f"{k}Count") for k in RESULTS}
    actual = {k: sum(1 for t in tests if t["result"] == k) for k in RESULTS}
    warnings = [
        f"{k}Count in the file is {declared[k]} but the Tests list has {actual[k]}"
        for k in RESULTS
        if isinstance(declared[k], int) and declared[k] != actual[k]
    ]
    if isinstance(doc.get("TotalCount"), int) and doc["TotalCount"] != len(tests):
        warnings.append(f"TotalCount in the file is {doc['TotalCount']} but the Tests list has {len(tests)}")
    return {
        "tool": "maester_map",
        "results_file": results_path.name,
        "results_sha256": digest,
        "executed_at": doc.get("ExecutedAt") if isinstance(doc.get("ExecutedAt"), str) else None,
        "tenant_name": str(doc.get("TenantName") or ""),
        "tenant_id": str(doc.get("TenantId") or ""),
        "as_of": as_of.strftime("%Y-%m-%d"),
        "max_age_days": args.max_age_days,
        "freshness": freshness,
        "map_file": Path(args.map).name if args.map else None,
        "summary": {
            "tests": len(tests),
            "results": actual,
            "mapped_tests": sum(1 for t in annotated if t["iso27001"] or t["soc2"]),
            "controls": {s: sum(1 for c in out_controls if c["state"] == s) for s in (SUPPORTED, CONTRADICTED, NOT_ASSESSABLE)},
        },
        "controls": out_controls,
        "unmapped_tests": [{"id": t["id"], "result": t["result"]} for t in annotated if not t["iso27001"] and not t["soc2"]],
        "unmatched_map_rows": [
            {"line": r["line"], "match": r["match"], "framework": r["framework"], "control": r["control"]} for r in rows if r["line"] not in rule_hits
        ],
        "warnings": warnings,
        "annotated_tests": annotated,
        "disclaimer": DISCLAIMER,
    }


def scrub(text: str, rep: dict, redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        for value, prefix in ((rep["tenant_id"], "tenant-id-"), (rep["tenant_name"], "tenant-")):
            if value:
                text = text.replace(value, prefix + hashlib.sha256(value.lower().encode()).hexdigest()[:8])
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8] + "@redacted.invalid", text)
    return text


def cell(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(rep: dict) -> str:
    s = rep["summary"]
    fr = rep["freshness"]
    res = ", ".join(f"{v} {k}" for k, v in s["results"].items() if v)
    lines = [
        f"## Maester control map: {cell(rep['results_file'])}",
        "",
        f"Tenant {cell(rep['tenant_name'] or 'unknown')} ({cell(rep['tenant_id'] or 'no TenantId')}). "
        f"ExecutedAt {cell(rep['executed_at'] or 'missing')}. SHA-256 `{rep['results_sha256']}`.",
        f"{s['tests']} tests ({res}); {s['mapped_tests']} mapped by {cell(rep['map_file'] or 'no map')}.",
        "",
        f"**Stale:** {fr['reason']}. Re-run Maester before using these results as evidence." if fr["stale"] else f"Freshness: {fr['reason']}.",
        "",
        "| Framework | Control | Topic (paraphrase) | State | Passed | Failed | Investigate | Skipped | NotRun | Error |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for c in rep["controls"]:
        n = c["counts"]
        lines.append(
            f"| {c['framework']} | {c['control']} | {cell(c['topic'])} | {c['state']} | {n['Passed']} | {n['Failed']} | "
            f"{n['Investigate']} | {n['Skipped']} | {n['NotRun']} | {n['Error']} |"
        )
    if not rep["controls"]:
        lines.append("| | | no map rows | | | | | | | |")
    lines += [
        "",
        f"States: `{SUPPORTED}`, `{CONTRADICTED}`, `{NOT_ASSESSABLE}`. Skipped, NotRun, Error and Investigate never count as support.",
    ]
    for c in rep["controls"]:
        lines += ["", f"### {c['framework']} {c['control']} ({c['state']})", ""]
        for r in c["rules"]:
            lines.append(f"- Map line {r['line']}: `{cell(r['match'])}`" + (f", {cell(r['note'])}" if r["note"] else ""))
        for t in c["tests"]:
            flag = " (needs human review)" if t["result"] == "Investigate" else ""
            lines.append(f"- {cell(t['id'])} {t['result']}{flag}: {cell(t['title'])} {t['citation']}")
        if c["gap"]:
            lines.append(f"- {c['gap']}")
    if rep["unmatched_map_rows"]:
        lines += ["", "### Map rows that matched no test", ""]
        lines += [f"- Line {r['line']}: `{cell(r['match'])}` to {r['framework']} {r['control']}" for r in rep["unmatched_map_rows"]]
    lines += ["", f"### Unmapped tests ({len(rep['unmapped_tests'])})", ""]
    lines.append(", ".join(f"{cell(t['id'])} ({t['result']})" for t in rep["unmapped_tests"]) or "none")
    if rep["warnings"]:
        lines += ["", "### Warnings", ""] + [f"- {cell(w)}" for w in rep["warnings"]]
    lines += ["", rep["disclaimer"]]
    return "\n".join(lines)


def to_csv(rep: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Index", "Id", "Title", "Result", "Severity", "Block", "Tag", "iso27001", "soc2", "HelpUrl"])
    for t in rep["annotated_tests"]:
        tags, iso, soc2 = "; ".join(t["tags"]), "; ".join(t["iso27001"]), "; ".join(t["soc2"])
        w.writerow([t["index"], t["id"], t["title"], t["result"], t["severity"], t["block"], tags, iso, soc2, t["help_url"]])
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="Maester results JSON (Invoke-Maester -OutputJsonFile)")
    ap.add_argument("--map", help="mapping CSV: match, framework, control, note")
    ap.add_argument("--identifiers", action="append", help="extra identifier list in the references table format (repeatable)")
    ap.add_argument("--as-of", help="evaluate freshness as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--max-age-days", type=int, default=30, help="a run older than this many days before --as-of is stale (default 30)")
    ap.add_argument("--annotated-csv", help="write the test list with iso27001 and soc2 columns to this CSV")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="tokenise TenantName, TenantId and e-mail addresses")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    try:
        rep = evaluate(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = scrub(json.dumps(rep, indent=2, ensure_ascii=False) if args.json else render(rep), rep, args.redact)
    try:
        if args.annotated_csv:
            Path(args.annotated_csv).write_text(scrub(to_csv(rep), rep, args.redact), encoding="utf-8", newline="")
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return 1 if rep["freshness"]["stale"] or any(c["state"] == CONTRADICTED for c in rep["controls"]) else 0


if __name__ == "__main__":
    sys.exit(main())
