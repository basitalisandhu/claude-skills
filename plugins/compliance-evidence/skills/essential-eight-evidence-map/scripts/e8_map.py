#!/usr/bin/env python3
"""Map an evidence pack to the ASD Essential Eight Maturity Model (November 2023) and report, per mitigation
strategy, which requirements have evidence, which do not, and the maturity level each strategy can claim today.

Inputs:
  pack            an evidence pack folder with manifest.json (from evidence-pack-builder). Each cited file must be in
                  the manifest, present in the pack and match its SHA-256.
  --map           your mapping of requirements to evidence, as CSV with columns requirement, evidence, state
                  (optional: supported or contradicted; default supported) and note, or as JSON: either
                  {"PA-ML1-01": ["path", ...]} or a list of {"requirement", "evidence", "state", "note"} objects.
                  The requirement may be an id or a glob such as "RB-ML1-*".
  --catalogue     the requirement list (default: references/e8-requirements-2023-11.json in this skill: 153
                  requirements across the eight strategies, ML1 to ML3, with the model's own wording under CC BY 4.0
                  and ids added by this repository, for example PA-ML1-01 is the first requirement that Patch
                  applications introduces at Maturity Level One)

Result states (one per requirement):
  supported       at least one mapped evidence file is valid and no mapping row marks it contradicted
  contradicted    a mapping row with valid evidence marks the requirement contradicted (the evidence shows it is not met)
  not assessable  no mapped evidence, or every mapped file is missing from the manifest, missing from the pack,
                  fails its hash check, or is older than --max-age-days

Claimable maturity level per strategy: the highest level L (0 to 3) such that every requirement of every level up
to L is supported. Requirements that a higher level replaces (for example a patch window that tightens) still count
for the levels that list them. Unmapped manifest files are listed as candidates per strategy by keyword, to help
write the mapping; a candidate is never counted as evidence.

Every output is preparation for a human assessor; an Essential Eight assessment follows ASD's assessment process
and is not replaced by this matrix.

Output: Markdown (default) or --json, to stdout or --out; --csv writes one row per requirement. --redact replaces
e-mail addresses with stable tokens; secret-shaped strings are always masked.

Exit codes: 0 every strategy claims at least --target (default 1), 1 a strategy is below --target (a person needs to
act), 2 bad input. Standard library only. Reads files only; no network.
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
from fnmatch import fnmatchcase
from pathlib import Path

UTC = timezone.utc  # noqa: UP017 (keeps Python 3.10 working)
SUPPORTED, CONTRADICTED, NOT_ASSESSABLE = "supported", "contradicted", "not assessable"
DISCLAIMER = "Preparation for a human assessor: this is not an Essential Eight assessment, an audit opinion or an attestation."
DEFAULT_CATALOGUE = Path(__file__).resolve().parent.parent / "references" / "e8-requirements-2023-11.json"
KEYWORDS = {
    "PA": r"patch|update|vulnerab|scan|inspector|dependabot|defender-vuln|asset|inventory|browser|office",
    "PO": r"patch|update|ring|windows-update|wufb|ssm|inspector|vulnerab|os-version|firmware|driver",
    "MFA": r"mfa|multi-factor|conditional-access|authentication-method|phishing|fido|passkey|signin",
    "RA": r"admin|privileg|pim|role|jump|laps|credential-guard|break-?glass",
    "AC": r"app(lication)?-?control|wdac|applocker|allowlist|blocklist|driver",
    "OM": r"macro|office|trusted-location|trusted-publisher",
    "UH": r"browser|edge|chrome|asr|attack-surface|powershell|office|pdf|java|hardening",
    "RB": r"backup|restore|snapshot|recovery|retention|vault",
}
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc}") from exc


def parse_dt(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    s = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(s if "T" in s else s + "T00:00:00+00:00")
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def load_catalogue(path: Path) -> dict:
    doc = read_json(path)
    reqs = doc.get("requirements") if isinstance(doc, dict) else None
    if not isinstance(reqs, list) or not reqs or not isinstance(doc.get("strategies"), list):
        raise InputError(f"{path.name}: expected a catalogue with strategies and requirements")
    for r in reqs:
        if not {"id", "strategy", "levels", "text"} <= set(r):
            raise InputError(f"{path.name}: every requirement needs id, strategy, levels and text")
    return doc


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_pack(folder: Path) -> tuple[dict[str, dict], dict]:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    manifest = folder / "manifest.json"
    if not manifest.is_file():
        raise InputError(f"{folder}: no manifest.json; build the pack with evidence-pack-builder first")
    doc = read_json(manifest)
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
        raise InputError("manifest.json: expected an evidence pack manifest with a files list")
    root = Path(doc["source_root"]) if doc.get("mode") == "reference" and doc.get("source_root") else folder / "evidence"
    files = {}
    for f in doc["files"]:
        if not isinstance(f, dict) or not f.get("path"):
            raise InputError("manifest.json: every file entry needs a path")
        files[f["path"]] = dict(f, _abs=root / f["path"])
    return files, doc


def load_map(path: Path | None) -> list[dict]:
    if path is None:
        return []
    if path.suffix.lower() == ".csv":
        try:
            with path.open(encoding="utf-8-sig", newline="") as fh:
                rows = [{str(k).strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in csv.DictReader(fh)]
        except (OSError, csv.Error) as exc:
            raise InputError(f"{path}: cannot read CSV: {exc}") from exc
    else:
        doc = read_json(path)
        if isinstance(doc, dict):
            rows = [{"requirement": k, "evidence": e} for k, v in doc.items() for e in ([v] if isinstance(v, str) else v or [])]
        elif isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
            rows = doc
        else:
            raise InputError(f"{path.name}: expected an object of requirement to evidence list, or a list of rows")
    for r in rows:
        if not r.get("requirement") or not r.get("evidence"):
            raise InputError(f"{path.name}: every mapping row needs requirement and evidence")
        state = str(r.get("state") or SUPPORTED).strip().lower()
        if state not in (SUPPORTED, CONTRADICTED):
            raise InputError(f"{path.name}: state must be supported or contradicted, not {state!r}")
        r["state"] = state
    return rows


def validate(path: str, files: dict[str, dict], now: datetime, max_age: int | None, cache: dict) -> str | None:
    """None when the evidence file is usable, otherwise the reason it is not."""
    if path in cache:
        return cache[path]
    f = files.get(path)
    reason = None
    if f is None:
        reason = "not in the manifest"
    elif not f["_abs"].is_file():
        reason = "listed in the manifest but missing from the pack"
    elif f.get("sha256") and sha256(f["_abs"]) != f["sha256"]:
        reason = "SHA-256 does not match the manifest"
    elif max_age is not None:
        when = parse_dt(f.get("collected_at"))
        if when is None or (now - when).days > max_age:
            reason = f"collected more than {max_age} days before {now.strftime('%Y-%m-%d')}" if when else "no collection date"
    cache[path] = reason
    return reason


def evaluate(args) -> dict:
    cat = load_catalogue(Path(args.catalogue))
    files, manifest = load_pack(Path(args.pack))
    rows = load_map(Path(args.map) if args.map else None)
    now = parse_dt(args.as_of) if args.as_of else datetime.now(UTC)
    if now is None:
        raise InputError(f"--as-of: cannot parse {args.as_of!r}; use YYYY-MM-DD")
    ids = {r["id"] for r in cat["requirements"]}
    for r in rows:
        if not any(fnmatchcase(i, r["requirement"]) for i in ids):
            raise InputError(f"mapping names an unknown requirement {r['requirement']!r}")
    cache: dict[str, str | None] = {}
    results, gaps_by_file, mapped = [], {}, set()
    for req in cat["requirements"]:
        mine = [r for r in rows if fnmatchcase(req["id"], r["requirement"])]
        good, bad, contradicted = [], [], False
        for r in mine:
            mapped.add(r["evidence"])
            why = validate(r["evidence"], files, now, args.max_age_days, cache)
            if why:
                bad.append(f"{r['evidence']}: {why}")
                gaps_by_file[r["evidence"]] = why
                continue
            good.append(r["evidence"])
            contradicted |= r["state"] == CONTRADICTED
        state = CONTRADICTED if contradicted else SUPPORTED if good else NOT_ASSESSABLE
        results.append(
            {
                "id": req["id"],
                "strategy": req["strategy"],
                "levels": req["levels"],
                "state": state,
                "citations": [f"[evidence: {p}]" for p in sorted(set(good))],
                "notes": sorted({r.get("note", "") for r in mine if r.get("note")}),
                "gaps": bad if not good else [],
                "text": req["text"],
            }
        )
    strategies = []
    for s in cat["strategies"]:
        mine = [r for r in results if r["strategy"] == s["name"]]
        per_level = {}
        claim = 0
        for lvl in (1, 2, 3):
            need = [r for r in mine if lvl in r["levels"]]
            per_level[f"ML{lvl}"] = {
                "required": len(need),
                SUPPORTED: sum(r["state"] == SUPPORTED for r in need),
                CONTRADICTED: sum(r["state"] == CONTRADICTED for r in need),
                NOT_ASSESSABLE: sum(r["state"] == NOT_ASSESSABLE for r in need),
            }
            if claim == lvl - 1 and need and all(r["state"] == SUPPORTED for r in need):
                claim = lvl
        rx = re.compile(KEYWORDS.get(s["code"], r"(?!)"), re.I)
        candidates = sorted(
            p for p, f in files.items() if p not in mapped and rx.search(" ".join(str(f.get(k) or "") for k in ("path", "command", "description")))
        )
        strategies.append({"code": s["code"], "strategy": s["name"], "claimable_level": claim, "levels": per_level, "candidates": candidates})
    return {
        "tool": "e8_map",
        "model": f"{cat.get('title', 'Essential Eight Maturity Model')} ({cat.get('version', 'unknown version')})",
        "pack": Path(args.pack).name,
        "pack_built_at": manifest.get("built_at", ""),
        "as_of": now.strftime("%Y-%m-%d"),
        "target": args.target,
        "strategies": strategies,
        "requirements": results,
        "unusable_evidence": dict(sorted(gaps_by_file.items())),
        "disclaimer": DISCLAIMER,
    }


def scrub(text: str, redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8] + "@redacted.invalid", text)
    return text


def cell(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(rep: dict) -> str:
    lines = [
        f"## Essential Eight evidence map: {cell(rep['pack'])}",
        "",
        f"Model: {rep['model']}. Evaluated as of {rep['as_of']}; target Maturity Level {rep['target']}.",
        "",
        "| Strategy | ML1 supported | ML2 supported | ML3 supported | Claimable now |",
        "|---|---|---|---|---|",
    ]
    for s in rep["strategies"]:
        cells = []
        for lvl in ("ML1", "ML2", "ML3"):
            c = s["levels"][lvl]
            extra = f", {c[CONTRADICTED]} contradicted" if c[CONTRADICTED] else ""
            cells.append(f"{c[SUPPORTED]}/{c['required']}{extra}")
        lines.append(f"| {s['strategy']} | {' | '.join(cells)} | ML{s['claimable_level']} |")
    lines += [
        "",
        f"States: `{SUPPORTED}`, `{CONTRADICTED}`, `{NOT_ASSESSABLE}`. A level is claimed only when every requirement up to it is `{SUPPORTED}`.",
    ]
    for s in rep["strategies"]:
        lines += [
            "",
            f"### {s['strategy']} (claimable ML{s['claimable_level']})",
            "",
            "| Requirement | Levels | State | Evidence or gap | Requirement text |",
            "|---|---|---|---|---|",
        ]
        for r in (x for x in rep["requirements"] if x["strategy"] == s["strategy"]):
            ev = " ".join(r["citations"]) or "; ".join(r["gaps"]) or "no evidence mapped"
            text = r["text"] if len(r["text"]) <= 140 else r["text"][:137] + "..."
            lines.append(f"| {r['id']} | {','.join(f'ML{x}' for x in r['levels'])} | {r['state']} | {cell(ev)} | {cell(text)} |")
        if s["candidates"]:
            lines.append("")
            lines.append("Unmapped files that may be relevant (not counted): " + ", ".join(f"`{cell(c)}`" for c in s["candidates"]))
    if rep["unusable_evidence"]:
        lines += ["", "### Evidence that could not be used", ""] + [f"- {cell(p)}: {cell(w)}" for p, w in rep["unusable_evidence"].items()]
    lines += ["", rep["disclaimer"]]
    return "\n".join(lines)


def to_csv(rep: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["requirement", "strategy", "levels", "state", "evidence", "gaps", "text"])
    for r in rep["requirements"]:
        w.writerow(
            [r["id"], r["strategy"], " ".join(f"ML{x}" for x in r["levels"]), r["state"], " ".join(r["citations"]), "; ".join(r["gaps"]), r["text"]]
        )
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pack", help="evidence pack folder with manifest.json")
    ap.add_argument("--map", help="requirement to evidence mapping (CSV or JSON)")
    ap.add_argument("--catalogue", default=str(DEFAULT_CATALOGUE), help="requirement catalogue JSON (default: the bundled November 2023 list)")
    ap.add_argument("--target", type=int, choices=[1, 2, 3], default=1, help="maturity level every strategy should claim (default 1)")
    ap.add_argument("--max-age-days", type=int, help="treat evidence collected more than this many days before --as-of as not assessable")
    ap.add_argument("--as-of", help="evaluate evidence age as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses with stable tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    ap.add_argument("--csv", help="also write one row per requirement as CSV to this path")
    args = ap.parse_args(argv)
    if args.max_age_days is not None and args.max_age_days < 0:
        print("error: --max-age-days must be 0 or more", file=sys.stderr)
        return 2
    try:
        rep = evaluate(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = scrub(json.dumps(rep, indent=2, ensure_ascii=False) if args.json else render(rep), args.redact)
    try:
        if args.csv:
            Path(args.csv).write_text(scrub(to_csv(rep), args.redact), encoding="utf-8", newline="")
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return int(any(s["claimable_level"] < args.target for s in rep["strategies"]))


if __name__ == "__main__":
    sys.exit(main())
