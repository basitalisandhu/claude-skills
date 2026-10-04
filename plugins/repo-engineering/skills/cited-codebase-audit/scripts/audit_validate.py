#!/usr/bin/env python3
"""Accept an audit finding only when every citation it makes resolves in the repository.

A citation resolves when:
  CIT-PATH     the path is relative and stays inside the repository
  CIT-FILE     the file exists
  CIT-LINE     the line (or start-end range) is within the file
  CIT-SNIPPET  the quoted snippet appears on the cited line(s) after whitespace normalisation
A finding with no citation at all is rejected (CIT-NONE).

Report-level checks (warnings, never rejections): a category outside the fixed checklist, a severity outside
critical/high/medium/low/info, and a report without "considered_and_rejected" or "not_examined" sections.

Input: JSON with "findings": [{"id", "category", "severity", "title", "citations": [{"path", "line", "snippet"}]}].
A finding may instead carry "location": "path:line" (or "path:start-end") and "snippet".

Exit codes: 0 every finding accepted (or the acceptance rate meets --min-accept), 1 otherwise, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

CHECKLIST = ("structure", "entry-points", "dependency-hygiene", "dead-code", "test-coverage", "secrets-config",
             "ci-health")
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_FILE_BYTES = 5_000_000


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def parse_location(loc: str) -> tuple[str, str]:
    m = re.match(r"^(.*?):(\d+(?:-\d+)?)$", loc.strip())
    if not m:
        return loc.strip(), ""
    return m.group(1), m.group(2)


def citations_of(finding: dict) -> list[dict]:
    cites = finding.get("citations")
    out: list[dict] = []
    if isinstance(cites, list):
        for c in cites:
            if isinstance(c, str):
                path, line = parse_location(c)
                out.append({"path": path, "line": line, "snippet": ""})
            elif isinstance(c, dict):
                if "location" in c and "path" not in c:
                    path, line = parse_location(str(c["location"]))
                    out.append({"path": path, "line": line, "snippet": c.get("snippet", "")})
                else:
                    out.append(c)
    elif isinstance(finding.get("location"), str):
        path, line = parse_location(finding["location"])
        out.append({"path": path, "line": line, "snippet": finding.get("snippet", "")})
    return out


class Resolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel: str) -> list[str] | None:
        if rel not in self._cache:
            p = self.root / rel
            try:
                if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                    self._cache[rel] = None
                else:
                    self._cache[rel] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._cache[rel] = None
        return self._cache[rel]

    def check(self, cite: dict) -> tuple[str | None, str]:
        """Return (error code or None, detail)."""
        path = str(cite.get("path") or "").strip()
        if not path:
            return "CIT-PATH", "citation has no path"
        if os.path.isabs(path) or path.startswith("~"):
            return "CIT-PATH", f"{path}: absolute paths are not accepted; cite relative to the repository root"
        rel = Path(os.path.normpath(path)).as_posix()
        if rel == ".." or rel.startswith("../"):
            return "CIT-PATH", f"{path}: points outside the repository"
        resolved = (self.root / rel).resolve()
        if self.root not in resolved.parents and resolved != self.root:
            return "CIT-PATH", f"{path}: resolves outside the repository"
        lines = self.lines(rel)
        if lines is None:
            return "CIT-FILE", f"{path}: file not found (or not a readable text file)"
        raw_line = str(cite.get("line", "")).strip()
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", raw_line)
        if not m:
            return "CIT-LINE", f"{path}: line {raw_line!r} is not a number or a start-end range"
        start = int(m.group(1))
        end = int(m.group(2) or start)
        if start < 1 or end < start or end > len(lines):
            return "CIT-LINE", f"{path}:{raw_line}: out of range (file has {len(lines)} lines)"
        snippet = norm(str(cite.get("snippet") or ""))
        if not snippet:
            return "CIT-SNIPPET", f"{path}:{raw_line}: no snippet quoted"
        extra = str(cite.get("snippet")).count("\n")
        window = norm(" ".join(lines[start - 1: max(end, start + extra)]))
        if snippet not in window:
            actual = norm(lines[start - 1])[:100]
            return "CIT-SNIPPET", f"{path}:{raw_line}: snippet not found there; line {start} reads {actual!r}"
        return None, f"{rel}:{raw_line}"


def validate(report: dict, root: Path) -> dict:
    resolver = Resolver(root)
    accepted, rejected, warnings = [], [], []
    for i, f in enumerate(report.get("findings", [])):
        if not isinstance(f, dict):
            rejected.append({"index": i, "finding": f, "errors": [{"code": "CIT-NONE", "detail": "not an object"}]})
            continue
        fid = f.get("id", f"#{i + 1}")
        cat = f.get("category")
        if cat not in CHECKLIST:
            warnings.append(f"{fid}: category {cat!r} is not one of {', '.join(CHECKLIST)}")
        sev = str(f.get("severity", "")).lower()
        if sev not in SEVERITIES:
            warnings.append(f"{fid}: severity {f.get('severity')!r} is not one of {', '.join(SEVERITIES)}")
        cites = citations_of(f)
        errors = []
        if not cites:
            errors.append({"code": "CIT-NONE", "detail": "no citation"})
        for c in cites:
            code, detail = resolver.check(c)
            if code:
                errors.append({"code": code, "detail": detail})
        if errors:
            rejected.append({"id": fid, "title": f.get("title", ""), "errors": errors, "finding": f})
        else:
            accepted.append(f)
    for section in ("considered_and_rejected", "not_examined"):
        if not isinstance(report.get(section), list):
            warnings.append(f"report has no {section!r} list; an honest audit states both")
    total = len(accepted) + len(rejected)
    rate = round(100.0 * len(accepted) / total, 1) if total else 0.0
    return {
        "stats": {"total": total, "accepted": len(accepted), "rejected": len(rejected), "acceptance_rate": rate},
        "accepted": accepted,
        "rejected": rejected,
        "warnings": warnings,
    }


def render(result: dict) -> str:
    s = result["stats"]
    out = []
    for r in result["rejected"]:
        out.append(f"REJECTED {r.get('id', r.get('index'))}: {r.get('title', '')}".rstrip())
        for e in r["errors"]:
            out.append(f"  {e['code']}  {e['detail']}")
    for f in result["accepted"]:
        out.append(f"accepted {f.get('id', '')}: {f.get('title', '')}".rstrip())
    for w in result["warnings"]:
        out.append(f"warning: {w}")
    out.append("")
    out.append(f"{s['accepted']} of {s['total']} findings accepted ({s['acceptance_rate']}%), {s['rejected']} rejected")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="audit_validate.py",
                                 description="Reject audit findings whose path:line citations do not resolve.")
    ap.add_argument("report", help="audit report JSON")
    ap.add_argument("repo", help="repository root the citations refer to")
    ap.add_argument("--json", action="store_true", help="print the validation result as JSON")
    ap.add_argument("--out", metavar="FILE",
                    help="write the report with only accepted findings, plus rejected_findings and validation stats")
    ap.add_argument("--min-accept", type=float, metavar="PCT",
                    help="exit 0 when at least PCT percent are accepted (default: every finding must be accepted)")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return 2
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        print("error: report must be a JSON object with a 'findings' list", file=sys.stderr)
        return 2
    result = validate(report, root)
    if args.out:
        cleaned = dict(report)
        cleaned["findings"] = result["accepted"]
        cleaned["rejected_findings"] = result["rejected"]
        cleaned["validation"] = {"stats": result["stats"], "warnings": result["warnings"]}
        Path(args.out).write_text(json.dumps(cleaned, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2) if args.json else render(result))
    s = result["stats"]
    if args.min_accept is not None:
        return 0 if s["acceptance_rate"] >= args.min_accept else 1
    return 1 if s["rejected"] else 0


if __name__ == "__main__":
    sys.exit(main())
