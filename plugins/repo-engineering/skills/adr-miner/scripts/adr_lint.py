#!/usr/bin/env python3
"""Check an ADR folder (docs/adr by default) for numbering, status and supersession problems.

ADR files are named NNNN-title.md (three to five digits). README, index and template files are skipped.
Rules:
  ADR-GAP         a number missing between the lowest and highest ADR
  ADR-DUP         two files share a number
  ADR-NAME        a Markdown file that does not follow the NNNN-title.md pattern (warning)
  ADR-TITLE       no level-one heading
  ADR-STATUS      no status, or a status outside proposed, accepted, rejected, deprecated, superseded
                  (statuses are read from "Status: x", "* Status: x", a "## Status" section, or YAML
                  frontmatter "status: x")
  ADR-SUPERSEDED  status superseded without a link or reference to the ADR that replaces it
  ADR-LINK        a relative link to an ADR file that does not exist
  ADR-BACKLINK    ADR A says it is superseded by B, but B does not mention A (warning)
Errors make the exit code 1; warnings do not unless --strict. Exit 2 when the folder does not exist.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^(\d{3,5})-[\w.-]+\.md$")
SKIP_NAMES = {"readme.md", "index.md", "template.md", "adr-template.md", "0000-template.md", "_template.md"}
STATUSES = {"proposed", "accepted", "rejected", "deprecated", "superseded", "draft"}
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")
REF_RE = re.compile(r"\b(?:ADR[- ]?)?(\d{3,5})\b")


def status_of(text: str) -> tuple[str | None, int]:
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for i, ln in enumerate(lines[1:], 2):
            if ln.strip() == "---":
                break
            m = re.match(r"^status:\s*['\"]?([^'\"]+)", ln, re.IGNORECASE)
            if m:
                return m.group(1).strip(), i
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*(?:[-*]\s*)?\**status\**\s*:\s*\**\s*(.+?)\s*\**\s*$", ln, re.IGNORECASE)
        if m:
            return m.group(1).strip(), i
        if re.match(r"^#{2,3}\s*status\s*$", ln, re.IGNORECASE):
            for j, nxt in enumerate(lines[i:], i + 1):
                if nxt.strip():
                    if nxt.lstrip().startswith("#"):
                        break
                    return nxt.strip().strip("*_ "), j
    return None, 0


def lint(adr_dir: Path) -> dict:
    files = sorted(p for p in adr_dir.iterdir() if p.is_file() and p.suffix.lower() == ".md")
    findings: list[dict] = []
    adrs: dict[int, list[Path]] = {}
    texts: dict[Path, str] = {}

    def add(rule: str, level: str, path: Path, line: int, detail: str) -> None:
        findings.append({"rule": rule, "level": level, "file": path.name, "line": line, "detail": detail})

    for p in files:
        if p.name.lower() in SKIP_NAMES:
            continue
        m = NAME_RE.match(p.name)
        if not m:
            add("ADR-NAME", "warning", p, 0, "file name does not follow NNNN-title.md")
            continue
        adrs.setdefault(int(m.group(1)), []).append(p)
        texts[p] = p.read_text(encoding="utf-8", errors="replace")
    numbers = sorted(adrs)
    for n, paths in adrs.items():
        if len(paths) > 1:
            for p in paths[1:]:
                add("ADR-DUP", "error", p, 0, f"number {n} is also used by {paths[0].name}")
    if numbers:
        missing = sorted(set(range(numbers[0], numbers[-1] + 1)) - set(numbers))
        for n in missing:
            findings.append({"rule": "ADR-GAP", "level": "error", "file": "", "line": 0,
                             "detail": f"no ADR numbered {n:04d} between {numbers[0]:04d} and {numbers[-1]:04d}"})
    by_name = {p.name: p for p in texts}
    superseded_by: dict[Path, list[Path]] = {}
    statuses: dict[str, str | None] = {}
    for p, text in texts.items():
        if not re.search(r"^#\s+\S", text, re.MULTILINE):
            add("ADR-TITLE", "error", p, 1, "no level-one heading")
        status, line = status_of(text)
        statuses[p.name] = status
        word = status.split()[0].lower().strip(".,:;") if status else None
        if status is None:
            add("ADR-STATUS", "error", p, 0, "no status line or section")
        elif word not in STATUSES:
            add("ADR-STATUS", "error", p, line, f"unknown status {status!r}")
        targets: list[Path] = []
        for lm in LINK_RE.finditer(text):
            link = lm.group(1)
            if link.startswith(("http://", "https://", "mailto:")):
                continue
            ln = text[: lm.start()].count("\n") + 1
            target = (p.parent / link).resolve()
            if NAME_RE.match(Path(link).name) and not target.exists():
                add("ADR-LINK", "error", p, ln, f"link to {link} does not resolve")
            elif target.exists() and target.parent == adr_dir.resolve() and target.name in by_name:
                targets.append(by_name[target.name])
        if word == "superseded":
            sup_text = status + "\n" + "\n".join(ln for ln in text.splitlines() if re.search(r"supersed", ln, re.I))
            refs = {int(r) for r in REF_RE.findall(sup_text)}
            newer = [t for t in targets if t != p and re.search(re.escape(t.name), sup_text)]
            newer += [adrs[r][0] for r in sorted(refs) if r in adrs and adrs[r][0] != p and adrs[r][0] not in newer]
            if not newer:
                add("ADR-SUPERSEDED", "error", p, line, "status is superseded but no replacing ADR is linked or named")
            superseded_by[p] = newer
    for old, newer in superseded_by.items():
        m = NAME_RE.match(old.name)
        num = int(m.group(1)) if m else -1
        for new in newer:
            body = texts.get(new, "")
            if old.name not in body and not re.search(rf"\b(?:ADR[- ]?)?0*{num}\b", body):
                add("ADR-BACKLINK", "warning", new, 0, f"{old.name} says it is superseded by this ADR, which does "
                                                       f"not mention it")
    order = {"ADR-GAP": 0, "ADR-DUP": 1, "ADR-STATUS": 2, "ADR-SUPERSEDED": 3, "ADR-LINK": 4, "ADR-TITLE": 5,
             "ADR-BACKLINK": 6, "ADR-NAME": 7}
    findings.sort(key=lambda f: (order[f["rule"]], f["file"], f["line"], f["detail"]))
    return {"adr_dir": str(adr_dir), "adrs": len(texts), "numbers": [f"{n:04d}" for n in numbers],
            "statuses": statuses, "findings": findings,
            "errors": sum(f["level"] == "error" for f in findings),
            "warnings": sum(f["level"] == "warning" for f in findings)}


def render(rep: dict) -> str:
    out = [f"ADR lint: {rep['adr_dir']}", f"{rep['adrs']} ADRs, {rep['errors']} error(s), {rep['warnings']} "
                                          f"warning(s)", ""]
    for f in rep["findings"]:
        loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else f["file"] or "(folder)"
        out.append(f"{f['level']:<8} {f['rule']:<15} {loc:<40} {f['detail']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="adr_lint.py",
                                 description="Check an ADR folder for numbering gaps, missing status and broken "
                                             "supersession links.")
    ap.add_argument("adr_dir", nargs="?", default="docs/adr", help="ADR folder (default: docs/adr)")
    ap.add_argument("--strict", action="store_true", help="warnings also make the exit code 1")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    adr_dir = Path(args.adr_dir)
    if not adr_dir.is_dir():
        print(f"error: not a directory: {args.adr_dir}", file=sys.stderr)
        return 2
    rep = lint(adr_dir)
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 1 if rep["errors"] or (args.strict and rep["warnings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
