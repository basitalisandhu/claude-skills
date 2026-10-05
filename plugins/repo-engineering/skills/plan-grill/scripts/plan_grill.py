#!/usr/bin/env python3
"""Check an implementation plan (Markdown) for the sections and answers it needs before coding starts.

Required sections, matched by heading text at any level (aliases in brackets):
  scope           [scope, goals, non-goals, objectives, problem]
  interfaces      [interfaces, API, contracts, endpoints, CLI, public surface]
  data            [data, schema, storage, data model, migrations, persistence]
  failure-modes   [failure modes, failures, risks, error handling, edge cases]
  rollout         [rollout, deployment, release, launch, rollback]
  tests           [tests, testing, test plan, verification]
  open-questions  [open questions, questions, unknowns, unresolved]

Gaps (id: when it fires):
  missing-section     no heading matches the section
  thin-section        the section has fewer than --min-words words (not applied to open questions)
  placeholder         the section holds TBD, TODO, TBC, ???, "to be decided", "fill in" or a bare N/A
  no-rollback         the rollout section never says how to go back (rollback, revert, feature flag, kill switch)
  no-failure-list     the failure-modes section has no list item
  no-test-kind        the tests section names no kind of test (unit, integration, end-to-end, manual, load, ...)
  unanswered-question an open question with no owner (@name, "owner:") or answer ("answer:", "decided:", "->"),
                      or a line ending in "?" anywhere else in the plan

No model calls and no network: the checks are text rules, so a plan can pass them and still be wrong.

Usage:
    plan_grill.py PLAN.md [--sections a,b,...] [--min-words N] [--json | --markdown] [--out FILE]

Exit codes: 0 no gaps, 1 gaps for the author to answer, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SECTIONS: dict[str, tuple[str, re.Pattern[str]]] = {
    "scope": ("Scope", re.compile(r"\b(scope|goals?|non-goals?|objectives?|problem)\b", re.I)),
    "interfaces": (
        "Interfaces",
        re.compile(r"\b(interfaces?|apis?|contracts?|endpoints?|cli|public surface)\b", re.I),
    ),
    "data": ("Data", re.compile(r"\b(data|schema|storage|data model|migrations?|persistence)\b", re.I)),
    "failure-modes": (
        "Failure modes",
        re.compile(r"\b(failure modes?|failures?|risks?|error handling|edge cases?)\b", re.I),
    ),
    "rollout": ("Rollout", re.compile(r"\b(roll-?out|deploy(ment)?|release|launch|rollback)\b", re.I)),
    "tests": ("Tests", re.compile(r"\b(tests?|testing|test plan|verification)\b", re.I)),
    "open-questions": ("Open questions", re.compile(r"\b(open questions?|questions|unknowns|unresolved)\b", re.I)),
}
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
PLACEHOLDER_RE = re.compile(
    r"\b(TBD|TODO|TBC|FIXME)\b|\?\?\?|to be (decided|determined|confirmed)|fill (this )?in", re.I
)
BARE_NA_RE = re.compile(r"^\s*(?:[-*]\s*)?(n/?a|none yet)\.?\s*$", re.I)
ROLLBACK_RE = re.compile(r"roll ?back|revert|feature flag|kill switch|back out|undo", re.I)
TEST_KIND_RE = re.compile(
    r"\b(unit|integration|end-to-end|e2e|manual|load|contract|regression|acceptance|smoke|property|snapshot)\b", re.I
)
LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
ANSWERED_RE = re.compile(
    r"@[\w-]+|\bowner\s*:|\banswer(ed)?\s*:|\bdecided\s*:|\bresolved\s*:|->|=>|\[x\]|\bA\s*:", re.I
)
NO_QUESTIONS_RE = re.compile(r"^\s*(?:[-*]\s*)?(none|no open questions)\.?\s*$", re.I)


def parse(text: str) -> tuple[list[tuple[int, int, str]], list[str], set[int]]:
    """Return (headings as (line index, level, text), lines, line indexes inside code fences)."""
    lines = text.splitlines()
    headings: list[tuple[int, int, str]] = []
    fenced: set[int] = set()
    in_fence = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            fenced.add(i)
            continue
        if in_fence:
            fenced.add(i)
            continue
        m = HEADING_RE.match(line)
        if m:
            headings.append((i, len(m.group(1)), m.group(2)))
    return headings, lines, fenced


def section_lines(headings: list[tuple[int, int, str]], lines: list[str], index: int) -> list[int]:
    start, level, _ = headings[index]
    end = len(lines)
    for i, lvl, _ in headings[index + 1 :]:
        if lvl <= level:
            end = i
            break
    return list(range(start + 1, end))


def grill(text: str, wanted: list[str], min_words: int) -> dict:
    headings, lines, fenced = parse(text)
    gaps: list[dict] = []
    sections: dict[str, dict] = {}
    claimed: dict[int, str] = {}

    def gap(section: str, rule: str, detail: str, line: int | None = None) -> None:
        gaps.append({"section": section, "rule": rule, "line": line, "detail": detail})

    for key in wanted:
        title, pattern = SECTIONS[key]
        matched = [n for n, (_, _, h) in enumerate(headings) if pattern.search(h)]
        if not matched:
            sections[key] = {"title": title, "headings": [], "words": 0, "status": "missing"}
            gap(key, "missing-section", f"no heading for {title.lower()}")
            continue
        body_idx = sorted({i for n in matched for i in section_lines(headings, lines, n) if i not in fenced})
        for i in body_idx:
            claimed.setdefault(i, key)
        body = [lines[i] for i in body_idx]
        words = len(re.findall(r"[A-Za-z0-9][\w'-]*", " ".join(b for b in body if not HEADING_RE.match(b))))
        before = len(gaps)
        if words < min_words and key != "open-questions":
            gap(key, "thin-section", f"{words} words (at least {min_words} expected)", headings[matched[0]][0] + 1)
        for i in body_idx:
            if PLACEHOLDER_RE.search(lines[i]) or BARE_NA_RE.match(lines[i]):
                gap(key, "placeholder", lines[i].strip()[:100], i + 1)
        if key == "rollout" and not ROLLBACK_RE.search(" ".join(body)):
            gap(key, "no-rollback", "says how to ship but not how to go back", headings[matched[0]][0] + 1)
        if key == "failure-modes" and not any(LIST_ITEM_RE.match(b) for b in body):
            gap(key, "no-failure-list", "list each failure mode and what happens", headings[matched[0]][0] + 1)
        if key == "tests" and not TEST_KIND_RE.search(" ".join(body)):
            gap(key, "no-test-kind", "name the kinds of test (unit, integration, end-to-end, manual)")
        if key == "open-questions":
            for i in body_idx:
                line = lines[i]
                if not LIST_ITEM_RE.match(line) or NO_QUESTIONS_RE.match(line):
                    continue
                if not ANSWERED_RE.search(line):
                    gap(key, "unanswered-question", line.strip()[:100] + " (no owner or answer)", i + 1)
        sections[key] = {
            "title": title,
            "headings": [headings[n][2] for n in matched],
            "words": words,
            "status": "gaps" if len(gaps) > before else "ok",
        }

    for i, line in enumerate(lines):
        in_questions = claimed.get(i) == "open-questions" and LIST_ITEM_RE.match(line)
        if i in fenced or in_questions or HEADING_RE.match(line):
            continue
        stripped = line.strip()
        if stripped.endswith("?") and not ANSWERED_RE.search(stripped):
            gap(claimed.get(i, "(outside the sections)"), "unanswered-question", stripped[:100], i + 1)
            if claimed.get(i) in sections:
                sections[claimed[i]]["status"] = "gaps"

    ready = sum(1 for s in sections.values() if s["status"] == "ok")
    return {"sections": sections, "ready": ready, "required": len(wanted), "gaps": gaps}


def render(rep: dict, plan: str, markdown: bool) -> str:
    head = f"{rep['ready']} of {rep['required']} sections ready, {len(rep['gaps'])} gaps"
    if markdown:
        lines = [f"## Plan grill: {plan}", "", f"**{head}**", "", "| Section | Status | Heading | Words |"]
        lines.append("|---|---|---|---|")
        for s in rep["sections"].values():
            lines.append(f"| {s['title']} | {s['status']} | {', '.join(s['headings']) or '(none)'} | {s['words']} |")
        lines += ["", "| Line | Section | Gap | Detail |", "|---|---|---|---|"]
        for g in rep["gaps"]:
            detail = g["detail"].replace("|", "\\|")
            lines.append(f"| {g['line'] or ''} | {g['section']} | {g['rule']} | {detail} |")
        return "\n".join(lines) + "\n"
    lines = [f"plan-grill: {plan}: {head}"]
    for s in rep["sections"].values():
        lines.append(f"  {s['title']}: {s['status']}")
    for g in rep["gaps"]:
        where = f"line {g['line']}" if g["line"] else "plan"
        lines.append(f"  [{g['rule']}] {g['section']} ({where}): {g['detail']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="plan_grill.py",
        description="Check an implementation plan for required sections and unanswered questions (offline).",
        epilog="Exit codes: 0 no gaps, 1 gaps for the author to answer, 2 bad input.",
    )
    parser.add_argument("plan", help="the plan, a Markdown file")
    parser.add_argument("--sections", help=f"comma-separated subset of: {', '.join(SECTIONS)} (default: all)")
    parser.add_argument("--min-words", type=int, default=12, help="words a section needs (default 12)")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON report")
    fmt.add_argument("--markdown", action="store_true", help="Markdown report")
    parser.add_argument("--out", help="write the report to this file instead of stdout")
    args = parser.parse_args(argv)
    path = Path(args.plan)
    if not path.is_file():
        print(f"plan_grill.py: plan not found: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        print(f"plan_grill.py: plan is empty: {path}", file=sys.stderr)
        return 2
    wanted = list(SECTIONS)
    if args.sections:
        wanted = [s.strip() for s in args.sections.split(",") if s.strip()]
        unknown = [s for s in wanted if s not in SECTIONS]
        if unknown or not wanted:
            print(f"plan_grill.py: unknown sections: {', '.join(unknown) or '(none given)'}", file=sys.stderr)
            return 2
    if args.min_words < 0:
        print("plan_grill.py: --min-words must be 0 or more", file=sys.stderr)
        return 2
    rep = grill(text, wanted, args.min_words)
    rep["plan"] = path.as_posix()
    out = json.dumps(rep, indent=2) + "\n" if args.json else render(rep, path.as_posix(), args.markdown)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 1 if rep["gaps"] else 0


if __name__ == "__main__":
    sys.exit(main())
