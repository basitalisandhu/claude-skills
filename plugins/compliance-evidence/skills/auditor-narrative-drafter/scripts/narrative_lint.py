#!/usr/bin/env python3
"""Lint a control narrative against its control map before it goes to an assessor.

Usage:
  narrative_lint.py <narrative.md> <control-map.json> [--phrases FILE ...]

Rules (each problem is reported with its line number):
  UNCITED-CLAIM     a sentence states a control outcome (supports, meets, satisfies, compliant, in place, effective,
                    enforced, operating, passes, fails, contradicts, implemented, adequate and similar) without an
                    inline citation [evidence: <file>#<field>]. Sentences that say "not assessable" are allowed.
  UNKNOWN-CITATION  a citation's file#field is not cited anywhere in the control map, so it cannot be traced to a
                    hashed file in the pack
  WRONG-CONTROL-CITATION
                    a known citation under a control heading is not mapped to that control
  STATE-MISMATCH    under a "## <identifier>" heading, a sentence claims support while the control map's state for
                    that control is contradicted or not assessable, or claims a contradiction while the state is
                    supported
  UNKNOWN-CONTROL   a "## <identifier>" heading names a control that is not in the control map
  CERTAINTY         a forbidden certainty word or phrase: "fully compliant", "guarantee", "guarantees", "guaranteed",
                    "100%", "100 percent" (text inside `inline code`, which quotes exported values, is not checked)
  COPIED-TEXT       a line of more than 25 words contains a phrase from a forbidden-phrases list (--phrases files;
                    default references/forbidden-phrases.md, which ships empty: lines starting with "phrase:")
  NO-DISCLAIMER     the text never says it is preparation for a human assessor

The linter checks form, not truth: a narrative that passes still needs the assessor to read the cited files.

Exit codes: 0 no problems, 1 problems found, 2 bad input. Nothing here calls any API.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    SUPPORTED,
    InputError,
    add_common_args,
    cell,
    dumps,
    load_json,
    redact,
)

DEFAULT_PHRASES = Path(__file__).resolve().parent.parent / "references" / "forbidden-phrases.md"
CITATION_RE = re.compile(r"\[evidence:\s*([^\s#\]]+)#(\S+?)\](?=\s|$|[.,;:)\[])")
OUTCOME_RE = re.compile(
    r"\b(support(s|ed|ing)?|meets?|met|satisf(y|ies|ied)|compliant|compl(y|ies)|in place|effective(ly)?|enforced|"
    r"operating|pass(es|ed)?|contradict(s|ed)?|fail(s|ed)?|implemented|adequate(ly)?)\b", re.I)
SUPPORT_RE = re.compile(r"\b(support(s|ed)?|consistent with|meets?|satisf(y|ies|ied))\b", re.I)
NEGATION_RE = re.compile(r"\b(not|no|never|cannot|does not|do not|nor|without)\b", re.I)
CONTRA_RE = re.compile(r"\bcontradict(s|ed)?\b", re.I)
CERTAINTY_RE = re.compile(r"(fully\s+compliant|\bguarantee[sd]?\b|\b100\s*%|\b100\s+percent\b)", re.I)
HEADING_ID_RE = re.compile(r"^##\s+([A-Z]{1,3}\d*(?:\.\d+)+)\b")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\[\"(])")
EXEMPT_PREFIXES = ("topic (paraphrase):",)
DISCLAIMER_RE = re.compile(r"preparation\s+for\s+a\s+human\s+assessor", re.I)
MAX_WORDS = 25


def load_phrases(paths: list[str]) -> list[str]:
    phrases: list[str] = []
    for p in paths:
        try:
            text = Path(p).read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"{p}: cannot read: {exc}") from exc
        for line in text.splitlines():
            m = re.match(r"^phrase:\s*(.+?)\s*$", line)
            if m:
                phrases.append(" ".join(m.group(1).lower().split()))
    return phrases


def map_index(path: str) -> tuple[dict[str, str], set[tuple[str, str]], dict[str, set[tuple[str, str]]]]:
    data = load_json(Path(path))
    if not isinstance(data, dict) or not isinstance(data.get("controls"), list):
        raise InputError(f"{path}: not a control map written by control_map.py")
    states = {c["id"]: c["state"] for c in data["controls"] if isinstance(c, dict) and "id" in c}
    cites = {(c["file"], c["field"]) for ctrl in data["controls"] for c in ctrl.get("citations") or []
             if isinstance(c, dict) and c.get("file") and c.get("field")}
    control_cites = {
        ctrl["id"]: {(cite["file"], cite["field"]) for cite in ctrl.get("citations") or []
                     if isinstance(cite, dict) and cite.get("file") and cite.get("field")}
        for ctrl in data["controls"] if isinstance(ctrl, dict) and "id" in ctrl
    }
    return states, cites, control_cites


def blocks(text: str):
    """Yield (line number, line) for prose lines, skipping fenced code blocks."""
    fenced = False
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            yield no, line


def lint(text: str, states: dict[str, str], cites: set[tuple[str, str]], phrases: list[str],
         control_cites: dict[str, set[tuple[str, str]]] | None = None) -> list[dict]:
    problems: list[dict] = []

    def add(no: int, rule: str, msg: str, excerpt: str) -> None:
        problems.append({"line": no, "rule": rule, "message": msg, "text": excerpt.strip()[:160]})

    if not DISCLAIMER_RE.search(text):
        add(1, "NO-DISCLAIMER", "the narrative must say it is preparation for a human assessor, not an opinion or attestation", "")
    current: str | None = None
    for no, line in blocks(text):
        stripped = line.strip()
        m = HEADING_ID_RE.match(stripped)
        if m:
            current = m.group(1)
            if current not in states:
                add(no, "UNKNOWN-CONTROL", f"{current} is not in the control map", stripped)
            continue
        if stripped.startswith("#"):
            current = None if stripped.startswith("# ") else current
            continue
        if not stripped:
            continue
        prose = stripped.lstrip(">").lstrip("-*").strip()
        words = len(prose.split())
        lowered = " ".join(prose.lower().split())
        if words > MAX_WORDS:
            for ph in phrases:
                if ph and ph in lowered:
                    add(no, "COPIED-TEXT", f"line of {words} words contains a forbidden phrase ({ph[:40]!r}); write the "
                        "topic in your own words and cite the identifier instead", prose)
                    break
        if stripped.startswith(">"):
            continue
        for ref_file, ref_field in CITATION_RE.findall(prose):
            if (ref_file, ref_field) not in cites:
                add(no, "UNKNOWN-CITATION", f"{ref_file}#{ref_field} is not cited in the control map", prose)
            elif control_cites is not None and current in states \
                    and (ref_file, ref_field) not in control_cites.get(current, set()):
                add(no, "WRONG-CONTROL-CITATION",
                    f"{ref_file}#{ref_field} is not cited for {current} in the control map", prose)
        if prose.lower().startswith(EXEMPT_PREFIXES):
            continue
        for sentence in SENTENCE_SPLIT_RE.split(prose):
            bare = INLINE_CODE_RE.sub("", sentence)
            for hit in CERTAINTY_RE.finditer(bare):
                add(no, "CERTAINTY", f"forbidden certainty wording {hit.group(0)!r}", sentence)
            has_cite = bool(CITATION_RE.search(sentence))
            claim_text = CITATION_RE.sub("", bare)
            if "not assessable" in claim_text.lower():
                continue
            if OUTCOME_RE.search(claim_text) and not has_cite:
                add(no, "UNCITED-CLAIM", "states a control outcome without an [evidence: file#field] citation", sentence)
            if current and current in states:
                state = states[current]
                negated = bool(NEGATION_RE.search(claim_text))
                if SUPPORT_RE.search(claim_text) and not negated and state != SUPPORTED:
                    add(no, "STATE-MISMATCH", f"claims support but the control map says {current} is {state}", sentence)
                if CONTRA_RE.search(claim_text) and not negated and state == SUPPORTED:
                    add(no, "STATE-MISMATCH", f"claims a contradiction but the control map says {current} is supported", sentence)
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="narrative_lint.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("narrative", help="Markdown narrative to check")
    ap.add_argument("control_map", help="control map JSON the narrative was drafted from")
    ap.add_argument("--phrases", action="append", help="forbidden-phrases file (repeatable); default references/forbidden-phrases.md")
    add_common_args(ap, fail_on=False)
    args = ap.parse_args(argv)
    try:
        try:
            text = Path(args.narrative).read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"{args.narrative}: cannot read: {exc}") from exc
        states, cites, control_cites = map_index(args.control_map)
        phrases = load_phrases(args.phrases or ([str(DEFAULT_PHRASES)] if DEFAULT_PHRASES.is_file() else []))
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = lint(text, states, cites, phrases, control_cites)
    if args.redact:
        problems = redact(problems)
    if args.json:
        print(dumps({"narrative": args.narrative, "problems": problems, "ok": not problems,
                     "checked_phrases": len(phrases)}))
    elif problems:
        print(f"# Narrative lint: {len(problems)} problem(s)\n\n| Line | Rule | Problem | Text |\n|---|---|---|---|")
        for p in problems:
            print(f"| {p['line']} | {p['rule']} | {cell(p['message'])} | {cell(p['text'])} |")
        print("\nFix every problem, then lint again. A clean result checks form only; the assessor still reads the cited files.")
    else:
        print(f"Narrative lint: no problems ({len(phrases)} forbidden phrase(s) checked). This checks form only; "
              "the assessor still reads the cited files.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
