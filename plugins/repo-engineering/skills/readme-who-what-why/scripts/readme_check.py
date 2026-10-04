#!/usr/bin/env python3
"""Check that a README answers six questions in its first screen, and flag hype words.

Elements (each scored 2 when found within the first screen, 1 when found later, 0 when absent; maximum 12):
  what     the first prose sentence says what the project is (flagged when longer than --max-words words)
  who      who it is for ("for developers", "if you", "is for", "teams that", ...)
  why      why it exists or what it replaces ("instead of", "replaces", "unlike", "because", "without", ...)
  install  a fenced code block with an install command (pip, npm, brew, cargo, go install, /plugin install, ...)
  example  a fenced block that runs something other than an install, or a Usage / Quickstart / Example heading
  ask      where to ask: issues, discussions, SECURITY.md, CONTRIBUTING, a forum or chat link

"First screen" is the first --screen-lines source lines (default 40), not counting leading badges and images.
Hype words outside code blocks are listed with their line numbers.

Exit codes: 0 every element in the first screen and no hype words, 1 gaps or hype words, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

INSTALL_RE = re.compile(
    r"(?<![\w/-])(pip3? install|pipx install|uv (?:add|pip install|tool install)|npm (?:i|install)|npx |"
    r"pnpm (?:add|install)|"
    r"yarn add|bun add|brew install|cargo install|go install|gem install|apt(?:-get)? install|"
    r"docker (?:pull|run)|/plugin install|/plugin marketplace add|claude plugin (?:install|marketplace add)|git clone|"
    r"composer require|dotnet add|conda install|nix (?:profile install|run))\b")
WHO_RE = re.compile(
    r"\b(for (?:developers|engineers|teams|maintainers|people|anyone|users|you|those|operators|admins|"
    r"researchers|data|students|beginners)|is for\b|built for\b|aimed at\b|intended for\b|designed for\b|"
    r"if you\b|who (?:want|need|maintain|run|build|use|write)|audience\b|teams that\b|people who\b)", re.IGNORECASE)
WHY_RE = re.compile(
    r"\b(why\b|instead of\b|replaces?\b|unlike\b|because\b|so that\b|without\b|rather than\b|"
    r"the problem\b|tired of\b|stops?\b|prevents?\b|avoids?\b|alternative to\b)", re.IGNORECASE)
ASK_RE = re.compile(
    r"(issues\b|/issues|discussions\b|SECURITY\.md|CONTRIBUTING|\bsupport\b|discord|slack|gitter|matrix\.to|"
    r"\bforum\b|mailing list|\bcontact\b|\bquestions?\b|\bask\b)", re.IGNORECASE)
EXAMPLE_HEADING_RE = re.compile(r"^#{1,6}\s+.*\b(usage|quick ?start|example|examples|getting started|try it|demo)\b",
                                re.IGNORECASE)
HYPE = [
    "blazing fast", "blazingly fast", "lightning fast", "lightning-fast", "revolutionary", "game-changing",
    "game changer", "cutting-edge", "cutting edge", "seamless", "seamlessly", "effortless", "effortlessly",
    "supercharge", "supercharged", "next-gen", "next-generation", "world-class", "best-in-class", "magical",
    "powerful", "robust", "state-of-the-art", "unleash", "unparalleled", "ultimate", "groundbreaking", "disruptive",
    "10x", "insanely", "incredible", "amazing", "awesome",
]
HYPE_RE = re.compile(r"(?<![\w-])(" + "|".join(re.escape(h) for h in HYPE) + r")(?![\w-])", re.IGNORECASE)
ELEMENTS = ("what", "who", "why", "install", "example", "ask")
ADVICE = {
    "what": "Open with one plain sentence: '<name> is a <kind of thing> that <does what>'.",
    "who": "Say who it is for in one clause: 'for maintainers who ...', 'if you ...'.",
    "why": "Say why it exists or what it replaces: 'instead of ...', 'unlike ...', 'so that ...'.",
    "install": "Give the install as one fenced code block that can be pasted as is.",
    "example": "Show one command or snippet that runs something real right after the install.",
    "ask": "Say where to ask: a link to issues or discussions, or the support contact.",
}


def blocks(lines: list[str]) -> list[dict]:
    out, cur = [], None
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if re.match(r"^(```|~~~)", s):
            if cur is None:
                cur = {"start": i, "lang": s.lstrip("`~").strip().lower(), "body": []}
            else:
                cur["end"] = i
                out.append(cur)
                cur = None
        elif cur is not None:
            cur["body"].append(line)
    return out


def check(text: str, screen_lines: int, max_words: int) -> dict:
    lines = text.splitlines()
    first_content = 1
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or re.match(r"^(\[!\[|!\[|<img|<p\b|</p>|<a\b|</a>|<div|</div>|<br)", s, re.IGNORECASE):
            continue
        first_content = i
        break
    screen_end = first_content + screen_lines - 1
    code = blocks(lines)
    in_code = set()
    for b in code:
        in_code |= set(range(b["start"], b.get("end", len(lines)) + 1))
    found: dict[str, dict] = {}
    notes: list[str] = []

    def mark(elem: str, line: int, evidence: str) -> None:
        if elem not in found:
            found[elem] = {"line": line, "evidence": evidence.strip()[:120]}

    for i, line in enumerate(lines, 1):
        s = line.strip()
        if i in in_code or not s or s.startswith(("#", "|", "<", "[![", "![", ">")) or re.match(r"^[-*_]{3,}$", s):
            continue
        first_sentence = re.split(r"(?<=[.!?])\s", re.sub(r"[*_`]", "", s))[0]
        mark("what", i, first_sentence)
        n = len(first_sentence.split())
        if n > max_words:
            notes.append(f"line {i}: the opening sentence has {n} words; aim for {max_words} or fewer")
        break
    for i, line in enumerate(lines, 1):
        if i in in_code:
            continue
        if WHO_RE.search(line):
            mark("who", i, WHO_RE.search(line).group(0))
        if WHY_RE.search(line):
            mark("why", i, WHY_RE.search(line).group(0))
        if ASK_RE.search(line):
            mark("ask", i, ASK_RE.search(line).group(0))
        if EXAMPLE_HEADING_RE.match(line.strip()):
            mark("example", i, line)
    install_block = None
    for b in code:
        body = "\n".join(b["body"])
        if INSTALL_RE.search(body):
            if install_block is None:
                install_block = b
                mark("install", b["start"], INSTALL_RE.search(body).group(0))
                cmds = [x for x in b["body"] if x.strip() and not x.strip().startswith("#")]
                if len(cmds) > 4:
                    notes.append(f"line {b['start']}: the install block has {len(cmds)} command lines; "
                                 "one or two are easier to paste")
            non_install = [x for x in b["body"] if x.strip() and not x.strip().startswith("#")
                           and not INSTALL_RE.search(x)]
            if install_block is not b and non_install:
                mark("example", b["start"], non_install[0])
        elif b["body"] and any(x.strip() for x in b["body"]):
            if install_block is not None or b["lang"] not in {"text", "txt", ""}:
                mark("example", b["start"], next(x for x in b["body"] if x.strip()))
    hype = []
    for i, line in enumerate(lines, 1):
        if i in in_code:
            continue
        for m in HYPE_RE.finditer(line):
            hype.append({"line": i, "word": m.group(1)})
    score = 0
    elements = {}
    todo = []
    for e in ELEMENTS:
        if e in found:
            in_screen = found[e]["line"] <= screen_end
            pts = 2 if in_screen else 1
            elements[e] = {"status": "first screen" if in_screen else "later", "points": pts, **found[e]}
            if not in_screen:
                todo.append(f"{e}: found at line {found[e]['line']}, move it into the first {screen_lines} lines. "
                            f"{ADVICE[e]}")
        else:
            pts = 0
            elements[e] = {"status": "missing", "points": 0}
            todo.append(f"{e}: missing. {ADVICE[e]}")
        score += pts
    for h in hype:
        todo.append(f"line {h['line']}: replace '{h['word']}' with a specific, checkable statement")
    return {
        "score": score,
        "max_score": 2 * len(ELEMENTS),
        "screen": {"first_line": first_content, "last_line": screen_end},
        "elements": elements,
        "hype_words": hype,
        "notes": notes,
        "todo": todo,
    }


def render(rep: dict, path: str) -> str:
    out = [f"README check: {path}  score {rep['score']}/{rep['max_score']} "
           f"(first screen = lines {rep['screen']['first_line']}-{rep['screen']['last_line']})", ""]
    for e in ELEMENTS:
        v = rep["elements"][e]
        where = f"line {v['line']}" if "line" in v else ""
        ev = f"  {v['evidence']!r}" if v.get("evidence") else ""
        out.append(f"  {e:<8} {v['status']:<13} {where:<10}{ev}")
    for n in rep["notes"]:
        out.append(f"  note: {n}")
    out.append("")
    if rep["todo"]:
        out.append("To do:")
        out += [f"  [ ] {t}" for t in rep["todo"]]
    else:
        out.append("Nothing to do: all six answers are in the first screen and no hype words were found.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="readme_check.py",
                                 description="Score whether a README answers what, who, why, install, example and "
                                             "where to ask in its first screen.")
    ap.add_argument("readme", help="path to README.md")
    ap.add_argument("--screen-lines", type=int, default=40, help="source lines that count as the first screen "
                                                                  "(default: 40)")
    ap.add_argument("--max-words", type=int, default=35, help="longest acceptable opening sentence (default: 35)")
    ap.add_argument("--min-score", type=int, help="exit 0 when the score is at least this, ignoring the other gates")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    try:
        text = Path(args.readme).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.readme}: {exc}", file=sys.stderr)
        return 2
    rep = check(text, max(5, args.screen_lines), args.max_words)
    print(json.dumps(rep, indent=2) if args.json else render(rep, args.readme))
    if args.min_score is not None:
        return 0 if rep["score"] >= args.min_score else 1
    return 1 if rep["todo"] else 0


if __name__ == "__main__":
    sys.exit(main())
