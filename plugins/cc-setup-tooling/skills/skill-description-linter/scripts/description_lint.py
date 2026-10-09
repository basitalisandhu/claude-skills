#!/usr/bin/env python3
"""description_lint.py: lint SKILL.md front matter against the description rules this plugin uses, and fix quoting.

Input: one or more SKILL.md files or folders (folders are searched for SKILL.md at any depth).

Rules (each finding cites the file and line):
  * front-matter-missing, front-matter-unclosed: no `---` block at the top, or one that is never closed;
  * yaml-unsafe: a value a strict YAML reader rejects (plain value with ': ' or ' #', a value starting with an
    indicator, an unclosed quote, tabs, duplicate keys);
  * name-missing, name-mismatch, name-format: no name, a name that differs from the folder, or one that is not
    lowercase letters, digits and single hyphens (at most 64 characters);
  * description-missing;
  * description-not-double-quoted: the description is plain, single-quoted or a block scalar (fixable);
  * description-too-long: longer than --max-chars (default 600);
  * description-verb-start: the first word is not a capitalised plain word, or is one of the starters that never
    open with an action (A, An, The, This, It, Use and similar);
  * description-no-trigger-phrase: no phrase in double quotes that a user would type;
  * description-no-use-when, description-no-not-for: no "Use when" sentence, no "Not for" sentence;
  * limits-missing: the body has no "## Limits" heading.

--fix rewrites the description (and any other top-level value flagged yaml-unsafe) as one double-quoted line in
place, then lints again; everything else is reported for a person. --diff shows what --fix would change and writes
nothing. The listing cost of each description (characters, and tokens estimated as characters / 4) is reported.

Exit codes: 0 no findings, 1 at least one finding (after fixing, when --fix is given), 2 bad input (no SKILL.md
found, unreadable path).
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _skillmd  # noqa: E402

NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
NON_VERB_STARTS = {
    "a",
    "an",
    "the",
    "this",
    "that",
    "these",
    "those",
    "it",
    "its",
    "our",
    "your",
    "my",
    "skill",
    "tool",
    "plugin",
    "helper",
    "utility",
    "script",
    "when",
    "for",
    "if",
    "use",
    "used",
    "using",
}
FIXABLE = {"description-not-double-quoted", "yaml-unsafe"}


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def lint_text(text: str, folder_name: str, max_chars: int) -> tuple[list[dict], dict]:
    fm = _skillmd.parse(text)
    findings: list[dict] = []

    def add(rule: str, line: int, detail: str) -> None:
        findings.append({"rule": rule, "line": line, "detail": detail, "fixable": rule in FIXABLE})

    info = {"name": None, "description_chars": 0, "estimated_tokens": 0, "trigger_phrases": []}
    if not fm.present:
        add("front-matter-missing", 1, "no front matter block at the top of the file")
        return findings, info
    if not fm.closed:
        add("front-matter-unclosed", 1, "front matter opened with --- but never closed")
        return findings, info
    for line, problem in fm.problems:
        add("yaml-unsafe", line, problem)
    name = fm.fields.get("name")
    info["name"] = name.value if name else None
    if name is None or not name.value:
        add("name-missing", 1, "no name in the front matter")
    else:
        if name.value != folder_name:
            add("name-mismatch", name.line, f"name {name.value!r} differs from the folder {folder_name!r}")
        if not isinstance(name.value, str) or not NAME_RE.fullmatch(name.value) or len(name.value) > 64:
            add("name-format", name.line, "name must be lowercase letters, digits and single hyphens, at most 64")
    desc = fm.fields.get("description")
    if desc is None or not isinstance(desc.value, str) or not desc.value.strip():
        add("description-missing", desc.line if desc else 1, "no description")
        return findings, info
    text_d = desc.value.strip()
    info["description_chars"] = len(text_d)
    info["estimated_tokens"] = (len(text_d) + 3) // 4
    phrases = _skillmd.quoted_phrases(text_d)
    info["trigger_phrases"] = phrases
    if desc.style != "double":
        add("description-not-double-quoted", desc.line, f"description is a {desc.style} scalar; use one quoted line")
    if len(text_d) > max_chars:
        add("description-too-long", desc.line, f"{len(text_d)} characters; the limit is {max_chars}")
    first = text_d.split()[0].rstrip(".,;:!?)\"'") if text_d.split() else ""
    if not re.fullmatch(r"[A-Z][a-z]+(?:-[a-z]+)*", first) or first.lower() in NON_VERB_STARTS:
        add("description-verb-start", desc.line, f"starts with {first!r}; start with the action, such as 'Review'")
    if not phrases:
        add("description-no-trigger-phrase", desc.line, 'no phrase in double quotes a user would type, e.g. "..."')
    if "Use when" not in text_d:
        add("description-no-use-when", desc.line, "no 'Use when ...' sentence")
    if "Not for" not in text_d:
        add("description-no-not-for", desc.line, "no 'Not for ...' sentence")
    body = text.replace("\r\n", "\n").split("\n")[fm.body_start :]
    if not any(re.fullmatch(r"##\s+Limits\s*", ln) for ln in body):
        add("limits-missing", fm.end_line, "the body has no '## Limits' section")
    return findings, info


def fixed_text(text: str) -> str:
    """Return text with the description and any unsafe top-level scalar rewritten as one double-quoted line."""
    fm = _skillmd.parse(text)
    if not fm.closed:
        return text
    lines = text.replace("\r\n", "\n").split("\n")
    unsafe_lines = {line for line, _ in fm.problems}
    replace: dict[int, tuple[int, str]] = {}
    keys = sorted(fm.fields.values(), key=lambda s: s.line)
    for idx, s in enumerate(keys):
        if not isinstance(s.value, str) or s.style in ("double", "list", "map", "empty"):
            continue
        if s.key != "description" and s.line not in unsafe_lines:
            continue
        nxt = keys[idx + 1].line if idx + 1 < len(keys) else fm.end_line
        span_end = s.line if s.style != "block" else nxt - 1
        if s.style == "block":
            while span_end > s.line and not lines[span_end - 1].strip():
                span_end -= 1
        replace[s.line] = (span_end, f"{s.key}: {_skillmd.encode_double(s.value)}")
    out, i = [], 0
    while i < len(lines):
        if i + 1 in replace:
            end, new = replace[i + 1]
            out.append(new)
            i = end
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="description_lint.py",
        description="Lint SKILL.md front matter (quoting, length, verb start, trigger phrase, Use when, Not for, "
        "name, strict YAML, Limits) and fix the quoting.",
        epilog="Exit codes: 0 no findings, 1 at least one finding, 2 bad input.",
    )
    p.add_argument("paths", nargs="+", help="SKILL.md files or folders to search")
    p.add_argument("--max-chars", type=int, default=600, help="description length limit (default 600)")
    p.add_argument("--fix", action="store_true", help="rewrite descriptions and unsafe values as double-quoted lines")
    p.add_argument("--diff", action="store_true", help="show what --fix would change; write nothing")
    p.add_argument("--json", action="store_true", help="print the computed data as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def render(rep: dict) -> str:
    out = ["# Skill description lint", ""]
    out += ["| Skill | File | Chars | Est. tokens | Findings |", "|---|---|---|---|---|"]
    for s in rep["skills"]:
        out.append(
            f"| {s['name'] or '(none)'} | `{s['file']}` | {s['description_chars']} | {s['estimated_tokens']} | "
            f"{len(s['findings'])} |"
        )
    out += [
        "",
        f"{len(rep['skills'])} skill(s), {rep['finding_count']} finding(s), {rep['fixed']} file(s) fixed. "
        f"Listing cost {rep['total_chars']} characters, about {rep['total_tokens']} tokens (characters / 4).",
        "",
        "## Findings",
        "",
    ]
    if not rep["finding_count"]:
        out.append("None.")
    for s in rep["skills"]:
        for f in s["findings"]:
            fix = " (fixable with --fix)" if f["fixable"] else ""
            out.append(f"- `{s['file']}:{f['line']}` {f['rule']}: {f['detail']}{fix}")
    if rep.get("diff"):
        out += ["", "## Changes --fix would make", "", "```diff", rep["diff"].rstrip("\n"), "```"]
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = [Path(p) for p in args.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"description_lint.py: not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    files = _skillmd.find_skill_files(paths)
    if not files:
        print("description_lint.py: no SKILL.md found", file=sys.stderr)
        return 2
    skills, fixed, diffs = [], 0, []
    for f in files:
        text = _skillmd.read_text(f)
        if args.fix or args.diff:
            new = fixed_text(text)
            if new != text.replace("\r\n", "\n"):
                if args.diff:
                    diffs += difflib.unified_diff(
                        text.replace("\r\n", "\n").splitlines(keepends=True),
                        new.splitlines(keepends=True),
                        fromfile=f.as_posix(),
                        tofile=f.as_posix(),
                    )
                else:
                    f.write_text(new, encoding="utf-8", newline="\n")
                    fixed += 1
                    text = new
        findings, info = lint_text(text, f.parent.name, args.max_chars)
        skills.append({"file": f.as_posix(), **info, "findings": findings})
    rep = {
        "skills": skills,
        "finding_count": sum(len(s["findings"]) for s in skills),
        "fixed": fixed,
        "total_chars": sum(s["description_chars"] for s in skills),
        "total_tokens": sum(s["estimated_tokens"] for s in skills),
        "max_chars": args.max_chars,
    }
    if diffs:
        rep["diff"] = "".join(d if d.endswith("\n") else d + "\n" for d in diffs)
    text_out = json.dumps(rep, indent=2, sort_keys=True) + "\n" if args.json else render(rep)
    if args.out:
        Path(args.out).write_text(text_out, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text_out)
    return 1 if rep["finding_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
