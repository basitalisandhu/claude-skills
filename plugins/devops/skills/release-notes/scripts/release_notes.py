#!/usr/bin/env python3
"""Turn a git commit range into grouped release notes (Markdown or JSON).

Commits are classified by Conventional Commits prefixes (feat, fix, perf, refactor, docs, test, build, ci, chore,
revert; `!` or a BREAKING CHANGE footer marks a breaking change) and, when a commit has no prefix, by keywords in the
subject (add, fix, remove, upgrade). Issue references (#123, Closes #123, JIRA-123) are collected per entry.

Input is either a git repository (the script runs `git log` locally; no network) or a pre-captured log with
--input FILE / --input - produced by:
    git log --no-merges --date=short --format='%H%x1f%an%x1f%ad%x1f%s%x1f%b%x1e' v1.0.0..HEAD

Usage:
    release_notes.py [--repo DIR] [--range REV..REV] [--input FILE] [--version X.Y.Z] [--date YYYY-MM-DD]
                     [--repo-url https://github.com/owner/repo] [--authors] [--json]

Exit codes: 0 notes produced (possibly empty), 2 git failed or input unreadable.
Standard library only. Runs git locally when --input is not given. No network.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

VERSION = "0.1.0"
FORMAT = "%H%x1f%an%x1f%ad%x1f%s%x1f%b%x1e"
CC_RE = re.compile(r"^(?P<type>[A-Za-z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s*(?P<subject>.+)$")
ISSUE_RE = re.compile(r"(?:(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+)?(?:#(\d+)|\b([A-Z][A-Z0-9]+-\d+)\b)", re.I)
SECTIONS = [("breaking", "Breaking changes"), ("feat", "Features"), ("fix", "Bug fixes"), ("perf", "Performance"),
            ("refactor", "Refactoring"), ("docs", "Documentation"), ("test", "Tests"), ("build", "Build and dependencies"),
            ("ci", "CI"), ("revert", "Reverts"), ("other", "Other changes")]
TYPE_ALIASES = {"feature": "feat", "features": "feat", "bugfix": "fix", "fixes": "fix", "hotfix": "fix", "performance": "perf",
                "doc": "docs", "tests": "test", "style": "other", "chore": "build", "deps": "build", "dep": "build", "security": "fix"}
KEYWORDS = [("docs", re.compile(r"(?i)^(docs?|readme|document|changelog)\b|\b(readme|docs|documentation|docstrings?)\b")),
            ("fix", re.compile(r"(?i)^(fix|fixes|fixed|hotfix|bugfix|resolve|correct|repair)\b")),
            ("feat", re.compile(r"(?i)^(add|adds|added|implement|introduce|support|new)\b")),
            ("build", re.compile(r"(?i)^(bump|upgrade|update|pin|deps?|dependenc)\b")),
            ("refactor", re.compile(r"(?i)^(refactor|clean|cleanup|tidy|rename|move|simplify)\b")),
            ("test", re.compile(r"(?i)^(test|tests|spec)\b")),
            ("fix", re.compile(r"(?i)^(remove|delete|drop)\b"))]


def parse_log(raw: str) -> list[dict]:
    commits: list[dict] = []
    for rec in raw.split("\x1e"):
        rec = rec.strip("\n\r ")
        if not rec:
            continue
        parts = rec.split("\x1f")
        if len(parts) < 4:
            continue
        sha, author, date, subject = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
        body = parts[4].strip() if len(parts) > 4 else ""
        commits.append({"sha": sha, "author": author, "date": date, "subject": subject, "body": body})
    return commits


def classify(c: dict) -> dict:
    subject = c["subject"]
    m = CC_RE.match(subject)
    ctype, scope, breaking, text = "other", None, False, subject
    if m and m.group("type").lower() in {s for s, _ in SECTIONS} | set(TYPE_ALIASES):
        t = m.group("type").lower()
        ctype = TYPE_ALIASES.get(t, t)
        scope = m.group("scope") or None
        breaking = bool(m.group("bang"))
        text = m.group("subject").strip()
    else:
        for t, rx in KEYWORDS:
            if rx.search(subject):
                ctype = t
                break
    note = None
    fm = re.search(r"^BREAKING[ -]CHANGE[S]?:[ \t]*(.*?)(?:\n\s*\n|\Z)", c["body"], re.M | re.I | re.S)
    if fm:
        breaking = True
        note = " ".join(fm.group(1).split()) or None
    issues = sorted({(a or b) for a, b in ISSUE_RE.findall(subject + "\n" + c["body"])})
    text = text[0].upper() + text[1:] if text else text
    return {**c, "type": ctype, "scope": scope, "breaking": breaking, "breaking_note": note, "text": text, "issues": issues}


def build(commits: list[dict], version: str | None, date: str | None, repo_url: str | None, authors: bool) -> dict:
    entries = [classify(c) for c in commits]
    sections: dict[str, list[dict]] = {key: [] for key, _ in SECTIONS}
    for e in entries:
        if e["breaking"]:
            sections["breaking"].append(e)
        sections[e["type"] if e["type"] in sections else "other"].append(e)
    contributors = sorted({e["author"] for e in entries})
    return {"version": VERSION, "release": version or "Unreleased", "date": date or dt.date.today().isoformat(), "repo_url": repo_url,
            "commits": len(entries), "contributors": contributors if authors else None,
            "sections": [{"key": k, "title": t, "entries": sections[k]} for k, t in SECTIONS if sections[k]]}


def render_markdown(notes: dict, authors: bool) -> str:
    out = [f"## {notes['release']} ({notes['date']})", ""]
    if not notes["sections"]:
        out.append("No changes in this range.")
        return "\n".join(out) + "\n"
    url = notes.get("repo_url")
    for sec in notes["sections"]:
        out.append(f"### {sec['title']}")
        out.append("")
        for e in sec["entries"]:
            scope = f"**{e['scope']}:** " if e["scope"] else ""
            short = e["sha"][:7]
            link = f"[{short}]({url}/commit/{e['sha']})" if url else short
            issues = ""
            if e["issues"]:
                refs = [f"[#{i}]({url}/issues/{i})" if url and i.isdigit() else (f"#{i}" if i.isdigit() else i) for i in e["issues"]]
                issues = " (" + ", ".join(refs) + ")"
            author = f" by {e['author']}" if authors else ""
            note = f": {e['breaking_note']}" if sec["key"] == "breaking" and e.get("breaking_note") else ""
            out.append(f"- {scope}{e['text']}{note}{issues} ({link}){author}")
        out.append("")
    if authors and notes.get("contributors"):
        out.append("### Contributors")
        out.append("")
        out.append(", ".join(notes["contributors"]))
        out.append("")
    return "\n".join(out)


def git_log(repo: Path, rng: str | None) -> str:
    cmd = ["git", "-C", str(repo), "log", "--no-merges", "--date=short", f"--format={FORMAT}"]
    if rng:
        cmd.append(rng)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git exited {proc.returncode}")
    return proc.stdout


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="repository directory (default: current)")
    ap.add_argument("--range", dest="rng", help="revision range such as v1.2.0..HEAD (default: whole history)")
    ap.add_argument("--input", help="pre-captured git log file ('-' for stdin) instead of running git; capture it with: git log --no-merges --date=short --format='%%H%%x1f%%an%%x1f%%ad%%x1f%%s%%x1f%%b%%x1e' <range>")
    ap.add_argument("--version", help="release name for the heading (default: Unreleased)")
    ap.add_argument("--date", help="release date for the heading (default: today)")
    ap.add_argument("--repo-url", help="base URL for commit and issue links, for example https://github.com/owner/repo")
    ap.add_argument("--authors", action="store_true", help="append the author to each entry and list contributors")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.input == "-":
            raw = sys.stdin.read()
        elif args.input:
            p = Path(args.input)
            if not p.is_file():
                print(f"error: input not found: {args.input}", file=sys.stderr)
                return 2
            raw = p.read_text(encoding="utf-8", errors="replace")
        else:
            raw = git_log(Path(args.repo), args.rng)
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    notes = build(parse_log(raw), args.version, args.date, args.repo_url.rstrip("/") if args.repo_url else None, args.authors)
    print(json.dumps(notes, indent=2) if args.json else render_markdown(notes, args.authors), end="" if not args.json else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
