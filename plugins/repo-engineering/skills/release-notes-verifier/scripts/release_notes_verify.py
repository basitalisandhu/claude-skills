#!/usr/bin/env python3
"""Check a release's notes against the commits that actually landed between two tags.

Notes come from the CHANGELOG section for the --to version (Keep a Changelog style "## [1.2.0]", "## 1.2.0" or
"## v1.2.0", read from the --to revision) or from a file given with --notes. Each bullet is one note.
Commits come from "git log --no-merges <from>..<to>". With --gh, pull request titles are fetched read-only
with "gh pr view" for the (#N) numbers in commit subjects; without it, or when gh fails, commits alone are used.

Findings:
  REL-NOTE-UNMATCHED   a note that matches no commit (by PR number, SHA, backticked name, or shared words)
  REL-COMMIT-UNNOTED   a commit with no matching note, unless its subject matches --chore-pattern
  REL-VERSION          a manifest version at --to that differs from the tag's version (package.json,
                       pyproject.toml, Cargo.toml, .claude-plugin/plugin.json and marketplace.json, setup.cfg,
                       __version__ in Python files)
  REL-LINK             a "## [x.y.z]" heading with no "[x.y.z]: url" reference definition, a section with no
                       compare or release link at all, or a relative link to a file missing at --to
  REL-SECTION          no section for the version in the changelog

git and gh run with fixed argument lists and no shell; nothing is written. Exit codes: 0 consistent, 1 findings,
2 bad input (unknown revision, no git, unreadable notes).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import PurePosixPath

DEFAULT_CHORE = (r"^(chore|ci|build|test|tests|style)(\([^)]*\))?!?:|^Merge (branch|pull request|remote)|^Bump |"
                 r"^Release\b|^v?\d+\.\d+\.\d+$|\[(skip|no) changelog\]")
STOP = set("""a an and are as at be by for from has have in into is it its of on or that the this to was were
will with add added adds fix fixed fixes update updated updates change changed changes new now use uses""".split())
REV_RE = re.compile(r"^[\w./^~@{}-]+$")
GIT_TIMEOUT = 60


class GitError(Exception):
    pass


def git(repo: str, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", repo, "-c", "core.quotepath=off", *args], capture_output=True,
                              text=True, timeout=GIT_TIMEOUT, check=False, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(str(exc)) from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout


def words(text: str) -> set[str]:
    out = set()
    for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]+", text.lower()):
        w = w.strip("-_")
        if len(w) < 3 or w in STOP:
            continue
        for suffix in ("ing", "ed", "es", "s"):
            if w.endswith(suffix) and len(w) - len(suffix) >= 3:
                w = w[: -len(suffix)]
                break
        out.add(w)
    return out


def commits(repo: str, frm: str, to: str) -> list[dict]:
    out = git(repo, "log", "--no-color", "--no-merges", "--format=%x1e%H%x1f%s%x1f%b", f"{frm}..{to}")
    result = []
    for rec in out.split("\x1e")[1:]:
        sha, subject, body = (rec.split("\x1f") + ["", ""])[:3]
        prs = sorted({int(a or b) for a, b in re.findall(r"\(#(\d+)\)|(?:^|\s)#(\d+)\b", subject)})
        result.append({"sha": sha.strip(), "subject": subject.strip(), "body": body.strip(), "prs": prs,
                       "pr_title": None})
    return result


def gh_titles(repo: str, items: list[dict]) -> str:
    if not shutil.which("gh"):
        return "gh not on PATH; commits only"
    fetched = 0
    for c in items:
        for n in c["prs"][:1]:
            try:
                proc = subprocess.run(["gh", "pr", "view", str(n), "--json", "title"], cwd=repo, capture_output=True,
                                      text=True, timeout=20, check=False)
            except (OSError, subprocess.TimeoutExpired):
                return "gh failed; commits only"
            if proc.returncode != 0:
                return "gh could not read pull requests; commits only"
            try:
                c["pr_title"] = json.loads(proc.stdout).get("title")
                fetched += 1
            except json.JSONDecodeError:
                pass
    return f"gh read {fetched} pull request title(s)"


def find_section(text: str, version: str) -> tuple[list[tuple[int, str]], int, str] | None:
    lines = text.splitlines()
    head_re = re.compile(rf"^##\s+\[?v?{re.escape(version)}\]?(?:\s|$|\s*[-(])")
    start = next((i for i, ln in enumerate(lines) if head_re.match(ln)), None)
    if start is None:
        return None
    body = []
    for i in range(start + 1, len(lines)):
        if re.match(r"^##\s", lines[i]):
            break
        body.append((i + 1, lines[i]))
    return body, start + 1, lines[start]


def notes_from(body: list[tuple[int, str]]) -> list[dict]:
    notes: list[dict] = []
    for line, text in body:
        m = re.match(r"^\s*[-*+]\s+(.*)$", text)
        if m and len(text) - len(text.lstrip()) < 2:
            notes.append({"line": line, "text": m.group(1).strip()})
        elif notes and text.strip() and not text.lstrip().startswith("#") and (text.startswith("  ") or
                                                                              text.startswith("\t")):
            notes[-1]["text"] += " " + text.strip()
    return notes


def match(note: dict, c: dict) -> bool:
    text = note["text"]
    refs = {int(n) for n in re.findall(r"#(\d+)\b", text)}
    if refs & set(c["prs"]):
        return True
    if any(len(s) >= 7 and c["sha"].startswith(s.lower()) for s in re.findall(r"\b[0-9a-f]{7,40}\b", text)):
        return True
    ticks = {t.strip("()").lower() for t in re.findall(r"`([^`]+)`", text)}
    commit_text = " ".join(filter(None, [c["subject"], c["body"], c["pr_title"]])).lower()
    if ticks and any(len(t) >= 3 and t in commit_text for t in ticks):
        return True
    a = words(re.sub(r"`[^`]*`|\(#\d+\)|https?://\S+", " ", text))
    best = 0.0
    for candidate in filter(None, [c["subject"], c["pr_title"]]):
        b = words(re.sub(r"^\w+(\([^)]*\))?!?:\s*", "", candidate))
        common = a & b
        if a and b and len(common) >= 2:
            best = max(best, len(common) / min(len(a), len(b)))
    return best >= 0.5


def manifest_versions(repo: str, ref: str) -> list[dict]:
    try:
        tree = git(repo, "ls-tree", "-r", "--name-only", ref).splitlines()
    except GitError:
        return []
    found = []

    def show(path: str) -> str:
        try:
            return git(repo, "show", f"{ref}:{path}")
        except GitError:
            return ""

    for path in tree:
        name = PurePosixPath(path).name
        parts = PurePosixPath(path).parts
        if any(p in {"node_modules", "tests", "test", "fixtures", "examples", "vendor"} for p in parts[:-1]):
            continue
        text = None
        if name in {"package.json", "plugin.json", "marketplace.json"}:
            text = show(path)
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            if isinstance(data.get("version"), str):
                found.append({"path": path, "field": "version", "version": data["version"]})
            meta = data.get("metadata")
            if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                found.append({"path": path, "field": "metadata.version", "version": meta["version"]})
            for p in data.get("plugins", []) if isinstance(data.get("plugins"), list) else []:
                if isinstance(p, dict) and isinstance(p.get("version"), str):
                    found.append({"path": path, "field": f"plugins[{p.get('name')}].version",
                                  "version": p["version"]})
        elif name in {"pyproject.toml", "Cargo.toml"}:
            text = show(path)
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            for table, label in ((data.get("project"), "project.version"), (data.get("package"), "package.version"),
                                 (data.get("tool", {}).get("poetry"), "tool.poetry.version")):
                if isinstance(table, dict) and isinstance(table.get("version"), str):
                    found.append({"path": path, "field": label, "version": table["version"]})
        elif name == "setup.cfg":
            m = re.search(r"^version\s*=\s*([\w.+-]+)\s*$", show(path), re.MULTILINE)
            if m:
                found.append({"path": path, "field": "metadata.version", "version": m.group(1)})
        elif name.endswith(".py") and len(parts) <= 4:
            m = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", show(path), re.MULTILINE)
            if m:
                found.append({"path": path, "field": "__version__", "version": m.group(1)})
    return found


def verify(repo: str, frm: str, to: str, changelog: str, notes_file: str | None, chore: re.Pattern,
           use_gh: bool, version: str | None = None) -> dict:
    if version is None:
        version = re.sub(r"^[^\d]*", "", to.rsplit("/", 1)[-1])
    findings: list[dict] = []
    items = commits(repo, frm, to)
    gh_state = gh_titles(repo, items) if use_gh else "not used (pass --gh to read pull request titles)"
    source = notes_file or f"{changelog} at {to}"
    if notes_file:
        with open(notes_file, encoding="utf-8") as fh:
            text = fh.read()
        section = find_section(text, version)
        if section:
            body, head_line, heading = section
        else:
            body, head_line, heading = list(enumerate(text.splitlines(), 1)), 0, ""
    else:
        try:
            text = git(repo, "show", f"{to}:{changelog}")
        except GitError:
            text = ""
        section = find_section(text, version) if text else None
        if section is None:
            findings.append({"rule": "REL-SECTION", "location": changelog,
                             "detail": f"no section for {version} in {changelog} at {to}"})
            body, head_line, heading = [], 0, ""
        else:
            body, head_line, heading = section
    notes = notes_from(body)
    for c in items:
        c["chore"] = bool(chore.search(c["subject"]))
        c["notes"] = []
    for n in notes:
        n["commits"] = [c["sha"][:12] for c in items if match(n, c)]
        for c in items:
            if c["sha"][:12] in n["commits"]:
                c["notes"].append(n["line"])
        if not n["commits"]:
            findings.append({"rule": "REL-NOTE-UNMATCHED", "location": f"{PurePosixPath(source.split(' at ')[0])}:"
                                                                       f"{n['line']}",
                             "detail": f"no commit in {frm}..{to} matches: {n['text'][:120]}"})
    for c in items:
        if not c["notes"] and not c["chore"]:
            findings.append({"rule": "REL-COMMIT-UNNOTED", "location": c["sha"][:12],
                             "detail": f"commit has no note: {c['subject'][:120]}"})
    versions = manifest_versions(repo, to)
    for v in versions:
        if version and v["version"] != version:
            findings.append({"rule": "REL-VERSION", "location": v["path"],
                             "detail": f"{v['field']} is {v['version']}, the tag says {version}"})
    if heading:
        section_text = "\n".join(t for _, t in body)
        bracket = re.match(r"^##\s+\[([^\]]+)\]", heading)
        if bracket and not re.search(rf"^\[{re.escape(bracket.group(1))}\]:\s*\S+", text, re.MULTILINE):
            findings.append({"rule": "REL-LINK", "location": f"{changelog}:{head_line}",
                             "detail": f"heading [{bracket.group(1)}] has no reference definition "
                                       f"'[{bracket.group(1)}]: <compare or release URL>'"})
        elif not bracket and not re.search(r"https?://\S+", heading + "\n" + section_text):
            findings.append({"rule": "REL-LINK", "location": f"{changelog}:{head_line}",
                             "detail": "the section has no compare or release link"})
        if not notes_file:
            base = PurePosixPath(changelog).parent
            for line, t in body:
                for link in re.findall(r"\]\(([^)#\s]+)", t):
                    if link.startswith(("http://", "https://", "mailto:")):
                        continue
                    target = (base / link).as_posix()
                    try:
                        git(repo, "cat-file", "-e", f"{to}:{target}")
                    except GitError:
                        findings.append({"rule": "REL-LINK", "location": f"{changelog}:{line}",
                                         "detail": f"relative link {link} does not exist at {to}"})
    return {"repo": repo, "from": frm, "to": to, "version": version, "notes_source": source, "gh": gh_state,
            "notes": notes, "commits": [{k: c[k] for k in ("sha", "subject", "prs", "pr_title", "chore", "notes")}
                                        for c in items],
            "versions": versions, "findings": findings}


def render(rep: dict) -> str:
    out = [f"Release notes check: {rep['from']}..{rep['to']} (version {rep['version']})",
           f"notes: {rep['notes_source']}; {len(rep['notes'])} notes, {len(rep['commits'])} commits; {rep['gh']}",
           ""]
    for n in rep["notes"]:
        state = ", ".join(n["commits"]) if n["commits"] else "NO COMMIT"
        out.append(f"  note {n['line']:<4} [{state}] {n['text'][:100]}")
    out.append("")
    for c in rep["commits"]:
        state = "chore" if c["chore"] and not c["notes"] else (f"note line {c['notes'][0]}" if c["notes"]
                                                                else "NO NOTE")
        out.append(f"  {c['sha'][:12]} [{state}] {c['subject'][:100]}")
    out.append("")
    out.append(f"{len(rep['findings'])} finding(s)")
    for f in rep["findings"]:
        out.append(f"  {f['rule']:<19} {f['location']:<28} {f['detail']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="release_notes_verify.py",
                                 description="Compare release notes with the commits between two tags.")
    ap.add_argument("repo", help="repository root (a git work tree)")
    ap.add_argument("--from", dest="frm", required=True, metavar="TAG", help="previous release tag or revision")
    ap.add_argument("--to", required=True, metavar="TAG", help="release tag or revision being checked")
    ap.add_argument("--changelog", default="CHANGELOG.md", help="changelog path at --to (default: CHANGELOG.md)")
    ap.add_argument("--notes", metavar="FILE", help="read the notes from this file instead of the changelog")
    ap.add_argument("--chore-pattern", default=DEFAULT_CHORE, metavar="REGEX",
                    help="commit subjects matching this need no note (default: conventional chore, ci, build, "
                         "test and style prefixes, merges, Bump and Release subjects, [skip changelog])")
    ap.add_argument("--version", dest="version", metavar="X.Y.Z",
                    help="the release version (default: --to with any leading non-digits removed, for example "
                         "v1.2.0 -> 1.2.0)")
    ap.add_argument("--gh", action="store_true",
                    help="also read pull request titles with 'gh pr view' (read-only; contacts GitHub)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    if shutil.which("git") is None:
        print("error: git is not on PATH", file=sys.stderr)
        return 2
    for rev in (args.frm, args.to):
        if rev.startswith("-") or not REV_RE.match(rev):
            print(f"error: not a revision: {rev}", file=sys.stderr)
            return 2
    try:
        chore = re.compile(args.chore_pattern, re.IGNORECASE)
    except re.error as exc:
        print(f"error: bad --chore-pattern: {exc}", file=sys.stderr)
        return 2
    try:
        for rev in (args.frm, args.to):
            git(args.repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        rep = verify(args.repo, args.frm, args.to, args.changelog, args.notes, chore, args.gh, args.version)
    except GitError as exc:
        print(f"error: {exc or 'unknown revision'}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
