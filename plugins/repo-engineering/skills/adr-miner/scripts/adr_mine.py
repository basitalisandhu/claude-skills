#!/usr/bin/env python3
"""Find architecture decisions that were made but never written down, and draft MADR stubs for them.

Sources of decision candidates:
  commit      commit messages with a decision phrase: switch to, replace, adopt, drop, migrate, deprecate,
              in favour of (or favor), move to, instead of
  config      commits that change a dependency manifest, a CI file, a Dockerfile or a compose file in a way
              that looks like a decision: a dependency removed and another added in the same manifest, a
              Dockerfile FROM line changed, or a CI or container file added or deleted (not in the root commit,
              where every file is new)
  comment     TODO, NOTE, FIXME, HACK or XXX comments that carry a rationale (because, since, so that, due to,
              instead of, in favour of, we chose, decided), attributed to a commit with git blame
A commit found by both message and config is one candidate. Each candidate cites the commit SHA (and
path:line for comments) and becomes an ADR stub with status "proposed": context from the commit message and a
diff summary, the decision as the commit states it, and consequences left for the author. Nothing in a stub
is invented; considered options are not in history and are left for the author too.

git is run with a fixed argument list and no shell (log, show, ls-files, blame); nothing is written unless
--out-dir is given, and an existing file is never overwritten. Exit codes: 0 ok, 2 bad input or no git.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

DECISION_RE = re.compile(
    r"\b(switch(?:ed|es|ing)?\s+(?:\w+\s+){0,3}(?:to|from)|replac(?:e|es|ed|ing)|adopt(?:s|ed|ing)?|"
    r"drop(?:s|ped|ping)?|migrat(?:e|es|ed|ing|ion)|deprecat(?:e|es|ed|ing|ion)|in favou?r of|"
    r"mov(?:e|es|ed|ing) to|instead of)\b", re.IGNORECASE)
RATIONALE_RE = re.compile(r"\b(because|since|so that|due to|instead of|in favou?r of|we chose|decided|"
                          r"chosen|trade-?off)\b", re.IGNORECASE)
COMMENT_RE = re.compile(r"(?:#|//|/\*|--|<!--)\s*(TODO|NOTE|FIXME|HACK|XXX)\b[:(]?\s*(.*)$")
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt", "go.mod",
             "Cargo.toml", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "Pipfile",
             "setup.cfg", "setup.py"}
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".rb", ".java", ".kt", ".sh",
            ".yml", ".yaml", ".toml", ".tf", ".sql", ".c", ".h", ".cpp", ".cs", ".php", ".swift"}
GIT_TIMEOUT = 60


class GitError(Exception):
    pass


def git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), "-c", "core.quotepath=off", *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GIT_TIMEOUT, check=False,
                              encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(str(exc)) from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout


def file_kind(path: str) -> str | None:
    name = PurePosixPath(path).name
    if name in MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.(txt|in)", name):
        return "dependency manifest"
    if path.startswith(".github/workflows/") or name in {".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
                                                         "azure-pipelines.yml"} or path.startswith(".circleci/"):
        return "CI"
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
        return "Dockerfile"
    if name.startswith(("docker-compose", "compose.")):
        return "compose"
    return None


def commits(repo: Path, rev_range: str | None, max_count: int) -> list[dict]:
    args = ["log", "--no-color", "--no-merges", "--date=short", f"--max-count={max_count}",
            "--format=%x1e%H%x1f%P%x1f%ad%x1f%an%x1f%s%x1f%b%x1f", "--name-status"]
    if rev_range:
        args.append(rev_range)
    out = git(repo, *args)
    result = []
    for rec in out.split("\x1e")[1:]:
        parts = rec.split("\x1f")
        if len(parts) < 7:
            continue
        sha, parents, date, author, subject, body, names = parts[:7]
        files = []
        for line in names.strip().splitlines():
            cols = line.split("\t")
            if len(cols) >= 2:
                files.append({"status": cols[0][0], "path": cols[-1], "old_path": cols[1] if len(cols) > 2 else None})
        result.append({"sha": sha, "root": not parents.strip(), "date": date, "author": author,
                       "subject": subject.strip(), "body": body.strip(), "files": files})
    return result


def dep_names(lines: list[str], path: str) -> set[str]:
    names: set[str] = set()
    name = PurePosixPath(path).name
    for ln in lines:
        s = ln.strip().strip(",")
        if name == "package.json" or name == "composer.json":
            m = re.match(r'^"(@?[\w.@/-]+)"\s*:\s*"[^"]*"$', s)
            if m and m.group(1) not in {"name", "version", "description", "main", "license", "type"}:
                names.add(m.group(1))
        elif name in {"pyproject.toml", "Pipfile", "setup.cfg"} or name.startswith("requirements"):
            m = re.match(r'^"?([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:[<>=!~^ ]|"|$)', s)
            if m and not s.startswith(("[", "#", "name", "version", "requires-python", "description")):
                names.add(m.group(1).lower())
        elif name == "go.mod":
            m = re.match(r"^(?:require\s+)?([\w.-]+\.[\w./-]+)\s+v", s)
            if m:
                names.add(m.group(1))
        elif name in {"Cargo.toml", "Gemfile"}:
            m = re.match(r"^(?:gem\s+['\"])?([A-Za-z0-9_-]+)['\"]?\s*(?:=|,|$)", s)
            if m and m.group(1) not in {"name", "version", "edition", "authors", "source"}:
                names.add(m.group(1))
    return names


def diff_summary(repo: Path, sha: str, files: list[dict], root: bool = False) -> tuple[list[dict], list[str]]:
    """Per config file: added and removed lines (trimmed), and the reasons it looks like a decision.

    In the root commit every file is new, so additions there are not treated as decisions."""
    summaries, reasons = [], []
    for f in files:
        kind = file_kind(f["path"])
        if not kind:
            continue
        if root:
            continue
        if f["status"] in {"A", "D"} and kind in {"CI", "Dockerfile", "compose"}:
            verb = "added" if f["status"] == "A" else "deleted"
            reasons.append(f"{kind} file {f['path']} {verb}")
            summaries.append({"path": f["path"], "kind": kind, "status": f["status"], "added": [], "removed": []})
            continue
        if f["status"] == "D":
            continue
        try:
            patch = git(repo, "show", "--no-color", "--format=", "--unified=0", sha, "--", f["path"])
        except GitError:
            continue
        added = [ln[1:].rstrip() for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
        removed = [ln[1:].rstrip() for ln in patch.splitlines() if ln.startswith("-") and not ln.startswith("---")]
        added = [a for a in added if a.strip()]
        removed = [r for r in removed if r.strip()]
        summaries.append({"path": f["path"], "kind": kind, "status": f["status"], "added": added[:6],
                          "removed": removed[:6]})
        if kind == "dependency manifest":
            gone = dep_names(removed, f["path"]) - dep_names(added, f["path"])
            new = dep_names(added, f["path"]) - dep_names(removed, f["path"])
            if gone and new:
                reasons.append(f"{f['path']}: removed {', '.join(sorted(gone))}; added {', '.join(sorted(new))}")
        elif kind == "Dockerfile":
            old = [r for r in removed if r.strip().upper().startswith("FROM ")]
            new = [a for a in added if a.strip().upper().startswith("FROM ")]
            if old and new and old != new:
                reasons.append(f"{f['path']}: base image {old[0].split()[1]} -> {new[0].split()[1]}")
    return summaries, reasons


def comment_candidates(repo: Path, limit: int) -> list[dict]:
    try:
        tracked = git(repo, "ls-files", "-z").split("\0")
    except GitError:
        return []
    out = []
    for rel in sorted(t for t in tracked if t):
        if PurePosixPath(rel).suffix not in CODE_EXT and PurePosixPath(rel).name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            path = repo / rel
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = COMMENT_RE.search(line)
            if not m or not RATIONALE_RE.search(m.group(2)):
                continue
            sha = date = author = ""
            try:
                blame = git(repo, "blame", "--porcelain", "-L", f"{i},{i}", "--", rel)
                first = blame.splitlines()[0].split()
                sha = first[0] if first else ""
                am = re.search(r"^author (.*)$", blame, re.MULTILINE)
                tm = re.search(r"^author-time (\d+)$", blame, re.MULTILINE)
                author = am.group(1) if am else ""
                if tm:
                    date = datetime.datetime.fromtimestamp(int(tm.group(1)), datetime.UTC).date().isoformat()
            except (GitError, IndexError):
                pass
            if sha.strip("0") == "":
                sha = ""
            out.append({"source": ["comment"], "sha": sha, "date": date, "author": author,
                        "title": title_from(m.group(2)), "tag": m.group(1), "text": m.group(2).strip(" */->"),
                        "citation": f"{rel}:{i}"})
            if len(out) >= limit:
                return out
    return out


def title_from(subject: str) -> str:
    s = re.sub(r"^(\w+)(\([^)]*\))?!?:\s*", "", subject.strip())
    s = re.sub(r"\s*\(#\d+\)\s*$", "", s)
    s = s.rstrip(".")
    return (s[:1].upper() + s[1:])[:100] if s else "Untitled decision"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "decision"


def stub(n: int, c: dict) -> str:
    sha12 = c["sha"][:12] if c["sha"] else "uncommitted"
    lines = [f"# {n:04d}. {c['title']}", "", "- Status: proposed", f"- Date: {c['date'] or 'unknown'}",
             f"- Deciders: {c['author'] or 'unknown'} (author of the cited change; confirm)"]
    if c.get("citation"):
        lines.append(f"- Source: `{c['citation']}`, last changed in commit {sha12}")
    else:
        lines.append(f"- Source: commit {sha12}")
    lines += ["- Mined by: adr_mine.py; every line below comes from the cited source. Confirm before accepting.",
              "", "## Context and Problem Statement", ""]
    if "comment" in c["source"]:
        lines.append(f"A {c['tag']} comment at `{c['citation']}` records:")
        lines += ["", f"> {c['text']}", ""]
    else:
        lines.append(f"Commit {sha12} says:")
        lines += ["", f"> {c['subject']}"]
        for bl in c.get("body", "").splitlines():
            lines.append(f"> {bl}" if bl.strip() else ">")
        lines.append("")
        if c.get("diff"):
            lines.append("Configuration it changed:")
            lines.append("")
            for d in c["diff"]:
                change = {"A": "added", "D": "deleted"}.get(d["status"], "modified")
                lines.append(f"- `{d['path']}` ({d['kind']}, {change})")
                for r in d["removed"]:
                    lines.append(f"  - removed: `{r.strip()}`")
                for a in d["added"]:
                    lines.append(f"  - added: `{a.strip()}`")
            lines.append("")
        if c.get("reasons"):
            lines.append("Why this was picked up: " + "; ".join(c["reasons"]) + ".")
            lines.append("")
    lines += ["## Considered Options", "",
              "Not recorded in the history. Add only options you can cite (an issue, a pull request, a thread).",
              "", "## Decision Outcome", ""]
    if "comment" in c["source"]:
        lines.append(f"As stated in the comment: {c['text']}")
    else:
        lines.append(f"As stated in the commit: {c['subject']}")
    lines += ["", "## Consequences", "", "To be written by the author: what became easier, what became harder, "
              "and what follow-up work it created.", ""]
    return "\n".join(lines)


def existing_max(out_dir: Path) -> int:
    nums = [int(m.group(1)) for p in out_dir.glob("*.md") if (m := re.match(r"^(\d{3,5})-", p.name))]
    return max(nums, default=0)


def mine(repo: Path, rev_range: str | None, max_count: int, with_comments: bool) -> dict:
    found = []
    for c in commits(repo, rev_range, max_count):
        text = c["subject"] + "\n" + c["body"]
        words = sorted({m.group(1).lower() for m in DECISION_RE.finditer(text)})
        config_files = [f for f in c["files"] if file_kind(f["path"])]
        diff, reasons = diff_summary(repo, c["sha"], config_files, c["root"]) if config_files else ([], [])
        sources = []
        if words:
            sources.append("commit")
        if reasons:
            sources.append("config")
        if not sources:
            continue
        found.append({"source": sources, "sha": c["sha"], "date": c["date"], "author": c["author"],
                      "subject": c["subject"], "body": c["body"], "title": title_from(c["subject"]),
                      "decision_words": words, "reasons": reasons, "diff": diff,
                      "files": [f["path"] for f in c["files"]]})
    if with_comments:
        found += comment_candidates(repo, 200)
    return {"repo": str(repo), "range": rev_range or "HEAD", "candidates": found}


def render(rep: dict) -> str:
    out = [f"ADR candidates: {rep['repo']} ({rep['range']})", f"{len(rep['candidates'])} candidate(s)", ""]
    for i, c in enumerate(rep["candidates"], 1):
        where = c.get("citation") or (c["sha"][:12] if c["sha"] else "")
        out.append(f"{i:>3}. [{'+'.join(c['source'])}] {c['title']}  ({where}, {c['date'] or 'no date'})")
        for r in c.get("reasons", []):
            out.append(f"       {r}")
        if c.get("decision_words"):
            out.append(f"       decision words: {', '.join(c['decision_words'])}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="adr_mine.py",
                                 description="Mine git history and comments for undocumented decisions; draft MADR "
                                             "stubs.")
    ap.add_argument("repo", help="repository root (a git work tree)")
    ap.add_argument("--range", dest="rev_range", metavar="REV", help="revision range, for example v1.0..HEAD")
    ap.add_argument("--max-commits", type=int, default=2000, help="commits to read (default: 2000)")
    ap.add_argument("--no-comments", action="store_true", help="skip TODO and NOTE comment mining")
    ap.add_argument("--out-dir", metavar="DIR",
                    help="write one MADR stub per candidate here, numbered after the highest existing ADR; existing "
                         "files are never overwritten")
    ap.add_argument("--stubs", action="store_true", help="also print each MADR stub (in JSON: a stub_markdown field)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    if shutil.which("git") is None:
        print("error: git is not on PATH", file=sys.stderr)
        return 2
    if args.rev_range and (args.rev_range.startswith("-") or not re.fullmatch(r"[\w./^~@{}-]+", args.rev_range)):
        print(f"error: not a revision range: {args.rev_range}", file=sys.stderr)
        return 2
    try:
        git(repo, "rev-parse", "--is-inside-work-tree")
        rep = mine(repo, args.rev_range, max(1, args.max_commits), not args.no_comments)
    except GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    written = []
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        n = existing_max(out_dir)
        for c in rep["candidates"]:
            n += 1
            path = out_dir / f"{n:04d}-{slug(c['title'])}.md"
            if path.exists():
                continue
            path.write_text(stub(n, c), encoding="utf-8")
            c["stub"] = str(path)
            c["number"] = n
            written.append(str(path))
    rep["written"] = written
    if args.stubs:
        for i, c in enumerate(rep["candidates"], 1):
            c["stub_markdown"] = stub(c.get("number", i), c)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(render(rep))
        for c in rep["candidates"] if args.stubs else []:
            print("\n" + c["stub_markdown"])
        if written:
            print("\nWrote: " + ", ".join(written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
