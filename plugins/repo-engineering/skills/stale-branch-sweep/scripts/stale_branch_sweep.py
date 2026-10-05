#!/usr/bin/env python3
"""Stale-branch report from saved exports, with the delete commands written out for review and never run.

Inputs (export commands are in SKILL.md):
  --branches FILE   gh api repos/OWNER/REPO/branches --paginate (name, commit.sha, protected); the remote's list
  --refs FILE       git for-each-ref refs/remotes/<remote> with the tab-separated format
                    %(refname:short) %(objectname) %(committerdate:iso8601-strict) %(committername)
  --merged FILE     optional, the same for-each-ref output with --merged <remote>/<base>, or one branch per line
                    (git branch -r --merged): branches whose tip is already in the base branch
  --prs FILE        optional, gh pr list --state all --json number,headRefName,headRefOid,state,url

Each branch gets one status (the first that applies):
  base         the --base branch; never proposed
  protected    protected on GitHub; never proposed
  open-pr      an open pull request uses it; kept, with the PR cited
  merged       its tip is in the base branch, or a merged pull request has the same head commit; delete candidate
  stale        last commit older than --days and not merged; delete only after the owner agrees
  no-ref       on GitHub but not in the refs export (fetch with --prune and export again)
  active       none of the above
The owner of a branch is its last committer's name from the refs export.

The report lists `git push <remote> --delete <branch>` for merged branches and, commented out, for stale ones. The
script never runs git or any other command and never deletes anything.

Usage:
    stale_branch_sweep.py --branches branches.json --refs refs.txt [--merged merged.txt] [--prs prs.json]
        [--base main] [--remote origin] [--days 90] [--now ISO] [--json | --markdown] [--out FILE]

Exit codes: 0 nothing to clean up, 1 merged or stale branches for a human to review, 2 bad input.
Standard library only. No network.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import UTC, datetime
from pathlib import Path

STATUSES = ("base", "protected", "open-pr", "merged", "stale", "no-ref", "active")


class BadInput(ValueError):
    pass


def parse_time(text: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).astimezone(UTC)


def read_json(path: str, what: str) -> object:
    p = Path(path)
    if not p.is_file():
        raise BadInput(f"{what} file not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BadInput(f"{what} is not valid JSON: {exc}") from exc
    if isinstance(data, list) and data and all(isinstance(x, list) for x in data):  # gh api --paginate --slurp
        data = [item for page in data for item in page]
    if not isinstance(data, list):
        raise BadInput(f"{what} must be a JSON array")
    return data


def strip_remote(name: str, remote: str) -> str:
    for prefix in (f"refs/remotes/{remote}/", f"{remote}/"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def read_refs(path: str, remote: str) -> dict[str, dict]:
    p = Path(path)
    if not p.is_file():
        raise BadInput(f"refs file not found: {path}")
    refs: dict[str, dict] = {}
    for number, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            raise BadInput(f"refs line {number}: expected 4 tab-separated fields (name, sha, date, committer)")
        name = strip_remote(parts[0].strip(), remote)
        if name in ("HEAD", remote) or name.endswith("/HEAD"):
            continue
        when = parse_time(parts[2])
        if when is None:
            raise BadInput(f"refs line {number}: not an ISO date: {parts[2]!r}")
        refs[name] = {"sha": parts[1].strip(), "date": when, "committer": parts[3].strip() or "(unknown)"}
    return refs


def read_merged(path: str, remote: str) -> set[str]:
    p = Path(path)
    if not p.is_file():
        raise BadInput(f"merged file not found: {path}")
    names = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        field = line.split("\t")[0].strip().lstrip("* ").split(" -> ")[0].strip()
        if field:
            names.add(strip_remote(field, remote))
    return names


def analyse(args: argparse.Namespace) -> dict:
    branches = read_json(args.branches, "branches")
    refs = read_refs(args.refs, args.remote)
    merged = read_merged(args.merged, args.remote) if args.merged else set()
    prs = read_json(args.prs, "pull requests") if args.prs else []
    now = parse_time(args.now) if args.now else datetime.now(UTC).replace(microsecond=0)
    if now is None:
        raise BadInput(f"--now is not an ISO time: {args.now}")
    open_prs: dict[str, list[dict]] = {}
    merged_heads: dict[str, set[str]] = {}
    for pr in prs:
        if not isinstance(pr, dict) or "headRefName" not in pr:
            raise BadInput("every pull request needs headRefName (gh pr list --json headRefName,...)")
        state = str(pr.get("state", "")).upper()
        if state == "OPEN":
            open_prs.setdefault(pr["headRefName"], []).append(pr)
        elif state == "MERGED" and pr.get("headRefOid"):
            merged_heads.setdefault(pr["headRefName"], set()).add(pr["headRefOid"])

    rows = []
    for b in branches:
        if not isinstance(b, dict) or not isinstance(b.get("name"), str):
            raise BadInput("every branch needs a name (gh api repos/OWNER/REPO/branches)")
        name = b["name"]
        ref = refs.get(name)
        sha = (b.get("commit") or {}).get("sha") or (ref or {}).get("sha", "")
        row = {
            "branch": name,
            "sha": sha[:12],
            "owner": ref["committer"] if ref else None,
            "last_commit": ref["date"].strftime("%Y-%m-%dT%H:%M:%SZ") if ref else None,
            "age_days": round((now - ref["date"]).total_seconds() / 86400, 1) if ref else None,
            "prs": [{"number": p.get("number"), "url": p.get("url")} for p in open_prs.get(name, [])],
        }
        merged_by_pr = sha and sha in merged_heads.get(name, set())
        if name == args.base:
            row["status"], row["why"] = "base", "the base branch"
        elif b.get("protected"):
            row["status"], row["why"] = "protected", "protected on GitHub"
        elif row["prs"]:
            row["status"], row["why"] = "open-pr", "open PR " + ", ".join(f"#{p['number']}" for p in row["prs"])
        elif name in merged or merged_by_pr:
            row["status"] = "merged"
            row["why"] = f"tip is in {args.base}" if name in merged else "a merged PR has the same head commit"
        elif ref is None:
            row["status"], row["why"] = "no-ref", "not in the refs export; fetch with --prune and export again"
        elif row["age_days"] >= args.days:
            row["status"], row["why"] = "stale", f"no commit for {row['age_days']}d (threshold {args.days:g}d)"
        else:
            row["status"], row["why"] = "active", f"last commit {row['age_days']}d ago"
        rows.append(row)
    rows.sort(key=lambda r: (STATUSES.index(r["status"]), r["branch"]))
    remote = shlex.quote(args.remote)
    commands = [f"git push {remote} --delete {shlex.quote(r['branch'])}" for r in rows if r["status"] == "merged"]
    review = [f"# git push {remote} --delete {shlex.quote(r['branch'])}" for r in rows if r["status"] == "stale"]
    return {
        "as_of": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base": args.base,
        "remote": args.remote,
        "days": args.days,
        "counts": {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES},
        "branches": rows,
        "delete_commands": commands,
        "stale_commands_for_review": review,
    }


def render(rep: dict, markdown: bool) -> str:
    c = rep["counts"]
    head = (
        f"{len(rep['branches'])} branches as of {rep['as_of']}: {c['merged']} merged, {c['stale']} stale,"
        f" {c['open-pr']} with an open PR, {c['protected']} protected, {c['active']} active,"
        f" {c['no-ref']} without a ref"
    )
    lines = (
        [f"## Stale branch sweep (base {rep['base']})", "", head, ""] if markdown else [f"stale-branch-sweep: {head}"]
    )
    if markdown:
        lines += ["| Status | Branch | Owner (last committer) | Last commit | Why |", "|---|---|---|---|---|"]
        for r in rep["branches"]:
            cell = r["why"].replace("|", "\\|")
            lines.append(
                f"| {r['status']} | `{r['branch']}` | {r['owner'] or ''} | {r['last_commit'] or ''} | {cell} |"
            )
        lines.append("")
    else:
        for r in rep["branches"]:
            lines.append(f"  [{r['status']}] {r['branch']} ({r['owner'] or 'owner unknown'}): {r['why']}")
    block = ["# Merged branches: review, then run these yourself. This script never runs them."]
    block += rep["delete_commands"] or ["# (none)"]
    block += ["# Stale branches: ask each owner first, then uncomment."]
    block += rep["stale_commands_for_review"] or ["# (none)"]
    lines += (["```bash"] + block + ["```"]) if markdown else block
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="stale_branch_sweep.py",
        description="Stale-branch report from saved gh and git exports; prints delete commands, never runs them.",
        epilog="Exit codes: 0 nothing to clean up, 1 merged or stale branches to review, 2 bad input.",
    )
    parser.add_argument("--branches", required=True, help="gh api repos/OWNER/REPO/branches --paginate output")
    parser.add_argument("--refs", required=True, help="git for-each-ref output (name, sha, date, committer; tabs)")
    parser.add_argument("--merged", help="for-each-ref --merged output, or one branch name per line")
    parser.add_argument("--prs", help="gh pr list --state all --json number,headRefName,headRefOid,state,url output")
    parser.add_argument("--base", default="main", help="base branch (default main)")
    parser.add_argument("--remote", default="origin", help="remote name used in the refs and commands")
    parser.add_argument("--days", type=float, default=90.0, help="days without a commit before stale (default 90)")
    parser.add_argument("--now", help="the 'as of' time (ISO); default the current time")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON report")
    fmt.add_argument("--markdown", action="store_true", help="Markdown report")
    parser.add_argument("--out", help="write the report to this file instead of stdout")
    args = parser.parse_args(argv)
    try:
        rep = analyse(args)
    except BadInput as exc:
        print(f"stale_branch_sweep.py: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(rep, indent=2) + "\n" if args.json else render(rep, args.markdown)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 1 if rep["counts"]["merged"] or rep["counts"]["stale"] else 0


if __name__ == "__main__":
    sys.exit(main())
