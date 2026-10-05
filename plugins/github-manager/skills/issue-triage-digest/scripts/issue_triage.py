#!/usr/bin/env python3
"""Issue triage digest from a saved `gh issue list --json` export. Reads files only; no network.

Input folder (export commands are in SKILL.md):
  issues.json          gh issue list --state open --json number,title,url,author,labels,assignees,createdAt,
                       updatedAt,comments,reactionGroups (body optional; it widens the keyword match)
  meta.json            optional, {"repo": "owner/name", "exported_at": "<ISO time>"}: the "as of" time
Files may carry a prefix, for example fixture-issues.json. Split exports (issues-a.json, issues-b.json) are merged.

Checks, each row citing its issue number and URL:
  unlabelled           the issue has no label
  unanswered           nobody but the author (and bots) has commented, and it is older than --unanswered-days
  possible-duplicate   its title shares at least --similarity of its significant words (Jaccard) with an older
                       open issue; the older one is named
  stale                no update for --stale-days days
  popular              at least --reactions thumbs-up reactions
Suggested labels: with --keywords FILE (a small YAML or JSON map of label to keywords), each issue gets the labels
whose keywords appear as whole words in its title (and body, when exported), minus the labels it already has.

Writes text by default, Markdown with --markdown, JSON with --json; --out DIR writes issue-triage.md and
issue-triage.json there instead of printing. Counts per label and per check only; no per-person figures.

Exit codes: 0 nothing flagged, 1 at least one issue flagged, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ghexport import (  # noqa: E402
    InputError,
    Redactor,
    find_file,
    is_bot,
    iso,
    load_json,
    login_of,
    md_cell,
    merge_rows,
    parse_time,
    short,
    stem_files,
)

CHECKS = ("unlabelled", "unanswered", "possible-duplicate", "stale", "popular")
STOP_WORDS = set(
    "a an and are as at be but by can cannot does doesn't for from has have how i in into is it its not of on or "
    "should the this to too was when where which while why will with without".split()
)
WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")


def parse_keyword_map(text: str) -> dict[str, list[str]]:
    """Read `label: [kw, kw]` or `label:` followed by `- kw` lines (or the same as JSON). Raise InputError."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(f"keyword map is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or not all(
            isinstance(v, list) and all(isinstance(x, str) for x in v) for v in data.values()
        ):
            raise InputError("keyword map must map each label to a list of keywords")
        return {str(k): [x.lower() for x in v] for k, v in data.items()}

    def unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    out: dict[str, list[str]] = {}
    current: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        item = re.match(r"^\s+-\s+(.+)$", line)
        if item:
            if current is None:
                raise InputError(f"keyword map line {number}: a list item before any label")
            out[current].append(unquote(item.group(1)).lower())
            continue
        entry = re.match(r"""^("[^"]+"|'[^']+'|[^\s:][^:]*?)\s*:\s*(.*)$""", line)
        if not entry or line[0].isspace():
            raise InputError(f"keyword map line {number}: expected 'label: [keywords]' or '- keyword'")
        current = unquote(entry.group(1))
        out[current] = []
        rest = entry.group(2).strip()
        if rest:
            if not (rest.startswith("[") and rest.endswith("]")):
                raise InputError(f"keyword map line {number}: keywords must be a [list] or '- item' lines")
            out[current] = [unquote(x).lower() for x in rest[1:-1].split(",") if x.strip()]
    if not out:
        raise InputError("keyword map is empty")
    return out


def significant_words(title: str) -> set[str]:
    return {w.strip(".-+") for w in WORD_RE.findall(title.lower()) if w not in STOP_WORDS and len(w) > 2}


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def thumbs_up(issue: dict) -> int:
    for group in issue.get("reactionGroups") or []:
        if isinstance(group, dict) and group.get("content") == "THUMBS_UP":
            users = group.get("users")
            if isinstance(users, dict):
                return int(users.get("totalCount") or 0)
            return int(group.get("totalCount") or 0)
    return 0


def label_names(issue: dict) -> list[str]:
    out = []
    for label in issue.get("labels") or []:
        name = label.get("name") if isinstance(label, dict) else label
        if isinstance(name, str):
            out.append(name)
    return out


def suggest(issue: dict, keyword_map: dict[str, list[str]], have: list[str]) -> list[str]:
    text = f"{issue.get('title') or ''} {issue.get('body') or ''}".lower()
    words = set(WORD_RE.findall(text))
    have_lower = {h.lower() for h in have}
    hits = []
    for label, keywords in keyword_map.items():
        if label.lower() in have_lower:
            continue
        for kw in keywords:
            matched = kw in words if " " not in kw else re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", text)
            if matched:
                hits.append(label)
                break
    return hits


def analyse(folder: Path, args: argparse.Namespace) -> dict:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    paths = stem_files(folder, "issues")
    if not paths:
        raise InputError(f"{folder}: no issues.json (export it with gh issue list --json, see SKILL.md)")
    issues = [i for i in merge_rows(paths) if str(i.get("state", "OPEN")).upper() == "OPEN"]
    meta_path = find_file(folder, "meta")
    meta = load_json(meta_path) if meta_path else {}
    if not isinstance(meta, dict):
        raise InputError("meta.json must be an object")
    if args.now:
        now, source = parse_time(args.now), "--now"
        if now is None:
            raise InputError(f"--now is not an ISO time: {args.now}")
    elif parse_time(meta.get("exported_at")):
        now, source = parse_time(meta.get("exported_at")), "meta.json exported_at"
    else:
        now, source = datetime.now(UTC).replace(microsecond=0), "current time (no meta.json)"
    keyword_map: dict[str, list[str]] = {}
    if args.keywords:
        kpath = Path(args.keywords)
        if not kpath.is_file():
            raise InputError(f"{kpath}: keyword map not found")
        keyword_map = parse_keyword_map(kpath.read_text(encoding="utf-8"))

    logins: set[str] = set()
    for issue in issues:
        for who in [
            issue.get("author"),
            *[c.get("author") for c in issue.get("comments") or [] if isinstance(c, dict)],
        ]:
            if login_of(who):
                logins.add(login_of(who))
    red = Redactor(logins, args.redact)

    rows = []
    for issue in sorted(issues, key=lambda i: i.get("number", 0)):
        number = issue.get("number")
        created = parse_time(issue.get("createdAt"))
        updated = parse_time(issue.get("updatedAt")) or created
        if not isinstance(number, int) or created is None:
            raise InputError(f"issue {number!r}: needs an integer number and createdAt")
        author = login_of(issue.get("author"))
        responders = [
            c
            for c in issue.get("comments") or []
            if isinstance(c, dict) and login_of(c.get("author")) not in (None, author) and not is_bot(c.get("author"))
        ]
        labels = label_names(issue)
        age_days = round((now - created).total_seconds() / 86400, 1)
        idle_days = round((now - updated).total_seconds() / 86400, 1)
        rows.append(
            {
                "number": number,
                "title": red.text(short(issue.get("title"))),
                "url": issue.get("url") or "",
                "labels": labels,
                "assigned": bool(issue.get("assignees")),
                "created": iso(created),
                "updated": iso(updated),
                "age_days": age_days,
                "idle_days": idle_days,
                "comments": len(issue.get("comments") or []),
                "answered": bool(responders),
                "thumbs_up": thumbs_up(issue),
                "suggested_labels": suggest(issue, keyword_map, labels) if keyword_map else [],
                "checks": [],
                "_words": significant_words(issue.get("title") or ""),
            }
        )

    for row in rows:
        if not row["labels"]:
            row["checks"].append("unlabelled")
        if not row["answered"] and row["age_days"] >= args.unanswered_days:
            row["checks"].append("unanswered")
        if row["idle_days"] >= args.stale_days:
            row["checks"].append("stale")
        if row["thumbs_up"] >= args.reactions:
            row["checks"].append("popular")
    for i, row in enumerate(rows):
        best = None
        for older in rows[:i]:
            score = jaccard(row["_words"], older["_words"])
            if score >= args.similarity and (best is None or score > best[1]):
                best = (older["number"], score)
        if best:
            row["checks"].append("possible-duplicate")
            row["duplicate_of"] = best[0]
            row["similarity"] = round(best[1], 2)
    for row in rows:
        row.pop("_words")
        row["checks"] = [c for c in CHECKS if c in row["checks"]]

    by_check = {c: [r["number"] for r in rows if c in r["checks"]] for c in CHECKS}
    by_label: dict[str, int] = {}
    for row in rows:
        for label in row["labels"]:
            by_label[label] = by_label.get(label, 0) + 1
    suggested: dict[str, list[int]] = {}
    for row in rows:
        for label in row["suggested_labels"]:
            suggested.setdefault(label, []).append(row["number"])
    return {
        "repo": meta.get("repo"),
        "as_of": iso(now),
        "as_of_source": source,
        "thresholds": {
            "unanswered_days": args.unanswered_days,
            "stale_days": args.stale_days,
            "reactions": args.reactions,
            "similarity": args.similarity,
        },
        "summary": {
            "open_issues": len(rows),
            "flagged": sorted({r["number"] for r in rows if r["checks"]}),
            "by_check": by_check,
            "by_label": dict(sorted(by_label.items())),
            "suggested_labels": dict(sorted(suggested.items())),
        },
        "issues": [r for r in rows if r["checks"] or r["suggested_labels"]],
    }


def link(row: dict) -> str:
    return f"[#{row['number']}]({row['url']})" if row["url"] else f"#{row['number']}"


def why(row: dict, rep: dict) -> str:
    t = rep["thresholds"]
    parts = []
    for check in row["checks"]:
        if check == "unanswered":
            parts.append(
                f"no reply from anyone but the author in {row['age_days']}d (threshold {t['unanswered_days']}d)"
            )
        elif check == "stale":
            parts.append(f"no update for {row['idle_days']}d (threshold {t['stale_days']}d)")
        elif check == "popular":
            parts.append(f"{row['thumbs_up']} thumbs-up")
        elif check == "possible-duplicate":
            parts.append(f"title {int(row['similarity'] * 100)}% similar to #{row['duplicate_of']}")
        else:
            parts.append("no label")
    return "; ".join(parts)


def render_markdown(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        f"## Issue triage digest: {rep['repo'] or '(repository not recorded)'}",
        "",
        f"As of {rep['as_of']} ({rep['as_of_source']}). **{s['open_issues']} open issues**, "
        f"{len(s['flagged'])} flagged.",
        "",
        "| Check | Count | Issues |",
        "|---|---|---|",
    ]
    for check, numbers in s["by_check"].items():
        lines.append(f"| {check} | {len(numbers)} | {', '.join(f'#{n}' for n in numbers)} |")
    lines += [
        "",
        "### Issues",
        "",
        "| Issue | Title | Labels | Checks | Why | Suggested labels |",
        "|---|---|---|---|---|---|",
    ]
    for row in rep["issues"]:
        lines.append(
            f"| {link(row)} | {md_cell(row['title'])} | {md_cell(', '.join(row['labels']) or '(none)')} | "
            f"{', '.join(row['checks'])} | {md_cell(why(row, rep))} | {md_cell(', '.join(row['suggested_labels']))} |"
        )
    if s["by_label"]:
        lines += ["", "### Open issues per label", "", "| Label | Open |", "|---|---|"]
        lines += [f"| {md_cell(k)} | {v} |" for k, v in s["by_label"].items()]
    return "\n".join(lines) + "\n"


def render_text(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        f"issue triage: {rep['repo'] or '(repository not recorded)'} as of {rep['as_of']} ({rep['as_of_source']})",
        f"{s['open_issues']} open issues, {len(s['flagged'])} flagged",
    ]
    for check, numbers in s["by_check"].items():
        lines.append(f"  {check}: {len(numbers)}" + (f" ({', '.join(f'#{n}' for n in numbers)})" if numbers else ""))
    for row in rep["issues"]:
        extra = f"; suggest: {', '.join(row['suggested_labels'])}" if row["suggested_labels"] else ""
        lines.append(f"#{row['number']} {row['title']}: {why(row, rep) or 'no check fired'}{extra}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="issue_triage.py",
        description="Issue triage digest from saved gh issue list --json output (offline).",
        epilog="Exit codes: 0 nothing flagged, 1 at least one issue flagged, 2 bad input.",
    )
    parser.add_argument("folder", type=Path, help="folder with issues.json and optional meta.json")
    parser.add_argument("--keywords", help="YAML or JSON map of label to keywords, for suggested labels")
    parser.add_argument("--unanswered-days", type=float, default=7.0, help="age before an unanswered issue is flagged")
    parser.add_argument("--stale-days", type=float, default=60.0, help="days without update before stale (default 60)")
    parser.add_argument("--reactions", type=int, default=5, help="thumbs-up count that marks an issue popular")
    parser.add_argument("--similarity", type=float, default=0.6, help="title word overlap for a duplicate (0 to 1)")
    parser.add_argument("--now", help="the 'as of' time (ISO); default meta.json exported_at, else the current time")
    parser.add_argument("--redact", action="store_true", help="replace logins in titles with stable tokens")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON report")
    fmt.add_argument("--markdown", action="store_true", help="Markdown digest with issue links")
    parser.add_argument("--out", type=Path, help="write issue-triage.md and issue-triage.json into this folder")
    args = parser.parse_args(argv)
    if not 0 < args.similarity <= 1:
        print("issue_triage.py: --similarity must be above 0 and at most 1", file=sys.stderr)
        return 2
    try:
        rep = analyse(args.folder, args)
    except InputError as exc:
        print(f"issue_triage.py: {exc}", file=sys.stderr)
        return 2
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "issue-triage.md").write_text(render_markdown(rep), encoding="utf-8")
        (args.out / "issue-triage.json").write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {(args.out / 'issue-triage.md').as_posix()} and {(args.out / 'issue-triage.json').as_posix()}")
    elif args.json:
        print(json.dumps(rep, indent=2))
    elif args.markdown:
        print(render_markdown(rep), end="")
    else:
        print(render_text(rep), end="")
    return 1 if rep["summary"]["flagged"] else 0


if __name__ == "__main__":
    sys.exit(main())
