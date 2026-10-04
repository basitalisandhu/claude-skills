#!/usr/bin/env python3
"""Team-level iteration report from saved gh exports, with every number cited to its PR or issue rows. Offline.

Input folder (export commands are in SKILL.md):
  prs.json          gh pr list --json number,title,url,state,author,createdAt,mergedAt,closedAt,isDraft,commits,
                    reviews,closingIssuesReferences,body
  issues.json       gh issue list --json number,title,url,state,stateReason,createdAt,closedAt,milestone,
                    assignees,labels
  milestones.json   optional, gh api 'repos/OWNER/REPO/milestones?state=all' --paginate --slurp
An export may be split, for example prs-open.json and prs-closed.json; rows are merged by number. Files may carry
a prefix, for example fixture-prs.json.

For the window --from to --to (dates are whole UTC days, both inclusive):
  shipped           PRs merged in the window, with the issues each one closes (closingIssuesReferences, else
                    "fixes #N" / "closes #N" / "resolves #N" in the PR body)
  merged outside    PRs in the export merged before or after the window (listed so nothing is silently dropped)
  closed unmerged   PRs closed in the window without a merge
  scope             the milestone (--milestone, or the one milestone due in the window), else issues that were open
                    and assigned at the window start; the basis is printed
  completed         scope issues closed as completed in the window; not planned ones are listed apart
  carried over      scope issues still open at the end of the window
  newly opened      issues created in the window (marked when they are in scope)
  cycle time        per shipped PR, from the first commit (--cycle-start first-commit, the default; falls back to the
                    PR creation time when the export has no commits, and says so per PR) or from PR creation
                    (--cycle-start pr-open) to merge; median and p90 (nearest rank), in hours
  review turnaround per shipped PR, from PR creation to the first review by someone other than the author; median;
                    PRs merged with no such review are listed
Team level only: no per-person counts, rankings or author columns.

Exit codes: 0 report written, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ghexport import (  # noqa: E402
    InputError,
    Redactor,
    find_file,
    flatten_pages,
    hours_between,
    human_hours,
    iso,
    load_json,
    login_of,
    md_cell,
    median,
    merge_rows,
    parse_time,
    percentile_nearest_rank,
    short,
    stem_files,
)

CLOSING_RE = re.compile(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+#(\d+)\b")


def window(start: str, end: str) -> tuple[datetime, datetime]:
    """[start, end) in UTC. A bare end date covers that whole day."""
    lo, hi = parse_time(start), parse_time(end)
    if lo is None or hi is None:
        raise InputError("--from and --to must be ISO dates (2026-09-14) or times")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", end.strip()):
        hi += timedelta(days=1)
    if hi <= lo:
        raise InputError("--to must not be before --from")
    return lo, hi


def linked_issues(pr: dict) -> tuple[list[int], str]:
    refs = pr.get("closingIssuesReferences")
    if isinstance(refs, list) and refs:
        found = sorted({int(r["number"]) for r in refs if isinstance(r, dict) and "number" in r})
        return found, "closingIssuesReferences"
    found = sorted({int(n) for n in CLOSING_RE.findall(pr.get("body") or "")})
    return found, ("PR body keywords" if found else "none")


def first_commit(pr: dict) -> datetime | None:
    times = [parse_time(c.get("authoredDate") or c.get("committedDate")) for c in pr.get("commits") or []
             if isinstance(c, dict)]
    times = [t for t in times if t]
    return min(times) if times else None


def first_review(pr: dict) -> datetime | None:
    author = (login_of(pr.get("author")) or "").lower()
    times = []
    for r in pr.get("reviews") or []:
        if not isinstance(r, dict) or str(r.get("state") or "").upper() == "PENDING":
            continue
        if (login_of(r.get("author")) or "").lower() == author:
            continue
        t = parse_time(r.get("submittedAt"))
        if t:
            times.append(t)
    return min(times) if times else None


def milestone_of(issue: dict) -> dict | None:
    m = issue.get("milestone")
    return m if isinstance(m, dict) and m.get("title") else None


def analyse(folder: Path, start: str, end: str, milestone: str | None, cycle_start: str, redact: bool) -> dict:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    lo, hi = window(start, end)
    prs_paths, issues_paths = stem_files(folder, "prs"), stem_files(folder, "issues")
    if not prs_paths or not issues_paths:
        raise InputError(f"{folder}: needs prs.json and issues.json (or prs-<part>.json, issues-<part>.json, "
                         "optionally with a prefix such as fixture-)")
    prs = merge_rows(prs_paths)
    issues = merge_rows(issues_paths)
    ms_path = find_file(folder, "milestones")
    milestones = flatten_pages(load_json(ms_path)) if ms_path else []

    logins = {login_of(p.get("author")) or "" for p in prs} | {login_of(i.get("author")) or "" for i in issues}
    for i in issues:
        logins |= {login_of(a) or "" for a in i.get("assignees") or []}
    red = Redactor(logins, redact)
    issue_by_no = {int(i["number"]): i for i in issues}

    def inside(t: datetime | None) -> bool:
        return t is not None and lo <= t < hi

    # Scope.
    due_in_window = set()
    for m in milestones:
        if isinstance(m, dict) and inside(parse_time(m.get("due_on") or m.get("dueOn"))):
            due_in_window.add(m.get("title"))
    for i in issues:
        m = milestone_of(i)
        if m and inside(parse_time(m.get("dueOn") or m.get("due_on"))):
            due_in_window.add(m["title"])
    due_in_window.discard(None)
    if milestone:
        scope_basis = f"milestone {milestone!r} (--milestone)"
        scope_ms = milestone
    elif len(due_in_window) == 1:
        scope_ms = next(iter(due_in_window))
        scope_basis = f"milestone {scope_ms!r} (the one milestone due in the window)"
    else:
        scope_ms = None
        scope_basis = ("issues open and assigned at the window start"
                       + (f"; several milestones are due in the window ({', '.join(sorted(due_in_window))}), "
                          "pass --milestone to pick one" if due_in_window else "; no milestone is due in the window"))

    def in_scope(i: dict) -> bool:
        if scope_ms is not None:
            m = milestone_of(i)
            return bool(m and m["title"] == scope_ms)
        created, closed = parse_time(i.get("createdAt")), parse_time(i.get("closedAt"))
        return bool(created and created < lo and (closed is None or closed >= lo) and i.get("assignees"))

    scope = sorted((i for i in issues if in_scope(i)), key=lambda i: int(i["number"]))
    if scope_ms is not None and not scope:
        raise InputError(f"no issue in the export has milestone {scope_ms!r}")

    def issue_row(i: dict, **extra) -> dict:
        return {"number": int(i["number"]), "url": i.get("url"), "title": red.text(short(i.get("title"), 80)), **extra}

    completed, not_planned, carried = [], [], []
    for i in scope:
        closed = parse_time(i.get("closedAt"))
        created = parse_time(i.get("createdAt"))
        if created and created >= hi:
            continue
        reason = str(i.get("stateReason") or "COMPLETED").upper()
        if closed and closed < hi:
            if closed >= lo:
                (not_planned if reason == "NOT_PLANNED" else completed).append(issue_row(i, closed=iso(closed)))
        else:
            carried.append(issue_row(i, state="open" if not closed else f"closed after the window ({iso(closed)})"))
    scope_numbers = {int(i["number"]) for i in scope}
    opened = [issue_row(i, created=iso(parse_time(i.get("createdAt"))), in_scope=int(i["number"]) in scope_numbers)
              for i in sorted(issues, key=lambda i: int(i["number"])) if inside(parse_time(i.get("createdAt")))]

    shipped, outside, closed_unmerged = [], [], []
    for pr in sorted(prs, key=lambda p: int(p["number"])):
        merged, closed = parse_time(pr.get("mergedAt")), parse_time(pr.get("closedAt"))
        base = {"number": int(pr["number"]), "url": pr.get("url"), "title": red.text(short(pr.get("title"), 80))}
        if merged and inside(merged):
            created = parse_time(pr.get("createdAt"))
            fc = first_commit(pr)
            if cycle_start == "first-commit" and fc:
                start_t, start_basis = min(fc, created) if created else fc, "first commit"
                if created and created < fc:
                    start_basis = "PR opened (before its first commit)"
            else:
                start_t = created
                start_basis = "PR opened" if cycle_start == "pr-open" else "PR opened (no commits in the export)"
            review = first_review(pr)
            links, link_basis = linked_issues(pr)
            shipped.append({**base, "merged": iso(merged), "issues": links, "issues_basis": link_basis,
                            "cycle_start": iso(start_t), "cycle_start_basis": start_basis,
                            "cycle_hours": hours_between(start_t, merged) if start_t else None,
                            "first_review": iso(review),
                            "review_hours": hours_between(created, review) if review and created else None})
        elif merged:
            outside.append({**base, "merged": iso(merged), "when": "before" if merged < lo else "after"})
        elif closed and inside(closed) and str(pr.get("state") or "").upper() == "CLOSED":
            closed_unmerged.append({**base, "closed": iso(closed)})

    cycle = [p["cycle_hours"] for p in shipped if p["cycle_hours"] is not None]
    review = [p["review_hours"] for p in shipped if p["review_hours"] is not None]
    bases = sorted({p["cycle_start_basis"] for p in shipped})
    shipped_issue_numbers = sorted({n for p in shipped for n in p["issues"]})
    return {
        "window": {"from": iso(lo), "to_exclusive": iso(hi), "inclusive_dates": f"{start} to {end}"},
        "source_files": sorted(p.name for p in [*prs_paths, *issues_paths, ms_path] if p),
        "scope": {"basis": scope_basis, "milestone": scope_ms, "issues": sorted(scope_numbers)},
        "redacted": redact,
        "shipped": shipped,
        "shipped_issues": [issue_row(issue_by_no[n]) if n in issue_by_no else {"number": n, "url": None,
                           "title": "(not in the issues export)"} for n in shipped_issue_numbers],
        "shipped_without_issue": [p["number"] for p in shipped if not p["issues"]],
        "merged_outside_window": outside,
        "closed_unmerged": closed_unmerged,
        "completed": completed,
        "not_planned": not_planned,
        "carried_over": carried,
        "newly_opened": opened,
        "metrics": {
            "cycle_time": {"start": cycle_start, "start_bases": bases, "unit": "hours", "n": len(cycle),
                           "median": median(cycle), "p90": percentile_nearest_rank(cycle, 90),
                           "method": "median (mean of the two middle values when n is even); p90 by nearest rank",
                           "rows": [p["number"] for p in shipped if p["cycle_hours"] is not None]},
            "review_turnaround": {"from": "PR opened", "to": "first review by someone other than the author",
                                  "unit": "hours", "n": len(review), "median": median(review),
                                  "rows": [p["number"] for p in shipped if p["review_hours"] is not None],
                                  "merged_without_review": [p["number"] for p in shipped if p["review_hours"] is None]},
        },
        "team_level_only": True,
    }


def refs(rows: list) -> str:
    nums = [r if isinstance(r, int) else r["number"] for r in rows]
    return ", ".join(f"#{n}" for n in nums) if nums else "none"


def render_markdown(rep: dict) -> str:
    w, m = rep["window"], rep["metrics"]
    ct, rt = m["cycle_time"], m["review_turnaround"]
    start_word = "first commit" if ct["start"] == "first-commit" else "PR creation"

    def link(r: dict) -> str:
        return f"[#{r['number']}]({r['url']})" if r.get("url") else f"#{r['number']}"

    summary = [
        f"- Shipped {len(rep['shipped'])} PRs ({refs(rep['shipped'])}), closing {len(rep['shipped_issues'])} issues "
        f"({refs(rep['shipped_issues'])}); shipped PRs that link no issue: {len(rep['shipped_without_issue'])} "
        f"({refs(rep['shipped_without_issue'])}).",
        f"- Scope: {rep['scope']['basis']}, {len(rep['scope']['issues'])} issues ({refs(rep['scope']['issues'])}). "
        f"Completed {len(rep['completed'])} ({refs(rep['completed'])}), closed as not planned "
        f"{len(rep['not_planned'])} ({refs(rep['not_planned'])}), carried over {len(rep['carried_over'])} "
        f"({refs(rep['carried_over'])}).",
        f"- Newly opened in the window: {len(rep['newly_opened'])} issues ({refs(rep['newly_opened'])}), of which "
        f"{sum(1 for r in rep['newly_opened'] if r['in_scope'])} in scope "
        f"({refs([r for r in rep['newly_opened'] if r['in_scope']])}).",
        f"- Cycle time ({start_word} to merge, n={ct['n']}, rows {refs(ct['rows'])}): median "
        f"{human_hours(ct['median'])}, p90 {human_hours(ct['p90'])}. "
        f"Start bases used: {', '.join(ct['start_bases']) or 'none'}.",
        f"- Review turnaround (PR creation to first review by someone other than the author, n={rt['n']}, rows "
        f"{refs(rt['rows'])}): median {human_hours(rt['median'])}. Merged with no such review: "
        f"{len(rt['merged_without_review'])} ({refs(rt['merged_without_review'])}).",
        f"- Not counted: {len(rep['merged_outside_window'])} PRs merged outside the window "
        f"({refs(rep['merged_outside_window'])}) and {len(rep['closed_unmerged'])} closed without merging "
        f"({refs(rep['closed_unmerged'])}).",
    ]
    out = [f"## Iteration report: {w['inclusive_dates']}", "",
           f"Window {w['from']} to {w['to_exclusive']} (UTC, end exclusive). Source: {', '.join(rep['source_files'])}. "
           "Team level only: no per-person counts or rankings.", "", "### Summary", "", *summary, "",
           "### Shipped", "", "| PR | Title | Merged | Closes | Cycle start | Cycle time | First review after |",
           "|---|---|---|---|---|---|---|"]
    for p in rep["shipped"]:
        closes = f"{refs(p['issues'])} ({p['issues_basis']})" if p["issues"] else "none"
        review = human_hours(p["review_hours"]) if p["review_hours"] is not None else "no review"
        out.append(f"| {link(p)} | {md_cell(p['title'])} | {p['merged']} | {closes} | {p['cycle_start_basis']} | "
                   f"{human_hours(p['cycle_hours'])} | {review} |")
    sections = (("Carried over", rep["carried_over"], "state"), ("Completed", rep["completed"], "closed"),
                ("Closed as not planned", rep["not_planned"], "closed"),
                ("Newly opened", rep["newly_opened"], "created"),
                ("Merged outside the window (not counted)", rep["merged_outside_window"], "merged"),
                ("Closed without merging (not counted)", rep["closed_unmerged"], "closed"))
    for title, rows, key in sections:
        out += ["", f"### {title}", ""]
        if not rows:
            out.append("None.")
            continue
        out += [f"| Row | Title | {key.capitalize()} |", "|---|---|---|"]
        for r in rows:
            extra = r[key] + (" (in scope)" if r.get("in_scope") else "") if key == "created" else r[key]
            out.append(f"| {link(r)} | {md_cell(r['title'])} | {md_cell(extra)} |")
    out += ["", f"Method: {ct['method']}. Durations are wall-clock hours from the exported timestamps; nothing is "
            "estimated, and a row missing a timestamp is left out of that figure."]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iteration_report.py",
        description="Team-level iteration report from saved gh pr list and gh issue list exports (offline).",
        epilog="Exit codes: 0 report written, 2 bad input.",
    )
    parser.add_argument("folder", type=Path, help="folder with prs.json, issues.json and optional milestones.json")
    parser.add_argument("--from", dest="start", required=True, help="first day of the window (YYYY-MM-DD, UTC)")
    parser.add_argument("--to", dest="end", required=True, help="last day of the window, inclusive (YYYY-MM-DD, UTC)")
    parser.add_argument("--milestone", help="milestone title that defines the iteration scope")
    parser.add_argument("--cycle-start", choices=("first-commit", "pr-open"), default="first-commit",
                        help="where cycle time starts (default first-commit)")
    parser.add_argument("--redact", action="store_true", help="replace logins in titles with user-xxxxxx tokens")
    parser.add_argument("--json", action="store_true", help="JSON report")
    args = parser.parse_args(argv)
    try:
        rep = analyse(args.folder, args.start, args.end, args.milestone, args.cycle_start, args.redact)
    except InputError as exc:
        print(f"iteration_report.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2) if args.json else render_markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
