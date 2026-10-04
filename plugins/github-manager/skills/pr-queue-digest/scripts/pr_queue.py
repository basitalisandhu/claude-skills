#!/usr/bin/env python3
"""Stuck-PR and review-queue digest from saved `gh pr list --json` output. Reads files only; no network.

Input folder (export commands are in SKILL.md):
  prs.json             gh pr list --state open --json number,title,url,author,isDraft,createdAt,updatedAt,
                       reviewDecision,reviewRequests,reviews,commits,statusCheckRollup,mergeable,mergeStateStatus
  timeline-<N>.json    optional, gh api repos/OWNER/REPO/issues/N/timeline --paginate (review_requested and
                       ready_for_review times; without it, waits are measured from the PR's creation time)
  meta.json            optional, {"repo": "owner/name", "exported_at": "<ISO time>"}: the "as of" time
Files may carry a prefix, for example fixture-prs.json or fixture-timeline-101.json.

Checks, each row citing its PR number and URL:
  waiting-on-review                 not a draft, review requested, not approved, waiting longer than --hours
  blocked-on-reviewer               waiting, and the only requested reviewer is one person who has at least
                                    --reviewer-load other pending requests
  no-reviewer                       not a draft, no review requested and no review yet, open longer than --hours
  changes-requested-no-new-commits  the latest blocking review requested changes and no commit came after it
  re-request-needed                 commits came after a changes-requested review, and that reviewer was not
                                    re-requested
  failing-checks                    a check run or status context failed, errored, timed out or was cancelled
  needs-rebase                      mergeable is CONFLICTING, or mergeStateStatus is DIRTY or BEHIND
  approved-not-merged               approved, checks not failing, approved longer than --hours ago
  stale-draft                       a draft not updated for --stale-days days
Then a review-queue table per requested reviewer (counts only, sorted by name, not ranked) and a next-actions list
(nudge, re-request, request a reviewer, fix checks, rebase, merge, close as stale), one per PR, each citing the PR.

Exit codes: 0 nothing flagged, 1 at least one row flagged, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ghexport import (  # noqa: E402
    InputError,
    Redactor,
    find_file,
    flatten_pages,
    hours_between,
    human_hours,
    is_bot,
    iso,
    load_json,
    login_of,
    md_cell,
    numbered_files,
    parse_time,
    short,
)

FAILING = {"FAILURE", "ERROR", "TIMED_OUT", "CANCELLED", "STARTUP_FAILURE", "ACTION_REQUIRED"}
CHECKS = (
    "blocked-on-reviewer",
    "waiting-on-review",
    "no-reviewer",
    "changes-requested-no-new-commits",
    "re-request-needed",
    "failing-checks",
    "needs-rebase",
    "approved-not-merged",
    "stale-draft",
)
# One next action per PR: the first check in this order that flagged it decides the action.
ACTION_FOR = {
    "blocked-on-reviewer": "re-request",
    "failing-checks": "fix checks",
    "needs-rebase": "rebase",
    "re-request-needed": "re-request",
    "changes-requested-no-new-commits": "nudge",
    "waiting-on-review": "nudge",
    "no-reviewer": "request a reviewer",
    "approved-not-merged": "merge",
    "stale-draft": "close as stale",
}
ACTION_ORDER = list(ACTION_FOR)


def requested(pr: dict) -> list[tuple[str, str]]:
    """Pending review requests as (kind, name): ('user', login) or ('team', slug)."""
    out = []
    for req in pr.get("reviewRequests") or []:
        if not isinstance(req, dict):
            continue
        kind = "team" if req.get("__typename") == "Team" or ("slug" in req and "login" not in req) else "user"
        name = req.get("login") if kind == "user" else (req.get("slug") or req.get("name"))
        if name:
            out.append((kind, str(name)))
    return out


def failing_checks(pr: dict) -> list[str]:
    names = []
    for check in pr.get("statusCheckRollup") or []:
        if not isinstance(check, dict):
            continue
        state = str(check.get("conclusion") or check.get("state") or "").upper()
        if state in FAILING:
            names.append(f"{check.get('name') or check.get('context') or 'check'} ({state.lower()})")
    return names


def commit_times(pr: dict) -> list[datetime]:
    times = []
    for commit in pr.get("commits") or []:
        if isinstance(commit, dict):
            t = parse_time(commit.get("committedDate") or commit.get("authoredDate"))
            if t:
                times.append(t)
    return sorted(times)


def reviews_by_others(pr: dict) -> list[dict]:
    author = (login_of(pr.get("author")) or "").lower()
    out = []
    for review in pr.get("reviews") or []:
        if isinstance(review, dict) and (login_of(review.get("author")) or "").lower() != author:
            if parse_time(review.get("submittedAt")):
                out.append(review)
    return sorted(out, key=lambda r: parse_time(r.get("submittedAt")))


def timeline_times(events: list) -> tuple[dict[str, datetime], datetime | None]:
    """Latest review_requested time per reviewer (login or team slug, lowercased) and latest ready_for_review."""
    asked: dict[str, datetime] = {}
    ready = None
    for ev in events:
        if not isinstance(ev, dict):
            continue
        when = parse_time(ev.get("created_at"))
        if not when:
            continue
        if ev.get("event") == "review_requested":
            who = login_of(ev.get("requested_reviewer")) or login_of(ev.get("requested_team"))
            if who:
                asked[who.lower()] = max(when, asked.get(who.lower(), when))
        elif ev.get("event") == "ready_for_review":
            ready = max(when, ready) if ready else when
    return asked, ready


def analyse(folder: Path, hours: float, stale_days: float, reviewer_load: int, now_arg: str | None,
            redact: bool) -> dict:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    prs_path = find_file(folder, "prs")
    if prs_path is None:
        raise InputError(f"{folder}: no prs.json (or <prefix>-prs.json); see SKILL.md for the export command")
    prs = flatten_pages(load_json(prs_path))
    if not all(isinstance(p, dict) and "number" in p for p in prs):
        raise InputError(f"{prs_path}: expected a list of pull requests with a 'number' field")
    meta_path = find_file(folder, "meta")
    meta = load_json(meta_path) if meta_path else {}
    meta = meta if isinstance(meta, dict) else {}
    if now_arg:
        now, now_source = parse_time(now_arg), "--now"
        if now is None:
            raise InputError(f"--now {now_arg!r} is not an ISO date or time")
    elif parse_time(meta.get("exported_at")):
        now, now_source = parse_time(meta.get("exported_at")), f"{meta_path.name} exported_at"
    else:
        now, now_source = datetime.now(UTC).replace(microsecond=0), "current time (no meta.json exported_at)"
    timelines = {n: flatten_pages(load_json(p)) for n, p in numbered_files(folder, "timeline").items()}

    open_prs = [p for p in prs if str(p.get("state") or "OPEN").upper() == "OPEN"]
    logins: set[str] = set()
    for pr in open_prs:
        logins.add(login_of(pr.get("author")) or "")
        logins.update(name for kind, name in requested(pr) if kind == "user")
        logins.update(login_of(r.get("author")) or "" for r in pr.get("reviews") or [] if isinstance(r, dict))
    red = Redactor(logins, redact)

    # Pending requests per reviewer, across all open PRs (drafts included: a request on a draft is still a request).
    queue: dict[tuple[str, str], dict] = {}
    waits: dict[int, dict] = {}
    for pr in open_prs:
        number = int(pr["number"])
        asked, ready = timeline_times(timelines.get(number, []))
        created = parse_time(pr.get("createdAt"))
        for kind, name in requested(pr):
            if number in timelines and name.lower() in asked:
                since, basis = asked[name.lower()], "review requested (timeline)"
            elif ready:
                since, basis = ready, "ready for review (timeline)"
            else:
                since, basis = created, "PR opened (no timeline export)" if number not in timelines else "PR opened"
            wait = hours_between(since, now) if since else None
            entry = queue.setdefault((kind, name), {"prs": [], "waits": []})
            entry["prs"].append(number)
            if wait is not None:
                entry["waits"].append(wait)
            prev = waits.get(number)
            if wait is not None and (prev is None or wait > prev["hours"]):
                waits[number] = {"hours": wait, "since": iso(since), "basis": basis}

    findings: list[dict] = []

    def add(check: str, pr: dict, detail: str, **extra) -> None:
        findings.append({
            "check": check,
            "pr": int(pr["number"]),
            "url": pr.get("url"),
            "title": red.text(short(pr.get("title"), 80)),
            "detail": red.text(detail),
            **extra,
        })

    for pr in sorted(open_prs, key=lambda p: int(p["number"])):
        number = int(pr["number"])
        draft = bool(pr.get("isDraft"))
        decision = str(pr.get("reviewDecision") or "").upper()
        reqs = requested(pr)
        reviews = reviews_by_others(pr)
        commits = commit_times(pr)
        created = parse_time(pr.get("createdAt"))
        updated = parse_time(pr.get("updatedAt")) or created

        if draft:
            if updated and hours_between(updated, now) > stale_days * 24:
                age = hours_between(updated, now)
                add("stale-draft", pr, f"draft, last updated {iso(updated)} ({human_hours(age)} ago)",
                    hours=age, since=iso(updated), basis="updatedAt")
            continue

        bad = failing_checks(pr)
        if bad:
            add("failing-checks", pr, "failing: " + ", ".join(bad), checks=bad)

        mergeable = str(pr.get("mergeable") or "").upper()
        merge_state = str(pr.get("mergeStateStatus") or "").upper()
        if mergeable == "CONFLICTING" or merge_state in {"DIRTY", "BEHIND"}:
            why = "merge conflicts" if mergeable == "CONFLICTING" or merge_state == "DIRTY" else "branch is behind base"
            add("needs-rebase", pr, f"{why} (mergeable={mergeable or 'n/a'}, mergeStateStatus={merge_state or 'n/a'})")

        # Changes requested: who asked, and did commits follow?
        latest_by: dict[str, dict] = {}
        for review in reviews:
            state = str(review.get("state") or "").upper()
            if state in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                latest_by[(login_of(review.get("author")) or "").lower()] = review
        blocking = [r for r in latest_by.values() if str(r.get("state")).upper() == "CHANGES_REQUESTED"]
        pending_users = {name.lower() for kind, name in reqs if kind == "user"}
        for review in blocking:
            reviewer = login_of(review.get("author")) or "?"
            at = parse_time(review.get("submittedAt"))
            after = [c for c in commits if at and c > at]
            if not after:
                add("changes-requested-no-new-commits", pr,
                    f"{red.name(reviewer)} requested changes at {iso(at)}; no commit in the "
                    f"{human_hours(hours_between(at, now))} since",
                    hours=hours_between(at, now), since=iso(at), basis="changes-requested review",
                    reviewer=red.name(reviewer))
            elif reviewer.lower() not in pending_users:
                add("re-request-needed", pr,
                    f"{len(after)} commit(s) after {red.name(reviewer)}'s changes request at {iso(at)}; "
                    f"{red.name(reviewer)} not re-requested",
                    since=iso(at), reviewer=red.name(reviewer))

        if decision == "APPROVED":
            approvals = [r for r in latest_by.values() if str(r.get("state")).upper() == "APPROVED"]
            at = max((parse_time(r.get("submittedAt")) for r in approvals), default=None)
            if at and not bad and hours_between(at, now) > hours:
                add("approved-not-merged", pr, f"approved at {iso(at)} ({human_hours(hours_between(at, now))} ago)",
                    hours=hours_between(at, now), since=iso(at), basis="latest approval")
            continue

        if reqs and number in waits and waits[number]["hours"] > hours and not blocking:
            w = waits[number]
            users = [name for kind, name in reqs if kind == "user"]
            teams = [name for kind, name in reqs if kind == "team"]
            single = users[0] if len(users) == 1 and not teams else None
            others = len(queue[("user", single)]["prs"]) - 1 if single else 0
            names = ", ".join([red.name(u) for u in users] + [f"team {t}" for t in teams])
            if single and others >= reviewer_load:
                add("blocked-on-reviewer", pr,
                    f"only reviewer {red.name(single)} has {others} other pending requests; waiting "
                    f"{human_hours(w['hours'])} since {w['basis']}",
                    hours=w["hours"], since=w["since"], basis=w["basis"], reviewer=red.name(single),
                    reviewer_other_requests=sorted(n for n in queue[("user", single)]["prs"] if n != number))
            add("waiting-on-review", pr, f"waiting {human_hours(w['hours'])} on {names} since {w['basis']}",
                hours=w["hours"], since=w["since"], basis=w["basis"])
        elif not reqs and not reviews and created and hours_between(created, now) > hours:
            age = hours_between(created, now)
            add("no-reviewer", pr, f"open {human_hours(age)}, no review requested and no review",
                hours=age, since=iso(created), basis="PR opened")

    by_pr: dict[int, list[dict]] = {}
    for f in findings:
        by_pr.setdefault(f["pr"], []).append(f)
    actions = []
    for number in sorted(by_pr):
        rows = sorted(by_pr[number], key=lambda f: ACTION_ORDER.index(f["check"]))
        first = rows[0]
        reason = {
            "blocked-on-reviewer": f"ask a second reviewer or reassign: {first['detail']}",
            "failing-checks": f"ask the author to fix: {first['detail']}",
            "needs-rebase": f"ask the author to rebase: {first['detail']}",
            "re-request-needed": f"re-request review from {first.get('reviewer')}: commits since the changes request",
            "changes-requested-no-new-commits": f"check in with the author: {first['detail']}",
            "waiting-on-review": f"nudge the requested reviewers: {first['detail']}",
            "no-reviewer": "request a reviewer: " + first["detail"],
            "approved-not-merged": "merge, or record why it is held: " + first["detail"],
            "stale-draft": "ask the author, then close as stale if abandoned: " + first["detail"],
        }[first["check"]]
        actions.append({"action": ACTION_FOR[first["check"]], "pr": number, "url": first["url"],
                        "reason": reason, "checks": [f["check"] for f in rows]})

    queue_rows = []
    for (kind, name), entry in sorted(queue.items(), key=lambda kv: (kv[0][0] == "team", kv[0][1].lower())):
        queue_rows.append({
            "reviewer": red.name(name) if kind == "user" else f"team {name}",
            "kind": kind,
            "pending": len(entry["prs"]),
            "over_threshold": sum(1 for w in entry["waits"] if w > hours),
            "oldest_hours": max(entry["waits"]) if entry["waits"] else None,
            "prs": sorted(entry["prs"]),
        })

    counts = {c: sorted({f["pr"] for f in findings if f["check"] == c}) for c in CHECKS}
    return {
        "repo": meta.get("repo") or None,
        "as_of": iso(now),
        "as_of_source": now_source,
        "source_files": sorted([prs_path.name] + [p.name for p in numbered_files(folder, "timeline").values()]
                               + ([meta_path.name] if meta_path else [])),
        "thresholds": {"hours": hours, "stale_days": stale_days, "reviewer_load": reviewer_load},
        "redacted": redact,
        "summary": {
            "open_prs": len(open_prs),
            "drafts": sum(1 for p in open_prs if p.get("isDraft")),
            "bot_authored": sorted(int(p["number"]) for p in open_prs if is_bot(p.get("author"))),
            "flagged_prs": sorted(by_pr),
            "by_check": counts,
        },
        "findings": findings,
        "review_queue": queue_rows,
        "next_actions": actions,
    }


def ref(number: int) -> str:
    return f"#{number}"


def render_text(rep: dict) -> str:
    s = rep["summary"]
    t = rep["thresholds"]
    out = [
        f"PR queue digest{' for ' + rep['repo'] if rep['repo'] else ''}, as of {rep['as_of']} ({rep['as_of_source']})",
        f"{s['open_prs']} open PRs ({s['drafts']} drafts, {len(s['bot_authored'])} by bot accounts); "
        f"{len(s['flagged_prs'])} flagged; threshold {t['hours']:g}h, stale drafts after {t['stale_days']:g}d",
        "",
    ]
    for check in CHECKS:
        rows = [f for f in rep["findings"] if f["check"] == check]
        if rows:
            out.append(f"{check} ({len(rows)})")
            out += [f"  {ref(f['pr'])}  {f['detail']}" for f in rows]
    out += ["", "Review queue (pending requests per reviewer, sorted by name, not a ranking)"]
    out += [f"  {r['reviewer']:<16} pending {r['pending']:>2}  over {t['hours']:g}h {r['over_threshold']:>2}  "
            f"oldest {human_hours(r['oldest_hours'])}" for r in rep["review_queue"]]
    out += ["", "Next actions"]
    out += [f"  {a['action']:<18} {ref(a['pr'])}  {a['reason']}" for a in rep["next_actions"]]
    if not rep["next_actions"]:
        out.append("  none")
    return "\n".join(out)


def render_markdown(rep: dict) -> str:
    s = rep["summary"]
    t = rep["thresholds"]

    def link(number: int, url: str | None) -> str:
        return f"[#{number}]({url})" if url else f"#{number}"

    out = [
        f"## PR queue digest{': ' + rep['repo'] if rep['repo'] else ''}",
        "",
        f"As of {rep['as_of']} ({rep['as_of_source']}). Source: {', '.join(rep['source_files'])}. "
        f"Thresholds: waiting over {t['hours']:g} hours, drafts stale after {t['stale_days']:g} days, reviewer load "
        f"{t['reviewer_load']} other requests.",
        "",
        f"**{s['open_prs']} open PRs**, {s['drafts']} drafts, {len(s['bot_authored'])} by bot accounts"
        + (f" ({', '.join(ref(n) for n in s['bot_authored'])})" if s["bot_authored"] else "")
        + f"; {len(s['flagged_prs'])} flagged ({', '.join(ref(n) for n in s['flagged_prs']) or 'none'}).",
        "",
        "### Next actions",
        "",
        "| Action | PR | Why |",
        "|---|---|---|",
    ]
    out += [f"| {a['action']} | {link(a['pr'], a['url'])} | {md_cell(a['reason'])} |" for a in rep["next_actions"]]
    if not rep["next_actions"]:
        out.append("| none | | |")
    out += ["", "### Findings", "", "| Check | PR | Title | Detail |", "|---|---|---|---|"]
    for check in CHECKS:
        out += [f"| {check} | {link(f['pr'], f['url'])} | {md_cell(f['title'])} | {md_cell(f['detail'])} |"
                for f in rep["findings"] if f["check"] == check]
    out += ["", "### Review queue", "",
            "Pending review requests per reviewer, sorted by name. Counts only: this is the queue, not a measure "
            "of anyone.",
            "", f"| Reviewer | Pending | Over {t['hours']:g}h | Oldest wait | PRs |", "|---|---|---|---|---|"]
    out += [f"| {md_cell(r['reviewer'])} | {r['pending']} | {r['over_threshold']} | {human_hours(r['oldest_hours'])} | "
            f"{', '.join(ref(n) for n in r['prs'])} |" for r in rep["review_queue"]]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pr_queue.py",
        description="Stuck-PR and review-queue digest from saved gh pr list --json output (offline).",
        epilog="Exit codes: 0 nothing flagged, 1 at least one PR flagged, 2 bad input.",
    )
    parser.add_argument("folder", type=Path, help="folder with prs.json, optional timeline-<N>.json and meta.json")
    parser.add_argument("--hours", type=float, default=24.0, help="waiting threshold in hours (default 24)")
    parser.add_argument("--stale-days", type=float, default=14.0, help="days without update before a draft is stale "
                        "(default 14)")
    parser.add_argument("--reviewer-load", type=int, default=5,
                        help="other pending requests that make a sole reviewer a blocker (default 5)")
    parser.add_argument("--now", help="the 'as of' time (ISO); default meta.json exported_at, else the current time")
    parser.add_argument("--redact", action="store_true", help="replace logins with stable user-xxxxxx tokens")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON report")
    fmt.add_argument("--markdown", action="store_true", help="Markdown digest (tables with PR links)")
    args = parser.parse_args(argv)
    try:
        rep = analyse(args.folder, args.hours, args.stale_days, args.reviewer_load, args.now, args.redact)
    except InputError as exc:
        print(f"pr_queue.py: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rep, indent=2))
    elif args.markdown:
        print(render_markdown(rep))
    else:
        print(render_text(rep))
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
