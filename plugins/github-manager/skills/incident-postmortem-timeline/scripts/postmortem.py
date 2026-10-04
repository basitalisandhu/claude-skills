#!/usr/bin/env python3
"""Blameless postmortem timeline and document skeleton from a saved incident issue export. Offline.

Input folder (export commands are in SKILL.md):
  issue-<N>.json      gh issue view N --json number,title,url,body,author,createdAt,closedAt,state,labels,comments
                      (issue.json also works when its number is N)
  timeline-<N>.json   gh api repos/OWNER/REPO/issues/N/timeline --paginate (labels, assignments, comments,
                      cross-references, closes; timeline.json also works)
  pr-<M>.json         optional, gh pr view M --json number,title,url,state,author,createdAt,mergedAt,labels,
                      mergeCommit for each PR the incident references (or all of them in one array, prs.json);
                      the report lists referenced PRs that are missing, so a second run can fill them in
Files may carry a prefix, for example fixture-issue-412.json.

Builds:
  timeline   every exported event in time order: issue opened, labels added and removed, assignments, comments,
             cross-references, linked PR merges, closes and reopens; each row cites its event id, comment id,
             or PR number and merge time
  phases     detected (issue opened), acknowledged (earliest of: first comment by someone other than the reporter,
             an assignment, an --ack-labels label), mitigated (earliest of: an --mitigated-labels label, the merge of
             a referenced PR whose title or labels match --mitigation-pattern), resolved (earliest of: a
             --resolved-labels label, the issue closing as completed). Every signal found is listed; when two
             signals for one phase disagree, the gap is reported. A phase with no signal is "not found", never
             estimated.
  people     participants as roles (reporter, responder-N, change-author-N, automation-N); names only without --redact
  questions  contributing factors written as questions for the review, never as conclusions
  skeleton   a postmortem document in Markdown that cites each timeline row

Exit codes: 0 written, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ghexport import (  # noqa: E402
    InputError,
    Redactor,
    find_file,
    flatten_pages,
    human_delta,
    is_bot,
    iso,
    load_json,
    login_of,
    md_cell,
    numbered_files,
    parse_time,
    short,
)

DEFAULT_MITIGATION = r"(?i)\b(mitigat\w*|hotfix|revert\w*|roll ?back\w*|disable\w*|feature flag)\b"
DEFAULT_ACK = r"(?i)^(ack|acknowledged|investigating|triaged?)$"
DEFAULT_MITIGATED = r"(?i)^(status: ?)?mitigated$"
DEFAULT_RESOLVED = r"(?i)^(status: ?)?resolved$"
REF_RE = re.compile(r"(?<![\w/])#(\d+)\b")
COMMENT_ID_RE = re.compile(r"issuecomment-(\d+)")


def load_issue(folder: Path, number: int) -> tuple[dict, Path]:
    path = numbered_files(folder, "issue").get(number) or find_file(folder, "issue")
    if path is None:
        raise InputError(f"{folder}: no issue-{number}.json or issue.json; see SKILL.md for the export command")
    issue = load_json(path)
    if not isinstance(issue, dict) or "number" not in issue:
        raise InputError(f"{path}: expected one issue object from gh issue view --json")
    if int(issue["number"]) != number:
        raise InputError(f"{path}: holds issue #{issue['number']}, not #{number}")
    return issue, path


def label_name(ev: dict) -> str:
    label = ev.get("label")
    return str(label.get("name")) if isinstance(label, dict) else str(label or "")


class Roles:
    """Assign roles in order of first appearance: reporter, responder-N, change-author-N, automation-N."""

    def __init__(self, reporter: str | None) -> None:
        self.roles: dict[str, str] = {}
        self.first_seen: dict[str, str] = {}
        self.counts = {"responder": 0, "change-author": 0, "automation": 0}
        if reporter:
            self.roles[reporter.lower()] = "reporter"
            self.first_seen[reporter.lower()] = reporter

    def see(self, actor: object, kind: str = "responder") -> str | None:
        login = login_of(actor)
        if not login:
            return None
        key = login.lower()
        if key not in self.roles:
            kind = "automation" if is_bot(actor) else kind
            self.counts[kind] += 1
            self.roles[key] = f"{kind}-{self.counts[kind]}"
            self.first_seen[key] = login
        elif self.roles[key].startswith("change-author") and kind == "responder":
            pass  # keep the first role; a change author who later comments stays a change author
        return login


def build(folder: Path, number: int, mitigation_pattern: str, ack_labels: str, mitigated_labels: str,
          resolved_labels: str, lookback_hours: float, redact: bool) -> dict:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    try:
        mit_rx, ack_rx = re.compile(mitigation_pattern), re.compile(ack_labels)
        mitl_rx, res_rx = re.compile(mitigated_labels), re.compile(resolved_labels)
    except re.error as exc:
        raise InputError(f"bad pattern: {exc}") from exc
    issue, issue_path = load_issue(folder, number)
    tl_path = numbered_files(folder, "timeline").get(number) or find_file(folder, "timeline")
    events = flatten_pages(load_json(tl_path)) if tl_path else []
    prs_path = find_file(folder, "prs")
    pr_files = numbered_files(folder, "pr")
    prs = {int(p["number"]): p for p in (flatten_pages(load_json(prs_path)) if prs_path else [])
           if isinstance(p, dict) and "number" in p}
    for path in pr_files.values():
        one = load_json(path)
        if not isinstance(one, dict) or "number" not in one:
            raise InputError(f"{path}: expected one pull request object from gh pr view --json")
        prs[int(one["number"])] = one

    opened = parse_time(issue.get("createdAt"))
    if opened is None:
        raise InputError(f"{issue_path}: the issue has no createdAt")
    reporter = login_of(issue.get("author"))
    roles = Roles(reporter)
    rows: list[dict] = []

    def row(when: datetime | None, kind: str, what: str, who: str | None, cite: str, url: str | None = None,
            **extra) -> None:
        if when is None:
            return
        rows.append({"time": when, "kind": kind, "what": what, "who": who, "cite": cite, "url": url, **extra})

    row(opened, "opened", f"Issue opened: {short(issue.get('title'), 80)}", reporter, f"issue #{number} createdAt",
        issue.get("url"))

    referenced: set[int] = set(int(n) for n in REF_RE.findall(issue.get("body") or ""))
    comment_ids: set[str] = set()
    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        kind = ev.get("event")
        when = parse_time(ev.get("created_at") or ev.get("submitted_at"))
        actor = ev.get("actor") or ev.get("user")
        who = roles.see(actor)
        eid = ev.get("id")
        cite = f"event {eid}" if eid is not None else f"timeline row {idx + 1} ({kind}, no event id)"
        if kind == "labeled":
            row(when, "labeled", f"Label added: {label_name(ev)}", who, cite, label=label_name(ev))
        elif kind == "unlabeled":
            row(when, "unlabeled", f"Label removed: {label_name(ev)}", who, cite, label=label_name(ev))
        elif kind == "assigned":
            assignee = roles.see(ev.get("assignee"))
            row(when, "assigned", "Assigned to", who, cite, target=assignee)
        elif kind == "unassigned":
            row(when, "unassigned", "Unassigned", who, cite, target=roles.see(ev.get("assignee")))
        elif kind == "commented":
            comment_ids.add(str(eid))
            body = ev.get("body") or ""
            referenced |= {int(n) for n in REF_RE.findall(body)}
            row(when, "comment", f"Comment: {short(body, 110)}", who, f"comment {eid}", ev.get("html_url"))
        elif kind in {"cross-referenced", "connected"}:
            source = (ev.get("source") or {}).get("issue") or {}
            ref_no = source.get("number")
            if ref_no is not None:
                referenced.add(int(ref_no))
                is_pr = "pull_request" in source
                row(when, "reference", f"Referenced from {'PR' if is_pr else 'issue'} #{ref_no}: "
                    f"{short(source.get('title'), 70)}", who, cite, source.get("html_url"), ref=int(ref_no))
        elif kind in {"closed", "reopened"}:
            reason = ev.get("state_reason")
            row(when, kind, f"Issue {kind}" + (f" ({reason})" if reason else ""), who, cite, state_reason=reason)
        elif kind in {"renamed", "milestoned", "demilestoned", "locked", "transferred"}:
            row(when, kind, f"Issue {kind}", who, cite)

    for c in issue.get("comments") or []:
        if not isinstance(c, dict):
            continue
        m = COMMENT_ID_RE.search(c.get("url") or "")
        cid = m.group(1) if m else str(c.get("id"))
        if cid in comment_ids:
            continue
        comment_ids.add(cid)
        body = c.get("body") or ""
        referenced |= {int(n) for n in REF_RE.findall(body)}
        row(parse_time(c.get("createdAt")), "comment", f"Comment: {short(body, 110)}", roles.see(c.get("author")),
            f"comment {cid}", c.get("url"))

    referenced.discard(number)
    missing_prs = sorted(n for n in referenced if n not in prs and any(r.get("ref") == n for r in rows))
    for n in sorted(referenced):
        pr = prs.get(n)
        if not pr:
            continue
        roles.see(pr.get("author"), "change-author")
        merged = parse_time(pr.get("mergedAt"))
        labels = [str(lb.get("name") if isinstance(lb, dict) else lb) for lb in pr.get("labels") or []]
        sha = (pr.get("mergeCommit") or {}).get("oid") if isinstance(pr.get("mergeCommit"), dict) else None
        mitigation = bool(mit_rx.search(pr.get("title") or "") or any(mit_rx.search(lb) for lb in labels))
        if merged:
            before = merged < opened
            if before and (opened - merged).total_seconds() > lookback_hours * 3600:
                continue
            row(merged, "pr-merged", f"PR #{n} merged: {short(pr.get('title'), 80)}", login_of(pr.get("author")),
                f"PR #{n} mergedAt" + (f", merge commit {sha[:7]}" if sha else ""), pr.get("url"), pr=n,
                mitigation=mitigation, before_detection=before)
        else:
            state = str(pr.get("state") or "open").lower()
            row(parse_time(pr.get("createdAt")), "pr-opened",
                f"PR #{n} opened ({state}, not merged): {short(pr.get('title'), 70)}", login_of(pr.get("author")),
                f"PR #{n} createdAt", pr.get("url"), pr=n, open_followup=True)

    rows.sort(key=lambda r: (r["time"], r["cite"]))

    def who_text(login: str | None) -> str:
        if not login:
            return ""
        role = roles.roles.get(login.lower(), "")
        return role if redact else f"{login} ({role})" if role else login

    red = Redactor(set(roles.first_seen.values()), redact, dict(roles.roles))
    for r in rows:
        r["display"] = red.text(r["what"] + (" " + (who_text(r["target"]) or "?") if "target" in r else ""))

    # Phases.
    def signals(pred) -> list[dict]:
        return [r for r in rows if pred(r)]

    phase_signals = {
        "detected": signals(lambda r: r["kind"] == "opened"),
        "acknowledged": signals(lambda r: (r["kind"] == "comment" and r["who"] and reporter
                                           and r["who"].lower() != reporter.lower()
                                           and not is_bot({"login": r["who"]}))
                                or r["kind"] == "assigned"
                                or (r["kind"] == "labeled" and ack_rx.search(r.get("label") or ""))),
        "mitigated": signals(lambda r: (r["kind"] == "labeled" and mitl_rx.search(r.get("label") or ""))
                             or (r["kind"] == "pr-merged" and r.get("mitigation") and not r.get("before_detection"))),
        "resolved": signals(lambda r: (r["kind"] == "labeled" and res_rx.search(r.get("label") or ""))
                            or (r["kind"] == "closed" and str(r.get("state_reason") or "completed") == "completed")),
    }
    phases, notes = [], []
    for name, sig in phase_signals.items():
        if not sig:
            phases.append({"phase": name, "time": None, "since_detection": None, "signal": "not found in the export",
                           "cite": None, "signals": []})
            continue
        first = sig[0]
        phases.append({"phase": name, "time": iso(first["time"]),
                       "since_detection": human_delta(first["time"] - opened), "signal": first["display"],
                       "cite": first["cite"], "url": first.get("url"),
                       "signals": [{"time": iso(s["time"]), "signal": s["display"], "cite": s["cite"]} for s in sig]})
        kinds = {}
        for s in sig:
            kinds.setdefault(s["kind"], s)
        if len(kinds) > 1:
            later = [s for s in kinds.values() if s is not first]
            for s in later:
                notes.append({"phase": name, "earlier": first["cite"], "later": s["cite"],
                              "gap": human_delta(s["time"] - first["time"]),
                              "text": f"{name}: '{first['display']}' ({first['cite']}, {iso(first['time'])}) came "
                                      f"{human_delta(s['time'] - first['time'])} before '{s['display']}' ({s['cite']}, "
                                      f"{iso(s['time'])}); the timeline uses the earlier signal"})
    order = [p for p in phases if p["time"]]
    for a, b in zip(order, order[1:], strict=False):
        if b["time"] < a["time"]:
            notes.append({"phase": b["phase"], "text": f"{b['phase']} ({b['time']}) is recorded before "
                          f"{a['phase']} ({a['time']}); check which record is right"})

    # Questions, never conclusions.
    questions = [f"The earliest record in this export is the issue opened at {iso(opened)} (issue #{number}). What "
                 "was the first signal of the problem, and when did impact start?"]
    by_phase = {p["phase"]: p for p in phases}
    if by_phase["acknowledged"]["time"]:
        questions.append(f"Detection to acknowledgement took {by_phase['acknowledged']['since_detection']} "
                         f"({by_phase['acknowledged']['cite']}). How did responders learn about the incident, and "
                         "was that the expected path?")
    for n in notes:
        if n["phase"] == "mitigated" and "later" in n:
            questions.append(f"The mitigation signal {n['earlier']} came {n['gap']} before {n['later']}. What "
                             "confirmed that the mitigation worked, and when was that known?")
    for r in rows:
        if r["kind"] == "pr-merged" and r.get("before_detection"):
            questions.append(f"PR #{r['pr']} merged {human_delta(opened - r['time'])} before the issue was opened "
                             f"({r['cite']}); it is listed by time only. Was it related?")
    for r in rows:
        if r["kind"] == "pr-merged" and r.get("mitigation") and re.search(r"(?i)revert|roll ?back", r["what"]):
            questions.append(f"The mitigation included a revert or rollback (PR #{r['pr']}). What would have let "
                             "the team reach it sooner?")
    for p in phases:
        if not p["time"]:
            questions.append(f"No '{p['phase']}' signal was found in the export. When did it happen, and where was "
                             "it recorded?")
    for r in rows:
        if r.get("open_followup"):
            questions.append(f"PR #{r['pr']} is still open. Is it a follow-up action, and is it tracked?")
    if missing_prs:
        questions.append("These referenced PRs are not in prs.json, so their merge times are unknown here: "
                         + ", ".join(f"#{n}" for n in missing_prs) + ". When did each merge, if at all?")

    questions = [red.text(q) or "" for q in questions]

    # People.
    people = [{"role": role, "login": None if redact else roles.first_seen[key]}
              for key, role in sorted(roles.roles.items(), key=lambda kv: _role_key(kv[1]))]

    timeline = [{"time": iso(r["time"]), "since_detection": human_delta(r["time"] - opened), "what": r["display"],
                 "who": who_text(r["who"]), "cite": r["cite"], "url": r.get("url")} for r in rows]

    return {
        "issue": {"number": number, "title": red.text(issue.get("title")), "url": issue.get("url"),
                  "state": issue.get("state"), "labels": [str(lb.get("name") if isinstance(lb, dict) else lb)
                                                          for lb in issue.get("labels") or []]},
        "source_files": sorted(p.name for p in [issue_path, tl_path, prs_path, *pr_files.values()] if p),
        "redacted": redact,
        "phases": phases,
        "phase_notes": notes,
        "timeline": timeline,
        "people": people,
        "questions": questions,
        "referenced_prs_missing_from_export": missing_prs,
    }


def _role_key(role: str) -> tuple[int, int]:
    order = ["reporter", "responder", "change-author", "automation"]
    base, _, num = role.rpartition("-") if role != "reporter" else ("reporter", "", "0")
    return (order.index(base) if base in order else 9, int(num) if num.isdigit() else 0)


def render_markdown(rep: dict) -> str:
    i = rep["issue"]

    def cite(row: dict) -> str:
        return f"[{row['cite']}]({row['url']})" if row.get("url") else str(row.get("cite") or "")

    out = [
        f"# Postmortem: {md_cell(i['title'])} (#{i['number']})",
        "",
        "Status: draft for the review. Blameless: this document describes what happened and what the systems and "
        "processes allowed, not who is at fault. Every timeline row cites the exported event, comment or PR it "
        f"comes from. Source: {', '.join(rep['source_files'])}.",
        "",
        "## Summary",
        "",
        "_To be written at the review, from the timeline below._",
        "",
        "## Impact",
        "",
        "_To be written from monitoring or support data. This export holds no impact figures, so none are given._",
        "",
        "## Phases",
        "",
        "| Phase | Time (UTC) | Since detection | Signal | Citation |",
        "|---|---|---|---|---|",
    ]
    for p in rep["phases"]:
        out.append(f"| {p['phase']} | {p['time'] or 'not found'} | {p['since_detection'] or ''} | "
                   f"{md_cell(p['signal'])} | {cite(p) if p['cite'] else ''} |")
    if rep["phase_notes"]:
        out += ["", "Signals that disagree:", ""] + [f"- {md_cell(n['text'])}" for n in rep["phase_notes"]]
    out += ["", "## Timeline", "", "| Time (UTC) | Since detection | What | Who | Citation |", "|---|---|---|---|---|"]
    out += [f"| {r['time']} | {r['since_detection']} | {md_cell(r['what'])} | {md_cell(r['who'])} | {cite(r)} |"
            for r in rep["timeline"]]
    out += ["", "## People involved", "",
            "Listed as roles in order of first appearance" + (" (names withheld)." if rep["redacted"] else "."), ""]
    out += [f"- {p['role']}" + (f": {p['login']}" if p.get("login") else "") for p in rep["people"]]
    out += ["", "## Questions for the review", "",
            "Contributing factors are written as questions for the review to answer, not as conclusions.", ""]
    out += [f"{n}. {md_cell(q)}" for n, q in enumerate(rep["questions"], 1)]
    out += ["", "## Action items", "", "_Agree at the review. Give each an owner and link it to an issue._", "",
            "| Action | Issue | Owner |", "|---|---|---|", "| | | |"]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="postmortem.py",
        description="Blameless postmortem timeline and skeleton from a saved incident issue export (offline).",
        epilog="Exit codes: 0 written, 2 bad input.",
    )
    parser.add_argument("folder", type=Path, help="folder with issue-<N>.json, timeline-<N>.json and optional prs.json")
    parser.add_argument("--issue", type=int, required=True, help="the incident issue number")
    parser.add_argument("--mitigation-pattern", default=DEFAULT_MITIGATION,
                        help="regex on referenced PR titles and labels that marks a mitigation PR")
    parser.add_argument("--ack-labels", default=DEFAULT_ACK, help="regex for labels that mean acknowledged")
    parser.add_argument("--mitigated-labels", default=DEFAULT_MITIGATED, help="regex for labels that mean mitigated")
    parser.add_argument("--resolved-labels", default=DEFAULT_RESOLVED, help="regex for labels that mean resolved")
    parser.add_argument("--lookback-hours", type=float, default=48.0,
                        help="list referenced PRs merged up to this many hours before detection (default 48)")
    parser.add_argument("--redact", action="store_true", help="show people as roles only, and replace logins in text")
    parser.add_argument("--json", action="store_true", help="JSON report")
    args = parser.parse_args(argv)
    try:
        rep = build(args.folder, args.issue, args.mitigation_pattern, args.ack_labels, args.mitigated_labels,
                    args.resolved_labels, args.lookback_hours, args.redact)
    except InputError as exc:
        print(f"postmortem.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2) if args.json else render_markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
