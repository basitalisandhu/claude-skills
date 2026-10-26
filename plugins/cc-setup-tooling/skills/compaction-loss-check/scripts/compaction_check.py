#!/usr/bin/env python3
"""Check what each compaction in a Claude Code session may have dropped, and print what to re-state.

A transcript marks every compaction with a `compact_boundary` system line (trigger, tokens before and after) and
follows it with the summary the session continues from. For each boundary this script lists the trigger, the
tokens before and after, and the time since the last user message (an idle compaction happens after a long gap),
then checks the summary for what the session had collected before the boundary:

  - user instructions that look like standing rules (lines with never, always, do not, don't, must, only,
    from now on, stop)
  - files the session edited or wrote (Edit, Write, NotebookEdit and MultiEdit inputs)
  - branches it created (git checkout -b, git switch -c, git branch, git worktree add -b) and pull request numbers
  - open items of the last TodoWrite list, or of TaskCreate and TaskUpdate calls

A rule counts as kept when its key phrase (from the trigger word on, up to eight words) appears in the summary,
partly kept when most of its content words do, and missing otherwise; a file when its path or base name appears;
a branch or pull request when its name or number appears. Matching ignores case. --emit-recap prints a paste-ready
block of what is missing at the last boundary of each session.

Usage:
  compaction_check.py ~/.claude/projects
  compaction_check.py session.jsonl --format markdown
  compaction_check.py ~/.claude/projects --since 2026-10-20 --emit-recap

Local files only, no network. Exit codes: 0 nothing missing, 1 a standing rule or an edited file is missing from
a summary, 2 bad input (missing path, bad option, no compaction found, unwritable --out).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _transcript as tx  # noqa: E402

PROG = "compaction_check.py"
RULE_RE = re.compile(r"\b(never|always|do not|don't|dont|must|only|from now on|stop)\b", re.IGNORECASE)
REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL | re.IGNORECASE)
TAGGED_RE = re.compile(r"^\s*<([a-z-]+)>.*</\1>\s*$", re.DOTALL)
BRANCH_RE = re.compile(
    r"\bgit\s+(?:checkout\s+-[bB]|switch\s+-[cC]|branch(?!\s+-)|worktree\s+add\s+(?:\S+\s+)*?-[bB])\s+"
    r"(?P<name>[A-Za-z0-9][\w./-]*)"
)
PR_URL_RE = re.compile(r"/pull/(\d+)\b")
EDIT_TOOLS = {"Edit": "file_path", "Write": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
STOP = set(
    "a an and are as at be but by for from have i if in into is it its me my of on or our so than that the their them "
    "then there these this those to us was we were what when which who will with you your".split()
)


@dataclass
class Item:
    kind: str
    text: str
    first_line: str
    status: str = ""


@dataclass
class State:
    rules: dict[str, Item] = field(default_factory=dict)
    files: dict[str, Item] = field(default_factory=dict)
    branches: dict[str, Item] = field(default_factory=dict)
    prs: dict[str, Item] = field(default_factory=dict)
    todos: dict[str, dict] = field(default_factory=dict)
    task_counter: int = 0
    pending_pr: set[str] = field(default_factory=set)
    last_user_ts: object = None


def user_instruction_text(rec: tx.Record) -> str:
    """The text a person typed: user lines that are not tool results, meta lines or compaction summaries."""
    d = rec.data
    if d.get("isMeta") is True or d.get("isCompactSummary") is True:
        return ""
    msg = d.get("message")
    if not isinstance(msg, dict):
        return ""
    if any(b.get("type") == "tool_result" for b in tx.content_blocks(msg)):
        return ""
    text = REMINDER_RE.sub("", tx.message_text(msg))
    if TAGGED_RE.match(text):  # command echoes such as <command-name>...</command-name>
        return ""
    return text


def rule_lines(text: str) -> list[str]:
    out = []
    for raw in re.split(r"[\n\r]+|(?<=[.!?])\s+", text):
        line = raw.strip(" -*\t>")
        if 8 <= len(line) <= 300 and RULE_RE.search(line) and not line.startswith(("```", "http")):
            out.append(line)
    return out


def key_phrase(rule: str) -> str:
    m = RULE_RE.search(rule)
    words = rule[m.start() :].split() if m else rule.split()
    return " ".join(words[:8]).rstrip(".,;:!?")


def content_words(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9][a-z0-9_.-]*", text.lower()) if len(w) > 2 and w not in STOP]


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def check_rule(rule: str, summary: str) -> str:
    phrase = norm(key_phrase(rule))
    if phrase and phrase in summary:
        return "kept"
    words = set(content_words(key_phrase(rule))) - {m.lower() for m in RULE_RE.findall(rule)}
    if words:
        present = sum(1 for w in words if w in summary)
        if present / len(words) >= 0.6:
            return "partly"
    return "missing"


def base_name(path: str) -> str:
    return (PureWindowsPath(path).name if "\\" in path else PurePosixPath(path).name) or path


def check_file(path: str, summary: str) -> str:
    if path.lower() in summary:
        return "kept"
    return "kept" if base_name(path).lower() in summary else "missing"


def check_pr(number: str, summary: str) -> str:
    pat = rf"(?:#|pull/|\bpr\s*#?|pull request\s*#?){re.escape(number)}\b"
    return "kept" if re.search(pat, summary) else "missing"


def todo_update(state: State, name: str, inp: dict, where: str) -> None:
    if name == "TodoWrite" and isinstance(inp.get("todos"), list):
        state.todos = {}
        for i, t in enumerate(inp["todos"]):
            if isinstance(t, dict) and isinstance(t.get("content"), str):
                state.todos[str(t.get("id", i))] = {
                    "text": t["content"],
                    "status": str(t.get("status", "")),
                    "at": where,
                }
    elif name == "TaskCreate":
        state.task_counter += 1
        text = next((inp[k] for k in ("subject", "title", "description", "content") if isinstance(inp.get(k), str)), "")
        if text:
            state.todos[str(state.task_counter)] = {"text": text, "status": "pending", "at": where}
    elif name == "TaskUpdate":
        tid = str(inp.get("taskId", inp.get("id", "")))
        if tid in state.todos and isinstance(inp.get("status"), str):
            state.todos[tid]["status"] = inp["status"]


def find_summary(records: list[tx.Record], start: int) -> tuple[str | None, int | None]:
    """The compaction summary after a boundary: the next user line with isCompactSummary, before the next boundary
    or human message."""
    for rec in records[start + 1 : start + 60]:
        d = rec.data
        if d.get("isCompactSummary") is True:
            return tx.message_text(d.get("message")), rec.line
        if d.get("subtype") == "compact_boundary":
            break
        if rec.type == "user" and user_instruction_text(rec).strip():
            break
    return None, None


def analyse_file(records: list[tx.Record], since, until, idle_minutes: float) -> tuple[list[dict], bool]:
    """Boundaries of one transcript file. Returns the boundary reports and whether the file starts after an earlier
    compaction (so items said before it are not available)."""
    state = State()
    boundaries = []
    starts_compacted = False
    seen_conversation = False
    for i, rec in enumerate(records):
        d = rec.data
        where = f"{rec.path.name}:{rec.line}"
        if rec.type == "pr-link" and isinstance(d.get("prNumber"), int):
            state.prs.setdefault(str(d["prNumber"]), Item("pr", f"#{d['prNumber']}", where))
            continue
        if d.get("isCompactSummary") is True and not seen_conversation:
            starts_compacted = True
        if rec.type == "user":
            text = user_instruction_text(rec)
            if text.strip():
                seen_conversation = True
                state.last_user_ts = tx.parse_ts(d.get("timestamp")) or state.last_user_ts
                for line in rule_lines(text):
                    state.rules.setdefault(norm(line), Item("rule", line, where))
            for b in tx.content_blocks(d.get("message")):
                if b.get("type") == "tool_result":
                    tid = b.get("tool_use_id")
                    if tid in state.pending_pr:
                        for num in PR_URL_RE.findall(tx.tool_result_text(b)):
                            state.prs.setdefault(num, Item("pr", f"#{num}", where))
        elif rec.type == "assistant":
            seen_conversation = True
            for b in tx.content_blocks(d.get("message")):
                if b.get("type") != "tool_use":
                    continue
                name = b.get("name")
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                if name in EDIT_TOOLS and isinstance(inp.get(EDIT_TOOLS[name]), str):
                    path = inp[EDIT_TOOLS[name]]
                    state.files.setdefault(path, Item("file", path, where))
                elif name in ("TodoWrite", "TaskCreate", "TaskUpdate"):
                    todo_update(state, name, inp, where)
                elif name == "Bash" and isinstance(inp.get("command"), str):
                    cmd = inp["command"]
                    for m in BRANCH_RE.finditer(cmd):
                        state.branches.setdefault(m.group("name"), Item("branch", m.group("name"), where))
                    if re.search(r"\bgh\s+pr\s+create\b", cmd) and isinstance(b.get("id"), str):
                        state.pending_pr.add(b["id"])
        elif rec.type == "system" and d.get("subtype") == "compact_boundary":
            ts = tx.parse_ts(d.get("timestamp"))
            if not tx.in_window(ts, since, until):
                continue
            meta = d.get("compactMetadata") if isinstance(d.get("compactMetadata"), dict) else {}
            trigger = meta.get("trigger") if isinstance(meta.get("trigger"), str) else "(unknown)"
            gap = None
            if ts and state.last_user_ts:
                gap = round((ts - state.last_user_ts).total_seconds() / 60, 1)
            summary, summary_line = find_summary(records, i)
            boundaries.append(
                report_boundary(
                    state, rec, ts, trigger, meta, gap, summary, summary_line, idle_minutes, starts_compacted
                )
            )
    return boundaries, starts_compacted


def report_boundary(state, rec, ts, trigger, meta, gap, summary, summary_line, idle_minutes, starts_compacted) -> dict:
    s = norm(summary) if summary is not None else None
    items = []

    def add(item: Item, status: str) -> None:
        items.append({"kind": item.kind, "text": item.text, "first_seen": item.first_line, "status": status})

    for it in state.rules.values():
        add(it, check_rule(it.text, s) if s is not None else "unverified")
    for it in state.files.values():
        add(it, check_file(it.text, s) if s is not None else "unverified")
    for it in state.branches.values():
        add(it, ("kept" if it.text.lower() in s else "missing") if s is not None else "unverified")
    for num, it in state.prs.items():
        add(it, check_pr(num, s) if s is not None else "unverified")
    for t in state.todos.values():
        if t["status"].lower() in ("completed", "done", "deleted", "cancelled"):
            continue
        it = Item("todo", t["text"], t["at"])
        add(it, check_rule(t["text"], s).replace("partly", "kept") if s is not None else "unverified")
    pre, post = meta.get("preTokens"), meta.get("postTokens")
    idle = trigger not in ("auto", "manual") or (trigger == "auto" and gap is not None and gap >= idle_minutes)
    missing = [x for x in items if x["status"] in ("missing", "unverified")]
    return {
        "session": tx.session_id(rec),
        "project": tx.project_name(rec.path),
        "file": rec.path.name,
        "line": rec.line,
        "timestamp": ts.isoformat() if ts else None,
        "trigger": trigger,
        "pre_tokens": pre if isinstance(pre, int) else None,
        "post_tokens": post if isinstance(post, int) else None,
        "minutes_since_user_message": gap,
        "idle": idle,
        "summary_found": summary is not None,
        "summary_line": summary_line,
        "starts_after_earlier_compaction": starts_compacted,
        "items": items,
        "missing": len(missing),
        "missing_rules_or_files": sum(1 for x in missing if x["kind"] in ("rule", "file")),
    }


def recap(boundaries: list[dict]) -> str:
    last: dict[str, dict] = {}
    for b in boundaries:
        last[b["session"] + "/" + b["file"]] = b
    blocks = []
    for b in last.values():
        lost = [x for x in b["items"] if x["status"] in ("missing", "unverified")]
        if not lost:
            continue
        when = (b["timestamp"] or "")[:16].replace("T", " ")
        lines = [f"Re-stating context that the compaction at {when} UTC may have dropped:"]
        for kind, title in (
            ("rule", "Standing instructions (still apply)"),
            ("file", "Files edited in this session"),
            ("branch", "Branches created"),
            ("pr", "Pull requests opened"),
            ("todo", "Open to-do items"),
        ):
            group = [x["text"] for x in lost if x["kind"] == kind]
            if group:
                lines.append(f"{title}:")
                lines += [f"- {tx.one_line(g, 200)}" for g in group]
        blocks.append("\n".join(lines))
    return ("\n\n".join(blocks) or "Nothing to re-state: every item was found in the last summary.") + "\n"


def render(report: dict, fmt: str) -> str:
    h = (lambda t: f"## {t}") if fmt == "markdown" else (lambda t: f"{t}\n{'-' * len(t)}")
    r, s = report["read"], report["summary"]
    lines = ["# Compaction loss check" if fmt == "markdown" else "Compaction loss check", ""]
    lines.append(
        f"Read {r['files']} file(s), {r['lines']} line(s); {r['unreadable_lines']} unreadable, "
        f"{sum(r['unknown_types'].values())} of unknown types skipped."
    )
    lines += [
        "",
        f"- Compactions: {s['boundaries']} in {s['sessions']} transcript(s); triggers: "
        + ", ".join(f"{k} {v}" for k, v in sorted(s["triggers"].items())),
        f"- Idle compactions (a trigger other than auto or manual, or auto at least {s['idle_minutes']:g} minutes "
        f"after the last user message): {s['idle']}",
        f"- Summaries not found after the boundary: {s['summary_missing']}",
        f"- Items missing from a summary, counted per compaction: {s['missing_items']} "
        f"(standing rules {s['missing_rules']}, edited files "
        f"{s['missing_files']})",
    ]
    if s["starts_compacted"]:
        lines.append(
            f"- {s['starts_compacted']} transcript(s) start after an earlier compaction, so what was said before it "
            "is not in the file and cannot be checked."
        )
    for b in report["boundaries"]:
        when = (b["timestamp"] or "no time")[:16].replace("T", " ")
        title = f"Session {b['session'][:8]} at {when} ({b['file']}:{b['line']})"
        lines += ["", h(title), ""]
        gap = "n/a" if b["minutes_since_user_message"] is None else f"{b['minutes_since_user_message']:g} min"
        tokens = (
            f"{b['pre_tokens']:,} to {b['post_tokens']:,} tokens"
            if b["pre_tokens"] is not None and b["post_tokens"] is not None
            else "tokens not recorded"
        )
        lines.append(
            f"Trigger {b['trigger']}{' (idle)' if b['idle'] and b['trigger'] != 'idle' else ''}, {tokens}, "
            f"{gap} after the last user message"
            + ("" if b["summary_found"] else "; no summary found after the boundary")
            + "."
        )
        lost = [x for x in b["items"] if x["status"] in ("missing", "unverified")]
        part = [x for x in b["items"] if x["status"] == "partly"]
        kept = sum(1 for x in b["items"] if x["status"] == "kept")
        lines.append(f"Checked {len(b['items'])} item(s): {kept} kept, {len(part)} partly, {len(lost)} to re-state.")
        if lost:
            lines += ["", "Re-state these:"]
            lines += [f"- {x['kind']} ({x['status']}): {tx.one_line(x['text'], 160)}" for x in lost]
        if part:
            lines += ["", "Partly kept (most words present, check the meaning):"]
            lines += [f"- {x['kind']}: {tx.one_line(x['text'], 160)}" for x in part]
    lines += [
        "",
        "Substring matching misses paraphrase and can over-report; read the summary before re-stating. "
        "Run with --emit-recap for a block to paste into the session.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="For each compaction in Claude Code transcripts, show the trigger, tokens and idle gap, and "
        "check the summary for the standing rules, edited files, branches, pull requests and open to-dos said "
        "before it; list what to re-state.",
        epilog="Exit codes: 0 nothing missing, 1 a standing rule or edited file is missing from a summary, "
        "2 bad input or no compaction found.",
    )
    ap.add_argument("paths", nargs="*", help="transcript files or folders (folders are searched for *.jsonl)")
    ap.add_argument("--since", help="first UTC date of compactions to include, YYYY-MM-DD")
    ap.add_argument("--until", help="last UTC date of compactions to include, YYYY-MM-DD")
    ap.add_argument("--idle-minutes", type=float, default=30.0, help="gap that marks an idle compaction (30)")
    ap.add_argument("--emit-recap", action="store_true", help="print only a paste-ready recap block per session")
    ap.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--out", help="write the report to this file")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if exc.code in (0, None) else 2
    fmt = "json" if args.json else args.format
    try:
        if not args.paths:
            raise tx.InputError("give at least one transcript file or folder, for example ~/.claude/projects")
        if args.idle_minutes <= 0:
            raise tx.InputError("--idle-minutes must be more than 0")
        since = tx.parse_day(args.since, "--since") if args.since else None
        until = tx.parse_day(args.until, "--until") if args.until else None
        stats = tx.ReadStats()
        files = tx.collect_files(args.paths)
        boundaries: list[dict] = []
        compacted_files = 0
        usable = False
        for f in files:
            records = tx.read_records([f], stats)
            usable = usable or any(r.type in tx.CONVERSATION_TYPES for r in records)
            found, starts = analyse_file(records, since, until, args.idle_minutes)
            boundaries += found
            compacted_files += 1 if starts and found else 0
        if not usable:
            raise tx.InputError(f"nothing usable read. {stats.note()}")
        if not boundaries:
            raise tx.InputError(
                "no compaction (compact_boundary line) found"
                + (" inside --since/--until" if since or until else "")
                + f". {stats.note()}"
            )
        triggers: dict[str, int] = {}
        for b in boundaries:
            triggers[b["trigger"]] = triggers.get(b["trigger"], 0) + 1
        missing = [x for b in boundaries for x in b["items"] if x["status"] == "missing"]
        report = {
            "read": stats.to_dict(),
            "window": {"since": args.since, "until": args.until},
            "summary": {
                "boundaries": len(boundaries),
                "sessions": len({(b["session"], b["file"]) for b in boundaries}),
                "triggers": triggers,
                "idle": sum(1 for b in boundaries if b["idle"]),
                "idle_minutes": args.idle_minutes,
                "summary_missing": sum(1 for b in boundaries if not b["summary_found"]),
                "missing_items": len(missing),
                "missing_rules": sum(1 for x in missing if x["kind"] == "rule"),
                "missing_files": sum(1 for x in missing if x["kind"] == "file"),
                "starts_compacted": compacted_files,
            },
            "boundaries": boundaries,
        }
        if args.emit_recap:
            text = recap(boundaries)
        elif fmt == "json":
            text = json.dumps(report, indent=2, default=str) + "\n"
        else:
            text = render(report, fmt)
        tx.write_output(text, args.out)
    except tx.InputError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2
    return 1 if any(b["missing_rules_or_files"] for b in boundaries) else 0


if __name__ == "__main__":
    sys.exit(main())
