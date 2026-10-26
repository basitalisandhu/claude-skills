#!/usr/bin/env python3
"""Find the shell commands in Claude Code session transcripts that failed because of the shell, not the task.

Every Bash (and PowerShell) tool call is paired with its tool result. A call is a slip when the result shows the
shell itself refused or mangled the command: zsh errors such as `(eval):1: no matches found: --include=*.ts`,
`bad pattern`, `parse error`, `bad substitution`, `command not found: mapfile` or `unknown file attribute`; a
heredoc or bash syntax sent to PowerShell; a Bash command on Windows near or over the MSYS limit of about 8,186
characters, where the tool cuts it silently; a sandbox that cannot start /bin/bash. Interrupted and timed-out calls
are counted as stops, next to the slips. A slip is SILENT when the result was not marked as an error, so the
error text sat in the middle of output that looked fine.

The report gives slips per 1,000 Bash calls, per session and per pattern, the repeat rate (the same pattern again
in the same session), one example command per pattern (cut to 120 characters) and a fix for each pattern.
--emit-rule prints a short CLAUDE.md block for the patterns found.

Usage:
  shell_slips.py ~/.claude/projects
  shell_slips.py ~/.claude/projects --since 2026-10-01 --format markdown
  shell_slips.py session.jsonl --json --out slips.json
  shell_slips.py ~/.claude/projects --emit-rule

Local files only, no network. Exit codes: 0 no slip (or the rate is at most --max-rate), 1 slips found, 2 bad input
(missing path, bad option, no Bash calls found, unwritable --out).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _transcript as tx  # noqa: E402

PROG = "shell_slips.py"
SHELL_TOOLS = {"Bash", "PowerShell"}
MSYS_LIMIT = 8186

# A zsh error line: "(eval):3: msg" or "zsh:1: msg" or "zsh: msg", at the start of a line.
ZSH_ERR_RE = re.compile(r"^(?:\(eval\)|zsh):(?:\d+:)?[ \t]*(?P<msg>[^\n]+)$", re.MULTILINE)
BASH_ONLY_BUILTINS = {"mapfile", "readarray", "shopt", "compgen", "complete", "caller", "enable", "help"}
PS_ERROR_RE = re.compile(
    r"The token '&&' is not a valid statement separator|The '<' operator is reserved for future use|"
    r"Missing file specification after redirection operator|ParserError|is not recognized as the name of a cmdlet|"
    r"Unexpected token '.*' in expression or statement",
)
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?[A-Za-z_]\w*['\"]?")
BWRAP_RE = re.compile(r"bwrap: execvp /bin/(?:ba)?sh|execvp[^\n]*/bin/bash[^\n]*No such file", re.IGNORECASE)
TIMEOUT_RE = re.compile(r"Command timed out after|\bcommand timed out\b", re.IGNORECASE)
INTERRUPT_RE = re.compile(r"\[Request interrupted by user", re.IGNORECASE)

PATTERNS: dict[str, dict[str, str]] = {
    "glob-in-flag-value": {
        "kind": "slip",
        "title": "Unquoted glob in a flag value (zsh)",
        "fix": "Quote the glob: `--include='*.ts'`, `-name '*.py'`. zsh expands it against the working directory "
        "and aborts with `no matches found` when nothing matches.",
    },
    "unmatched-glob": {
        "kind": "slip",
        "title": "Unmatched path glob (zsh)",
        "fix": "Quote the pattern or use `find`; under zsh a glob that matches nothing aborts the whole command. "
        "`setopt no_nomatch` (for example in ~/.zshenv, only for Claude Code's shells) passes it through as bash does.",
    },
    "equals-expansion": {
        "kind": "slip",
        "title": "Word starting with = (zsh =cmd expansion)",
        "fix": "Quote words that start with `=`: `echo '===='`. `setopt no_equals` turns the expansion off.",
    },
    "bad-pattern": {
        "kind": "slip",
        "title": "zsh bad pattern",
        "fix": "Quote brackets, `^`, `#` and `~` in arguments, for example `git log 'HEAD^'` or `grep '[a-z]'`.",
    },
    "parse-error": {
        "kind": "slip",
        "title": "zsh parse error",
        "fix": "The command used syntax zsh parses differently; write it for zsh, or run it with `bash -c '...'`.",
    },
    "bad-substitution": {
        "kind": "slip",
        "title": "Bash-only expansion (bad substitution)",
        "fix": "`${!v}`, `${v,,}` and `${v^^}` are bash-only. Use zsh forms (`${(P)v}`, `${(L)v}`) or `bash -c`.",
    },
    "bash-only-builtin": {
        "kind": "slip",
        "title": "Bash-only builtin under zsh",
        "fix": "`mapfile`, `readarray` and `shopt` do not exist in zsh. Use a `while read` loop or `bash -c`.",
    },
    "colon-modifier": {
        "kind": "slip",
        "title": "Colon modifier after a variable (zsh)",
        "fix": "Write `${B}:path`, not `$B:path`; zsh reads `:h`, `:t`, `:r`, `:s` after a variable as modifiers.",
    },
    "array-subscript": {
        "kind": "slip",
        "title": "Brackets read as an array subscript (zsh)",
        "fix": 'Write `"${pat}[...]"`; zsh reads `$pat[...]` as a subscript.',
    },
    "unknown-file-attribute": {
        "kind": "slip",
        "title": "zsh glob qualifier (unknown file attribute)",
        "fix": "Quote words with parentheses after a glob, for example `'file(1).txt'`; zsh reads `(...)` as a "
        "glob qualifier.",
    },
    "command-not-found": {
        "kind": "slip",
        "title": "zsh command not found",
        "fix": "Check the program is installed and on PATH in non-interactive zsh (aliases and functions from "
        "~/.zshrc are not loaded).",
    },
    "heredoc-in-powershell": {
        "kind": "slip",
        "title": "Heredoc sent to PowerShell",
        "fix": "PowerShell has no `<<EOF`. Use a here-string (`@'` ... `'@`) piped to the program, or the Bash tool.",
    },
    "bash-syntax-in-powershell": {
        "kind": "slip",
        "title": "Bash syntax sent to PowerShell",
        "fix": "Use PowerShell syntax (`;` or `-and`, `$env:NAME`, `Get-ChildItem`), or send the command to the "
        "Bash tool.",
    },
    "windows-command-length": {
        "kind": "slip",
        "title": "Command near or over the Windows MSYS limit",
        "fix": f"The Windows Bash tool cuts a command near {MSYS_LIMIT:,} characters without an error. Write long "
        "content to a file with the Write tool and run a short command that reads it.",
    },
    "sandbox-shell-missing": {
        "kind": "slip",
        "title": "Sandbox could not start the shell",
        "fix": "The sandbox (bwrap) could not run /bin/bash. Check the shell path inside the sandbox; every command "
        "fails until it is fixed.",
    },
    "interrupted": {"kind": "stop", "title": "Interrupted", "fix": "Stopped by the user or a hook; not a shell slip."},
    "timed-out": {
        "kind": "stop",
        "title": "Timed out",
        "fix": "Run long commands in the background or raise the tool timeout; check for a command waiting on input.",
    },
}

RULE_LINES = {
    "glob-in-flag-value": "- Quote every glob that is a flag value: `--include='*.ts'`, `-name '*.py'`.",
    "unmatched-glob": "- Quote path globs that may match nothing, or use `find`; zsh aborts on no match.",
    "equals-expansion": "- Never start a word with `=`: write `echo '===='`.",
    "bad-pattern": "- Quote `[`, `^`, `#` and `~` in arguments (`'HEAD^'`, `'[a-z]'`).",
    "parse-error": "- Write commands for zsh, or wrap bash-only code in `bash -c '...'`.",
    "bad-substitution": "- No bash-only expansions (`${!v}`, `${v,,}`); use `bash -c` when they are needed.",
    "bash-only-builtin": "- No `mapfile`, `readarray` or `shopt`; use `while read` loops.",
    "colon-modifier": "- Brace variables before a colon: `${REF}:path`.",
    "array-subscript": '- Brace variables before brackets: `"${pat}[...]"`.',
    "unknown-file-attribute": "- Quote words with parentheses: `'file(1).txt'`.",
    "command-not-found": "- Aliases and functions from ~/.zshrc are not loaded; call programs by name or path.",
    "heredoc-in-powershell": "- PowerShell has no heredoc: use a here-string (`@'` ... `'@`) or the Bash tool.",
    "bash-syntax-in-powershell": "- Write PowerShell syntax for the PowerShell tool, bash syntax only for Bash.",
    "windows-command-length": f"- Keep each command well under {MSYS_LIMIT:,} characters on Windows; put long "
    "content in a file with the Write tool.",
    "sandbox-shell-missing": "- If every command fails with `bwrap: execvp`, stop and report it; do not retry.",
}


@dataclass
class ShellCall:
    id: str
    tool: str
    command: str
    session: str
    project: str
    ts: object
    order: tuple
    windows: bool
    result: str | None = None
    is_error: bool = False
    interrupted: bool = False
    patterns: list[str] = field(default_factory=list)
    repeats: set[str] = field(default_factory=set)


def result_texts(rec: tx.Record) -> dict[str, tuple[str, bool, bool]]:
    """tool_use_id -> (text, is_error, interrupted) for the tool results on a user line."""
    out = {}
    extra = ""
    interrupted = False
    tur = rec.data.get("toolUseResult")
    if isinstance(tur, dict):
        extra = "\n".join(str(tur.get(k)) for k in ("stdout", "stderr") if isinstance(tur.get(k), str))
        interrupted = tur.get("interrupted") is True
    blocks = [b for b in tx.content_blocks(rec.data.get("message")) if b.get("type") == "tool_result"]
    for b in blocks:
        tid = b.get("tool_use_id")
        if not isinstance(tid, str):
            continue
        text = tx.tool_result_text(b)
        if extra and len(blocks) == 1 and extra not in text:
            text = text + "\n" + extra
        out[tid] = (text, b.get("is_error") is True, interrupted and len(blocks) == 1)
    return out


def looks_windows(cwd: object) -> bool:
    return isinstance(cwd, str) and bool(re.match(r"^[A-Za-z]:[\\/]", cwd) or cwd.startswith("\\\\"))


def classify(call: ShellCall, limit: int) -> list[str]:
    text = call.result or ""
    found: list[str] = []

    def add(p: str) -> None:
        if p not in found:
            found.append(p)

    for m in ZSH_ERR_RE.finditer(text):
        msg = m.group("msg").strip()
        low = msg.lower()
        if low.startswith("no matches found"):
            word = msg.split(":", 1)[1].strip() if ":" in msg else ""
            add("glob-in-flag-value" if word.startswith("-") or re.match(r"^\w[\w.-]*=", word) else "unmatched-glob")
        elif re.match(r"^=\S* not found$", msg):
            add("equals-expansion")
        elif low.startswith("bad pattern"):
            add("bad-pattern")
        elif low.startswith("parse error"):
            add("parse-error")
        elif low.startswith("bad substitution"):
            add("bad-substitution")
        elif low.startswith("unrecognized modifier"):
            add("colon-modifier")
        elif low.startswith(("bad math expression", "invalid subscript")):
            add("array-subscript")
        elif low.startswith("unknown file attribute"):
            add("unknown-file-attribute")
        elif low.startswith("command not found"):
            name = msg.split(":", 1)[1].strip() if ":" in msg else ""
            add("bash-only-builtin" if name in BASH_ONLY_BUILTINS else "command-not-found")
    powershell = call.tool == "PowerShell"
    if PS_ERROR_RE.search(text) and (powershell or call.windows):
        add("heredoc-in-powershell" if HEREDOC_RE.search(call.command) else "bash-syntax-in-powershell")
    elif powershell and HEREDOC_RE.search(call.command):
        add("heredoc-in-powershell")
    if call.tool == "Bash" and call.windows and len(call.command) >= limit - 200:
        add("windows-command-length")
    if BWRAP_RE.search(text):
        add("sandbox-shell-missing")
    if call.interrupted or INTERRUPT_RE.search(text):
        add("interrupted")
    if TIMEOUT_RE.search(text):
        add("timed-out")
    return found


def load(records: list[tx.Record], since, until, platform: str, limit: int) -> tuple[list[ShellCall], int]:
    calls: dict[str, ShellCall] = {}
    results: dict[str, tuple[str, bool, bool]] = {}
    seq = 0
    for rec in records:
        seq += 1
        if rec.type == "assistant":
            for b in tx.content_blocks(rec.data.get("message")):
                if b.get("type") != "tool_use" or b.get("name") not in SHELL_TOOLS:
                    continue
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                cmd = inp.get("command") if isinstance(inp.get("command"), str) else ""
                tid = b.get("id") if isinstance(b.get("id"), str) else f"{rec.path}:{rec.line}"
                ts = tx.parse_ts(rec.data.get("timestamp"))
                if tid in calls or not tx.in_window(ts, since, until):
                    continue
                windows = platform == "windows" or (platform == "auto" and looks_windows(rec.data.get("cwd")))
                calls[tid] = ShellCall(
                    tid,
                    b["name"],
                    cmd,
                    tx.session_id(rec),
                    tx.project_name(rec.path),
                    ts,
                    (ts.isoformat() if ts else "", seq),
                    windows,
                )
        elif rec.type == "user":
            results.update(result_texts(rec))
    unpaired = 0
    for tid, call in calls.items():
        if tid in results:
            call.result, call.is_error, call.interrupted = results[tid]
        else:
            unpaired += 1
        call.patterns = classify(call, limit)
    return sorted(calls.values(), key=lambda c: (c.session, c.order)), unpaired


def per_1000(count: int, total: int) -> float:
    return round(count * 1000 / total, 1) if total else 0.0


def build(calls: list[ShellCall], unpaired: int, stats: tx.ReadStats, args) -> dict:
    seen: dict[str, set[str]] = defaultdict(set)
    for c in calls:
        for p in c.patterns:
            if PATTERNS[p]["kind"] == "slip" and p in seen[c.session]:
                c.repeats.add(p)
            seen[c.session].add(p)
    bash = [c for c in calls if c.tool == "Bash"]
    total = len(calls)
    slip_calls = [c for c in calls if any(PATTERNS[p]["kind"] == "slip" for p in c.patterns)]
    silent_calls = [c for c in slip_calls if not c.is_error]
    slip_events = sum(1 for c in calls for p in c.patterns if PATTERNS[p]["kind"] == "slip")
    repeat_events = sum(len(c.repeats) for c in calls)
    patterns = []
    for pid, meta in PATTERNS.items():
        hits = [c for c in calls if pid in c.patterns]
        if not hits:
            continue
        patterns.append(
            {
                "pattern": pid,
                "kind": meta["kind"],
                "title": meta["title"],
                "calls": len(hits),
                "per_1000": per_1000(len(hits), total),
                "silent": sum(1 for c in hits if not c.is_error),
                "sessions": len({c.session for c in hits}),
                "repeats": sum(1 for c in hits if pid in c.repeats),
                "example": tx.one_line(hits[0].command, 120),
                "fix": meta["fix"],
            }
        )
    patterns.sort(key=lambda p: (p["kind"] != "slip", -p["calls"], p["pattern"]))
    slip_ids = {c.id for c in slip_calls}
    by_session: dict[str, list[ShellCall]] = defaultdict(list)
    for c in calls:
        by_session[c.session].append(c)
    sessions = []
    for sid, cs in sorted(by_session.items()):
        sl = [c for c in cs if c.id in slip_ids]
        if not sl:
            continue
        top = Counter(p for c in sl for p in c.patterns if PATTERNS[p]["kind"] == "slip").most_common(1)[0][0]
        sessions.append(
            {
                "session": sid,
                "project": cs[0].project,
                "shell_calls": len(cs),
                "slip_calls": len(sl),
                "per_1000": per_1000(len(sl), len(cs)),
                "silent": sum(1 for c in sl if not c.is_error),
                "top_pattern": top,
            }
        )
    sessions.sort(key=lambda s: (-s["slip_calls"], s["session"]))
    long_elsewhere = sum(1 for c in bash if not c.windows and len(c.command) >= args.msys_limit - 200)
    rate = per_1000(len(slip_calls), total)
    return {
        "read": {**stats.to_dict(), "unpaired_calls": unpaired},
        "window": {"since": args.since, "until": args.until},
        "summary": {
            "shell_calls": total,
            "bash_calls": len(bash),
            "powershell_calls": total - len(bash),
            "sessions": len({c.session for c in calls}),
            "slip_calls": len(slip_calls),
            "slips_per_1000": rate,
            "silent_slip_calls": len(silent_calls),
            "silent_share": round(len(silent_calls) / len(slip_calls), 4) if slip_calls else None,
            "repeat_rate": round(repeat_events / slip_events, 4) if slip_events else None,
            "stops": sum(1 for c in calls if any(PATTERNS[p]["kind"] == "stop" for p in c.patterns)),
            "long_commands_not_windows": long_elsewhere,
            "max_rate": args.max_rate,
        },
        "patterns": patterns,
        "sessions": sessions,
        "flagged": bool(slip_calls) and rate > args.max_rate,
    }


def rule_block(report: dict) -> str:
    found = [p["pattern"] for p in report["patterns"] if p["kind"] == "slip"]
    lines = ["## Shell commands", ""]
    zsh = [p for p in found if p in RULE_LINES and "powershell" not in p and p not in ("windows-command-length",)]
    if zsh or not found:
        lines.append("The Bash tool runs commands in zsh on this machine, not bash.")
        lines.append("")
        lines += [RULE_LINES[p] for p in (zsh or ["glob-in-flag-value", "unmatched-glob", "equals-expansion"])]
    lines += [RULE_LINES[p] for p in found if p not in zsh and p in RULE_LINES]
    lines.append(
        "- Read the whole output for `(eval):N:` or `zsh:` lines before drawing conclusions: the call can "
        "report success when the shell failed."
    )
    return "\n".join(lines) + "\n"


def render(report: dict, fmt: str, top: int) -> str:
    h = (lambda t: f"## {t}") if fmt == "markdown" else (lambda t: f"{t}\n{'-' * len(t)}")
    code = (lambda t: f"`{t}`") if fmt == "markdown" else (lambda t: t)
    s, r = report["summary"], report["read"]
    lines = ["# Shell slip audit" if fmt == "markdown" else "Shell slip audit", ""]
    lines.append(
        f"Read {r['files']} file(s), {r['lines']} line(s); {r['unreadable_lines']} unreadable, "
        f"{sum(r['unknown_types'].values())} of unknown types skipped; {r['unpaired_calls']} call(s) had no result."
    )
    w = report["window"]
    if w["since"] or w["until"]:
        lines.append(f"Window (UTC dates): {w['since'] or 'start'} to {w['until'] or 'end'}.")

    def pct(x: float | None) -> str:
        return "n/a" if x is None else f"{x * 100:.0f}%"

    lines += [
        "",
        f"- Shell calls: {s['shell_calls']:,} (Bash {s['bash_calls']:,}, PowerShell {s['powershell_calls']:,}) in "
        f"{s['sessions']:,} session(s)",
        f"- Slips: {s['slip_calls']:,} call(s), {s['slips_per_1000']} per 1,000 shell calls",
        f"- Silent (result not marked as an error): {s['silent_slip_calls']:,} ({pct(s['silent_share'])})",
        f"- Repeat rate (same pattern again in the same session): {pct(s['repeat_rate'])}",
        f"- Interrupted or timed out: {s['stops']:,}",
    ]
    if s["long_commands_not_windows"]:
        lines.append(
            f"- Commands near or over {MSYS_LIMIT:,} characters outside Windows: {s['long_commands_not_windows']:,} "
            "(fine here, cut silently on Windows)"
        )
    lines += ["", h("Patterns"), ""]
    rows = [
        [code(p["pattern"]), p["kind"], f"{p['calls']:,}", str(p["per_1000"]), f"{p['silent']:,}", f"{p['repeats']:,}"]
        for p in report["patterns"]
    ]
    lines += tx.table(["Pattern", "Kind", "Calls", "Per 1,000", "Silent", "Repeats"], rows, fmt) if rows else ["None."]
    if report["patterns"]:
        lines += ["", h("Examples and fixes"), ""]
        for p in report["patterns"]:
            lines.append(f"- {code(p['pattern'])} ({p['title']}): {code(p['example'])}")
            lines.append(f"  Fix: {p['fix']}")
    if report["sessions"]:
        lines += ["", h(f"Sessions with slips (top {min(top, len(report['sessions']))})"), ""]
        rows = [
            [
                x["session"][:8],
                f"{x['shell_calls']:,}",
                f"{x['slip_calls']:,}",
                str(x["per_1000"]),
                f"{x['silent']:,}",
                x["top_pattern"],
            ]
            for x in report["sessions"][:top]
        ]
        lines += tx.table(["Session", "Shell calls", "Slips", "Per 1,000", "Silent", "Most common"], rows, fmt)
    lines += [
        "",
        "Run with --emit-rule for a CLAUDE.md block covering these patterns."
        if report["patterns"]
        else "No slips found.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Pair every Bash and PowerShell call in Claude Code transcripts with its result and count the "
        "calls that failed because of the shell (zsh glob and syntax errors, PowerShell given bash, Windows length "
        "cut-off), including silent ones, per 1,000 calls, per session and per pattern, with fixes.",
        epilog="Exit codes: 0 no slip (or at most --max-rate), 1 slips found, 2 bad input or no shell calls found.",
    )
    ap.add_argument("paths", nargs="*", help="transcript files or folders (folders are searched for *.jsonl)")
    ap.add_argument("--since", help="first UTC date to include, YYYY-MM-DD")
    ap.add_argument("--until", help="last UTC date to include, YYYY-MM-DD")
    ap.add_argument("--platform", choices=("auto", "windows", "posix"), default="auto", help="auto reads cwd")
    ap.add_argument("--msys-limit", type=int, default=MSYS_LIMIT, help=f"Windows command limit ({MSYS_LIMIT})")
    ap.add_argument("--max-rate", type=float, default=0.0, help="exit 1 only above this many slips per 1,000 (0)")
    ap.add_argument("--top", type=int, default=10, help="rows in the session table (10)")
    ap.add_argument("--emit-rule", action="store_true", help="print only a CLAUDE.md rule block for the patterns found")
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
        if args.max_rate < 0 or args.top < 1 or args.msys_limit < 1000:
            raise tx.InputError("--max-rate must be 0 or more, --top at least 1, --msys-limit at least 1000")
        since = tx.parse_day(args.since, "--since") if args.since else None
        until = tx.parse_day(args.until, "--until") if args.until else None
        stats = tx.ReadStats()
        records = tx.read_records(tx.collect_files(args.paths), stats)
        calls, unpaired = load(records, since, until, args.platform, args.msys_limit)
        if not calls:
            raise tx.InputError(f"no Bash or PowerShell calls found. {stats.note()}")
        report = build(calls, unpaired, stats, args)
        if args.emit_rule:
            text = rule_block(report)
        elif fmt == "json":
            text = json.dumps(report, indent=2, default=str) + "\n"
        else:
            text = render(report, fmt, args.top)
        tx.write_output(text, args.out)
    except tx.InputError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2
    return 1 if report["flagged"] else 0


if __name__ == "__main__":
    sys.exit(main())
