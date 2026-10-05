#!/usr/bin/env python3
"""Review an AI agent session log for signs of prompt injection taking effect, tool misuse, data leaving the boundary
and loops, and print a timeline with the flagged events.

Accepted log shapes (detected per file; JSON lines or one JSON document):
  transcript  Claude Code project transcript lines: {"type": "user"|"assistant", "timestamp", "message": {"role",
              "content": text or blocks of type text, tool_use (id, name, input) and tool_result (tool_use_id,
              content, is_error)}}
  messages    a chat messages list, or {"messages": [...]}: role user, assistant (with content blocks or tool_calls
              [{id, function: {name, arguments}}]) and tool (tool_call_id, content)
  events      generic event lines: {"timestamp", "type" or "event": prompt|tool_call|tool_result|message,
              "tool" or "name", "arguments" or "input", "output" or "result" or "content", "is_error"}

Flags (id, default severity). Every flag is structural: it looks at where values came from, which tool ran, and the
shape of arguments, not at known attack sentences.
  INJ-PROVENANCE      high      a host, URL or e-mail address in a consequential tool call (shell, network, send,
                                write) first appeared in an untrusted tool result (fetch, browse, search, mail or MCP
                                tools, or --untrusted-tool) and never in a user prompt; critical when the call is a
                                shell or network call
  INJ-ROLE-MARKER     medium    an untrusted tool result carries chat role markers (a line opening with system:,
                                assistant: or user:, or a tag named system, assistant, user or tool_result),
                                zero-width or bidirectional control characters, or Unicode tag characters
  TOOL-DENIED-RETRY   high      a tool call was denied or blocked, and within the next 5 calls a different tool
                                targeted the same path or host
  TOOL-DESTRUCTIVE    high      a shell command with a destructive shape: recursive forced delete, forced push,
                                hard reset, infrastructure destroy, dropping a database object, deleting cluster
                                resources, or a disk format
  TOOL-OUTSIDE-ROOT   medium    a file write or edit outside --root (only when --root is given)
  EGRESS-NETWORK      medium    a network call (fetch tool, or curl, wget and similar in a shell command) to a host
                                not on --allow-host; high when the call carries data (a POST or upload flag, or a
                                query string over 100 characters)
  EGRESS-SECRET       high      a secret-shaped string appears in a tool argument, tool result or assistant message
                                (it is masked in this report)
  EGRESS-IMAGE-URL    high      an assistant message renders a Markdown image from a host not on --allow-host with a
                                query string (a common way to carry data out)
  LOOP-REPEAT         medium    the same tool with the same arguments ran --repeat times (default 5) in a row
  LOOP-ERROR-STREAK   low       --repeat or more tool errors in a row

Output: Markdown (default) or JSON (--format json), to stdout or --out. The timeline lists every event (or only
flagged ones with --flagged-only), each summary cut to 160 characters. Secret-shaped strings are always masked;
--redact also replaces e-mail addresses and home directory user names with stable tokens.

Exit codes: 0 no flag at or above --fail-on (default high), 1 flags at or above --fail-on (a person should review the
session), 2 bad input (unreadable file, unknown shape). Standard library only. Read-only. No network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_BYTES = 50 * 1024 * 1024

SHELL_TOOLS = re.compile(
    r"(?i)^(bash|shell|sh|exec|execute|execute_command|run_command|run_shell|terminal|powershell|cmd)$"
)
FETCH_TOOLS = re.compile(
    r"(?i)(webfetch|web_fetch|fetch|http_request|http_get|browse|browser|navigate|get_webpage|open_url|curl)"
)
SEARCH_TOOLS = re.compile(r"(?i)(websearch|web_search|search_web|google|bing)")
MAIL_TOOLS = re.compile(
    r"(?i)(read_email|read_inbox|get_email|gmail|outlook|mail_read|list_messages)"
)
SEND_TOOLS = re.compile(
    r"(?i)(send|post|reply|publish|upload|share|email|slack|message|tweet|comment|create_issue|webhook)"
)
WRITE_TOOLS = re.compile(
    r"(?i)^(write|edit|multiedit|notebookedit|write_file|create_file|edit_file|str_replace\w*|apply_patch)$"
)
NET_CMD = re.compile(
    r"(?i)(?:^|[\s;|&(`])(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ssh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
)
DATA_FLAG = re.compile(
    r"(?i)(\s-d\s|\s--data\S*|\s-F\s|\s--form\b|\s-T\s|--upload-file|-X\s*POST|-X\s*PUT|--post-data|--post-file|-Method\s+Post)"
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
HOST_RE = re.compile(r"https?://([^/\s:\"'<>)\]]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)", re.IGNORECASE)
ROLE_LINE_RE = re.compile(r"(?im)^\s*(system|assistant|user)\s*:")
ROLE_TAG_RE = re.compile(r"(?i)</?\s*(system|assistant|user|tool_result)\b[^>]*>")
HIDDEN_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"
)
DENIED_RE = re.compile(
    r"(?i)\b(denied|not allowed|blocked|rejected|not permitted)\b|doesn't want to proceed"
)
PATH_RE = re.compile(r"(?:[A-Za-z]:\\|~?/)[^\s\"'`;|&<>]+")
# Destructive command shapes, one compiled pattern per family; matched only inside shell tool commands.
DESTRUCTIVE = [
    (
        "recursive forced delete",
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\b"
        ),
    ),
    (
        "forced push",
        re.compile(r"\bgit\s+push\b[^\n]*\s(--force\b|-f\b|--force-with-lease\b)"),
    ),
    (
        "hard reset or clean",
        re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-[a-zA-Z]*f)"),
    ),
    (
        "infrastructure destroy",
        re.compile(
            r"\b(terraform|tofu|pulumi|cdk)\s+(destroy|apply\s+[^\n]*-destroy)\b"
        ),
    ),
    (
        "database object dropped",
        re.compile(r"(?i)\b(drop\s+(table|database|schema)|truncate\s+table)\b"),
    ),
    ("cluster resources deleted", re.compile(r"\bkubectl\s+delete\b")),
    (
        "cloud resources deleted",
        re.compile(
            r"\baws\s+\S+\s+(delete-|terminate-|remove-)|\baz\s+\S+[^\n]*\sdelete\b|\bgcloud\s+[^\n]*\sdelete\b"
        ),
    ),
    (
        "disk format",
        re.compile(r"\b(mkfs(\.\w+)?|diskutil\s+erase\w*|format\s+[a-zA-Z]:)"),
    ),
]
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]{20,}=*"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{12,}"
    ),
]


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def mask(text: str) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    return text


def has_secret(text: str) -> bool:
    return any(rx.search(text) for rx in SECRET_RES)


def flat(value) -> str:
    """Text of a content value: a string, a list of blocks, or any JSON value."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(
            flat(v.get("text", v.get("content", "")) if isinstance(v, dict) else v)
            for v in value
        )
    if isinstance(value, dict):
        if "text" in value:
            return flat(value["text"])
        return json.dumps(value, sort_keys=True)
    return str(value)


def as_args(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"input": value}
        return parsed if isinstance(parsed, dict) else {"input": parsed}
    return {} if value is None else {"input": value}


def event(
    kind: str,
    ts,
    tool: str = "",
    args: dict | None = None,
    text: str = "",
    error: bool = False,
    call_id: str = "",
) -> dict:
    return {
        "kind": kind,
        "ts": str(ts or ""),
        "tool": tool,
        "args": args or {},
        "text": text,
        "error": bool(error),
        "call_id": str(call_id or ""),
    }


def from_blocks(role: str, content, ts, out: list[dict]) -> None:
    if isinstance(content, str) or content is None:
        text = flat(content)
        if text:
            out.append(event("prompt" if role == "user" else "message", ts, text=text))
        return
    if not isinstance(content, list):
        raise InputError("message content must be text or a list of blocks")
    for b in content:
        if not isinstance(b, dict):
            continue
        t = b.get("type")
        if t == "text" and b.get("text"):
            out.append(
                event(
                    "prompt" if role == "user" else "message", ts, text=str(b["text"])
                )
            )
        elif t == "tool_use":
            out.append(
                event(
                    "tool_call",
                    ts,
                    str(b.get("name", "")),
                    as_args(b.get("input")),
                    call_id=b.get("id", ""),
                )
            )
        elif t == "tool_result":
            out.append(
                event(
                    "tool_result",
                    ts,
                    text=flat(b.get("content")),
                    error=b.get("is_error", False),
                    call_id=b.get("tool_use_id", ""),
                )
            )


def from_message(m: dict, out: list[dict]) -> None:
    role = str(m.get("role", ""))
    ts = m.get("timestamp")
    if role == "tool":
        out.append(
            event(
                "tool_result",
                ts,
                text=flat(m.get("content")),
                error=m.get("is_error", False),
                call_id=m.get("tool_call_id", ""),
            )
        )
        return
    if role not in ("user", "assistant", "system"):
        raise InputError(f"unknown message role {role!r}")
    if role == "system":
        return
    from_blocks(role, m.get("content"), ts, out)
    for call in m.get("tool_calls") or []:
        fn = call.get("function") or {}
        out.append(
            event(
                "tool_call",
                ts,
                str(fn.get("name", "")),
                as_args(fn.get("arguments")),
                call_id=call.get("id", ""),
            )
        )


def from_record(r: dict, out: list[dict]) -> None:
    if isinstance(r.get("message"), dict) and r.get("type") in ("user", "assistant"):
        msg = r["message"]
        from_blocks(
            str(msg.get("role") or r["type"]),
            msg.get("content"),
            r.get("timestamp"),
            out,
        )
        return
    if "role" in r:
        from_message(r, out)
        return
    kind = str(r.get("type") or r.get("event") or "").lower()
    ts = r.get("timestamp") or r.get("time")
    tool = str(r.get("tool") or r.get("name") or "")
    if kind in ("prompt", "user", "user_message"):
        out.append(
            event(
                "prompt",
                ts,
                text=flat(r.get("content") or r.get("text") or r.get("prompt")),
            )
        )
    elif kind in ("tool_call", "tool_use", "pre_tool_use"):
        out.append(
            event(
                "tool_call",
                ts,
                tool,
                as_args(r.get("arguments") or r.get("input") or r.get("tool_input")),
                call_id=r.get("id", ""),
            )
        )
    elif kind in ("tool_result", "post_tool_use"):
        text = flat(
            r.get("output")
            or r.get("result")
            or r.get("content")
            or r.get("tool_response")
        )
        out.append(
            event(
                "tool_result",
                ts,
                tool,
                text=text,
                error=r.get("is_error", r.get("error", False)),
                call_id=r.get("id", ""),
            )
        )
    elif kind in ("message", "assistant", "final", "assistant_message"):
        out.append(event("message", ts, text=flat(r.get("content") or r.get("text"))))
    elif kind in ("summary", "system", "file-history-snapshot", "meta"):
        return
    else:
        raise InputError(f"unknown event type {kind or '(none)'!r}")


def load(path: Path) -> list[dict]:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise InputError(
                f"{path.name}: larger than {MAX_BYTES // (1024 * 1024)} MB"
            )
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    records: list = []
    try:
        doc = json.loads(text)
        records = (
            doc.get("messages")
            if isinstance(doc, dict) and isinstance(doc.get("messages"), list)
            else doc
        )
        if isinstance(records, dict):
            records = [records]
    except json.JSONDecodeError:
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}:{n}: not JSON: {exc.msg}") from exc
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise InputError(f"{path.name}: expected JSON lines or a list of objects")
    out: list[dict] = []
    for r in records:
        from_record(r, out)
    if not out:
        raise InputError(f"{path.name}: no prompts, tool calls or messages found")
    names = {
        e["call_id"]: e["tool"]
        for e in out
        if e["kind"] == "tool_call" and e["call_id"]
    }
    for e in out:
        if e["kind"] == "tool_result" and not e["tool"]:
            e["tool"] = names.get(e["call_id"], "")
    for i, e in enumerate(out):
        e["i"] = i + 1
    return out


def command_of(e: dict) -> str:
    a = e["args"]
    return (
        str(a.get("command") or a.get("cmd") or a.get("script") or a.get("input") or "")
        if SHELL_TOOLS.match(e["tool"])
        else ""
    )


def arg_text(e: dict) -> str:
    return json.dumps(e["args"], sort_keys=True, ensure_ascii=False)


def is_untrusted_source(tool: str, extra: re.Pattern | None) -> bool:
    return bool(
        FETCH_TOOLS.search(tool)
        or SEARCH_TOOLS.search(tool)
        or MAIL_TOOLS.search(tool)
        or tool.startswith("mcp__")
        or (extra and extra.search(tool))
    )


def is_network_call(e: dict) -> bool:
    return bool(FETCH_TOOLS.search(e["tool"]) or NET_CMD.search(command_of(e)))


def is_consequential(e: dict) -> bool:
    return bool(
        SHELL_TOOLS.match(e["tool"])
        or WRITE_TOOLS.match(e["tool"])
        or SEND_TOOLS.search(e["tool"])
        or FETCH_TOOLS.search(e["tool"])
    )


def hosts(text: str) -> set[str]:
    return {h.lower().split("@")[-1] for h in HOST_RE.findall(text)}


def designators(text: str) -> set[str]:
    return hosts(text) | {m.lower() for m in EMAIL_RE.findall(text)}


def targets(e: dict) -> set[str]:
    t = arg_text(e)
    return hosts(t) | {
        p.rstrip("/\\,.").lower() for p in PATH_RE.findall(t) if len(p) > 3
    }


def outside_root(path: str, root: str) -> bool:
    if not path:
        return False
    win = re.match(r"^[A-Za-z]:\\", path) or re.match(r"^[A-Za-z]:\\", root)
    P = PureWindowsPath if win else PurePosixPath
    p, r = P(path), P(root)
    if not p.is_absolute():
        return ".." in p.parts
    try:
        p.relative_to(r)
    except ValueError:
        return True
    return ".." in p.parts


def flag(
    flags: list[dict], e: dict, fid: str, sev: str, title: str, evidence: str
) -> None:
    flags.append(
        {
            "event": e["i"],
            "ts": e["ts"],
            "id": fid,
            "severity": sev,
            "tool": e["tool"],
            "title": title,
            "evidence": mask(evidence)[:240],
        }
    )


def review(events: list[dict], args) -> list[dict]:
    flags: list[dict] = []
    allow = {h.lower() for h in args.allow_host}
    extra = re.compile(args.untrusted_tool) if args.untrusted_tool else None
    prompt_values: set[str] = set()
    untrusted_values: dict[str, int] = {}
    last_denied: list[tuple[int, str, set[str]]] = []
    calls_seen = 0
    run_key, run_len, err_streak = None, 0, 0
    for e in events:
        text = e["text"]
        if e["kind"] == "prompt":
            prompt_values |= designators(text)
        if e["kind"] == "tool_result":
            if is_untrusted_source(e["tool"], extra):
                for v in designators(text):
                    untrusted_values.setdefault(v, e["i"])
                markers = []
                if ROLE_LINE_RE.search(text) or ROLE_TAG_RE.search(text):
                    markers.append("chat role marker")
                if HIDDEN_RE.search(text):
                    markers.append("hidden or control characters")
                if markers:
                    flag(
                        flags,
                        e,
                        "INJ-ROLE-MARKER",
                        "medium",
                        "Untrusted tool result carries role markers or hidden text",
                        f"{', '.join(markers)} in result of {e['tool'] or 'a tool'}",
                    )
            if e["error"]:
                err_streak += 1
            else:
                err_streak = 0
            if err_streak == args.repeat:
                flag(
                    flags,
                    e,
                    "LOOP-ERROR-STREAK",
                    "low",
                    "Many tool errors in a row",
                    f"{err_streak} consecutive errors",
                )
            if e["error"] and DENIED_RE.search(text):
                call = next(
                    (
                        c
                        for c in reversed(events[: e["i"] - 1])
                        if c["kind"] == "tool_call"
                        and (not e["call_id"] or c["call_id"] == e["call_id"])
                    ),
                    None,
                )
                if call:
                    last_denied.append((calls_seen, call["tool"], targets(call)))
        if e["kind"] in ("tool_result", "message", "tool_call"):
            blob = text if e["kind"] != "tool_call" else arg_text(e)
            if has_secret(blob):
                where = {
                    "tool_call": "tool arguments",
                    "tool_result": "a tool result",
                    "message": "an assistant message",
                }[e["kind"]]
                flag(
                    flags,
                    e,
                    "EGRESS-SECRET",
                    "high",
                    "Secret-shaped string in the session",
                    f"in {where}: {mask(blob)[:120]}",
                )
        if e["kind"] == "message":
            for url in IMAGE_RE.findall(text):
                host = hosts(url)
                if "?" in url and not host <= allow:
                    flag(
                        flags,
                        e,
                        "EGRESS-IMAGE-URL",
                        "high",
                        "Markdown image from an outside host with a query string",
                        url[:160],
                    )
        if e["kind"] != "tool_call":
            continue
        calls_seen += 1
        cmd, at = command_of(e), arg_text(e)
        key = (e["tool"], at)
        run_len = run_len + 1 if key == run_key else 1
        run_key = key
        if run_len == args.repeat:
            flag(
                flags,
                e,
                "LOOP-REPEAT",
                "medium",
                "Same tool call repeated",
                f"{e['tool']} with the same arguments {run_len} times in a row",
            )
        for name, rx in DESTRUCTIVE:
            if cmd and rx.search(cmd):
                flag(
                    flags,
                    e,
                    "TOOL-DESTRUCTIVE",
                    "high",
                    f"Destructive command: {name}",
                    cmd[:200],
                )
                break
        if args.root and WRITE_TOOLS.match(e["tool"]):
            path = str(
                e["args"].get("file_path")
                or e["args"].get("path")
                or e["args"].get("notebook_path")
                or ""
            )
            if outside_root(path, args.root):
                flag(
                    flags,
                    e,
                    "TOOL-OUTSIDE-ROOT",
                    "medium",
                    "File written outside the working root",
                    path,
                )
        if is_network_call(e):
            urls = URL_RE.findall(at)
            outside = sorted(h for h in hosts(at) if h not in allow)
            if outside:
                carries = bool(DATA_FLAG.search(" " + cmd + " ")) or any(
                    "?" in u and len(u.split("?", 1)[1]) > 100 for u in urls
                )
                flag(
                    flags,
                    e,
                    "EGRESS-NETWORK",
                    "high" if carries else "medium",
                    "Network call to a host not on the allow list"
                    + (" carrying data" if carries else ""),
                    ", ".join(outside),
                )
        if is_consequential(e):
            injected = sorted(
                v
                for v in designators(at)
                if v in untrusted_values and v not in prompt_values and v not in allow
            )
            if injected:
                sev = (
                    "critical"
                    if (SHELL_TOOLS.match(e["tool"]) or is_network_call(e))
                    else "high"
                )
                src = ", ".join(
                    f"{v} (from event {untrusted_values[v]})" for v in injected
                )
                flag(
                    flags,
                    e,
                    "INJ-PROVENANCE",
                    sev,
                    "Tool call uses a value that came only from untrusted content",
                    src,
                )
        for denied_at, denied_tool, denied_targets in last_denied:
            if (
                calls_seen - denied_at <= 5
                and e["tool"] != denied_tool
                and denied_targets & targets(e)
            ):
                shared = ", ".join(sorted(denied_targets & targets(e)))
                flag(
                    flags,
                    e,
                    "TOOL-DENIED-RETRY",
                    "high",
                    "Denied action retried with a different tool",
                    f"{denied_tool} was denied; {e['tool']} then targeted {shared}",
                )
                denied_targets.clear()
    return flags


def token(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:8]


def redact_people(text: str) -> str:
    text = EMAIL_RE.sub(lambda m: f"user-{token(m.group(0))}@redacted.invalid", text)
    return re.sub(
        r"(?i)(/Users/|/home/|\\Users\\)([^/\\\s\"']+)",
        lambda m: m.group(1) + "user-" + token(m.group(2)),
        text,
    )


def summary(e: dict) -> str:
    if e["kind"] == "tool_call":
        s = f"{e['tool']} {command_of(e) or arg_text(e)}"
    elif e["kind"] == "tool_result":
        s = ("ERROR " if e["error"] else "") + e["text"]
    else:
        s = e["text"]
    s = mask(" ".join(s.split()))
    return s[:157] + "..." if len(s) > 160 else s


def cell(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\n", " ")
    )


def render(rep: dict) -> str:
    lines = [f"## Agent session log review: {cell(rep['log'])}", ""]
    c = rep["counts"]
    lines.append(
        f"**Summary:** {rep['events']} events ({rep['tool_calls']} tool calls), {sum(c.values())} flags: "
        + ", ".join(f"{n} {s}" for s, n in c.items() if n)
        + "."
    )
    lines += ["", "### Flags", ""]
    if rep["flags"]:
        lines += [
            "| # | Event | Time | Severity | Flag | Tool | Finding | Evidence |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for n, f in enumerate(rep["flags"], 1):
            lines.append(
                f"| {n} | {f['event']} | {cell(f['ts'])} | {f['severity']} | {f['id']} | {cell(f['tool'])} | {cell(f['title'])} | {cell(f['evidence'])} |"
            )
    else:
        lines.append("No flags at or above the selected severity.")
    lines += [
        "",
        "### Timeline",
        "",
        "| Event | Time | Kind | Tool | Summary | Flags |",
        "|---|---|---|---|---|---|",
    ]
    for t in rep["timeline"]:
        lines.append(
            f"| {t['event']} | {cell(t['ts'])} | {t['kind']} | {cell(t['tool'])} | {cell(t['summary'])} | {', '.join(t['flags'])} |"
        )
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("log", help="session log file (JSON lines or JSON)")
    ap.add_argument(
        "--root", help="working root of the session; file writes outside it are flagged"
    )
    ap.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="host the agent may reach (repeatable)",
    )
    ap.add_argument(
        "--untrusted-tool",
        help="regular expression for more tool names whose results are untrusted",
    )
    ap.add_argument(
        "--repeat",
        type=int,
        default=5,
        help="repeats or consecutive errors that count as a loop (default 5)",
    )
    ap.add_argument(
        "--flagged-only",
        action="store_true",
        help="show only flagged events in the timeline",
    )
    ap.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="hide flags below this severity",
    )
    ap.add_argument(
        "--fail-on",
        choices=SEVERITIES + ["none"],
        default="high",
        help="exit 1 when a flag is at or above this severity (default high)",
    )
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument(
        "--redact",
        action="store_true",
        help="also replace e-mail addresses and home directory user names with tokens",
    )
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    if args.repeat < 2:
        print("error: --repeat must be at least 2", file=sys.stderr)
        return 2
    try:
        if args.untrusted_tool:
            re.compile(args.untrusted_tool)
        events = load(Path(args.log))
    except re.error as exc:
        print(
            f"error: --untrusted-tool is not a valid regular expression: {exc}",
            file=sys.stderr,
        )
        return 2
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    flags = [
        f
        for f in review(events, args)
        if RANK[f["severity"]] <= RANK[args.min_severity]
    ]
    flags.sort(key=lambda f: (f["event"], RANK[f["severity"]], f["id"]))
    by_event: dict[int, list[str]] = {}
    for f in flags:
        by_event.setdefault(f["event"], []).append(f["id"])
    timeline = [
        {
            "event": e["i"],
            "ts": e["ts"],
            "kind": e["kind"],
            "tool": e["tool"],
            "summary": summary(e),
            "flags": by_event.get(e["i"], []),
        }
        for e in events
        if not args.flagged_only or e["i"] in by_event
    ]
    rep = {
        "tool": "review_session_log",
        "log": Path(args.log).name,
        "events": len(events),
        "tool_calls": sum(1 for e in events if e["kind"] == "tool_call"),
        "counts": {s: sum(1 for f in flags if f["severity"] == s) for s in SEVERITIES},
        "flags": flags,
        "timeline": timeline,
        "note": "Flags are leads from fixed structural rules, not verdicts. Read the flagged events in the log before concluding anything.",
    }
    text = (
        json.dumps(rep, indent=2, ensure_ascii=False)
        if args.format == "json"
        else render(rep)
    )
    text = mask(text)
    if args.redact:
        text = redact_people(text)
    try:
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return (
        0
        if args.fail_on == "none"
        else int(any(RANK[f["severity"]] <= RANK[args.fail_on] for f in flags))
    )


if __name__ == "__main__":
    sys.exit(main())
