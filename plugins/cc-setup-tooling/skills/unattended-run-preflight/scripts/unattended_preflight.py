#!/usr/bin/env python3
"""Say which tool calls of an unattended Claude Code run would stop for a permission prompt, before the run.

A scheduled task, routine, CI job or `claude -p` run has nobody to answer a permission prompt: the call waits
until the run times out, or (in dontAsk mode, or headless without a prompt tool) it is refused and the run goes on
without it. This script replays the tool calls of a previous run, or a list you write, against the permission
rules in the settings files you name, and reports for each distinct call whether it runs without a prompt, is
refused by a deny rule, or needs approval, with the rule and scope that decided it. For the calls that need
approval it proposes the narrowest allow rule, and marks the ones a person should decide on.

Usage:
  unattended_preflight.py --project . --transcript ~/.claude/projects/<dir>/<session>.jsonl
  unattended_preflight.py --project . --user ~/.claude/settings.json --calls calls.json --mode dontAsk
  unattended_preflight.py --project . --transcript run.jsonl --emit-rules

Inputs (local files only, nothing is run, no network):
  --transcript FILE   a Claude Code session log (JSON lines); every tool_use block is a call, and a tool_result
                      that reports a permission refusal is marked as observed. Repeatable.
  --calls FILE        a JSON list of {"tool": "Bash", "input": {"command": "git status"}}. Repeatable.
  --project DIR       reads DIR/.claude/settings.json (project) and DIR/.claude/settings.local.json (local)
  --user FILE, --managed FILE, --settings FILE (repeatable, for a --settings flag the run passes)

The matching follows https://code.claude.com/docs/en/permissions (read 2026-10-20): deny, then ask, then allow,
first match wins across every scope; compound Bash commands are split and each part must be allowed; a fixed set
of wrappers is stripped; Read, Grep and Glob need no approval inside the working directories; a built-in set of
read-only Bash commands runs without a prompt. It is an approximation of that page, not the real engine: when in
doubt it reports "needs approval", never "runs".

Exit codes: 0 every call runs without a prompt and none is denied, 1 at least one call needs approval or is
denied, 2 bad input (missing file, invalid JSON, a settings value of the wrong type, no calls found).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MODES = ("default", "acceptEdits", "dontAsk", "bypassPermissions")
SCOPE_ORDER = ("managed", "settings", "local", "project", "user")

# From the tools reference: tools whose "Permission required" column says No. Read, Grep and Glob are handled
# separately because they still prompt outside the working directories.
NO_APPROVAL_TOOLS = {
    "Agent",
    "Task",
    "AskUserQuestion",
    "CronCreate",
    "CronDelete",
    "CronList",
    "EndConversation",
    "EnterPlanMode",
    "ExitWorktree",
    "ListAgents",
    "ListMcpResourcesTool",
    "LSP",
    "PushNotification",
    "ReadMcpResourceTool",
    "RemoteTrigger",
    "ReportFindings",
    "ScheduleWakeup",
    "SendFeedback",
    "SendMessage",
    "SendUserFile",
    "SubagentHandback",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "TodoWrite",
    "ToolSearch",
    "WaitForMcpServers",
}
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead", "LS"}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
PATH_KEYS = ("file_path", "path", "notebook_path")

# Built-in read-only Bash commands (permissions page, "Read-only commands"). The real set is larger; a command
# missing here is reported as needing approval, which is the safe direction.
READ_ONLY_COMMANDS = {
    "ls",
    "cat",
    "echo",
    "pwd",
    "head",
    "tail",
    "grep",
    "find",
    "wc",
    "which",
    "diff",
    "stat",
    "du",
    "cd",
    "true",
    "false",
    "date",
    "whoami",
}
READ_ONLY_GIT = {"status", "log", "diff", "show", "rev-parse", "describe", "ls-files", "blame", "shortlog"}
FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob"}
# Programs that run whatever follows them: an allow rule for them is as wide as allowing everything.
RUNNERS = {
    "bash",
    "sh",
    "zsh",
    "dash",
    "fish",
    "eval",
    "exec",
    "env",
    "sudo",
    "doas",
    "su",
    "xargs",
    "python",
    "python3",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "npx",
    "pnpx",
    "uvx",
    "pipx",
    "docker",
    "kubectl",
    "ssh",
    "devbox",
    "direnv",
    "mise",
    "watch",
    "setsid",
}
# Subcommands that change or publish something; a rule for them is flagged for a person to decide.
RISKY = re.compile(
    "|".join(
        [
            r"^(rm|rmdir|mv|dd|mkfs|chmod|chown|curl|wget|scp|rsync)\b",
            r"^git (push|reset|clean|rebase|checkout|switch|branch -[dD]|tag -d|commit)\b",
            r"^gh (pr (merge|close|create|comment|review|edit)|issue (close|create|comment|edit))\b",
            r"^gh (release|repo (delete|edit)|api)\b",
            r"^(npm|pnpm|yarn) (publish|install|add|remove)\b",
            r"^pip3? install\b",
            r"^terraform (apply|destroy|import)\b",
            r"^aws \S+ (delete|put|create|update|terminate|remove)",
        ]
    )
)
MULTI_LEVEL = {
    "gh",
    "glab",
    "aws",
    "az",
    "gcloud",
    "kubectl",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "go",
    "dotnet",
    "terraform",
}
MCP_WRITE = re.compile(
    r"(^|_)(create|add|insert|update|set|put|patch|delete|remove|drop|send|post|publish|write|execute|run|deploy|"
    r"move|rename|merge|push|comment|reply|close|archive|assign|upload|invite|share|approve|cancel)(_|$)"
)
REDIRECT = re.compile(r"(?:^|\s)(?:\d|&)?>>?\s*(?!&\d)(\S+)")
SEPARATORS = re.compile(r"\|\||&&|\|&|;|\||&|\n")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
REFUSAL = re.compile(
    r"(requires approval|requested permissions?|permission (to use|denied|was denied)|"
    r"was blocked|not allowed to use|haven't granted|has not been granted|denied by)",
    re.IGNORECASE,
)


class InputError(Exception):
    """Bad input: exit code 2."""


@dataclass
class Rule:
    text: str
    kind: str  # deny, ask, allow
    scope: str
    tool: str
    spec: str | None


@dataclass
class Call:
    tool: str
    input: dict
    source: str
    observed_refusal: bool = False
    count: int = 1


@dataclass
class Verdict:
    call: Call
    outcome: str  # runs, denied, needs-approval
    reason: str
    rule: str | None = None
    scope: str | None = None
    parts: list[dict] = field(default_factory=list)
    suggestion: list[str] = field(default_factory=list)
    decide: bool = False


# ---------------------------------------------------------------- settings


def read_json(path: Path, label: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(f"{label}: {path} not found") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"{label}: cannot read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{label}: {path} is not valid JSON ({exc.msg}, line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise InputError(f"{label}: {path} must hold a JSON object")
    return data


def parse_rule(text: str, kind: str, scope: str) -> Rule:
    m = re.fullmatch(r"([^()]+?)(?:\((.*)\))?", text.strip(), re.DOTALL)
    if not m:
        return Rule(text, kind, scope, text.strip(), None)
    return Rule(text, kind, scope, m.group(1).strip(), m.group(2))


def load_rules(sources: list[tuple[str, dict]]) -> tuple[list[Rule], list[str], str | None]:
    rules: list[Rule] = []
    dirs: list[str] = []
    default_mode = None
    for scope, data in sources:
        perms = data.get("permissions", {})
        if not isinstance(perms, dict):
            raise InputError(f"{scope} settings: permissions must be an object")
        for kind in ("deny", "ask", "allow"):
            items = perms.get(kind, [])
            if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
                raise InputError(f"{scope} settings: permissions.{kind} must be a list of strings")
            rules += [parse_rule(x, kind, scope) for x in items]
        extra = perms.get("additionalDirectories", [])
        if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
            raise InputError(f"{scope} settings: permissions.additionalDirectories must be a list of strings")
        dirs += extra
        mode = perms.get("defaultMode")
        if mode is not None and not isinstance(mode, str):
            raise InputError(f"{scope} settings: permissions.defaultMode must be a string")
        if mode and default_mode is None:
            default_mode = mode
    return rules, dirs, default_mode


# ---------------------------------------------------------------- calls


def load_transcript(path: Path) -> list[Call]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise InputError(f"transcript: {path} not found") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"transcript: cannot read {path}: {exc}") from exc
    calls: dict[str, Call] = {}
    order: list[Call] = []
    parsed = 0
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"transcript: {path} line {n} is not JSON ({exc.msg})") from exc
        parsed += 1
        if not isinstance(rec, dict):
            continue
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and isinstance(block.get("name"), str):
                inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                call = Call(block["name"], inp, f"{path.name}:{n}")
                order.append(call)
                if isinstance(block.get("id"), str):
                    calls[block["id"]] = call
            elif block.get("type") == "tool_result" and block.get("tool_use_id") in calls:
                text = block.get("content")
                if isinstance(text, list):
                    text = " ".join(str(x.get("text", "")) for x in text if isinstance(x, dict))
                if block.get("is_error") and isinstance(text, str) and REFUSAL.search(text):
                    calls[block["tool_use_id"]].observed_refusal = True
    if parsed == 0:
        raise InputError(f"transcript: {path} holds no JSON lines")
    return order


def load_calls(path: Path) -> list[Call]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"calls: {path} not found") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"calls: {path} is not readable JSON: {exc}") from exc
    if not isinstance(data, list):
        raise InputError(f"calls: {path} must hold a JSON list")
    out = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("tool", item.get("name")), str):
            raise InputError(f"calls: {path} item {i} needs a string 'tool'")
        inp = item.get("input", {})
        if not isinstance(inp, dict):
            raise InputError(f"calls: {path} item {i}: 'input' must be an object")
        out.append(Call(item.get("tool", item.get("name")), inp, f"{path.name}[{i}]"))
    return out


def dedupe(calls: list[Call]) -> list[Call]:
    seen: dict[str, Call] = {}
    for c in calls:
        key = c.tool + "\0" + json.dumps(subject_input(c), sort_keys=True)
        if key in seen:
            seen[key].count += 1
            seen[key].observed_refusal |= c.observed_refusal
        else:
            seen[key] = c
    return list(seen.values())


def subject_input(c: Call) -> dict:
    keep = ("command", "file_path", "path", "notebook_path", "url", "pattern", "query")
    return {k: c.input[k] for k in keep if k in c.input}


# ---------------------------------------------------------------- matching helpers


def glob_to_regex(pattern: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def resolve_path(raw: str, cwd: str, home: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("~/") or p == "~":
        p = home + p[1:]
    elif not p.startswith("/") and not re.match(r"^[A-Za-z]:/", p):
        p = cwd.rstrip("/") + "/" + p
    return str(PurePosixPath(os.path.normpath(p))).replace("\\", "/")


def path_rule_matches(spec: str, kind: str, target: str, cwd: str, root: str, home: str) -> bool:
    if spec.startswith("!"):
        return False
    if spec.startswith("//"):
        pat = spec[1:]
    elif spec.startswith("~/"):
        pat = home + spec[1:]
    elif spec.startswith("/"):
        pat = root.rstrip("/") + spec
    else:
        bare = spec[2:] if spec.startswith("./") else spec
        if "/" not in bare.rstrip("/") or (kind != "allow" and not spec.startswith("./") and "/" in bare):
            # bare names match at any depth; deny and ask directory patterns match at any depth too
            pat = cwd.rstrip("/") + "/**/" + bare
        else:
            pat = cwd.rstrip("/") + "/" + bare
    rx = glob_to_regex(pat)
    if rx.match(target):
        return True
    return pat.endswith("/**") and target == pat[:-3]


def url_host(url: str) -> str:
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)", url)
    return m.group(1).lower() if m else ""


def display(path: str, cwd: str, home: str) -> str:
    if path == cwd:
        return "."
    if path.startswith(cwd.rstrip("/") + "/"):
        return "./" + path[len(cwd.rstrip("/")) + 1 :]
    if path.startswith(home + "/"):
        return "~/" + path[len(home) + 1 :]
    return path


def inside(target: str, dirs: list[str]) -> bool:
    return any(target == d or target.startswith(d.rstrip("/") + "/") for d in dirs)


def bash_rule_matches(spec: str, command: str) -> bool:
    if spec.endswith(":*"):
        spec = spec[:-2] + " *"
    if "*" not in spec:
        return command == spec
    if spec.endswith(" *") and spec.count("*") == 1 and command == spec[:-2]:
        return True
    rx = "".join(".*" if ch == "*" else re.escape(ch) for ch in spec)
    return re.fullmatch(rx, command, re.DOTALL) is not None


def mcp_rule_matches(rule: Rule, tool: str) -> bool:
    name = rule.tool
    if rule.spec is not None:
        return False  # parenthesised mcp__ rules are skipped when settings load
    if name == tool:
        return True
    if "*" in name:
        if rule.kind == "allow" and not re.match(r"mcp__[^*]+?__", name):
            return False  # unanchored allow globs are skipped
        return fnmatch.fnmatchcase(tool, name)
    parts = tool.split("__")
    return len(parts) >= 3 and name == "mcp__" + parts[1]


def split_compound(command: str) -> list[str] | None:
    """Split on shell separators outside quotes. None when the command cannot be analysed."""
    if "$(" in command or "`" in command or "<(" in command or ">(" in command:
        return None
    parts, buf, quote = [], [], None
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        m = SEPARATORS.match(command, i)
        if m:
            parts.append("".join(buf).strip())
            buf = []
            i = m.end()
            continue
        buf.append(ch)
        i += 1
    if quote:
        return None
    parts.append("".join(buf).strip())
    if any(not p for p in parts[:-1]) or (len(parts) > 1 and not parts[-1]):
        return None
    return [p for p in parts if p]


def strip_wrappers(part: str) -> tuple[str, bool]:
    """Return (command for matching, had_assignment)."""
    try:
        words = shlex.split(part)
    except ValueError:
        return part, False
    had_assign = False
    while words and ASSIGNMENT.match(words[0]):
        words = words[1:]
        had_assign = True
    changed = True
    while changed and words:
        changed = False
        w = words[0]
        if w in WRAPPERS and not (w == "command" and len(words) > 1 and words[1] == "-v"):
            words = words[1:]
            if w == "timeout":
                while words and words[0].startswith("-"):
                    words = words[1:]
                if words and re.fullmatch(r"\d+(\.\d+)?[smhd]?", words[0]):
                    words = words[1:]
            elif w in ("nice", "stdbuf"):
                while words and words[0].startswith("-"):
                    flag = words.pop(0)
                    if flag in ("-n",) and words:
                        words.pop(0)
            changed = True
        elif w == "xargs" and len(words) > 1 and not words[1].startswith("-"):
            words = words[1:]
            changed = True
    return " ".join(shlex.quote(x) if re.search(r"\s", x) else x for x in words), had_assign


def is_read_only(cmd: str, cwd: str, dirs: list[str], home: str) -> bool:
    if "<" in cmd or ">" in cmd:
        return False
    try:
        words = shlex.split(cmd)
    except ValueError:
        return False
    if not words:
        return False
    prog = words[0]
    if prog == "git":
        return len(words) > 1 and words[1] in READ_ONLY_GIT and not any(w.startswith("--output") for w in words)
    if prog == "find":
        return not (FIND_ACTIONS & set(words)) and "-files0-from" not in words
    if prog == "cd":
        return len(words) == 1 or inside(resolve_path(words[1], cwd, home), dirs)
    if prog in ("sed", "sort", "awk"):
        return False
    return prog in READ_ONLY_COMMANDS


# ---------------------------------------------------------------- decisions


def first_match(rules: list[Rule], test) -> Rule | None:
    for kind in ("deny", "ask", "allow"):
        for scope in SCOPE_ORDER:
            for r in rules:
                if r.kind == kind and r.scope == scope and test(r):
                    return r
    return None


def program_rule(cmd: str) -> tuple[str, bool]:
    """The narrowest useful allow rule for one Bash subcommand, and whether a person should decide."""
    words = cmd.split()
    decide = bool(RISKY.search(cmd)) or bool(words and words[0] in RUNNERS)
    if words and words[0] in RUNNERS:
        return f"Bash({cmd})", True
    depth = 3 if words and words[0] in MULTI_LEVEL else 2
    lead = []
    for w in words:
        if len(lead) >= depth or w.startswith("-") or "/" in w or "=" in w or "." in w[1:]:
            break
        lead.append(w)
    if len(lead) >= 2:
        return f"Bash({' '.join(lead)} *)", decide
    return (f"Bash({cmd})" if len(words) > 1 else f"Bash({words[0]} *)"), decide


def split_redirects(cmd: str) -> tuple[str, list[str]]:
    """The command without output redirections, and the redirect targets other than /dev/null."""
    targets = [t for t in REDIRECT.findall(cmd) if t != "/dev/null"]
    return REDIRECT.sub("", cmd).strip(), targets


def judge_bash(call: Call, rules, mode, cwd, dirs, home) -> Verdict:
    command = call.input.get("command")
    if not isinstance(command, str) or not command.strip():
        return Verdict(call, "needs-approval", "no command text in the call")
    parts = split_compound(command)
    if parts is None:
        deny = first_match(rules, lambda r: r.tool == "Bash" and r.kind == "deny" and r.spec is None)
        if deny:
            return Verdict(call, "denied", "the Bash tool is denied", deny.text, deny.scope)
        if mode == "bypassPermissions":
            return Verdict(call, "runs", "bypassPermissions mode")
        return Verdict(
            call,
            "needs-approval",
            "command substitution, process substitution, an unterminated quote or an empty side of && or || "
            "cannot be split safely, so allow rules do not cover it",
            suggestion=[],
            decide=True,
        )
    results = []
    for raw in parts:
        bare, targets = split_redirects(raw)
        cmd, had_assign = strip_wrappers(bare)
        for t in targets:
            v = judge_path(Call("Write", {"file_path": t}, call.source), rules, mode, cwd, cwd, dirs, home)
            results.append(
                {"part": f"> {t}", "outcome": v.outcome, "rule": v.rule, "scope": v.scope, "suggest": v.suggestion}
            )
        rule = first_match(
            rules,
            lambda r, cmd=cmd, had_assign=had_assign: (
                r.tool == "Bash"
                and (r.spec is None or r.spec == "*" or bash_rule_matches(r.spec, cmd))
                and not (r.kind == "allow" and had_assign and r.spec not in (None, "*"))
            ),
        )
        if rule and rule.kind == "deny":
            results.append({"part": cmd, "outcome": "denied", "rule": rule.text, "scope": rule.scope})
        elif rule and rule.kind == "ask":
            results.append({"part": cmd, "outcome": "needs-approval", "rule": rule.text, "scope": rule.scope})
        elif rule:
            results.append({"part": cmd, "outcome": "runs", "rule": rule.text, "scope": rule.scope})
        elif is_read_only(cmd, cwd, dirs, home):
            results.append({"part": cmd, "outcome": "runs", "rule": "built-in read-only command", "scope": None})
        elif mode == "bypassPermissions":
            results.append({"part": cmd, "outcome": "runs", "rule": "bypassPermissions mode", "scope": None})
        else:
            results.append({"part": cmd, "outcome": "needs-approval", "rule": None, "scope": None})
    if any(r["outcome"] == "denied" for r in results):
        hit = next(r for r in results if r["outcome"] == "denied")
        return Verdict(call, "denied", f"`{hit['part']}` matches a deny rule", hit["rule"], hit["scope"], results)
    pending = [r for r in results if r["outcome"] == "needs-approval"]
    if not pending:
        return Verdict(call, "runs", "every part is allowed", parts=results)
    suggestion, decide = [], False
    for r in pending:
        if r["rule"]:
            decide = True  # an ask rule is a decision someone made; do not override it silently
            continue
        if "suggest" in r:
            suggestion += [x for x in r["suggest"] if x not in suggestion]
            continue
        rule_text, risky = program_rule(r["part"])
        suggestion.append(rule_text)
        decide |= risky
    first = pending[0]
    why = f"ask rule {first['rule']} ({first['scope']})" if first["rule"] else "no allow rule covers"
    return Verdict(
        call, "needs-approval", f"`{first['part']}`: {why}", first["rule"], first["scope"], results, suggestion, decide
    )


def judge_path(call: Call, rules, mode, cwd, root, dirs, home) -> Verdict:
    raw = next((call.input[k] for k in PATH_KEYS if isinstance(call.input.get(k), str)), None)
    is_edit = call.tool in EDIT_TOOLS
    family = "Edit" if is_edit else "Read"
    target = cwd if raw is None else resolve_path(raw, cwd, home)
    shown = display(target, cwd, home)

    def test(r: Rule) -> bool:
        if r.tool == call.tool and r.spec is None:
            return True
        if r.tool != family:
            return False
        if r.spec is None or r.spec == "*" or r.spec == "**":
            return True
        return path_rule_matches(r.spec, r.kind, target, cwd, root, home)

    rule = first_match(rules, test)
    if rule and rule.kind == "deny":
        return Verdict(call, "denied", f"{shown} matches a deny rule", rule.text, rule.scope)
    if rule and rule.kind == "ask":
        return Verdict(call, "needs-approval", f"ask rule for {shown}", rule.text, rule.scope, decide=True)
    if rule:
        return Verdict(call, "runs", f"allow rule covers {shown}", rule.text, rule.scope)
    in_wd = inside(target, dirs)
    if not is_edit and in_wd:
        return Verdict(call, "runs", "read inside the working directories needs no approval")
    if mode == "bypassPermissions":
        return Verdict(call, "runs", "bypassPermissions mode")
    if is_edit and mode == "acceptEdits" and in_wd:
        return Verdict(call, "runs", "acceptEdits mode, inside the working directories")
    parent = str(PurePosixPath(target).parent)
    if parent.startswith(cwd.rstrip("/") + "/") or parent == cwd:
        rel = parent[len(cwd) :].lstrip("/")
        spec = f"./{rel}/**" if rel else "./" + PurePosixPath(target).name
    elif parent.startswith(home.rstrip("/") + "/"):
        spec = "~/" + parent[len(home) :].lstrip("/") + "/**"
    else:
        spec = "/" + parent + "/**"
    where = "outside the working directories" if not in_wd else "inside the working directories"
    return Verdict(
        call,
        "needs-approval",
        f"{'edit' if is_edit else 'read'} of {shown} {where}, no allow rule",
        suggestion=[f"{family}({spec})"],
        decide=is_edit and not in_wd,
    )


def judge_simple(call: Call, rules, mode) -> Verdict:
    tool = call.tool
    if tool == "WebFetch":
        url = call.input.get("url") if isinstance(call.input.get("url"), str) else ""
        host = url_host(url)

        def test(r: Rule) -> bool:
            if r.tool != "WebFetch":
                return False
            if r.spec is None:
                return True
            if not r.spec.startswith("domain:"):
                return False
            pat = r.spec[7:].lower()
            if pat == "*":
                return True
            if pat.startswith("*."):
                return host.endswith(pat[1:])
            return host == pat

        rule = first_match(rules, test)
        suggestion = [f"WebFetch(domain:{host})"] if host else []
        writes = False
    elif tool.startswith("mcp__"):
        rule = first_match(rules, lambda r: (r.tool == "*" and r.kind != "allow") or mcp_rule_matches(r, tool))
        suggestion = [tool]
        writes = bool(MCP_WRITE.search(tool.split("__")[-1].lower()))
    else:
        rule = first_match(rules, lambda r: r.tool == tool and r.spec is None)
        suggestion = [tool]
        writes = False
    if rule and rule.kind == "deny":
        return Verdict(call, "denied", "matches a deny rule", rule.text, rule.scope)
    if rule and rule.kind == "ask":
        return Verdict(call, "needs-approval", "matches an ask rule", rule.text, rule.scope, decide=True)
    if rule:
        return Verdict(call, "runs", "allow rule", rule.text, rule.scope)
    if tool in NO_APPROVAL_TOOLS:
        return Verdict(call, "runs", "tool needs no approval")
    if mode == "bypassPermissions":
        return Verdict(call, "runs", "bypassPermissions mode")
    known = tool.startswith("mcp__") or tool in {"WebFetch", "WebSearch", "Skill", "Workflow", "Monitor", "Artifact"}
    why = "no allow rule" if known else "not a tool this script knows; assumed to need approval"
    if writes:
        why += "; the name says it changes something"
    return Verdict(call, "needs-approval", why, suggestion=suggestion, decide=writes or not known)


def judge(call: Call, rules, mode, cwd, root, dirs, home) -> Verdict:
    if call.tool in ("Bash", "PowerShell"):
        if call.tool == "PowerShell":
            call = Call("Bash", call.input, call.source, call.observed_refusal, call.count)
        return judge_bash(call, rules, mode, cwd, dirs, home)
    if call.tool in READ_TOOLS or call.tool in EDIT_TOOLS:
        return judge_path(call, rules, mode, cwd, root, dirs, home)
    return judge_simple(call, rules, mode)


# ---------------------------------------------------------------- report


def label(c: Call, cwd: str, home: str) -> str:
    inp = subject_input(c)
    if c.tool == "Bash":
        return f"Bash: {inp.get('command', '')}"
    for k in PATH_KEYS:
        if isinstance(inp.get(k), str):
            return f"{c.tool}: {display(resolve_path(inp[k], cwd, home), cwd, home)}"
    if inp:
        return f"{c.tool}: {next(iter(inp.values()))}"
    return c.tool


def effect(outcome: str, mode: str) -> str:
    if outcome == "runs":
        return "runs"
    if outcome == "denied":
        return "refused (deny rule)"
    return "refused without asking (dontAsk)" if mode == "dontAsk" else "waits for a person (stalls)"


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# Unattended run preflight",
        "",
        f"Mode: {report['mode']}. Scopes read: {', '.join(report['scopes']) or 'none'}. "
        f"Calls: {s['calls']} ({s['distinct']} distinct).",
        "",
        f"- Runs without a prompt: {s['runs']}",
        f"- Needs approval: {s['needs_approval']} (unattended effect: {effect('needs-approval', report['mode'])})",
        f"- Denied by a rule: {s['denied']}",
        f"- Refused in the recorded run: {s['observed_refusals']}",
        "",
        "## Calls that would stop the run",
        "",
    ]
    stop = [v for v in report["calls"] if v["outcome"] != "runs"]
    if not stop:
        lines.append("None.")
    for v in stop:
        seen = " Refused in the recorded run." if v["observed_refusal"] else ""
        rule = f" Rule: `{v['rule']}` ({v['scope']})." if v["rule"] else ""
        lines.append(f"- **{v['outcome']}** `{v['call']}` (x{v['count']}, {v['source']}): {v['reason']}.{rule}{seen}")
    lines += ["", "## Proposed allow rules", ""]
    if not report["proposed"]["allow"] and not report["proposed"]["decide"]:
        lines.append("None needed.")
    for r in report["proposed"]["allow"]:
        lines.append(f"- `{r}`")
    if report["proposed"]["decide"]:
        lines += ["", "Decide before allowing (they change, publish or run arbitrary code, or an ask rule exists):", ""]
        lines += [f"- `{r}`" for r in report["proposed"]["decide"]]
    lines += ["", "## Calls that run", ""]
    ok = [v for v in report["calls"] if v["outcome"] == "runs"]
    lines += [f"- `{v['call']}`: {v['reason']}" + (f" (`{v['rule']}`)" if v["rule"] else "") for v in ok] or ["None."]
    lines += [
        "",
        "This is an approximation of the documented matching; confirm in one supervised run with the same mode.",
    ]
    return "\n".join(lines) + "\n"


def build_report(verdicts: list[Verdict], mode: str, scopes: list[str], cwd: str, home: str) -> dict:
    allow, decide = [], []
    for v in verdicts:
        for s in v.suggestion:
            target = decide if v.decide else allow
            if s not in allow and s not in decide:
                target.append(s)
    calls = [
        {
            "call": label(v.call, cwd, home),
            "tool": v.call.tool,
            "outcome": v.outcome,
            "effect": effect(v.outcome, mode),
            "reason": v.reason,
            "rule": v.rule,
            "scope": v.scope,
            "count": v.call.count,
            "source": v.call.source,
            "observed_refusal": v.call.observed_refusal,
            "parts": v.parts,
        }
        for v in verdicts
    ]
    return {
        "mode": mode,
        "scopes": scopes,
        "summary": {
            "calls": sum(v.call.count for v in verdicts),
            "distinct": len(verdicts),
            "runs": sum(v.outcome == "runs" for v in verdicts),
            "needs_approval": sum(v.outcome == "needs-approval" for v in verdicts),
            "denied": sum(v.outcome == "denied" for v in verdicts),
            "observed_refusals": sum(v.call.observed_refusal for v in verdicts),
        },
        "calls": calls,
        "proposed": {"allow": allow, "decide": decide},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="unattended_preflight.py",
        description="Replay the tool calls of a Claude Code run against your permission rules and list the calls "
        "that would stop an unattended run (scheduled task, routine, CI, claude -p), with proposed allow rules.",
        epilog="Exit codes: 0 every call runs without a prompt, 1 at least one call needs approval or is denied, "
        "2 bad input.",
    )
    ap.add_argument("--transcript", action="append", default=[], help="Claude Code session log (JSON lines)")
    ap.add_argument("--calls", action="append", default=[], help='JSON list of {"tool": ..., "input": {...}}')
    ap.add_argument("--project", help="project folder: reads .claude/settings.json and .claude/settings.local.json")
    ap.add_argument("--user", help="user settings file, for example ~/.claude/settings.json")
    ap.add_argument("--managed", help="managed settings file")
    ap.add_argument("--settings", action="append", default=[], help="a file the run passes with --settings")
    ap.add_argument("--mode", choices=MODES, help="permission mode of the run (default: defaultMode or default)")
    ap.add_argument("--cwd", help="working directory of the run (default: the project folder)")
    ap.add_argument("--add-dir", action="append", default=[], help="an additional working directory")
    ap.add_argument("--home", help="home folder for ~ paths (default: yours)")
    ap.add_argument("--emit-rules", action="store_true", help="print only the proposed permissions block as JSON")
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--out", help="write the report to this file")
    args = ap.parse_args(argv)

    try:
        sources: list[tuple[str, dict]] = []
        if args.managed:
            sources.append(("managed", read_json(Path(args.managed), "managed")))
        for f in args.settings:
            sources.append(("settings", read_json(Path(f), "settings")))
        if args.project:
            proj = Path(args.project)
            if not proj.is_dir():
                raise InputError(f"project: {proj} is not a folder")
            for scope, name in (("local", "settings.local.json"), ("project", "settings.json")):
                p = proj / ".claude" / name
                if p.exists():
                    sources.append((scope, read_json(p, scope)))
        if args.user:
            p = Path(args.user).expanduser()
            if p.exists():
                sources.append(("user", read_json(p, "user")))
        rules, extra_dirs, default_mode = load_rules(sources)
        mode = args.mode or (default_mode if default_mode in MODES else "default")
        calls: list[Call] = []
        for t in args.transcript:
            calls += load_transcript(Path(t).expanduser())
        for c in args.calls:
            calls += load_calls(Path(c).expanduser())
        if not calls:
            raise InputError("no tool calls found: give --transcript or --calls with at least one call")
    except InputError as exc:
        print(f"unattended_preflight.py: {exc}", file=sys.stderr)
        return 2

    home = (args.home or str(Path.home())).replace("\\", "/").rstrip("/")
    root = str(Path(args.project).resolve()).replace("\\", "/") if args.project else os.getcwd().replace("\\", "/")
    cwd = resolve_path(args.cwd, root, home) if args.cwd else root
    dirs = [cwd] + [resolve_path(d, cwd, home) for d in [*extra_dirs, *args.add_dir]]
    verdicts = [judge(c, rules, mode, cwd, root, dirs, home) for c in dedupe(calls)]
    report = build_report(verdicts, mode, [s for s, _ in sources], cwd, home)

    if args.emit_rules:
        text = json.dumps({"permissions": {"allow": report["proposed"]["allow"]}}, indent=2) + "\n"
    elif args.json or args.format == "json":
        text = json.dumps(report, indent=2) + "\n"
    else:
        text = render_markdown(report)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    s = report["summary"]
    return 1 if s["needs_approval"] or s["denied"] else 0


if __name__ == "__main__":
    sys.exit(main())
