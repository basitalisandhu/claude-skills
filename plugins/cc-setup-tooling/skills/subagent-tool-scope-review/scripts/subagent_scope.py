#!/usr/bin/env python3
"""Review the tools each Claude Code subagent can use, and flag agents that can do more than their job needs.

A subagent file (.claude/agents/<name>.md, ~/.claude/agents/, or a plugin's agents/ folder) with no `tools` line
inherits every tool the session has, including every tool of every connected MCP server. A field name Claude Code
does not know (such as `allowed-tools`, which belongs to skills) is ignored silently, so the agent keeps everything.
This script reads the front matter of every agent file, works out what each agent can actually reach, and reports
it with findings and a narrower `tools` line where the agent's own description says it only reads.

Usage:
  subagent_scope.py --project .
  subagent_scope.py --project . --user-agents ~/.claude/agents --mcp .mcp.json --mcp ~/.claude.json
  subagent_scope.py --plugin path/to/plugin --format json --fail-on medium

Field names, defaults and MCP rule forms come from https://code.claude.com/docs/en/sub-agents and the tool list
from https://code.claude.com/docs/en/tools-reference (both read 2026-10-20). Local files only, no network.

Exit codes: 0 no finding at or above --fail-on (default high), 1 at least one, 2 bad input (a folder or --mcp
file missing, invalid JSON in --mcp, no agent files found).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high")
DOCUMENTED_FIELDS = {
    "name",
    "description",
    "tools",
    "disallowedTools",
    "model",
    "permissionMode",
    "mcpServers",
    "hooks",
    "skills",
    "maxTurns",
    "memory",
    "background",
    "omitClaudeMd",
    "effort",
    "isolation",
    "initialPrompt",
    "autoCompactWindow",
    "color",
    "experimental",
}
PLUGIN_IGNORED = {"permissionMode", "mcpServers", "hooks", "initialPrompt"}
# Fields from other file types that people copy into agent files; the agent then keeps every tool.
LOOKALIKES = {
    "allowed-tools": "tools",
    "allowedTools": "tools",
    "allowed_tools": "tools",
    "disallowed-tools": "disallowedTools",
    "disallowed_tools": "disallowedTools",
    "permission-mode": "permissionMode",
    "permission_mode": "permissionMode",
    "mcp-servers": "mcpServers",
    "mcp_servers": "mcpServers",
}
BUILTIN_TOOLS = {
    "Agent",
    "Artifact",
    "AskUserQuestion",
    "Bash",
    "CronCreate",
    "CronDelete",
    "CronList",
    "Edit",
    "EndConversation",
    "EnterPlanMode",
    "EnterWorktree",
    "ExitPlanMode",
    "ExitWorktree",
    "Glob",
    "Grep",
    "ListAgents",
    "ListMcpResourcesTool",
    "LSP",
    "Monitor",
    "NotebookEdit",
    "PowerShell",
    "PushNotification",
    "Read",
    "ReadMcpResourceTool",
    "RemoteTrigger",
    "ReportFindings",
    "ScheduleWakeup",
    "SendFeedback",
    "SendMessage",
    "SendUserFile",
    "ShareOnboardingGuide",
    "Skill",
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
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
    # legacy names still accepted
    "Task",
    "MultiEdit",
}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell", "Monitor"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}
READ_ONLY_SET = ["Read", "Grep", "Glob"]
READ_ONLY_WORDS = re.compile(
    r"\b(review(?:s|er|ing)?|audit(?:s|or|ing)?|read[- ]only|research(?:er|es|ing)?|explor(?:e|er|es|ing)|"
    r"analy[sz](?:e|es|er|ing|is)|investigat(?:e|es|or|ing)|inspect(?:s|or|ing)?|summari[sz](?:e|es|er|ing)|"
    r"plan(?:ner|ning)?|search(?:es|er|ing)?|explain(?:s|er|ing)?|triage)\b",
    re.IGNORECASE,
)
WRITE_WORDS = re.compile(
    r"\b(writ(?:e|es|ing)|edit(?:s|ing)?|fix(?:es|ing)?|implement(?:s|ing)?|refactor(?:s|ing)?|build(?:s|ing)?|"
    r"creat(?:e|es|ing)|generat(?:e|es|ing)|updat(?:e|es|ing)|migrat(?:e|es|ing)|deploy(?:s|ing)?|"
    r"run(?:s|ning)?|test(?:s|ing)?|install(?:s|ing)?)\b",
    re.IGNORECASE,
)
WEB_WORDS = re.compile(r"\b(web|internet|online|docs? site|url|search the)\b", re.IGNORECASE)


class InputError(Exception):
    """Bad input: exit code 2."""


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str
    fix: str


@dataclass
class Agent:
    path: Path
    shown: str
    scope: str
    fields: dict
    raw_keys: list[str]
    parse_error: str | None = None
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------- front matter


def split_frontmatter(text: str) -> tuple[str | None, str | None]:
    text = text.lstrip("﻿")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "no front matter (the file must start with ---)"
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            return "\n".join(lines[1:i]), None
    return None, "front matter is not closed with ---"


def scalar(value: str):
    v = value.strip()
    if v.startswith(("'", '"')) and v.endswith(v[0]) and len(v) >= 2:
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        return [scalar(x) for x in split_inline(v[1:-1])]
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v


def split_inline(body: str) -> list[str]:
    out, buf, depth, quote = [], [], 0, None
    for ch in body:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return out


def parse_frontmatter(block: str) -> tuple[dict, list[str]]:
    """A small reader for the YAML subset agent files use: top-level keys, scalars, inline and block lists.

    Nested mappings under a key (hooks, mcpServers inline definitions, experimental) are kept as the list of
    their first-level item names, which is all this review needs.
    """
    fields: dict = {}
    keys: list[str] = []
    current = None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
        if m and not line[0].isspace():
            current = m.group(1)
            keys.append(current)
            value = m.group(2).strip()
            fields[current] = scalar(value) if value and value not in ("|", ">", "|-", ">-") else []
            continue
        if current is None:
            continue
        item = re.match(r"^\s+-\s*(.*)$", line)
        if item and isinstance(fields[current], list):
            text = item.group(1).strip()
            name = re.match(r"^([A-Za-z0-9_.@/-]+)\s*:(\s|$)", text)
            fields[current].append({"name": name.group(1), "inline": True} if name else scalar(text))
            continue
        nested = re.match(r"^(\s+)([A-Za-z0-9_.@/-]+)\s*:", line)
        if nested and isinstance(fields[current], list) and len(nested.group(1)) <= 2:
            fields[current].append({"name": nested.group(2), "inline": True})
        elif nested is None and isinstance(fields[current], list) and not fields[current]:
            fields[current] = line.strip()  # folded or literal text
        elif isinstance(fields[current], str):
            fields[current] = (fields[current] + " " + line.strip()).strip()
    return fields, keys


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x["name"]) if isinstance(x, dict) else str(x) for x in value]
    return [x.strip() for x in str(value).split(",") if x.strip()]


# ---------------------------------------------------------------- MCP servers


def load_mcp(paths: list[str], project: Path | None) -> list[str]:
    names: list[str] = []
    for raw in paths:
        p = Path(raw).expanduser()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise InputError(f"--mcp: {p} not found") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InputError(f"--mcp: {p} is not readable JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise InputError(f"--mcp: {p} must hold a JSON object")
        blocks = [data.get("mcpServers")]
        projects = data.get("projects")
        if isinstance(projects, dict) and project is not None:
            entry = projects.get(str(project.resolve()))
            if isinstance(entry, dict):
                blocks.append(entry.get("mcpServers"))
        for block in blocks:
            if block is None:
                continue
            if not isinstance(block, dict):
                raise InputError(f"--mcp: {p}: mcpServers must be an object")
            names += [n for n in block if n not in names]
    return names


def mcp_key(server: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", server)


# ---------------------------------------------------------------- review


def find_agents(project: Path | None, user_dirs: list[str], plugins: list[str]) -> list[tuple[Path, str, str]]:
    found: list[tuple[Path, str, str]] = []
    roots: list[tuple[Path, str, Path]] = []
    if project is not None:
        roots.append((project / ".claude" / "agents", "project", project))
    for d in user_dirs:
        p = Path(d).expanduser()
        if not p.is_dir():
            raise InputError(f"--user-agents: {p} is not a folder")
        roots.append((p, "user", p))
    for d in plugins:
        p = Path(d).expanduser()
        if not p.is_dir():
            raise InputError(f"--plugin: {p} is not a folder")
        roots.append((p / "agents", "plugin", p))
    for folder, scope, base in roots:
        if not folder.is_dir():
            continue
        for f in sorted(folder.rglob("*.md")):
            try:
                shown = f.relative_to(base).as_posix()
            except ValueError:
                shown = f.as_posix()
            found.append((f, scope, shown))
    return found


def add(agent: Agent, rule: str, severity: str, detail: str, fix: str) -> None:
    agent.findings.append(Finding(rule, severity, detail, fix))


def review(agent: Agent, servers: list[str]) -> dict:
    f = agent.fields
    is_plugin = agent.scope == "plugin"
    name = f.get("name") if isinstance(f.get("name"), str) else ""
    desc = f.get("description") if isinstance(f.get("description"), str) else ""
    if not name:
        add(agent, "missing-name", "low", "no `name` field", "add a lowercase name; it is required")
    elif ":" in name:
        add(agent, "name-colon", "low", f"name `{name}` contains `:`", "`:` is reserved for plugin-scoped names")
    if not desc:
        add(agent, "missing-description", "low", "no `description` field", "say when Claude should delegate to it")

    for key in agent.raw_keys:
        if key in LOOKALIKES:
            real = LOOKALIKES[key]
            severity = "high" if real == "tools" and "tools" not in f else "medium"
            add(
                agent,
                "lookalike-field",
                severity,
                f"`{key}` is not a subagent field and is ignored, so it restricts nothing",
                f"rename it to `{real}`",
            )
        elif key not in DOCUMENTED_FIELDS:
            add(agent, "unknown-field", "low", f"`{key}` is not a documented subagent field (ignored)", "remove it")
        elif is_plugin and key in PLUGIN_IGNORED:
            add(
                agent,
                "plugin-ignored-field",
                "low",
                f"`{key}` is ignored for plugin subagents",
                "move the agent to .claude/agents to use it, or drop the field",
            )

    tools = as_list(f.get("tools")) if "tools" in f else None
    disallowed = as_list(f.get("disallowedTools"))
    own_servers = as_list(f.get("mcpServers")) if not is_plugin else []
    inline = [x["name"] for x in f.get("mcpServers", []) if isinstance(x, dict)] if not is_plugin else []
    reachable_servers = list(dict.fromkeys([*servers, *own_servers]))

    def removed(tool: str) -> bool:
        for d in disallowed:
            base = d.split("(", 1)[0].strip()
            if base == tool or (base.endswith("*") and tool.startswith(base[:-1])):
                return True
        return False

    def server_removed(server: str) -> bool:
        key = f"mcp__{mcp_key(server)}"
        return any(d in ("mcp__*", key, key + "__*") for d in disallowed)

    if tools is None:
        builtins = sorted(t for t in BUILTIN_TOOLS - {"Task", "MultiEdit"} if not removed(t))
        mcp_grants = [f"mcp__{mcp_key(s)}__* (inherited)" for s in reachable_servers if not server_removed(s)]
        inherits_mcp = not any(d == "mcp__*" for d in disallowed)
    else:
        # a bracketed entry such as Bash(npm test *) is counted as the whole tool: the safe reading
        bases = {t.split("(", 1)[0].strip() for t in tools}
        builtins = sorted(t for t in bases if t in BUILTIN_TOOLS and not removed(t))
        mcp_grants = [t for t in tools if t.startswith("mcp__") and not removed(t)]
        mcp_grants += [f"mcp__{mcp_key(s)}__* (mcpServers)" for s in own_servers if not server_removed(s)]
        inherits_mcp = False
        for t in tools:
            if t not in BUILTIN_TOOLS and not t.startswith("mcp__"):
                base = t.split("(", 1)[0]
                if base in BUILTIN_TOOLS:
                    add(
                        agent,
                        "specifier-in-tools",
                        "medium",
                        f"`{t}` in `tools`: the documented form is a tool name; a rule in brackets may not narrow it",
                        f"list `{base}` and narrow it with permission rules or a PreToolUse hook",
                    )
                else:
                    add(agent, "unknown-tool", "low", f"`{t}` is not a built-in tool name", "check the spelling")
        if not tools:
            add(agent, "empty-tools", "low", "`tools` is empty", "list the tools, or remove the line to inherit")
    for d in disallowed:
        if "(" in d:
            add(
                agent,
                "disallowed-specifier",
                "info",
                f"`{d}` in `disallowedTools` removes the whole `{d.split('(', 1)[0]}` tool, not one pattern",
                "use a deny permission rule for one pattern",
            )

    can_write = bool(WRITE_TOOLS & set(builtins))
    can_shell = bool(SHELL_TOOLS & set(builtins))
    can_net = bool(NETWORK_TOOLS & set(builtins))
    text = f"{name} {desc}"
    reads_only = bool(READ_ONLY_WORDS.search(text)) and not WRITE_WORDS.search(text)

    if tools is None:
        what = "every built-in tool"
        if reachable_servers and inherits_mcp:
            what += " and every tool of " + ", ".join(f"`{s}`" for s in reachable_servers)
        elif inherits_mcp:
            what += " and every MCP tool the session connects"
        severity = "high" if (can_write or can_shell) and reads_only else "medium"
        add(
            agent,
            "inherits-all-tools",
            severity,
            f"no `tools` line, so it inherits {what}",
            "add a `tools` line with only what the job needs"
            + ("" if not reads_only else f", for example `tools: {', '.join(suggest_tools(text))}`"),
        )
    elif reads_only and (can_write or can_shell):
        granted = sorted((WRITE_TOOLS | SHELL_TOOLS) & set(builtins))
        add(
            agent,
            "read-only-job-with-write-tools",
            "high",
            f"the description says it reviews or reads, but it can use {', '.join(granted)}",
            f"use `tools: {', '.join(suggest_tools(text))}`",
        )
    for t in tools or []:
        parts = t.split("__")
        if t == "mcp__*" or (parts[0] == "mcp" and (len(parts) == 2 or (len(parts) == 3 and parts[2] == "*"))):
            add(
                agent,
                "server-wide-mcp-grant",
                "high" if t == "mcp__*" else "medium",
                f"`{t}` gives every tool of {'every server' if t == 'mcp__*' else 'the server'}, "
                "including tools added later",
                "name the tools it needs, such as `mcp__<server>__get_issue`",
            )

    mode = f.get("permissionMode")
    if isinstance(mode, str) and mode:
        if is_plugin:
            pass  # reported as plugin-ignored-field
        elif mode == "bypassPermissions":
            add(
                agent,
                "bypass-mode",
                "high",
                "`permissionMode: bypassPermissions` skips every permission prompt for this agent",
                "use `default`, or `acceptEdits` for an agent that only edits files",
            )
        elif mode in ("auto", "dontAsk", "acceptEdits") and reads_only:
            add(
                agent,
                "loose-mode-for-reader",
                "medium",
                f"`permissionMode: {mode}` on an agent whose description says it only reads",
                "use `default` or `plan`",
            )
        elif mode not in ("default", "acceptEdits", "auto", "dontAsk", "bypassPermissions", "plan", "manual"):
            add(agent, "unknown-mode", "low", f"`permissionMode: {mode}` is not a documented value", "fix it")

    for srv in inline:
        add(
            agent,
            "inline-mcp-server",
            "medium",
            f"defines its own MCP server `{srv}`, started when the agent starts and outside the project's .mcp.json",
            "pin the package version and review it with connector-register or mcp-server-review",
        )
    return {
        "builtins": builtins,
        "mcp": mcp_grants,
        "inherits_mcp": inherits_mcp,
        "writes": can_write,
        "shell": can_shell,
        "network": can_net,
        "reads_only_job": reads_only,
        "suggested_tools": suggest_tools(text) if reads_only else None,
    }


def suggest_tools(text: str) -> list[str]:
    out = list(READ_ONLY_SET)
    if WEB_WORDS.search(text):
        out += ["WebFetch", "WebSearch"]
    return out


# ---------------------------------------------------------------- output


def render_markdown(result: dict) -> str:
    lines = ["# Subagent tool scope review", ""]
    s = result["summary"]
    lines.append(
        f"Agents: {s['agents']}. MCP servers known: {', '.join(result['servers']) or 'none given (--mcp)'}. "
        f"Findings: {s['high']} high, {s['medium']} medium, {s['low']} low, {s['info']} info."
    )
    lines += ["", "| Agent | Scope | Tools | MCP | Writes | Shell | Web |", "|---|---|---|---|---|---|---|"]
    for a in result["agents"]:
        e = a["effective"]
        if a["error"]:
            lines.append(f"| `{a['file']}` | {a['scope']} | unreadable | | | | |")
            continue
        tools = "all (inherited)" if a["inherits_all"] else (", ".join(e["builtins"]) or "none")
        mcp = ", ".join(e["mcp"]) or ("all connected" if e["inherits_mcp"] else "none")
        yes = {True: "yes", False: "no"}
        lines.append(
            f"| `{a['name'] or a['file']}` | {a['scope']} | {tools} | {mcp} | "
            f"{yes[e['writes']]} | {yes[e['shell']]} | {yes[e['network']]} |"
        )
    lines += ["", "## Findings", ""]
    any_finding = False
    for a in result["agents"]:
        for fd in a["findings"]:
            any_finding = True
            lines.append(f"- {fd['severity']} {fd['rule']} `{a['file']}`: {fd['detail']}. Fix: {fd['fix']}.")
    if not any_finding:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="subagent_scope.py",
        description="Show what each Claude Code subagent can reach (built-in tools, MCP servers, write, shell, web) "
        "and flag agents with more access than their description needs.",
        epilog="Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 bad input.",
    )
    ap.add_argument("--project", help="project folder: reads .claude/agents/**/*.md")
    ap.add_argument("--user-agents", action="append", default=[], help="a user agents folder, e.g. ~/.claude/agents")
    ap.add_argument("--plugin", action="append", default=[], help="a plugin folder: reads its agents/**/*.md")
    ap.add_argument("--mcp", action="append", default=[], help=".mcp.json or ~/.claude.json, for server names")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:], default="high", help="lowest severity for exit 1")
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--out", help="write the report to this file")
    args = ap.parse_args(argv)

    try:
        project = Path(args.project) if args.project else None
        if project is not None and not project.is_dir():
            raise InputError(f"--project: {project} is not a folder")
        if project is None and not args.user_agents and not args.plugin:
            raise InputError("give --project, --user-agents or --plugin")
        servers = load_mcp(args.mcp, project)
        files = find_agents(project, args.user_agents, args.plugin)
        if not files:
            raise InputError("no agent files found (looked for .claude/agents/*.md, agents/*.md)")
    except InputError as exc:
        print(f"subagent_scope.py: {exc}", file=sys.stderr)
        return 2

    agents_out = []
    for path, scope, shown in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            block, err = None, f"cannot read: {exc}"
        else:
            block, err = split_frontmatter(text)
        agent = Agent(path, shown, scope, {}, [], err)
        effective = None
        if block is not None:
            agent.fields, agent.raw_keys = parse_frontmatter(block)
            effective = review(agent, servers)
        else:
            add(agent, "invalid-file", "low", err or "unreadable", "start the file with front matter between ---")
        agents_out.append(
            {
                "file": f"{scope}:{shown}",
                "scope": scope,
                "name": agent.fields.get("name") if isinstance(agent.fields.get("name"), str) else None,
                "error": err,
                "inherits_all": block is not None and "tools" not in agent.fields,
                "effective": effective
                or {
                    "builtins": [],
                    "mcp": [],
                    "inherits_mcp": False,
                    "writes": False,
                    "shell": False,
                    "network": False,
                },
                "findings": [fd.__dict__ for fd in agent.findings],
            }
        )
    counts = {sev: sum(fd["severity"] == sev for a in agents_out for fd in a["findings"]) for sev in SEVERITIES}
    result = {"servers": servers, "summary": {"agents": len(agents_out), **counts}, "agents": agents_out}
    text = json.dumps(result, indent=2) + "\n" if (args.json or args.format == "json") else render_markdown(result)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    floor = SEVERITIES.index(args.fail_on)
    return 1 if any(counts[s] for s in SEVERITIES[floor:]) else 0


if __name__ == "__main__":
    sys.exit(main())
