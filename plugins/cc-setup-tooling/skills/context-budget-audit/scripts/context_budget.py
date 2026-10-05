#!/usr/bin/env python3
"""context_budget.py: size what a Claude Code project puts in context on every turn, rank it, and flag waste.

Input: a project folder, and optionally a home folder (--home), extra skill folders (--skills), a plugins root
(--plugins-root, default <home>/.claude/plugins) and saved MCP `tools/list` results (--mcp-tools NAME=FILE).

What it counts as loaded on every turn:
  * memory files: CLAUDE.md, CLAUDE.local.md and .claude/CLAUDE.md in the project, ~/.claude/CLAUDE.md with --home,
    and every file they import with an `@path` line (followed five levels deep);
  * rules: .claude/rules/**/*.md in the project and the home folder; a rule whose front matter has `paths:` loads
    only when matching files are read, so it is listed as conditional and left out of the total;
  * skills: each skill's listing entry (name, description and when_to_use, capped at 1,536 characters as the
    Claude Code skills docs state); the SKILL.md body loads only when the skill is used and is listed separately;
  * MCP tools: name, description and input schema of every tool in each saved tools/list result.
AGENTS.md is counted only when a memory file imports it; otherwise it is listed as not loaded by Claude Code.
CLAUDE.md files in subfolders load when Claude reads files there, so they are listed as on demand. Hooks are listed
from the settings files; SessionStart and UserPromptSubmit hooks can add context whose size is unknown at rest.

Tokens are estimated as characters / 4 (rounded up), not counted with a tokenizer.

Findings: large-item (an every-turn item over --max-item-tokens), duplicate-file (two loaded files with the same
text), duplicate-block (a paragraph of 80 or more characters repeated across memory and rules files), stale-path (a
backticked relative path that exists neither from the project root nor from the file's folder), stale-date (a
heading dated more than --stale-days before --as-of), missing-import (an @path that does not exist),
description-truncated (a skill listing entry over 1,536 characters), over-budget (total above --budget).

Exit codes: 0 no findings, 1 at least one finding, 2 bad input (project folder missing, unreadable tools/list file,
bad --as-of).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _skillmd  # noqa: E402

LISTING_CAP = 1536
FENCE_RE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
IMPORT_RE = re.compile(r"(?:^|\s)@((?:~/|\.{1,2}/|/)?[\w.-][\w./-]*)")
PATH_RE = re.compile(r"`((?:\.{1,2}/)?[\w.-]+(?:/[\w.-]+)+/?|[\w-]+\.(?:md|py|sh|json|toml|ya?ml|ts|js))`")
DATE_HEAD_RE = re.compile(r"^#{1,6}\s.*?(\d{4}-\d{2}-\d{2})", re.MULTILINE)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def tokens(chars: int) -> int:
    return (chars + 3) // 4


def rel(path: Path, project: Path, home: Path | None) -> str:
    for base, label in ((project, "."), (home, "~")):
        if base is None:
            continue
        try:
            return f"{label}/{path.resolve().relative_to(base.resolve()).as_posix()}"
        except ValueError:
            continue
    return path.as_posix()


def strip_code(text: str) -> str:
    return FENCE_RE.sub("", text)


def collect_memory(project: Path, home: Path | None) -> tuple[list[tuple[Path, str]], list[dict]]:
    """Memory files and their @imports, as (path, kind) pairs, plus missing-import findings."""
    roots = [project / "CLAUDE.md", project / "CLAUDE.local.md", project / ".claude" / "CLAUDE.md"]
    if home is not None:
        roots.append(home / ".claude" / "CLAUDE.md")
    seen: dict[Path, str] = {}
    findings: list[dict] = []
    queue = [(p, "memory", 0) for p in roots if p.is_file()]
    while queue:
        path, kind, depth = queue.pop(0)
        key = path.resolve()
        if key in seen:
            continue
        seen[key] = kind
        if depth >= 5:
            continue
        for target in IMPORT_RE.findall(strip_code(_skillmd.read_text(path))):
            if target.startswith("~/"):
                if home is None:
                    continue
                cand = home / target[2:]
            elif target.startswith("/"):
                cand = Path(target)
            else:
                cand = path.parent / target
            if cand.is_file():
                queue.append((cand, "import", depth + 1))
            elif "/" in target or "." in target:
                findings.append({"rule": "missing-import", "item": path.as_posix(), "detail": f"@{target} not found"})
    return [(Path(p), k) for p, k in seen.items()], findings


def rule_files(base: Path) -> list[Path]:
    folder = base / ".claude" / "rules"
    return sorted(p for p in folder.rglob("*.md") if p.is_file()) if folder.is_dir() else []


def skill_roots(project: Path, home: Path | None, extra: list[Path], plugins_root: Path | None) -> list[Path]:
    roots = [project / ".claude" / "skills"]
    if home is not None:
        roots.append(home / ".claude" / "skills")
    roots += extra
    if plugins_root is not None and (plugins_root / "cache").is_dir():
        roots.append(plugins_root / "cache")
    return [r for r in roots if r.is_dir()]


def read_tools(spec: str) -> tuple[str, list[dict]]:
    name, _, file = spec.partition("=") if "=" in spec else (Path(spec).stem, "", spec)
    path = Path(file)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: cannot read tools/list JSON: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]
    tools = data.get("tools") if isinstance(data, dict) else data
    if not isinstance(tools, list):
        raise InputError(f"{path}: expected {{'tools': [...]}}, a list, or a JSON-RPC result")
    return name, [t for t in tools if isinstance(t, dict)]


def hooks_from(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for event, groups in (hooks or {}).items() if isinstance(hooks, dict) else []:
        for g in groups if isinstance(groups, list) else []:
            for h in g.get("hooks", []) if isinstance(g, dict) else []:
                if isinstance(h, dict):
                    out.append({"event": event, "matcher": g.get("matcher", ""), "type": h.get("type", "")})
    return out


def paragraphs(text: str) -> list[str]:
    return [re.sub(r"\s+", " ", p).strip().lower() for p in re.split(r"\n\s*\n", strip_code(text))]


def analyse(args: argparse.Namespace) -> dict:
    project = Path(args.project)
    if not project.is_dir():
        raise InputError(f"{project}: not a folder")
    home = Path(args.home) if args.home else None
    as_of = dt.date.today() if args.as_of is None else None
    if args.as_of is not None:
        try:
            as_of = dt.date.fromisoformat(args.as_of)
        except ValueError as exc:
            raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD") from exc
    plugins_root = Path(args.plugins_root) if args.plugins_root else (home / ".claude" / "plugins" if home else None)
    items: list[dict] = []
    findings: list[dict] = []
    texts: dict[str, tuple[Path, str]] = {}

    def add(category: str, name: str, chars: int, load: str, note: str = "") -> None:
        items.append(
            {"category": category, "item": name, "chars": chars, "tokens": tokens(chars), "load": load, "note": note}
        )

    memory, missing = collect_memory(project, home)
    findings += missing
    imported = {p.resolve() for p, k in memory}
    for path, kind in sorted(memory, key=lambda x: x[0].as_posix()):
        t = _skillmd.read_text(path)
        name = rel(path, project, home)
        texts[name] = (path, t)
        add("memory" if kind == "memory" else "import", name, len(t), "every turn")
    agents = project / "AGENTS.md"
    if agents.is_file() and agents.resolve() not in imported:
        add(
            "memory",
            rel(agents, project, home),
            len(_skillmd.read_text(agents)),
            "not loaded",
            "Claude Code reads AGENTS.md only through an @AGENTS.md import",
        )
    for sub in sorted(project.rglob("CLAUDE.md")):
        if sub.parent != project and sub.parent != project / ".claude" and not SKIP_DIRS & set(sub.parts):
            add(
                "memory",
                rel(sub, project, home),
                len(_skillmd.read_text(sub)),
                "on demand",
                "loads when Claude reads files in that folder",
            )
    for base in [project] + ([home] if home else []):
        for path in rule_files(base):
            t = _skillmd.read_text(path)
            fm = _skillmd.parse(t)
            name = rel(path, project, home)
            if "paths" in fm.fields:
                add("rules", name, len(t), "conditional", "has paths: front matter")
            else:
                texts[name] = (path, t)
                add("rules", name, len(t), "every turn")
    for root in skill_roots(project, home, [Path(s) for s in args.skills], plugins_root):
        for f in _skillmd.find_skill_files([root]):
            t = _skillmd.read_text(f)
            fm = _skillmd.parse(t)
            entry = len(fm.text("name") or f.parent.name) + len(fm.text("description")) + len(fm.text("when_to_use"))
            name = f"{fm.text('name') or f.parent.name} ({rel(f.parent, project, home)})"
            add("skills", name, min(entry, LISTING_CAP), "every turn", "listing entry")
            if entry > LISTING_CAP:
                findings.append(
                    {
                        "rule": "description-truncated",
                        "item": name,
                        "detail": f"listing entry is {entry} characters; the host cuts it at {LISTING_CAP}",
                    }
                )
            body = "\n".join(t.replace("\r\n", "\n").split("\n")[fm.body_start :]) if fm.closed else t
            add("skill bodies", f"{name} body", len(body), "on invoke")
    for spec in args.mcp_tools:
        server, tools = read_tools(spec)
        for tool in tools:
            chars = len(str(tool.get("name", ""))) + len(str(tool.get("description", "")))
            chars += len(json.dumps(tool.get("inputSchema", {}), separators=(",", ":"), sort_keys=True))
            add("mcp tools", f"mcp__{server}__{tool.get('name', '?')}", chars, "every turn")
    settings = [project / ".claude" / "settings.json", project / ".claude" / "settings.local.json"]
    if home is not None:
        settings.append(home / ".claude" / "settings.json")
    for s in settings:
        for h in hooks_from(s):
            adds = h["event"] in ("SessionStart", "UserPromptSubmit")
            add(
                "hooks",
                f"{h['event']} {h['matcher'] or '*'} ({rel(s, project, home)})",
                0,
                "unknown" if adds else "none",
                "can add context at run time" if adds else "no context at rest",
            )

    every = [i for i in items if i["load"] == "every turn"]
    for i in every:
        if i["tokens"] > args.max_item_tokens:
            findings.append(
                {
                    "rule": "large-item",
                    "item": i["item"],
                    "detail": f"about {i['tokens']} tokens; the limit is {args.max_item_tokens}",
                }
            )
    digests: dict[str, str] = {}
    for name, (_, t) in sorted(texts.items()):
        d = hashlib.sha256(re.sub(r"\s+", " ", t).strip().encode("utf-8")).hexdigest()
        if d in digests:
            findings.append({"rule": "duplicate-file", "item": name, "detail": f"same text as {digests[d]}"})
        else:
            digests[d] = name
    first_seen: dict[str, str] = {}
    for name, (_, t) in sorted(texts.items()):
        for para in paragraphs(t):
            if len(para) < 80:
                continue
            if para in first_seen and first_seen[para] != name:
                findings.append(
                    {
                        "rule": "duplicate-block",
                        "item": name,
                        "detail": f'paragraph also in {first_seen[para]}: "{para[:60]}..."',
                    }
                )
            first_seen.setdefault(para, name)
    for name, (src, t) in sorted(texts.items()):
        for p in sorted(set(PATH_RE.findall(strip_code(t)))):
            if p.startswith(("http", "~", "$", "-")) or "*" in p:
                continue
            if not (project / p).exists() and not (src.parent / p).exists():
                findings.append({"rule": "stale-path", "item": name, "detail": f"`{p}` does not exist"})
        for m in DATE_HEAD_RE.finditer(t):
            try:
                d = dt.date.fromisoformat(m.group(1))
            except ValueError:
                continue
            if (as_of - d).days > args.stale_days:
                findings.append(
                    {
                        "rule": "stale-date",
                        "item": name,
                        "detail": f"heading dated {d.isoformat()}, {(as_of - d).days} days before {as_of.isoformat()}",
                    }
                )
    total = sum(i["tokens"] for i in every)
    if args.budget is not None and total > args.budget:
        findings.append(
            {
                "rule": "over-budget",
                "item": "total",
                "detail": f"about {total} tokens every turn; the budget is {args.budget}",
            }
        )
    by_cat: dict[str, int] = {}
    for i in every:
        by_cat[i["category"]] = by_cat.get(i["category"], 0) + i["tokens"]
    items.sort(key=lambda i: (-i["tokens"], i["category"], i["item"]))
    findings.sort(key=lambda f: (f["rule"], f["item"], f["detail"]))
    return {
        "as_of": as_of.isoformat(),
        "estimate": "tokens = characters / 4, rounded up",
        "every_turn_tokens": total,
        "every_turn_chars": sum(i["chars"] for i in every),
        "by_category": dict(sorted(by_cat.items())),
        "user_scope_read": home is not None,
        "items": items,
        "findings": findings,
    }


def render(rep: dict, top: int) -> str:
    every = [i for i in rep["items"] if i["load"] == "every turn"]
    other = [i for i in rep["items"] if i["load"] != "every turn"]
    out = ["# Context budget", ""]
    out.append(
        f"Every turn: about {rep['every_turn_tokens']} tokens ({rep['every_turn_chars']} characters; "
        f"{rep['estimate']})."
    )
    if not rep["user_scope_read"]:
        out.append("User scope (~/.claude) was not read; pass --home to include it.")
    out += ["", "| Category | Tokens |", "|---|---|"]
    out += [f"| {c} | {t} |" for c, t in rep["by_category"].items()]
    out += ["", f"## Largest every-turn items (top {top})", "", "| # | Item | Category | Tokens |", "|---|---|---|---|"]
    out += [f"| {n} | {i['item']} | {i['category']} | {i['tokens']} |" for n, i in enumerate(every[:top], start=1)]
    if other:
        out += [
            "",
            "## Not loaded every turn",
            "",
            "| Item | Category | Load | Tokens | Note |",
            "|---|---|---|---|---|",
        ]
        out += [f"| {i['item']} | {i['category']} | {i['load']} | {i['tokens']} | {i['note']} |" for i in other]
    out += ["", "## Findings", ""]
    out += [f"- {f['rule']} `{f['item']}`: {f['detail']}" for f in rep["findings"]] or ["None."]
    out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="context_budget.py",
        description="Estimate the tokens a Claude Code project loads on every turn (memory files, imports, rules, "
        "skill listings, MCP tool schemas), rank the biggest items and flag duplicates and stale sections.",
        epilog="Exit codes: 0 no findings, 1 at least one finding, 2 bad input.",
    )
    p.add_argument("project", help="the project folder")
    p.add_argument("--home", default=None, help="home folder whose .claude/ is read too (default: not read)")
    p.add_argument("--skills", action="append", default=[], help="extra folder of skills (repeatable)")
    p.add_argument("--plugins-root", default=None, help="plugins folder (default: <home>/.claude/plugins)")
    p.add_argument("--mcp-tools", action="append", default=[], help="saved tools/list result, NAME=FILE (repeatable)")
    p.add_argument("--max-item-tokens", type=int, default=2000, help="flag every-turn items above this (default 2000)")
    p.add_argument("--budget", type=int, default=None, help="flag when the every-turn total is above this")
    p.add_argument("--stale-days", type=int, default=365, help="flag dated headings older than this (default 365)")
    p.add_argument("--as-of", default=None, help="date to judge dated headings against, YYYY-MM-DD (default today)")
    p.add_argument("--top", type=int, default=15, help="rows in the ranked table (default 15)")
    p.add_argument("--json", action="store_true", help="print the computed data as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rep = analyse(args)
    except InputError as exc:
        print(f"context_budget.py: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n" if args.json else render(rep, args.top)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
