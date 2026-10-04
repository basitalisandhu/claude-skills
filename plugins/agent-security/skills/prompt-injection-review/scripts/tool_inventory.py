#!/usr/bin/env python3
"""Inventory the tools an agent codebase exposes and the untrusted inputs it reads, to seed a prompt-injection review.

For each tool definition it records name, file, line, parameters, a tier guess (consequential or regular) and the
designator-like parameters (recipients, URLs, amounts, ids, paths) that a provenance rule must cover. It also lists
readers of untrusted content (web, e-mail, tickets, documents, repo issues, retrieval) and MCP tool descriptions.

Heuristics only: it reads source text, never executes it. Review the output, do not trust it blindly.

Usage:
  tool_inventory.py [ROOT] [--format json|markdown] [--out FILE]

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next", "target", "vendor", ".tox", "site-packages"}
MAX_FILES = 5000  # stop walking after this many source files; the summary says so
MAX_FILE_BYTES = 1_000_000  # skip larger files (generated bundles, vendored blobs); the summary counts them
EXTS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt", ".cs", ".rb"}

CONSEQUENTIAL_VERBS = re.compile(r"(?i)\b(send|post|publish|email|mail|message|notify|transfer|pay|charge|refund|purchase|buy|order|book|reserve|delete|remove|drop|destroy|wipe|truncate|update|modify|edit|write|create|insert|upsert|put|patch|execute|exec|run|shell|bash|command|deploy|release|merge|push|commit|approve|grant|revoke|share|invite|upload|download|install|schedule|cancel|close|open_pr|comment|forward|reply|call|dial|sms|tweet|archive|move|rename|chmod|sudo)\b")
READ_VERBS = re.compile(r"(?i)\b(get|list|read|fetch|search|find|query|lookup|view|show|describe|count|check|retrieve|load|scan|browse|summari[sz]e|parse|extract)\b")
DESIGNATOR_PARAMS = re.compile(r"(?i)^(to|recipient|recipients|cc|bcc|email|emails|address|addresses|url|urls|uri|link|href|endpoint|host|domain|webhook|channel|user|users|username|user_id|account|iban|account_number|amount|total|price|phone|number|target|destination|dest|path|file|file_path|filename|filepath|dir|directory|command|cmd|script|query|sql|repo|repository|branch|owner|org|participants|attendees|id|.*_id|ids|.*_ids|key|.*_url|.*_email|.*_path)$")
UNTRUSTED_READERS = re.compile(r"(?i)\b(get_webpage|fetch_url|fetch_page|browse|web_search|search_web|read_email|get_emails?|read_inbox|list_emails|get_messages?|read_messages?|read_channel|get_tickets?|read_ticket|get_issues?|read_issue|list_issues|get_pull_requests?|get_comments?|read_file|get_document|read_document|load_document|retrieve|similarity_search|vector_search|rag|get_calendar|list_events|get_reviews|read_pdf|scrape|crawl|transcribe)\b")

# tool definition patterns per language family; group "name" is the tool name
PY_PATTERNS = [
    re.compile(r"^\s*@(?:[\w.]+\.)?tool(?:\((?P<args>[^)]*)\))?\s*$"),
    re.compile(r"^\s*@(?:[\w.]+\.)?function_tool(?:\([^)]*\))?\s*$"),
    re.compile(r"^\s*@(?:[\w.]+\.)?(?:agent|kernel)_function(?:\([^)]*\))?\s*$"),
]
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)")
PY_TOOL_CLASS = re.compile(r"^\s*(?:Structured|Base)?Tool(?:\.from_function)?\(\s*(?:name\s*=\s*)?['\"](?P<name>[\w-]+)['\"]")
PY_FUNCTIONS_SCHEMA = re.compile(r"[\"']name[\"']\s*:\s*[\"'](?P<name>[\w-]+)[\"']\s*,\s*[\"']description[\"']")
JS_PATTERNS = [
    re.compile(r"\.registerTool\(\s*['\"](?P<name>[\w-]+)['\"]"),
    re.compile(r"\.tool\(\s*['\"](?P<name>[\w-]+)['\"]"),
    re.compile(r"\btool\(\s*\{[^}]*?\bname\s*:\s*['\"](?P<name>[\w-]+)['\"]"),
    re.compile(r"\b(?P<name>\w+)\s*:\s*tool\(\s*\{"),
    re.compile(r"new\s+(?:Dynamic(?:Structured)?Tool|FunctionTool)\(\s*\{[^}]*?\bname\s*:\s*['\"](?P<name>[\w-]+)['\"]"),
    re.compile(r"\bname\s*:\s*['\"](?P<name>[\w-]+)['\"]\s*,\s*description\s*:"),
]
JS_PARAMS = re.compile(r"(?:async\s*)?\(\s*\{\s*(?P<params>[^}]*)\}")
MCP_DESCRIPTION = re.compile(r"(?s)description\s*[:=]\s*(?:\(\s*)?(?P<q>[\"'`])(?P<desc>.*?)(?P=q)")
POISON_HINTS = re.compile(r"(?i)(ignore (all |the )?(previous|other) (instructions|tools)|do not (tell|mention|inform)|before (using|calling) (this|any) tool|always (call|use|include)|<!--|hidden|secret instruction|system prompt|read ~/|\.ssh|\.env|api[_ ]?key|pass(word)?|exfiltrat)")


def tier_for(name: str, params: list[str]) -> tuple[str, list[str]]:
    designators = [p for p in params if DESIGNATOR_PARAMS.match(p)]
    if CONSEQUENTIAL_VERBS.search(name.replace("_", " ")) and not (READ_VERBS.search(name.replace("_", " ")) and not designators):
        return "consequential", designators
    if designators and any(d.lower() in {"url", "urls", "command", "cmd", "sql", "script", "path", "file_path"} for d in designators) and not READ_VERBS.search(name):
        return "consequential", designators
    return "regular", designators


def split_params(raw: str) -> list[str]:
    out = []
    for part in re.split(r",(?![^\[\]{}()]*[\]})])", raw):
        p = part.strip()
        if not p or p in {"self", "cls", "*", "/"} or p.startswith(("*", "**")):
            continue
        name = re.split(r"[:=\s]", p, 1)[0].strip()
        if name and name not in {"ctx", "context", "env", "state", "config", "run_manager", "callbacks"}:
            out.append(name)
    return out


def scan_file(path: Path, root: Path) -> tuple[list[dict], list[dict], list[dict]]:
    tools: list[dict] = []
    readers: list[dict] = []
    descriptions: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return tools, readers, descriptions
    lines = text.splitlines()
    rel = str(path.relative_to(root))
    if path.suffix == ".py":
        for i, line in enumerate(lines):
            if any(p.match(line) for p in PY_PATTERNS):
                for j in range(i + 1, min(i + 6, len(lines))):
                    m = PY_DEF.match(lines[j])
                    if m:
                        params = split_params(m.group("params"))
                        tier, des = tier_for(m.group("name"), params)
                        tools.append({"name": m.group("name"), "file": rel, "line": j + 1, "params": params, "tier": tier, "designators": des, "kind": "decorator"})
                        break
            m = PY_TOOL_CLASS.search(line)
            if m:
                tier, des = tier_for(m.group("name"), [])
                tools.append({"name": m.group("name"), "file": rel, "line": i + 1, "params": [], "tier": tier, "designators": des, "kind": "class"})
        for m in PY_FUNCTIONS_SCHEMA.finditer(text):
            name = m.group("name")
            if not any(t["name"] == name for t in tools):
                tier, des = tier_for(name, [])
                tools.append({"name": name, "file": rel, "line": text.count("\n", 0, m.start()) + 1, "params": [], "tier": tier, "designators": des, "kind": "schema"})
    elif path.suffix in {".ts", ".tsx", ".js", ".mjs", ".cjs"}:
        for pat in JS_PATTERNS:
            for m in pat.finditer(text):
                name = m.group("name")
                if any(t["name"] == name and t["file"] == rel for t in tools):
                    continue
                window = text[m.end(): m.end() + 1200]
                pm = JS_PARAMS.search(window)
                params = [p.strip().split(":")[0].split("=")[0].strip() for p in pm.group("params").split(",") if p.strip()] if pm else []
                params = [p for p in params if re.match(r"^\w+$", p)]
                tier, des = tier_for(name, params)
                tools.append({"name": name, "file": rel, "line": text.count("\n", 0, m.start()) + 1, "params": params, "tier": tier, "designators": des, "kind": "registration"})
    for m in UNTRUSTED_READERS.finditer(text):
        readers.append({"name": m.group(0), "file": rel, "line": text.count("\n", 0, m.start()) + 1})
    for t in tools:
        start = sum(len(l) + 1 for l in lines[: t["line"] - 1])
        window = text[max(0, start - 200): start + 1500]
        dm = MCP_DESCRIPTION.search(window)
        if dm:
            desc = dm.group("desc")
            flagged = bool(POISON_HINTS.search(desc)) or len(desc) > 800 or bool(re.search("[​-‏⁠﻿]", desc))
            descriptions.append({"tool": t["name"], "file": rel, "line": t["line"], "length": len(desc), "suspicious": flagged, "excerpt": desc[:160]})
    seen_readers = set()
    uniq = []
    for r in readers:
        key = (r["name"].lower(), r["file"])
        if key not in seen_readers:
            seen_readers.add(key)
            uniq.append(r)
    return tools, uniq, descriptions


def inventory(root: Path) -> dict:
    tools: list[dict] = []
    readers: list[dict] = []
    descriptions: list[dict] = []
    files = 0
    skipped_large = 0
    truncated = False
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in EXTS or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.startswith("test_") or path.name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js")):
            continue
        if files >= MAX_FILES:
            truncated = True
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
        except OSError:
            continue
        files += 1
        t, r, d = scan_file(path, root)
        tools += t
        readers += r
        descriptions += d
    consequential = [t for t in tools if t["tier"] == "consequential"]
    pairs = []
    for c in consequential:
        same_file = [r for r in readers if r["file"] == c["file"]]
        if same_file:
            pairs.append({"tool": c["name"], "file": c["file"], "readers_nearby": sorted({r["name"] for r in same_file}), "designators": c["designators"]})
    return {
        "root": str(root), "files_scanned": files, "skipped_large_files": skipped_large, "truncated": truncated,
        "summary": {"tools": len(tools), "consequential": len(consequential), "regular": len(tools) - len(consequential),
                    "untrusted_readers": len(readers), "suspicious_descriptions": sum(1 for d in descriptions if d["suspicious"])},
        "tools": tools, "untrusted_readers": readers, "tool_descriptions": descriptions, "candidate_flows": pairs,
    }


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    limits = ""
    if inv.get("skipped_large_files"):
        limits += f" Skipped {inv['skipped_large_files']} file(s) over {MAX_FILE_BYTES} bytes."
    if inv.get("truncated"):
        limits += f" Stopped after {MAX_FILES} files; point the script at a subdirectory for the rest."
    out = [f"# Tool inventory for `{inv['root']}`", "", f"Files scanned: {inv['files_scanned']}. Tools: {s['tools']} ({s['consequential']} consequential, {s['regular']} regular). Untrusted readers: {s['untrusted_readers']}. Suspicious tool descriptions: {s['suspicious_descriptions']}.{limits}", ""]
    out += ["## Tools", "", "| Tool | Tier | Designator params | Location |", "|---|---|---|---|"]
    for t in sorted(inv["tools"], key=lambda x: (x["tier"] != "consequential", x["name"])):
        out.append(f"| `{t['name']}` | {t['tier']} | {', '.join(t['designators']) or '-'} | `{t['file']}:{t['line']}` |")
    out += ["", "## Untrusted readers", ""]
    out += [f"- `{r['name']}` in `{r['file']}:{r['line']}`" for r in inv["untrusted_readers"]] or ["- none detected"]
    out += ["", "## Candidate flows to trace (consequential tool with an untrusted reader in the same file)", ""]
    out += [f"- `{p['tool']}` ({', '.join(p['designators']) or 'no designator params'}) near {', '.join('`' + r + '`' for r in p['readers_nearby'])} in `{p['file']}`" for p in inv["candidate_flows"]] or ["- none detected"]
    sus = [d for d in inv["tool_descriptions"] if d["suspicious"]]
    out += ["", "## Tool descriptions to read in full", ""]
    out += [f"- `{d['tool']}` (`{d['file']}:{d['line']}`, {d['length']} chars): {d['excerpt']!r}" for d in sus] or ["- none flagged"]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--format", choices=["json", "markdown"], default="json")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    inv = inventory(Path(args.root).resolve())
    text = to_markdown(inv) if args.format == "markdown" else json.dumps(inv, indent=1)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
