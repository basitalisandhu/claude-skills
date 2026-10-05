#!/usr/bin/env python3
"""perm_merge.py: merge Claude Code permission rules from several sources into one least-privilege list, and diff it
against the current settings file.

Sources (--source, repeatable), each one of:
  * a settings file, or the block claude-mcp-allow prints: {"permissions": {"allow": [...], "ask": [...]}};
  * a bare permissions block: {"allow": [...], "ask": [...], "deny": [...]};
  * a text file with one rule per line: `deny Bash(rm -rf *)`, `ask Bash(git push *)`, `allow Read(./src/**)`;
    `#` starts a comment.
--current names the settings file to compare with (and to keep the other keys of). Its rules are merged too unless
--replace is given.

Rules:
  * exact duplicates (after trimming) are dropped;
  * a rule in deny is removed from ask and allow, and a rule in ask is removed from allow, because Claude Code
    evaluates deny, then ask, then allow; each removal is a finding (conflict-allow-deny, conflict-ask-deny,
    conflict-allow-ask) so a person sees what was asked for twice;
  * broad-allow: an allow rule that covers a whole tool or server (Bash, Bash(*), Read(**), Edit(/**), WebFetch,
    WebFetch(domain:*), mcp__*, mcp__server, mcp__server__*);
  * malformed-rule: text that is not Tool or Tool(specifier); it is dropped;
  * deny-removed: with --replace, a deny rule in the current file that the merged list no longer has.
The merged block lists deny, then ask, then allow, each sorted, so diffs stay stable.

Output: --emit report (default) prints the merged lists, the findings and the diff against --current; --emit
settings prints the whole settings file (the current file's other keys kept, in order) with the merged permissions.
Nothing is written unless --out is given.

Exit codes: 0 no findings, 1 at least one finding, 2 bad input (a source that is missing or cannot be parsed).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

LISTS = ("deny", "ask", "allow")
RULE_RE = re.compile(r"^(?:mcp__[\w-]+(?:__[\w*-]+)?|[A-Z][A-Za-z]*(?:\(.+\))?)$", re.DOTALL)
BROAD_RE = re.compile(
    r"^(?:Bash|Bash\(\*\)|Bash\(:\*\)|Read|Edit|Write|WebFetch|WebSearch|"
    r"(?:Read|Edit|Write)\((?:/|//|~/|\./)?\*\*(?:/\*)?\)|WebFetch\(domain:\*\))$"
)


def broad(rule: str) -> bool:
    """True for a rule that covers a whole tool, or a whole MCP server (mcp__*, mcp__server, mcp__server__*)."""
    if rule.startswith("mcp__"):
        rest = rule[len("mcp__") :]
        return rest == "*" or "__" not in rest or rest.endswith("__*")
    return bool(BROAD_RE.match(rule))


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path}: expected a JSON object")
    return data


def read_source(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        raise InputError(f"{path}: not found")
    text = path.read_text(encoding="utf-8")
    out: dict[str, list[str]] = {k: [] for k in LISTS}
    if text.lstrip().startswith("{"):
        data = load_json(path)
        block = data.get("permissions", data)
        if not isinstance(block, dict):
            raise InputError(f"{path}: permissions must be an object")
        for key in LISTS:
            rules = block.get(key, [])
            if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
                raise InputError(f"{path}: {key} must be a list of strings")
            out[key] += rules
        return out
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split(" #", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if not line:
            continue
        kind, _, rule = line.partition(" ")
        if kind not in LISTS or not rule.strip():
            raise InputError(f"{path}:{number}: expected 'deny|ask|allow <rule>'")
        out[kind].append(rule.strip())
    return out


def merge(sources: list[tuple[str, dict[str, list[str]]]]) -> tuple[dict[str, list[str]], list[dict]]:
    findings: list[dict] = []
    merged: dict[str, set[str]] = {k: set() for k in LISTS}
    origin: dict[tuple[str, str], str] = {}
    for label, rules in sources:
        for key in LISTS:
            for raw in rules.get(key, []):
                rule = raw.strip()
                if not RULE_RE.match(rule):
                    findings.append({"rule": "malformed-rule", "list": key, "item": raw, "detail": f"from {label}"})
                    continue
                merged[key].add(rule)
                origin.setdefault((key, rule), label)
    for rule in sorted(merged["deny"] & merged["allow"]):
        findings.append(
            {
                "rule": "conflict-allow-deny",
                "list": "allow",
                "item": rule,
                "detail": f"allowed in {origin[('allow', rule)]}, denied in {origin[('deny', rule)]}; kept deny",
            }
        )
    for rule in sorted(merged["deny"] & merged["ask"]):
        findings.append(
            {
                "rule": "conflict-ask-deny",
                "list": "ask",
                "item": rule,
                "detail": f"ask in {origin[('ask', rule)]}, denied in {origin[('deny', rule)]}; kept deny",
            }
        )
    merged["allow"] -= merged["deny"]
    merged["ask"] -= merged["deny"]
    for rule in sorted(merged["ask"] & merged["allow"]):
        findings.append(
            {
                "rule": "conflict-allow-ask",
                "list": "allow",
                "item": rule,
                "detail": f"allowed in {origin[('allow', rule)]}, ask in {origin[('ask', rule)]}; kept ask",
            }
        )
    merged["allow"] -= merged["ask"]
    for rule in sorted(merged["allow"]):
        if broad(rule):
            findings.append(
                {
                    "rule": "broad-allow",
                    "list": "allow",
                    "item": rule,
                    "detail": f"covers a whole tool or server (from {origin[('allow', rule)]})",
                }
            )
    return {k: sorted(merged[k]) for k in LISTS}, findings


def diff(current: dict[str, list[str]], merged: dict[str, list[str]]) -> dict[str, dict[str, list[str]]]:
    return {
        k: {
            "added": sorted(set(merged[k]) - set(current.get(k, []))),
            "removed": sorted(set(current.get(k, [])) - set(merged[k])),
        }
        for k in LISTS
    }


def settings_with(current: dict, merged: dict[str, list[str]]) -> dict:
    out: dict = {}
    old = current.get("permissions") if isinstance(current.get("permissions"), dict) else {}
    perms = {k: merged[k] for k in LISTS if merged[k]}
    perms.update({k: v for k, v in old.items() if k not in LISTS})
    for key, value in current.items():
        out[key] = perms if key == "permissions" else value
    if "permissions" not in out:
        out["permissions"] = perms
    return out


def render(rep: dict) -> str:
    out = ["# Permission rules, merged", "", f"Sources: {', '.join(rep['sources'])}.", ""]
    for k in LISTS:
        out.append(f"## {k} ({len(rep['merged'][k])})")
        out.append("")
        out += [f"- `{r}`" for r in rep["merged"][k]] or ["None."]
        out.append("")
    out += ["## Changes against the current settings", ""]
    if rep["current"] is None:
        out.append("No --current file; every rule is new.")
    else:
        changed = False
        for k in LISTS:
            for r in rep["diff"][k]["added"]:
                out.append(f"- + {k} `{r}`")
                changed = True
            for r in rep["diff"][k]["removed"]:
                out.append(f"- - {k} `{r}`")
                changed = True
        if not changed:
            out.append("None.")
    out += ["", "## Findings", ""]
    out += [f"- {f['rule']} ({f['list']}) `{f['item']}`: {f['detail']}" for f in rep["findings"]] or ["None."]
    out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="perm_merge.py",
        description="Merge Claude Code allow, ask and deny rules from several sources, drop duplicates and "
        "conflicts, order deny before allow, and diff against the current settings.",
        epilog="Exit codes: 0 no findings, 1 at least one finding, 2 bad input.",
    )
    p.add_argument("--source", action="append", default=[], help="settings file, permissions block or rule list")
    p.add_argument("--current", default=None, help="the settings file to compare with (default: none)")
    p.add_argument("--replace", action="store_true", help="do not merge the current file's rules")
    p.add_argument("--emit", choices=("report", "settings"), default="report", help="what to print (default report)")
    p.add_argument("--json", action="store_true", help="print the report as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the output to this file instead of standard output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not args.source and not args.current:
            raise InputError("give at least one --source (or a --current file to tidy)")
        current_data: dict | None = None
        current_rules: dict[str, list[str]] = {k: [] for k in LISTS}
        if args.current:
            cur = Path(args.current)
            if cur.is_file():
                current_data = load_json(cur)
                current_rules = read_source(cur)
            else:
                current_data = {}
        sources = [(s, read_source(Path(s))) for s in args.source]
        if args.current and not args.replace:
            sources.insert(0, (args.current, current_rules))
        merged, findings = merge(sources)
    except InputError as exc:
        print(f"perm_merge.py: {exc}", file=sys.stderr)
        return 2
    changes = diff(current_rules, merged)
    if args.replace:
        for rule in changes["deny"]["removed"]:
            findings.append({"rule": "deny-removed", "list": "deny", "item": rule, "detail": "in --current only"})
    rep = {
        "sources": [label for label, _ in sources] or ["(none)"],
        "current": args.current,
        "merged": merged,
        "diff": changes,
        "findings": findings,
    }
    if args.emit == "settings":
        text = json.dumps(settings_with(current_data or {}, merged), indent=2) + "\n"
    elif args.json:
        text = json.dumps(rep, indent=2, sort_keys=True) + "\n"
    else:
        text = render(rep)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
