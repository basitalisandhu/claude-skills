#!/usr/bin/env python3
"""Check a register of allowed MCP servers, connectors and plugins against saved tool listings and manifests.

usage: connector_register.py REGISTER [--tools DIR] [--manifests DIR] [--as-of YYYY-MM-DD]
                             [--classifications LIST] [--json] [--out FILE]

REGISTER is a CSV, a YAML file (a list of entries, or a mapping with one key holding that list) or a JSON file
with the same shape. Fields per entry: name (required), kind (mcp-server, connector, plugin), owner, purpose,
data_classification, permissions (a list, or text separated by semicolons), review_date (the next review is due
on this date, YYYY-MM-DD), and optionally tools (the tool names allowed) and version.

--tools DIR holds one saved MCP tools/list result per server, named <register name>.json: {"tools": [...]},
{"result": {"tools": [...]}} or a list of such pages. --manifests DIR holds one permission manifest per entry,
named <register name>.json, with a "permissions", "scopes" or "oauth_scopes" list.

The YAML reader understands the subset used by registers: block mappings and lists, plain or quoted scalars, inline
[a, b] lists and # comments. Anchors, multi-line strings and flow mappings are refused as bad input.

Rules:
  missing-owner, missing-purpose, missing-classification, missing-permissions, missing-review-date
                          a required field is empty
  invalid-classification  data_classification is not one of --classifications
  invalid-review-date     review_date is not YYYY-MM-DD
  review-overdue          review_date is before --as-of
  duplicate-name          two entries share a name
  unregistered-server     a tool listing exists for a name the register does not hold (only with --tools)
  not-present             a registered mcp-server has no tool listing, so it may be gone (only with --tools)
  unregistered-tool       the listing has a tool the entry's tools list does not allow
  tool-gone               the entry allows a tool the listing no longer offers
  undeclared-permission   the manifest holds a permission the register does not record
  permission-not-in-manifest  the register records a permission the manifest no longer holds

Exit codes: 0 no finding, 1 at least one finding, 2 bad input.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import date
from pathlib import Path

REQUIRED = {
    "owner": "missing-owner",
    "purpose": "missing-purpose",
    "data_classification": "missing-classification",
    "permissions": "missing-permissions",
    "review_date": "missing-review-date",
}
MAPPING_ENTRY_RE = re.compile(r"""^(?:"[^"]*"|'[^']*'|[^\s"'\[{#-][^:]*?|-[^\s:][^:]*?)\s*:(?:\s|$)""")


class InputError(Exception):
    """Bad input: exit code 2."""


# ---- a small YAML subset reader (standard library only) ----------------------------------------------------------


def strip_comment(line: str) -> str:
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def scalar(text: str):
    text = text.strip()
    if text[:1] in "&*!|>{" or text.startswith("? "):
        raise InputError(f"YAML: unsupported construct {text[:20]!r} (anchors, tags, blocks or flow mappings)")
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [scalar(x) for x in next(csv.reader([inner], skipinitialspace=True))] if inner else []
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text in ("~", "null", "Null", "NULL"):
        return None
    return text


def parse_yaml(text: str):
    lines: list[tuple[int, str, int]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.strip() in ("---", "...") or not strip_comment(raw).strip():
            continue
        line = strip_comment(raw)
        indent = len(line) - len(line.lstrip(" "))
        if line[:indent].count("\t") or line.lstrip(" ").startswith("\t"):
            raise InputError(f"YAML line {number}: tabs are not allowed for indentation")
        lines.append((indent, line.strip(), number))
    if not lines:
        return None
    value, pos = parse_block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise InputError(f"YAML line {lines[pos][2]}: unexpected indentation")
    return value


def is_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def parse_block(lines: list, pos: int, indent: int):
    if is_item(lines[pos][1]):
        seq = []
        while pos < len(lines) and lines[pos][0] == indent and is_item(lines[pos][1]):
            content = lines[pos][1][1:].strip()
            if not content:
                if pos + 1 >= len(lines) or lines[pos + 1][0] <= indent:
                    seq.append(None)
                    pos += 1
                    continue
                item, pos = parse_block(lines, pos + 1, lines[pos + 1][0])
            elif MAPPING_ENTRY_RE.match(content):
                lines[pos] = (indent + 2, content, lines[pos][2])
                item, pos = parse_block(lines, pos, indent + 2)
            else:
                item, pos = scalar(content), pos + 1
            seq.append(item)
        return seq, pos
    mapping: dict = {}
    while pos < len(lines) and lines[pos][0] == indent and not is_item(lines[pos][1]):
        content, number = lines[pos][1], lines[pos][2]
        if not MAPPING_ENTRY_RE.match(content):
            raise InputError(f"YAML line {number}: expected 'key: value', found {content[:40]!r}")
        key, _, rest = content.partition(":")
        key = str(scalar(key))
        pos += 1
        if rest.strip():
            mapping[key] = scalar(rest)
        elif pos < len(lines) and (lines[pos][0] > indent or (lines[pos][0] == indent and is_item(lines[pos][1]))):
            mapping[key], pos = parse_block(lines, pos, lines[pos][0])
        else:
            mapping[key] = None
    return mapping, pos


# ---- inputs ------------------------------------------------------------------------------------------------------


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v or "").strip()]
    return [v.strip() for v in str(value).split(";") if v.strip()]


def load_register(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    text = read_text(path)
    if suffix == ".csv":
        try:
            rows = list(csv.DictReader(io.StringIO(text)))
        except csv.Error as exc:
            raise InputError(f"{path.name}: not a readable CSV: {exc}") from exc
        entries = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in rows]
        lines = list(range(2, len(entries) + 2))
    else:
        if suffix == ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}: not valid JSON: {exc}") from exc
        else:
            data = parse_yaml(text)
        if isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), list):
            data = next(iter(data.values()))
        if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
            raise InputError(f"{path.name}: expected a list of entries (or one key holding that list)")
        entries = [{str(k).strip().lower(): v for k, v in e.items()} for e in data]
        lines = [None] * len(entries)
    if not entries:
        raise InputError(f"{path.name}: the register has no entries")
    out = []
    for n, (e, line) in enumerate(zip(entries, lines, strict=True), start=1):
        name = str(e.get("name") or "").strip()
        if not name:
            raise InputError(f"{path.name}: entry {n} has no name")
        out.append(
            {
                "name": name,
                "kind": str(e.get("kind") or "").strip().lower(),
                "owner": str(e.get("owner") or "").strip(),
                "purpose": str(e.get("purpose") or "").strip(),
                "data_classification": str(e.get("data_classification") or "").strip(),
                "permissions": as_list(e.get("permissions")),
                "review_date": str(e.get("review_date") or "").strip(),
                "tools": as_list(e.get("tools")) if e.get("tools") not in (None, "") else None,
                "version": str(e.get("version") or "").strip(),
                "line": line,
            }
        )
    return out


def tool_names(data) -> list[str]:
    pages = data if isinstance(data, list) else [data]
    names: list[str] = []
    for page in pages:
        if not isinstance(page, dict):
            continue
        tools = page.get("tools")
        if tools is None and isinstance(page.get("result"), dict):
            tools = page["result"].get("tools")
        if tools is None:
            continue
        if not isinstance(tools, list):
            raise InputError("tools is not a list")
        names += [str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name")]
    return sorted(set(names))


def load_folder(folder: str | None, reader) -> dict[str, object] | None:
    if not folder:
        return None
    path = Path(folder)
    if not path.is_dir():
        raise InputError(f"{folder}: not a folder")
    out = {}
    for f in sorted(path.glob("*.json")):
        try:
            data = json.loads(read_text(f))
        except json.JSONDecodeError as exc:
            raise InputError(f"{f.name}: not valid JSON: {exc}") from exc
        try:
            out[f.stem] = reader(data)
        except InputError as exc:
            raise InputError(f"{f.name}: {exc}") from exc
    return out


def manifest_permissions(data) -> list[str]:
    if not isinstance(data, dict):
        raise InputError("expected an object with a permissions, scopes or oauth_scopes list")
    for key in ("permissions", "scopes", "oauth_scopes"):
        if key in data:
            return as_list(data[key])
    raise InputError("no permissions, scopes or oauth_scopes list")


# ---- checks ------------------------------------------------------------------------------------------------------


def check(entries: list[dict], listings, manifests, as_of: date, classes: set[str]) -> list[dict]:
    findings: list[dict] = []

    def add(rule: str, name: str, detail: str, line=None) -> None:
        findings.append({"rule": rule, "name": name, "detail": detail, "line": line})

    seen: dict[str, int] = {}
    for e in entries:
        name, line = e["name"], e["line"]
        seen[name] = seen.get(name, 0) + 1
        if seen[name] == 2:
            add("duplicate-name", name, "more than one entry has this name", line)
        for field, rule in REQUIRED.items():
            if not e[field]:
                add(rule, name, f"{field} is empty", line)
        if e["data_classification"] and e["data_classification"].lower() not in classes:
            add("invalid-classification", name, f"{e['data_classification']!r} is not one of {sorted(classes)}", line)
        if e["review_date"]:
            try:
                due = date.fromisoformat(e["review_date"])
            except ValueError:
                add("invalid-review-date", name, f"{e['review_date']!r} is not YYYY-MM-DD", line)
            else:
                if due < as_of:
                    add("review-overdue", name, f"review was due {due} ({(as_of - due).days} days ago)", line)
        if listings is not None:
            if name in listings:
                offered = set(listings[name])
                if e["tools"] is not None:
                    for t in sorted(offered - set(e["tools"])):
                        add("unregistered-tool", name, f"tool {t!r} is offered but not in the register", line)
                    for t in sorted(set(e["tools"]) - offered):
                        add("tool-gone", name, f"tool {t!r} is in the register but no longer offered", line)
            elif e["kind"] in ("mcp-server", "mcp", ""):
                add("not-present", name, "registered, but there is no saved tool listing for it", line)
        if manifests is not None and name in manifests:
            held, declared = set(manifests[name]), set(e["permissions"])
            for p in sorted(held - declared):
                add("undeclared-permission", name, f"manifest holds {p!r}, the register does not record it", line)
            for p in sorted(declared - held):
                add("permission-not-in-manifest", name, f"register records {p!r}, the manifest does not hold it", line)
    names = {e["name"] for e in entries}
    for server in sorted(set(listings or {}) - names):
        add("unregistered-server", server, f"a tool listing exists with {len(listings[server])} tool(s), but no entry")
    return findings


def render(doc: dict) -> str:
    lines = [
        "# Connector and MCP server register check",
        "",
        f"As of {doc['as_of']}. {len(doc['entries'])} entries, {len(doc['findings'])} findings. Tool listings: "
        f"{', '.join(doc['listings']) or 'none' if doc['listings'] is not None else 'not given'}; manifests: "
        f"{', '.join(doc['manifests']) or 'none' if doc['manifests'] is not None else 'not given'}.",
        "",
        "| Name | Kind | Owner | Classification | Permissions | Review due | Findings |",
        "|---|---|---|---|---|---|---|",
    ]
    per = {}
    for f in doc["findings"]:
        per[f["name"]] = per.get(f["name"], 0) + 1
    for e in doc["entries"]:
        lines.append(
            f"| {e['name']} | {e['kind'] or '-'} | {e['owner'] or '-'} | {e['data_classification'] or '-'} | "
            f"{'; '.join(e['permissions']) or '-'} | {e['review_date'] or '-'} | {per.get(e['name'], 0)} |"
        )
    lines += ["", "## Findings", ""]
    for f in doc["findings"]:
        where = f" (line {f['line']})" if f["line"] else ""
        lines.append(f"- {f['name']}{where} [{f['rule']}]: {f['detail']}")
    if not doc["findings"]:
        lines.append("No findings. Record who checked the register and when.")
    else:
        lines += ["", "Owner to update the register or the server, and the date: ____"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="connector_register.py",
        description="Check an MCP server, connector and plugin register against saved tool listings and manifests.",
        epilog="Exit codes: 0 no finding, 1 at least one finding, 2 bad input.",
    )
    ap.add_argument("register", help="register as CSV, YAML or JSON")
    ap.add_argument("--tools", help="folder of saved tools/list results, one <name>.json per server")
    ap.add_argument("--manifests", help="folder of permission manifests, one <name>.json per entry")
    ap.add_argument("--as-of", help="date judged against, YYYY-MM-DD (default today)")
    ap.add_argument(
        "--classifications",
        default="public,internal,confidential,restricted",
        help="allowed data classifications, comma separated (public,internal,confidential,restricted)",
    )
    ap.add_argument("--json", action="store_true", help="print the check as JSON")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        try:
            as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
        except ValueError as exc:
            raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD") from exc
        entries = load_register(Path(args.register))
        listings = load_folder(args.tools, tool_names)
        manifests = load_folder(args.manifests, manifest_permissions)
        classes = {c.strip().lower() for c in args.classifications.split(",") if c.strip()}
        findings = check(entries, listings, manifests, as_of, classes)
    except InputError as exc:
        print(f"connector_register.py: {exc}", file=sys.stderr)
        return 2
    doc = {
        "as_of": as_of.isoformat(),
        "entries": entries,
        "listings": sorted(listings) if listings is not None else None,
        "manifests": sorted(manifests) if manifests is not None else None,
        "findings": findings,
    }
    text = json.dumps(doc, indent=2) + "\n" if args.json else render(doc)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
