#!/usr/bin/env python3
"""Read, check and update a CHANGELOG.md that follows the Keep a Changelog format.

Subcommands:
  check                 validate structure: title, [Unreleased] section, versions in descending order with ISO
                        dates, only the standard categories (Added, Changed, Deprecated, Removed, Fixed, Security),
                        no empty categories, link references for every version when any exist
  show [VERSION]        print one version's section (default: Unreleased) as Markdown
  add CATEGORY TEXT     append an entry under [Unreleased] / CATEGORY (creates the category in standard order)
  release VERSION       turn [Unreleased] into [VERSION] - today (or --date), start a fresh [Unreleased], and update
                        the compare links when --repo-url is given or links already exist
  latest                print the newest released version number

All subcommands take --file (default CHANGELOG.md) and --json. `add` and `release` rewrite the file in place
(--dry-run prints the result instead).

Exit codes: 0 ok, 1 check found problems (or nothing to release), 2 bad input.
Standard library only. No network.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
CATEGORIES = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]
VERSION_HEADER_RE = re.compile(r"^## \[(?P<name>[^\]]+)\](?:\s*-\s*(?P<date>\S+))?(?P<rest>.*)$")
CATEGORY_RE = re.compile(r"^### (?P<name>.+?)\s*$")
LINK_RE = re.compile(r"^\[(?P<name>[^\]]+)\]:\s*(?P<url>\S+)\s*$")
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse(text: str) -> dict:
    lines = text.splitlines()
    doc = {"preamble": [], "versions": [], "links": {}, "link_lines": []}
    current = None
    category = None
    for no, line in enumerate(lines, 1):
        lm = LINK_RE.match(line)
        if lm and (current is not None or doc["versions"]):
            doc["links"][lm.group("name")] = lm.group("url")
            doc["link_lines"].append(no)
            continue
        vm = VERSION_HEADER_RE.match(line)
        if vm:
            current = {"name": vm.group("name"), "date": vm.group("date"), "line": no, "categories": [], "rest": vm.group("rest").strip(), "body": []}
            doc["versions"].append(current)
            category = None
            continue
        if current is None:
            doc["preamble"].append(line)
            continue
        cm = CATEGORY_RE.match(line)
        if cm:
            category = {"name": cm.group("name"), "line": no, "entries": []}
            current["categories"].append(category)
            continue
        if category is not None and line.strip().startswith(("- ", "* ")):
            category["entries"].append(line.strip()[2:].strip())
        elif category is not None and line.startswith("  ") and category["entries"]:
            category["entries"][-1] += " " + line.strip()
        current["body"].append(line)
    return doc


def semver_key(name: str):
    m = SEMVER_RE.match(name)
    if not m:
        return None
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre is None else -1, pre or "")


def check(doc: dict) -> list[dict]:
    problems: list[dict] = []

    def add(line, msg):
        problems.append({"line": line, "message": msg})

    if not any(l.startswith("# ") for l in doc["preamble"]):
        add(1, "missing top-level title (# Changelog)")
    names = [v["name"] for v in doc["versions"]]
    if "Unreleased" not in names:
        add(1, "missing [Unreleased] section")
    elif names[0] != "Unreleased":
        add(doc["versions"][names.index("Unreleased")]["line"], "[Unreleased] should be the first section")
    released = [v for v in doc["versions"] if v["name"] != "Unreleased"]
    for v in released:
        if semver_key(v["name"]) is None:
            add(v["line"], f"version {v['name']!r} is not semantic (MAJOR.MINOR.PATCH)")
        if not v["date"]:
            add(v["line"], f"version {v['name']} has no date")
        else:
            try:
                dt.date.fromisoformat(v["date"])
            except ValueError:
                add(v["line"], f"version {v['name']} date {v['date']!r} is not YYYY-MM-DD")
        if v["rest"] and not re.match(r"^\[YANKED\]$", v["rest"], re.I):
            add(v["line"], f"unexpected text after the version header: {v['rest']!r}")
    keys = [semver_key(v["name"]) for v in released]
    for a, b, va in zip(keys, keys[1:], released):
        if a and b and a < b:
            add(va["line"], f"versions are not in descending order around {va['name']}")
    for v in doc["versions"]:
        seen = set()
        for c in v["categories"]:
            if c["name"] not in CATEGORIES:
                add(c["line"], f"non-standard category {c['name']!r}; use one of {', '.join(CATEGORIES)}")
            if c["name"] in seen:
                add(c["line"], f"duplicate category {c['name']} in {v['name']}")
            seen.add(c["name"])
            if not c["entries"]:
                add(c["line"], f"empty category {c['name']} in {v['name']}")
        if v["name"] != "Unreleased" and not v["categories"] and not any(l.strip() for l in v["body"]):
            add(v["line"], f"version {v['name']} has no entries")
    if doc["links"]:
        for v in doc["versions"]:
            if v["name"] not in doc["links"]:
                add(v["line"], f"no link reference for [{v['name']}]")
    return problems


def render(doc: dict) -> str:
    out = list(doc["preamble"])
    while out and not out[-1].strip():
        out.pop()
    for v in doc["versions"]:
        out.append("")
        header = f"## [{v['name']}]" + (f" - {v['date']}" if v["date"] else "") + (f" {v['rest']}" if v["rest"] else "")
        out.append(header)
        for c in v["categories"]:
            out.append("")
            out.append(f"### {c['name']}")
            out.append("")
            out += [f"- {e}" for e in c["entries"]]
    if doc["links"]:
        out.append("")
        out += [f"[{name}]: {url}" for name, url in doc["links"].items()]
    return "\n".join(out) + "\n"


def cmd_add(doc: dict, category: str, text: str) -> None:
    cat_name = category.capitalize()
    if cat_name not in CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
    unreleased = next((v for v in doc["versions"] if v["name"] == "Unreleased"), None)
    if unreleased is None:
        unreleased = {"name": "Unreleased", "date": None, "line": 0, "categories": [], "rest": "", "body": []}
        doc["versions"].insert(0, unreleased)
    cat = next((c for c in unreleased["categories"] if c["name"] == cat_name), None)
    if cat is None:
        cat = {"name": cat_name, "line": 0, "entries": []}
        unreleased["categories"].append(cat)
        unreleased["categories"].sort(key=lambda c: CATEGORIES.index(c["name"]) if c["name"] in CATEGORIES else 99)
    cat["entries"].append(text.strip())


def cmd_release(doc: dict, version: str, date: str, repo_url: str | None) -> None:
    version = version.lstrip("v")
    if semver_key(version) is None:
        raise ValueError(f"{version!r} is not a semantic version")
    unreleased = next((v for v in doc["versions"] if v["name"] == "Unreleased"), None)
    if unreleased is None or not any(c["entries"] for c in unreleased["categories"]):
        raise LookupError("nothing to release: [Unreleased] is empty")
    if any(v["name"] == version for v in doc["versions"]):
        raise ValueError(f"version {version} already exists")
    unreleased["name"] = version
    unreleased["date"] = date
    doc["versions"].insert(0, {"name": "Unreleased", "date": None, "line": 0, "categories": [], "rest": "", "body": []})
    base = repo_url.rstrip("/") if repo_url else None
    if base is None and doc["links"]:
        sample = next(iter(doc["links"].values()))
        m = re.match(r"^(https?://[^\s]+?)/(?:compare|releases/tag)/", sample)
        base = m.group(1) if m else None
    if base:
        released = [v["name"] for v in doc["versions"] if v["name"] != "Unreleased"]
        links = {"Unreleased": f"{base}/compare/v{released[0]}...HEAD"}
        for newer, older in zip(released, released[1:]):
            links[newer] = f"{base}/compare/v{older}...v{newer}"
        links[released[-1]] = doc["links"].get(released[-1], f"{base}/releases/tag/v{released[-1]}")
        doc["links"] = links


def section_markdown(v: dict) -> str:
    out = [f"## [{v['name']}]" + (f" - {v['date']}" if v["date"] else "")]
    for c in v["categories"]:
        out += ["", f"### {c['name']}", ""] + [f"- {e}" for e in c["entries"]]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="CHANGELOG.md")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the updated file instead of writing it")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def command(name: str) -> argparse.ArgumentParser:
        # The global options are repeated on every subcommand so that `check --json` works as well as `--json check`;
        # SUPPRESS keeps the subcommand from overwriting a value given before it.
        sp = sub.add_parser(name)
        sp.add_argument("--file", default=argparse.SUPPRESS)
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        sp.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS)
        return sp

    command("check")
    sp = command("show")
    sp.add_argument("version", nargs="?", default="Unreleased")
    sa = command("add")
    sa.add_argument("category", help="Added, Changed, Deprecated, Removed, Fixed or Security")
    sa.add_argument("text")
    sr = command("release")
    sr.add_argument("version")
    sr.add_argument("--date", default=dt.date.today().isoformat())
    sr.add_argument("--repo-url", help="base URL for compare links, for example https://github.com/owner/repo")
    command("latest")
    args = ap.parse_args(argv)
    path = Path(args.file)
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 2
    doc = parse(path.read_text(encoding="utf-8"))
    if args.cmd == "check":
        problems = check(doc)
        if args.json:
            print(json.dumps({"version": VERSION, "file": str(path), "ok": not problems, "problems": problems, "versions": [v["name"] for v in doc["versions"]]}, indent=2))
        else:
            print(f"changelog check {VERSION}: {path}: {len(doc['versions'])} sections, {len(problems)} problems")
            for p in problems:
                print(f"  line {p['line']}: {p['message']}")
        return 1 if problems else 0
    if args.cmd == "show":
        v = next((v for v in doc["versions"] if v["name"] == args.version.lstrip("v")), None)
        if v is None:
            print(f"error: no section [{args.version}]", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"name": v["name"], "date": v["date"], "categories": [{"name": c["name"], "entries": c["entries"]} for c in v["categories"]]}, indent=2))
        else:
            print(section_markdown(v), end="")
        return 0
    if args.cmd == "latest":
        released = [v for v in doc["versions"] if v["name"] != "Unreleased"]
        if not released:
            print("error: no released version", file=sys.stderr)
            return 1
        print(json.dumps({"version": released[0]["name"], "date": released[0]["date"]}) if args.json else released[0]["name"])
        return 0
    try:
        if args.cmd == "add":
            cmd_add(doc, args.category, args.text)
        elif args.cmd == "release":
            cmd_release(doc, args.version, args.date, args.repo_url)
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = render(doc)
    if args.dry_run:
        print(text, end="")
    else:
        path.write_text(text, encoding="utf-8")
        if args.json:
            print(json.dumps({"version": VERSION, "file": str(path), "command": args.cmd, "written": True}))
        else:
            print(f"updated {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
