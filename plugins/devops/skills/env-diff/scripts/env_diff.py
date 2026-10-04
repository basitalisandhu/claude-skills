#!/usr/bin/env python3
"""Compare the keys of a .env template with one or more real .env files, without ever printing a value.

Reports, per real file: keys missing (declared in the template but absent), extra (present but not declared),
empty (present with no value), and duplicated keys. For the template it reports keys whose example value looks
like a real credential (long random string) rather than a placeholder, and malformed lines in any file.
Values are never printed; the report shows only key names and whether a value is set.

Usage:
    env_diff.py TEMPLATE ENVFILE [ENVFILE ...] [--json] [--allow-extra] [--ignore KEY ...]

Exit codes: 0 every real file declares every template key, 1 missing keys (or extra keys without --allow-extra), 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"
LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$")
PLACEHOLDER_RE = re.compile(r"(?i)^(|\"\"|''|changeme|change[-_]me|xxx+|your[-_a-z]*|<[^>]*>|\.\.\.|\*+|example|placeholder|dummy|secret|password|todo|tbd|replace[-_a-z]*|\$\{?[A-Z_]+\}?|null|none|true|false|\d{1,5}|localhost|127\.0\.0\.1|https?://(localhost|example\.(com|org)|127\.0\.0\.1)[^\s]*)$")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def parse_env(text: str) -> tuple[dict[str, str], list[str], list[int]]:
    """Return ({key: value}, malformed lines, duplicate keys as line numbers)."""
    values: dict[str, str] = {}
    malformed: list[str] = []
    dups: list[str] = []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            malformed.append(f"line {no}")
            continue
        key, val = m.group(1), m.group(2).strip()
        if val[:1] in "\"'" and len(val) >= 2 and val[-1] == val[0]:
            val = val[1:-1]
        elif val[:1] not in "\"'":
            val = val.split(" #", 1)[0].rstrip()
        if key in values:
            dups.append(f"{key} (line {no})")
        values[key] = val
    return values, malformed, dups


def compare(template: dict[str, str], real: dict[str, str], ignore: set[str]) -> dict:
    tkeys = set(template) - ignore
    rkeys = set(real) - ignore
    return {"missing": sorted(tkeys - rkeys), "extra": sorted(rkeys - tkeys),
            "empty": sorted(k for k in rkeys & tkeys if real[k] == ""),
            "set": sorted(k for k in rkeys & tkeys if real[k] != "")}


def suspicious_template_values(template: dict[str, str]) -> list[str]:
    out = []
    for k, v in template.items():
        if len(v) >= 16 and not PLACEHOLDER_RE.match(v) and entropy(v) >= 3.5 and not v.startswith(("http://localhost", "postgres://localhost", "redis://localhost")):
            out.append(k)
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("template", help=".env.example or another template")
    ap.add_argument("envfiles", nargs="+", help="real .env files to check")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--allow-extra", action="store_true", help="do not fail on keys that the template does not declare")
    ap.add_argument("--ignore", action="append", default=[], metavar="KEY", help="key to ignore (repeatable)")
    args = ap.parse_args(argv)
    tpath = Path(args.template)
    if not tpath.is_file():
        print(f"error: template not found: {tpath}", file=sys.stderr)
        return 2
    template, t_malformed, t_dups = parse_env(tpath.read_text(encoding="utf-8", errors="replace"))
    ignore = set(args.ignore)
    report = {"version": VERSION, "template": {"file": str(tpath), "keys": len(template), "malformed": t_malformed, "duplicates": t_dups,
                                               "values_that_look_real": suspicious_template_values(template)}, "files": []}
    fail = False
    for f in args.envfiles:
        p = Path(f)
        if not p.is_file():
            print(f"error: file not found: {f}", file=sys.stderr)
            return 2
        real, malformed, dups = parse_env(p.read_text(encoding="utf-8", errors="replace"))
        cmp = compare(template, real, ignore)
        cmp.update({"file": str(p), "keys": len(real), "malformed": malformed, "duplicates": dups})
        report["files"].append(cmp)
        if cmp["missing"] or (cmp["extra"] and not args.allow_extra):
            fail = True
    report["ok"] = not fail
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        t = report["template"]
        print(f"env-diff {VERSION}: template {t['file']} declares {t['keys']} keys" + (f", {len(t['malformed'])} malformed lines" if t["malformed"] else "") + (f", duplicates: {', '.join(t['duplicates'])}" if t["duplicates"] else ""))
        if t["values_that_look_real"]:
            print(f"  template values that look like real credentials (rotate and replace with placeholders): {', '.join(t['values_that_look_real'])}")
        for c in report["files"]:
            print(f"  {c['file']}: {len(c['set'])} set, {len(c['empty'])} empty, {len(c['missing'])} missing, {len(c['extra'])} extra")
            for label in ("missing", "empty", "extra"):
                if c[label]:
                    print(f"    {label}: {', '.join(c[label])}")
            if c["duplicates"]:
                print(f"    duplicate keys: {', '.join(c['duplicates'])}")
            if c["malformed"]:
                print(f"    malformed: {', '.join(c['malformed'])}")
        print("ok" if report["ok"] else "not ok: missing or undeclared keys")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
