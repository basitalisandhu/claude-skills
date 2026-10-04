#!/usr/bin/env python3
"""Test a regular expression against labelled cases and warn about patterns that can backtrack badly.

Cases come from a file (one per line: `+ text that must match`, `- text that must not match`, `= text => expected
group or named groups as JSON`; blank lines and # comments ignored) or from --match / --no-match arguments.
For every case the report says whether it behaved as expected, what matched, and the captured groups. The
pattern is also checked for nested quantifiers such as (a+)+ and (.*)* and for alternations whose branches
overlap under a quantifier, the usual causes of catastrophic backtracking, and it is timed against a few
adversarial inputs built from the pattern itself.

The dialect is Python's re. Most JavaScript and PCRE patterns behave the same for the subset people write by
hand; look-behind must be fixed-width, and \\d \\w \\s match Unicode in Python unless --ascii is given.

Usage:
    regex_tester.py PATTERN [--cases FILE] [--match TEXT ...] [--no-match TEXT ...] [--flags imsx] [--ascii]
                    [--search|--fullmatch] [--json]

Exit codes: 0 every case behaved as expected and no backtracking warning, 1 a case failed or a warning fired, 2 bad pattern or input.
Standard library only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

VERSION = "0.1.0"
FLAG_MAP = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}
GROUP_RE = re.compile(r"\((?:\?:|\?P<\w+>|\?<\w+>)?(?P<inner>(?:[^()\\]|\\.)*)\)(?P<q>[+*]|\{\d*,\d*\})")
ATOM_RE = re.compile(r"^\^?(?:\\.|\[(?:[^\]\\]|\\.)*\]|\.|[^\\\[.|^$])(?P<q>[+*]|\{\d*,\d*\})")
OVERLAP_ALT_RE = re.compile(r"\(([^()|]+)\|([^()|]+)\)[+*]")


def parse_cases(text: str) -> list[dict]:
    cases: list[dict] = []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        tag, _, rest = line.partition(" ")
        if tag == "+":
            cases.append({"line": no, "expect": "match", "text": rest})
        elif tag == "-":
            cases.append({"line": no, "expect": "no-match", "text": rest})
        elif tag == "=":
            if " => " not in rest:
                raise ValueError(f"line {no}: expected 'text => expected'")
            text_part, expected = rest.rsplit(" => ", 1)
            try:
                exp = json.loads(expected)
            except json.JSONDecodeError:
                exp = expected
            cases.append({"line": no, "expect": "groups", "text": text_part, "expected": exp})
        else:
            raise ValueError(f"line {no}: case lines start with '+', '-' or '='")
    return cases


def run_case(rx: re.Pattern, case: dict, mode: str) -> dict:
    fn = {"search": rx.search, "match": rx.match, "fullmatch": rx.fullmatch}[mode]
    start = time.perf_counter()
    m = fn(case["text"])
    elapsed_ms = (time.perf_counter() - start) * 1000
    result = {"line": case.get("line"), "expect": case["expect"], "text": case["text"], "matched": bool(m), "ms": round(elapsed_ms, 3)}
    if m:
        result["match"] = m.group(0)
        result["span"] = list(m.span())
        result["groups"] = list(m.groups())
        result["named"] = m.groupdict()
    if case["expect"] == "match":
        result["ok"] = bool(m)
    elif case["expect"] == "no-match":
        result["ok"] = not m
    else:
        exp = case["expected"]
        if not m:
            result["ok"] = False
        elif isinstance(exp, dict):
            result["ok"] = all(m.groupdict().get(k) == v for k, v in exp.items())
        elif isinstance(exp, list):
            result["ok"] = list(m.groups()) == exp
        else:
            result["ok"] = (m.group(1) if m.groups() else m.group(0)) == exp
        result["expected"] = exp
    return result


def static_warnings(pattern: str) -> list[str]:
    out: list[str] = []
    for g in GROUP_RE.finditer(pattern):
        inner = g.group("inner")
        branches = inner.split("|") if "|" in inner else [inner]
        if any(ATOM_RE.match(b.strip()) for b in branches if b.strip()):
            out.append(f"nested quantifier ({inner}){g.group('q')}: the inner repetition starts with a quantified token, so non-matching input can backtrack exponentially; start the group with a fixed delimiter or merge the quantifiers")
            break
    for m in OVERLAP_ALT_RE.finditer(pattern):
        a, b = m.group(1), m.group(2)
        if a and b and (a[0] == b[0] or a in b or b in a or set(a) & set(b) and ("\\" in a or "\\" in b)):
            out.append(f"alternation ({a}|{b}) under a quantifier has overlapping branches: ambiguous matching backtracks; reorder or make branches disjoint")
    if re.search(r"\.\*.*\.\*", pattern):
        out.append("two .* in one pattern: quadratic scanning on long inputs; anchor or replace with [^x]* classes")
    if pattern.count("(") > 10:
        out.append("more than ten groups; consider named groups (?P<name>...) and re.X with comments")
    return out


def adversarial_timing(rx: re.Pattern, pattern: str) -> list[dict]:
    seeds = ["a" * 24 + "!", "ab" * 12 + "!", "x" * 30, " " * 20 + "!", "aaaa\n" * 6, "@" * 25 + "!", "1" * 25 + "!"]
    literal_chars = sorted(set(re.sub(r"\\.|\[.*?\]|[()+*?{}|^$.]", "", pattern)))
    if literal_chars:
        seeds.append("".join(literal_chars) * 8 + "!")
    out = []
    for s in seeds:
        start = time.perf_counter()
        rx.search(s)
        ms = (time.perf_counter() - start) * 1000
        out.append({"input": s[:24] + ("..." if len(s) > 24 else ""), "ms": round(ms, 3)})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pattern")
    ap.add_argument("--cases", help="file of labelled cases")
    ap.add_argument("--match", action="append", default=[], metavar="TEXT")
    ap.add_argument("--no-match", action="append", default=[], metavar="TEXT")
    ap.add_argument("--flags", default="", help="any of i m s x a")
    ap.add_argument("--ascii", action="store_true", help="ASCII-only \\d \\w \\s (like JavaScript without the u flag)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--search", action="store_true", help="find anywhere (default)")
    mode.add_argument("--fullmatch", action="store_true", help="the whole text must match")
    mode.add_argument("--match-start", action="store_true", help="match at the start only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    flags = 0
    for ch in args.flags:
        if ch not in FLAG_MAP:
            print(f"error: unknown flag {ch!r}", file=sys.stderr)
            return 2
        flags |= FLAG_MAP[ch]
    if args.ascii:
        flags |= re.A
    try:
        rx = re.compile(args.pattern, flags)
    except re.error as exc:
        print(f"error: invalid pattern: {exc}", file=sys.stderr)
        return 2
    cases: list[dict] = []
    if args.cases:
        p = Path(args.cases)
        if not p.is_file():
            print(f"error: cases file not found: {p}", file=sys.stderr)
            return 2
        try:
            cases += parse_cases(p.read_text(encoding="utf-8"))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    cases += [{"expect": "match", "text": t} for t in args.match]
    cases += [{"expect": "no-match", "text": t} for t in args.no_match]
    mode_name = "fullmatch" if args.fullmatch else "match" if args.match_start else "search"
    results = [run_case(rx, c, mode_name) for c in cases]
    warnings = static_warnings(args.pattern)
    timing = adversarial_timing(rx, args.pattern)
    slow = [t for t in timing if t["ms"] > 50]
    if slow:
        warnings.append("adversarial input took over 50 ms: " + ", ".join(f"{t['input']!r} {t['ms']} ms" for t in slow))
    failed = [r for r in results if not r["ok"]]
    report = {"version": VERSION, "pattern": args.pattern, "flags": args.flags + ("a" if args.ascii and "a" not in args.flags else ""), "mode": mode_name,
              "groups": rx.groups, "named_groups": list(rx.groupindex), "cases": results, "passed": len(results) - len(failed), "failed": len(failed),
              "warnings": warnings, "timing": timing}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"regex-tester {VERSION}: /{args.pattern}/{report['flags']} ({mode_name}), {rx.groups} groups" + (f" named {', '.join(rx.groupindex)}" if rx.groupindex else "") + f": {report['passed']} passed, {report['failed']} failed")
        for r in results:
            mark = "ok  " if r["ok"] else "FAIL"
            shown = f"matched {r['match']!r} groups={r['groups']}" if r["matched"] else "no match"
            exp = f" expected {r['expected']!r}" if "expected" in r else ""
            print(f"  {mark} [{r['expect']:<8}] {r['text']!r}: {shown}{exp}")
        for w in warnings:
            print(f"  warning: {w}")
    return 1 if (failed or warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
