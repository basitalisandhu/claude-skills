#!/usr/bin/env python3
"""Cluster log lines into templates so a large log reads as a short list of distinct messages.

Each line is normalised: timestamps, UUIDs, hex ids, IP addresses, numbers, quoted strings, file paths and
e-mail addresses are replaced with placeholders (<ts>, <uuid>, <hex>, <ip>, <n>, <str>, <path>, <email>). Lines
that normalise to the same template form one cluster. For every cluster the report gives the count, the level
(parsed from the line when present), the first and last line numbers, one verbatim example, and a rough rate.
Clusters are ranked by severity first (error > warn > info > debug) and then by count.

Input: one or more log files, or stdin when no file is given. Lines are read as UTF-8 with replacement.
Stack traces: lines that start with whitespace or "at " or "File " are attached to the previous line's cluster.

Usage:
    log_triage.py [FILE ...] [--json] [--top N] [--level LEVEL] [--grep REGEX] [--no-collapse]

Exit codes: 0 normally, 1 when --fail-on-level is given and a cluster at that level or above exists, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

VERSION = "0.1.0"
LEVELS = ["fatal", "critical", "error", "warn", "info", "debug", "trace"]
LEVEL_RANK = {lv: i for i, lv in enumerate(LEVELS)}
LEVEL_RE = re.compile(r"(?<![A-Za-z])(FATAL|CRITICAL|CRIT|ERROR|ERR|WARNING|WARN|INFO|DEBUG|TRACE|PANIC|EMERG|ALERT|NOTICE)(?![A-Za-z])", re.I)
LEVEL_ALIAS = {"crit": "critical", "err": "error", "warning": "warn", "panic": "fatal", "emerg": "fatal", "alert": "critical", "notice": "info"}

NORMALISERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"), "<ts>"),
    (re.compile(r"\b[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}\b"), "<ts>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<time>"),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<uuid>"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "<email>"),
    (re.compile(r"https?://[^\s\"']+"), "<url>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"(?:^|(?<=[\s=:(\[\"']))(?:/[\w.@+-]+){2,}/?"), "<path>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<str>"),
    (re.compile(r"(?<![A-Za-z_])[-+]?\d+(?:\.\d+)?(?:ms|s|us|µs|ns|KB|MB|GB|kb|mb|gb|%)?(?![A-Za-z_])"), "<n>"),
]
CONTINUATION_RE = re.compile(r"^(\s+|at |File \"|Traceback|Caused by|\.\.\. \d+ more|\t)")


def normalise(line: str) -> str:
    s = line.strip()
    for rx, rep in NORMALISERS:
        s = rx.sub(rep, s)
    s = re.sub(r"\s+", " ", s)
    return s


def level_of(line: str) -> str | None:
    m = LEVEL_RE.search(line[:160])
    if not m:
        return None
    lv = m.group(1).lower()
    return LEVEL_ALIAS.get(lv, lv)


def cluster(lines, grep: re.Pattern[str] | None, min_level: str | None, collapse: bool) -> dict:
    clusters: "OrderedDict[str, dict]" = OrderedDict()
    last_key = None
    total = 0
    skipped = 0
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        total += 1
        if collapse and CONTINUATION_RE.match(line) and last_key is not None:
            c = clusters[last_key]
            c["continuation_lines"] += 1
            if len(c["example_tail"]) < 6:
                c["example_tail"].append(line)
            continue
        if grep and not grep.search(line):
            skipped += 1
            continue
        lv = level_of(line)
        if min_level and (lv is None or LEVEL_RANK.get(lv, 99) > LEVEL_RANK[min_level]):
            skipped += 1
            last_key = None
            continue
        key = normalise(line)
        c = clusters.get(key)
        if c is None:
            c = clusters[key] = {"template": key, "level": lv, "count": 0, "first_line": no, "last_line": no, "example": line,
                                 "continuation_lines": 0, "example_tail": []}
        c["count"] += 1
        c["last_line"] = no
        if lv and (c["level"] is None or LEVEL_RANK.get(lv, 99) < LEVEL_RANK.get(c["level"], 99)):
            c["level"] = lv
        last_key = key
    out = list(clusters.values())
    out.sort(key=lambda c: (LEVEL_RANK.get(c["level"] or "zzz", 99), -c["count"], c["first_line"]))
    return {"version": VERSION, "lines": total, "lines_skipped": skipped, "clusters": out}


def render_text(report: dict, top: int) -> str:
    cl = report["clusters"]
    lines = [f"log-triage {report['version']}: {report['lines']} lines, {len(cl)} distinct templates" + (f", {report['lines_skipped']} filtered out" if report["lines_skipped"] else "")]
    by_level: dict[str, int] = {}
    for c in cl:
        by_level[c["level"] or "none"] = by_level.get(c["level"] or "none", 0) + c["count"]
    lines.append("by level: " + ", ".join(f"{k}={v}" for k, v in sorted(by_level.items(), key=lambda kv: LEVEL_RANK.get(kv[0], 99))))
    lines.append(f"{'count':>6} {'level':<8} {'lines':<13} template")
    for c in cl[:top]:
        span = f"{c['first_line']}-{c['last_line']}" if c["count"] > 1 else str(c["first_line"])
        t = c["template"] if len(c["template"]) <= 110 else c["template"][:107] + "..."
        lines.append(f"{c['count']:>6} {(c['level'] or '-'):<8} {span:<13} {t}")
        if c["continuation_lines"]:
            lines.append(f"{'':>6} {'':<8} {'':<13}   +{c['continuation_lines']} continuation lines (stack trace), e.g. {c['example_tail'][0].strip()[:80]}")
    if len(cl) > top:
        lines.append(f"... {len(cl) - top} more templates (use --top or --json)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="log files (stdin when none)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--level", choices=LEVELS, help="keep only lines at this level or more severe")
    ap.add_argument("--grep", metavar="REGEX", help="keep only lines matching this regular expression")
    ap.add_argument("--no-collapse", action="store_true", help="treat indented continuation lines as their own lines")
    ap.add_argument("--fail-on-level", choices=LEVELS, help="exit 1 when any cluster is at this level or more severe")
    args = ap.parse_args(argv)
    try:
        grep = re.compile(args.grep) if args.grep else None
    except re.error as exc:
        print(f"error: bad --grep: {exc}", file=sys.stderr)
        return 2
    lines: list[str] = []
    if args.files:
        for f in args.files:
            p = Path(f)
            if not p.is_file():
                print(f"error: not a file: {f}", file=sys.stderr)
                return 2
            lines += p.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = sys.stdin.read().splitlines()
    report = cluster(lines, grep, args.level, not args.no_collapse)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report, args.top))
    if args.fail_on_level:
        worst = min((LEVEL_RANK.get(c["level"], 99) for c in report["clusters"] if c["level"]), default=99)
        return 1 if worst <= LEVEL_RANK[args.fail_on_level] else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
