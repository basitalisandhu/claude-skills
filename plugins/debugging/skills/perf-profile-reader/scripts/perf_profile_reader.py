#!/usr/bin/env python3
"""Summarise a text profile from py-spy, pprof or cProfile into the few functions that matter.

Formats (auto-detected, or forced with --format):
  collapsed   py-spy `record --format raw`, or any flamegraph "collapsed stacks" file: one `a;b;c <samples>` per line.
              Reports self and total samples per frame and the hottest full stacks.
  pprof       `go tool pprof -text` / `-top` output: a header, then rows `flat flat% sum% cum cum% name`.
  cprofile    Python `cProfile` / `pstats` print_stats output: rows `ncalls tottime percall cumtime percall file:line(func)`.
  pyspy-dump  `py-spy dump` output: thread headers and indented frames; reports frame frequency across threads.

The summary is the same for every format: top functions by self time (where the time is spent) and by total or
cumulative time (what called the expensive code), the share of the total they account for, and a few checks:
a single frame over half the time, GC or lock frames high in the list, and deep recursion.

Usage:
    perf_profile_reader.py FILE [--json] [--top N] [--format collapsed|pprof|cprofile|pyspy-dump]

Exit codes: 0 summary produced, 2 unreadable or unrecognised input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "0.1.0"
PPROF_ROW = re.compile(r"^\s*([\d.]+)(?:[a-zµ]+)?\s+([\d.]+)%\s+([\d.]+)%\s+([\d.]+)(?:[a-zµ]+)?\s+([\d.]+)%\s+(.+?)\s*$")
CPROFILE_ROW = re.compile(r"^\s*(\d+(?:/\d+)?)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(.+?)\s*$")
COLLAPSED_ROW = re.compile(r"^(.+?)\s+(\d+)\s*$")
HOT_SPOT_WORDS = ("gc_collect", "gc.collect", "runtime.gcBgMarkWorker", "runtime.mallocgc", "lock", "Lock", "mutex", "Mutex", "semaphore",
                  "wait", "select", "poll", "sleep", "recv", "read(", "write(")


def detect(text: str) -> str | None:
    head = text[:4000]
    if "Thread " in head and re.search(r"^\s+\S.*\(.*:\d+\)\s*$", head, re.M) and "py-spy" in head.lower() or re.search(r"^Thread 0x[0-9A-Fa-f]+ \(", head, re.M):
        return "pyspy-dump"
    if re.search(r"^\s*flat\s+flat%\s+sum%\s+cum\s+cum%", head, re.M):
        return "pprof"
    if re.search(r"^\s*ncalls\s+tottime\s+percall\s+cumtime", head, re.M):
        return "cprofile"
    lines = [ln for ln in head.splitlines() if ln.strip()]
    if lines and sum(bool(COLLAPSED_ROW.match(ln) and ";" in ln) for ln in lines[:20]) >= max(1, len(lines[:20]) // 2):
        return "collapsed"
    return None


def parse_collapsed(text: str) -> dict:
    self_c: Counter[str] = Counter()
    total_c: Counter[str] = Counter()
    stacks: Counter[str] = Counter()
    total = 0
    max_depth = 0
    for ln in text.splitlines():
        m = COLLAPSED_ROW.match(ln)
        if not m:
            continue
        frames = [f for f in m.group(1).split(";") if f]
        n = int(m.group(2))
        if not frames:
            continue
        total += n
        max_depth = max(max_depth, len(frames))
        stacks[";".join(frames)] += n
        self_c[frames[-1]] += n
        for f in set(frames):
            total_c[f] += n
    return {"unit": "samples", "total": total, "self": self_c, "cumulative": total_c, "stacks": stacks, "max_depth": max_depth}


def parse_pprof(text: str) -> dict:
    self_c: Counter[str] = Counter()
    total_c: Counter[str] = Counter()
    total = 0.0
    unit = "flat"
    m = re.search(r"Showing nodes accounting for .*? of ([\d.]+)([a-zµ]*)\s+total", text)
    if m:
        total = float(m.group(1))
        unit = m.group(2) or "samples"
    for ln in text.splitlines():
        r = PPROF_ROW.match(ln)
        if not r or ln.strip().startswith("flat"):
            continue
        flat, _, _, cum, _, name = r.groups()
        self_c[name] += float(flat)
        total_c[name] = max(total_c[name], float(cum))
    if not total:
        total = sum(self_c.values())
    return {"unit": unit, "total": total, "self": self_c, "cumulative": total_c, "stacks": None, "max_depth": None}


def parse_cprofile(text: str) -> dict:
    self_c: Counter[str] = Counter()
    total_c: Counter[str] = Counter()
    calls: dict[str, str] = {}
    total = 0.0
    m = re.search(r"function calls(?: \([^)]*\))? in ([\d.]+) (?:CPU )?seconds", text)
    if m:
        total = float(m.group(1))
    for ln in text.splitlines():
        r = CPROFILE_ROW.match(ln)
        if not r:
            continue
        ncalls, tottime, _, cumtime, _, name = r.groups()
        self_c[name] += float(tottime)
        total_c[name] = max(total_c[name], float(cumtime))
        calls[name] = ncalls
    if not total:
        total = sum(self_c.values())
    return {"unit": "seconds", "total": total, "self": self_c, "cumulative": total_c, "stacks": None, "max_depth": None, "calls": calls}


def parse_pyspy_dump(text: str) -> dict:
    self_c: Counter[str] = Counter()
    total_c: Counter[str] = Counter()
    threads = 0
    stack: list[str] = []
    max_depth = 0
    frame_re = re.compile(r"^\s+(\S.*?)\s+\((.+?):(\d+)\)\s*$")
    for ln in text.splitlines():
        if ln.startswith("Thread "):
            if stack:
                self_c[stack[0]] += 1
                for f in set(stack):
                    total_c[f] += 1
                max_depth = max(max_depth, len(stack))
            stack = []
            threads += 1
            continue
        m = frame_re.match(ln)
        if m:
            stack.append(f"{m.group(1)} ({m.group(2)}:{m.group(3)})")
    if stack:
        self_c[stack[0]] += 1
        for f in set(stack):
            total_c[f] += 1
        max_depth = max(max_depth, len(stack))
    return {"unit": "threads", "total": threads, "self": self_c, "cumulative": total_c, "stacks": None, "max_depth": max_depth}


def summarise(parsed: dict, fmt: str, top: int) -> dict:
    total = parsed["total"] or 1
    def rows(counter: Counter) -> list[dict]:
        out = []
        for name, v in counter.most_common(top):
            row = {"name": name, "value": round(v, 4) if isinstance(v, float) else v, "percent": round(100.0 * v / total, 1)}
            if parsed.get("calls") and name in parsed["calls"]:
                row["calls"] = parsed["calls"][name]
            out.append(row)
        return out
    by_self = rows(parsed["self"])
    by_total = rows(parsed["cumulative"])
    checks: list[str] = []
    if by_self and by_self[0]["percent"] >= 50:
        checks.append(f"one frame holds {by_self[0]['percent']}% of self time: {by_self[0]['name']}")
    hot = [r["name"] for r in by_self[:10] if any(w in r["name"] for w in HOT_SPOT_WORDS)]
    if hot:
        checks.append("waiting, locking or GC frames in the top ten by self time: " + "; ".join(hot[:3]) + " (the program may be blocked rather than busy)")
    if parsed.get("max_depth") and parsed["max_depth"] > 60:
        checks.append(f"deepest stack has {parsed['max_depth']} frames (recursion or a very deep call chain)")
    if len(parsed["self"]) > 0 and sum(v for _, v in parsed["self"].most_common(5)) / total < 0.3:
        checks.append("time is spread thinly (top five frames under 30%); look at cumulative rows for the caller that fans out")
    summary = {"version": VERSION, "format": fmt, "unit": parsed["unit"], "total": parsed["total"], "frames": len(parsed["self"]),
               "max_depth": parsed.get("max_depth"), "top_self": by_self, "top_cumulative": by_total, "checks": checks}
    if parsed.get("stacks"):
        summary["top_stacks"] = [{"stack": s, "samples": n, "percent": round(100.0 * n / total, 1)} for s, n in parsed["stacks"].most_common(min(top, 5))]
    return summary


def render_text(s: dict) -> str:
    lines = [f"perf-profile-reader {s['version']}: format={s['format']}, total={s['total']} {s['unit']}, {s['frames']} distinct frames" + (f", max depth {s['max_depth']}" if s.get("max_depth") else "")]
    lines.append("top by self (where time is spent):")
    for r in s["top_self"]:
        extra = f" calls={r['calls']}" if "calls" in r else ""
        lines.append(f"  {r['percent']:>5}%  {r['value']:>10}  {r['name'][:100]}{extra}")
    lines.append("top by cumulative (what calls the expensive code):")
    for r in s["top_cumulative"]:
        lines.append(f"  {r['percent']:>5}%  {r['value']:>10}  {r['name'][:100]}")
    if s.get("top_stacks"):
        lines.append("hottest full stacks:")
        for r in s["top_stacks"]:
            lines.append(f"  {r['percent']:>5}%  {r['stack'][-140:]}")
    if s["checks"]:
        lines.append("checks:")
        lines += [f"  - {c}" for c in s["checks"]]
    return "\n".join(lines)


PARSERS = {"collapsed": parse_collapsed, "pprof": parse_pprof, "cprofile": parse_cprofile, "pyspy-dump": parse_pyspy_dump}


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="profile text file ('-' for stdin)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--format", choices=sorted(PARSERS), help="force the input format instead of auto-detecting")
    args = ap.parse_args(argv)
    if args.file == "-":
        text = sys.stdin.read()
    else:
        p = Path(args.file)
        if not p.is_file():
            print(f"error: not a file: {p}", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
    fmt = args.format or detect(text)
    if fmt is None:
        print("error: could not recognise the profile format; pass --format", file=sys.stderr)
        return 2
    parsed = PARSERS[fmt](text)
    if not parsed["self"]:
        print(f"error: no rows parsed as {fmt}", file=sys.stderr)
        return 2
    s = summarise(parsed, fmt, args.top)
    print(json.dumps(s, indent=2) if args.json else render_text(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
