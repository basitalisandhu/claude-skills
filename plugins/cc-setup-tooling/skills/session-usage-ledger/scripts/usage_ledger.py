#!/usr/bin/env python3
"""Add up the API usage recorded in Claude Code session transcripts, and say which part of it moved.

Every assistant line of a transcript carries the `usage` block of the API response it came from: input, output,
cache read and cache write tokens, with the cache writes split into 5-minute and 1-hour lifetimes. One response can
be split over several lines that repeat the usage block, so calls are deduplicated by message id and request id
before anything is summed (the largest value of each field wins, because a streamed response can repeat a partial
count first).

The ledger is grouped per day (UTC), session, model and project, with the cache-hit ratio
read / (read + write + uncached input), the size of each session's first call (the fixed context sent before any
work) and the share used by subagents. Two periods can be compared (--compare-weeks, or --baseline A..B --period
C..D) to show which component moved: more calls, more context per call, fewer cache hits, or 1-hour writes turning
into 5-minute writes. That separates "I used more" from "the meter changed".

Usage:
  usage_ledger.py ~/.claude/projects
  usage_ledger.py ~/.claude/projects --since 2026-10-01 --format markdown
  usage_ledger.py ~/.claude/projects --compare-weeks --expect-ttl 1h
  usage_ledger.py ~/.claude/projects --baseline 2026-10-01..2026-10-07 --period 2026-10-08..2026-10-14 --json

It reads local files only (no network) and never claims what a plan meter counted: plan quotas and weekly
percentages are not in the transcript, and prices appear only when you pass --rates.

Exit codes: 0 nothing flagged, 1 at least one finding, 2 bad input (missing path, bad option, nothing usable read,
unwritable --out).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _transcript as tx  # noqa: E402

PROG = "usage_ledger.py"
FIELDS = ("input", "output", "cache_read", "write_5m", "write_1h", "write_other")
RATIO_METRICS = ("cache_hit_ratio", "share_5m_of_writes")
RATE_KEYS = ("input", "output", "cache_read", "cache_write_5m", "cache_write_1h")


@dataclass
class Call:
    key: tuple
    ts: datetime | None
    session: str
    project: str
    model: str
    subagent: bool
    input: int = 0
    output: int = 0
    cache_read: int = 0
    write_5m: int = 0
    write_1h: int = 0
    write_other: int = 0

    @property
    def write(self) -> int:
        return self.write_5m + self.write_1h + self.write_other

    @property
    def context(self) -> int:
        """Tokens sent with the call: uncached input, cache read and cache write."""
        return self.input + self.cache_read + self.write

    @property
    def total(self) -> int:
        return self.context + self.output


def as_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def usage_fields(usage: dict) -> dict[str, int]:
    write_total = as_int(usage.get("cache_creation_input_tokens"))
    split = usage.get("cache_creation") if isinstance(usage.get("cache_creation"), dict) else {}
    w5 = as_int(split.get("ephemeral_5m_input_tokens"))
    w1 = as_int(split.get("ephemeral_1h_input_tokens"))
    return {
        "input": as_int(usage.get("input_tokens")),
        "output": as_int(usage.get("output_tokens")),
        "cache_read": as_int(usage.get("cache_read_input_tokens")),
        "write_5m": w5,
        "write_1h": w1,
        "write_other": max(write_total - w5 - w1, 0),
    }


def load_calls(records: list[tx.Record]) -> tuple[list[Call], int]:
    """API calls from assistant lines, deduplicated. Returns the calls and the number of repeated lines merged."""
    calls: dict[tuple, Call] = {}
    merged = 0
    for rec in records:
        if rec.type != "assistant":
            continue
        msg = rec.data.get("message")
        if not isinstance(msg, dict) or not isinstance(msg.get("usage"), dict):
            continue
        model = msg.get("model") if isinstance(msg.get("model"), str) else "(unknown)"
        if model == "<synthetic>":  # written by the client, not an API response
            continue
        mid, rid = msg.get("id"), rec.data.get("requestId")
        key = (
            (mid, rid)
            if (isinstance(mid, str) and mid) or (isinstance(rid, str) and rid)
            else (str(rec.path), rec.line)
        )
        values = usage_fields(msg["usage"])
        ts = tx.parse_ts(rec.data.get("timestamp"))
        call = calls.get(key)
        if call is None:
            calls[key] = Call(
                key, ts, tx.session_id(rec), tx.project_name(rec.path), model, tx.is_subagent(rec), **values
            )
            continue
        merged += 1
        for name, v in values.items():
            setattr(call, name, max(getattr(call, name), v))
        if ts and (call.ts is None or ts < call.ts):
            call.ts = ts
    return list(calls.values()), merged


def hit_ratio(read: int, write: int, uncached: int) -> float | None:
    denom = read + write + uncached
    return read / denom if denom else None


def summarise(calls: list[Call]) -> dict:
    s = {f: sum(getattr(c, f) for c in calls) for f in FIELDS}
    s["calls"] = len(calls)
    s["cache_write"] = s["write_5m"] + s["write_1h"] + s["write_other"]
    s["context"] = s["input"] + s["cache_read"] + s["cache_write"]
    s["total"] = s["context"] + s["output"]
    ratio = hit_ratio(s["cache_read"], s["cache_write"], s["input"])
    s["cache_hit_ratio"] = round(ratio, 4) if ratio is not None else None
    split = s["write_5m"] + s["write_1h"]
    s["share_5m_of_writes"] = round(s["write_5m"] / split, 4) if split else None
    s["context_per_call"] = round(s["context"] / len(calls)) if calls else 0
    s["output_per_call"] = round(s["output"] / len(calls)) if calls else 0
    sub = [c for c in calls if c.subagent]
    s["subagent_calls"] = len(sub)
    s["subagent_share"] = round(sum(c.total for c in sub) / s["total"], 4) if s["total"] else None
    return s


def first_calls(calls: list[Call]) -> dict[str, Call]:
    """The first API call of each session: of the main thread when it has one, else of its first subagent."""
    by_session: dict[str, list[Call]] = defaultdict(list)
    for c in calls:
        by_session[c.session].append(c)
    out = {}
    far = datetime.max.replace(tzinfo=None)
    for sid, cs in by_session.items():
        main = [c for c in cs if not c.subagent] or cs
        out[sid] = min(main, key=lambda c: c.ts.replace(tzinfo=None) if c.ts else far)
    return out


def median(values: list[int]) -> int:
    if not values:
        return 0
    v = sorted(values)
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else round((v[mid - 1] + v[mid]) / 2)


def load_rates(path: str) -> dict[str, dict[str, float]]:
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise tx.InputError(f"--rates {path}: no such file") from None
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise tx.InputError(f"--rates {path}: not a readable JSON file ({exc.__class__.__name__})") from None
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise tx.InputError(f'--rates {path}: expected {{"model prefix": {{"input": 3.0, ...}}}} (per million tokens)')
    for model, rates in data.items():
        for k, v in rates.items():
            if k not in RATE_KEYS or not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
                raise tx.InputError(f"--rates {path}: {model}.{k} must be one of {', '.join(RATE_KEYS)} with a number")
    return data


def cost(calls: list[Call], rates: dict[str, dict[str, float]]) -> tuple[float, int]:
    """Estimated cost from the user's own rates; returns (cost, calls with no matching rate)."""
    total, unpriced = 0.0, 0
    keys = sorted(rates, key=len, reverse=True)
    for c in calls:
        r = next((rates[k] for k in keys if k != "*" and c.model.startswith(k)), rates.get("*"))
        if r is None:
            unpriced += 1
            continue
        total += (
            c.input * r.get("input", 0)
            + c.output * r.get("output", 0)
            + c.cache_read * r.get("cache_read", 0)
            + (c.write_5m + c.write_other) * r.get("cache_write_5m", 0)
            + c.write_1h * r.get("cache_write_1h", r.get("cache_write_5m", 0))
        ) / 1_000_000
    return round(total, 4), unpriced


def group(calls: list[Call], keyfn) -> dict[str, list[Call]]:
    out: dict[str, list[Call]] = defaultdict(list)
    for c in calls:
        out[keyfn(c)].append(c)
    return out


def day_of(c: Call) -> str:
    return c.ts.date().isoformat() if c.ts else "(no date)"


def change(a: float | None, b: float | None) -> float | None:
    if a is None or b is None or a == 0:
        return None
    return round((b - a) / a, 4)


def compare(base: list[Call], per: list[Call], base_range: tuple[date, date], per_range: tuple[date, date]) -> dict:
    a, b = summarise(base), summarise(per)
    fa, fb = first_calls(base), first_calls(per)
    a["sessions"], b["sessions"] = len(fa), len(fb)
    a["first_call_median"] = median([c.context for c in fa.values()])
    b["first_call_median"] = median([c.context for c in fb.values()])
    days_a = (base_range[1] - base_range[0]).days + 1
    days_b = (per_range[1] - per_range[0]).days + 1
    a["days"], b["days"] = days_a, days_b
    metrics = [
        "calls",
        "sessions",
        "context_per_call",
        "output_per_call",
        "first_call_median",
        "cache_hit_ratio",
        "share_5m_of_writes",
        "cache_write",
        "total",
    ]
    rows = {}
    for m in metrics:
        va, vb = a.get(m), b.get(m)
        if m in RATIO_METRICS:
            diff = round(vb - va, 4) if va is not None and vb is not None else None
            rows[m] = {"baseline": va, "period": vb, "change_points": diff}
        else:
            rows[m] = {"baseline": va, "period": vb, "change": change(va, vb)}
    moved: list[str] = []
    # Per-day rates so periods of different length compare fairly.
    ta, tb = a["total"] / days_a, b["total"] / days_b
    ca, cb = a["calls"] / days_a, b["calls"] / days_b
    if ta and tb and ca and cb and a["context_per_call"] and b["context_per_call"]:
        log_total = math.log(tb / ta)
        log_calls = math.log(cb / ca)
        log_size = log_total - log_calls
        head = (
            f"Tokens per day changed {fmt_pct(tb / ta - 1)}; calls per day changed {fmt_pct(cb / ca - 1)} and "
            f"tokens per call {fmt_pct((tb / cb) / (ta / ca) - 1)}"
        )
        if abs(log_total) > 1e-9 and log_calls * log_total >= 0 and log_size * log_total >= 0:
            calls_part = log_calls / log_total
            moved.append(
                f"{head}, so about {fmt_share(calls_part)} of the change is the number of calls and "
                f"{fmt_share(1 - calls_part)} the size of each call."
            )
        else:
            moved.append(f"{head}: the two moved in opposite directions.")
    ha, hb = a["cache_hit_ratio"], b["cache_hit_ratio"]
    if ha is not None and hb is not None and abs(hb - ha) >= 0.05:
        word = "fell" if hb < ha else "rose"
        moved.append(f"Cache-hit ratio {word} from {fmt_ratio(ha)} to {fmt_ratio(hb)}.")
    sa, sb = a["share_5m_of_writes"], b["share_5m_of_writes"]
    if sa is not None and sb is not None and sb - sa >= 0.2:
        moved.append(
            f"5-minute cache writes went from {fmt_ratio(sa)} to {fmt_ratio(sb)} of split writes: 1-hour writes "
            "turned into 5-minute writes, which expire sooner and are written again."
        )
    if a["first_call_median"] and b["first_call_median"]:
        fc = b["first_call_median"] / a["first_call_median"] - 1
        if abs(fc) >= 0.2:
            moved.append(
                f"Median first-call size changed {fmt_pct(fc)} "
                f"({a['first_call_median']:,} to {b['first_call_median']:,} tokens)."
            )
    if ta and tb and abs(tb / ta - 1) < 0.1:
        moved.append(
            "Token volume per day is within 10% of the baseline. If a plan meter moved much more than that, "
            "these transcripts do not explain it."
        )
    return {
        "baseline": {"from": base_range[0].isoformat(), "to": base_range[1].isoformat(), **a},
        "period": {"from": per_range[0].isoformat(), "to": per_range[1].isoformat(), **b},
        "metrics": rows,
        "moved": moved,
        "per_day_total_change": change(ta, tb),
    }


def fmt_pct(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x * 100:+.0f}%"


def fmt_share(x: float) -> str:
    return f"{max(0.0, min(1.0, x)) * 100:.0f}%"


def fmt_ratio(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def build(calls: list[Call], args, stats: tx.ReadStats, merged: int, rates) -> dict:
    overall = summarise(calls)
    firsts = first_calls(calls)
    first_sizes = sorted(((sid, c.context) for sid, c in firsts.items()), key=lambda x: -x[1])
    overall["sessions"] = len(firsts)
    overall["first_call_median"] = median([s for _, s in first_sizes])
    overall["first_call_max"] = first_sizes[0][1] if first_sizes else 0

    def rows(groups: dict[str, list[Call]], sort_total: bool) -> list[dict]:
        out = []
        for k, cs in groups.items():
            row = {"key": k, **summarise(cs)}
            if rates is not None:
                row["estimated_cost"], row["unpriced_calls"] = cost(cs, rates)
            out.append(row)
        return sorted(out, key=lambda r: -r["total"]) if sort_total else sorted(out, key=lambda r: r["key"])

    sessions = rows(group(calls, lambda c: c.session), True)
    for r in sessions:
        r["first_call"] = firsts[r["key"]].context
        r["project"] = firsts[r["key"]].project
    report = {
        "read": {**stats.to_dict(), "repeated_lines_merged": merged},
        "window": {"since": args.since, "until": args.until},
        "summary": overall,
        "days": rows(group(calls, day_of), False),
        "models": rows(group(calls, lambda c: c.model), True),
        "projects": rows(group(calls, lambda c: c.project), True),
        "sessions": sessions,
        "findings": [],
    }
    if rates is not None:
        report["summary"]["estimated_cost"], report["summary"]["unpriced_calls"] = cost(calls, rates)
    if args.compare:
        report["comparison"] = args.compare_fn(calls)
    report["findings"] = findings(report, args)
    return report


def findings(report: dict, args) -> list[dict]:
    out = []
    s = report["summary"]
    if args.expect_ttl == "1h" and s["share_5m_of_writes"] is not None and s["share_5m_of_writes"] > args.max_5m_share:
        days = [d["key"] for d in report["days"] if (d["share_5m_of_writes"] or 0) > args.max_5m_share]
        out.append(
            {
                "id": "cache-ttl-5m",
                "message": f"{fmt_ratio(s['share_5m_of_writes'])} of split cache writes used the 5-minute lifetime "
                f"while 1 hour was expected (threshold {fmt_ratio(args.max_5m_share)}). Days affected: "
                f"{', '.join(days[:10]) or 'none'}{' ...' if len(days) > 10 else ''}.",
            }
        )
    if s["cache_hit_ratio"] is not None and s["cache_hit_ratio"] < args.min_hit_ratio:
        low = [
            d["key"]
            for d in report["days"]
            if d["cache_hit_ratio"] is not None and d["cache_hit_ratio"] < args.min_hit_ratio
        ]
        out.append(
            {
                "id": "low-cache-hit",
                "message": f"cache-hit ratio {fmt_ratio(s['cache_hit_ratio'])} is below "
                f"{fmt_ratio(args.min_hit_ratio)}. "
                f"Days below: {len(low)} of {len(report['days'])}.",
            }
        )
    if s["first_call_median"] > args.max_first_call:
        above = sum(1 for r in report["sessions"] if r["first_call"] > args.max_first_call)
        out.append(
            {
                "id": "first-call-overhead",
                "message": f"median first-call size {s['first_call_median']:,} tokens is above "
                f"{args.max_first_call:,}; "
                f"{above} of {len(report['sessions'])} sessions start above it (largest {s['first_call_max']:,}).",
            }
        )
    comp = report.get("comparison")
    if comp and comp["per_day_total_change"] is not None and comp["per_day_total_change"] > args.max_jump:
        out.append(
            {
                "id": "period-jump",
                "message": f"tokens per day rose {fmt_pct(comp['per_day_total_change'])} from the baseline "
                f"(threshold {fmt_pct(args.max_jump)}). See 'What moved'.",
            }
        )
    return out


def n(x: int) -> str:
    return f"{x:,}"


def n_or_na(x: int | None) -> str:
    return "n/a" if x is None else n(x)


def render(report: dict, fmt: str, top: int) -> str:
    h = (lambda t: f"## {t}") if fmt == "markdown" else (lambda t: f"{t}\n{'-' * len(t)}")
    s = report["summary"]
    lines = ["# Session usage ledger" if fmt == "markdown" else "Session usage ledger", ""]
    r = report["read"]
    lines.append(
        f"Read {r['files']} file(s), {r['lines']} line(s); {r['unreadable_lines']} unreadable, "
        f"{sum(r['unknown_types'].values())} of unknown types skipped; {r['repeated_lines_merged']} repeated "
        "assistant line(s) merged into their API call."
    )
    w = report["window"]
    if w["since"] or w["until"]:
        lines.append(f"Window (UTC dates): {w['since'] or 'start'} to {w['until'] or 'end'}.")
    lines += [
        "",
        f"- API calls: {n(s['calls'])} in {n(s['sessions'])} session(s); subagent calls {n(s['subagent_calls'])} "
        f"({fmt_ratio(s['subagent_share'])} of tokens)",
        f"- Input (uncached) {n(s['input'])}, output {n(s['output'])}, cache read {n(s['cache_read'])}, "
        f"cache write {n(s['cache_write'])} (5m {n(s['write_5m'])}, 1h {n(s['write_1h'])}, "
        f"unsplit {n(s['write_other'])})",
        f"- Cache-hit ratio {fmt_ratio(s['cache_hit_ratio'])}; 5-minute share of split writes "
        f"{fmt_ratio(s['share_5m_of_writes'])}",
        f"- First call per session: median {n(s['first_call_median'])} tokens, largest {n(s['first_call_max'])}",
    ]
    if "estimated_cost" in s:
        lines.append(
            f"- Estimated cost from your rates file: {s['estimated_cost']:.2f} "
            f"({s['unpriced_calls']} call(s) with no rate)"
        )
    lines.append("")

    head = ["Calls", "Input", "Output", "Cache read", "Write 5m", "Write 1h", "Hit ratio"]

    def cells(row: dict) -> list[str]:
        return [
            n(row["calls"]),
            n(row["input"]),
            n(row["output"]),
            n(row["cache_read"]),
            n(row["write_5m"]),
            n(row["write_1h"]),
            fmt_ratio(row["cache_hit_ratio"]),
        ]

    lines += [h("Per day (UTC)"), ""]
    lines += tx.table(["Day", *head], [[d["key"], *cells(d)] for d in report["days"]], fmt)
    lines += ["", h("Per model"), ""]
    lines += tx.table(
        ["Model", *head],
        [[f"`{m['key']}`" if fmt == "markdown" else m["key"], *cells(m)] for m in report["models"]],
        fmt,
    )
    lines += ["", h("Per project"), ""]
    lines += tx.table(["Project", *head], [[p["key"], *cells(p)] for p in report["projects"][:top]], fmt)
    if len(report["projects"]) > top:
        lines.append(f"({len(report['projects']) - top} more in --json)")
    lines += ["", h(f"Largest sessions (top {min(top, len(report['sessions']))})"), ""]
    lines += tx.table(
        ["Session", "First call", *head],
        [[r["key"][:8], n(r["first_call"]), *cells(r)] for r in report["sessions"][:top]],
        fmt,
    )
    comp = report.get("comparison")
    if comp:
        a, b = comp["baseline"], comp["period"]
        lines += ["", h(f"Comparison: {a['from']}..{a['to']} against {b['from']}..{b['to']}"), ""]
        rows = []
        for m, v in comp["metrics"].items():
            if m in RATIO_METRICS:
                pts = v["change_points"]
                delta = "n/a" if pts is None else f"{pts * 100:+.1f} points"
                rows.append([m.replace("_", " "), fmt_ratio(v["baseline"]), fmt_ratio(v["period"]), delta])
            else:
                rows.append([m.replace("_", " "), n_or_na(v["baseline"]), n_or_na(v["period"]), fmt_pct(v["change"])])
        lines += tx.table(["Metric", "Baseline", "Period", "Change"], rows, fmt)
        lines += ["", h("What moved"), ""]
        lines += [f"- {m}" for m in comp["moved"]] or ["- Nothing moved by more than the reporting thresholds."]
    lines += ["", h("Findings"), ""]
    lines += [f"- {f['id']}: {f['message']}" for f in report["findings"]] or ["- None."]
    lines += [
        "",
        "Transcripts record what each API response reported. Plan quotas, weekly percentages and what a usage "
        "meter counted are not in them.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Add up the API usage in Claude Code session transcripts per day, session, model and project, "
        "with cache-hit ratio, 5-minute and 1-hour cache writes, first-call size and subagent share, and compare two "
        "periods to see which component moved.",
        epilog="Exit codes: 0 nothing flagged, 1 at least one finding, 2 bad input or nothing usable read.",
    )
    ap.add_argument("paths", nargs="*", help="transcript files or folders (folders are searched for *.jsonl)")
    ap.add_argument("--since", help="first UTC date to include, YYYY-MM-DD")
    ap.add_argument("--until", help="last UTC date to include, YYYY-MM-DD")
    ap.add_argument("--compare-weeks", action="store_true", help="compare the last 7 days with the 7 before them")
    ap.add_argument("--baseline", help="baseline range YYYY-MM-DD..YYYY-MM-DD (with --period)")
    ap.add_argument("--period", help="period to compare with the baseline, YYYY-MM-DD..YYYY-MM-DD")
    ap.add_argument("--expect-ttl", choices=("5m", "1h"), help="the cache lifetime you expect; 1h flags 5m writes")
    ap.add_argument("--max-5m-share", type=float, default=0.5, help="with --expect-ttl 1h: flag above this (0.5)")
    ap.add_argument("--min-hit-ratio", type=float, default=0.8, help="flag a cache-hit ratio below this (0.8)")
    ap.add_argument("--max-first-call", type=int, default=50000, help="flag a median first call above (50000)")
    ap.add_argument("--max-jump", type=float, default=0.5, help="flag a per-day token rise above this (0.5)")
    ap.add_argument("--rates", help='JSON {"model prefix": {"input": per-million, ...}} to estimate cost')
    ap.add_argument("--top", type=int, default=10, help="rows in the project and session tables (10)")
    ap.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--out", help="write the report to this file")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if exc.code in (0, None) else 2
    fmt = "json" if args.json else args.format
    try:
        if not args.paths:
            raise tx.InputError("give at least one transcript file or folder, for example ~/.claude/projects")
        since = tx.parse_day(args.since, "--since") if args.since else None
        until = tx.parse_day(args.until, "--until") if args.until else None
        if bool(args.baseline) != bool(args.period):
            raise tx.InputError("--baseline and --period go together")
        if args.compare_weeks and args.baseline:
            raise tx.InputError("use --compare-weeks or --baseline/--period, not both")
        if not (0 <= args.max_5m_share <= 1 and 0 <= args.min_hit_ratio <= 1) or args.top < 1:
            raise tx.InputError("--max-5m-share and --min-hit-ratio take a fraction from 0 to 1; --top at least 1")
        ranges = (
            (tx.parse_range(args.baseline, "--baseline"), tx.parse_range(args.period, "--period"))
            if args.baseline
            else None
        )
        rates = load_rates(args.rates) if args.rates else None
        stats = tx.ReadStats()
        records = tx.read_records(tx.collect_files(args.paths), stats)
        all_calls, merged = load_calls(records)
        if not all_calls:
            raise tx.InputError(f"no API usage found in the transcripts. {stats.note()}")
        calls = [c for c in all_calls if tx.in_window(c.ts, since, until)]
        if not calls:
            raise tx.InputError("no API calls inside --since/--until")
        args.compare = bool(args.compare_weeks or ranges)

        def compare_fn(cs: list[Call]) -> dict:
            if ranges:
                (a0, a1), (b0, b1) = ranges
            else:
                last = max(c.ts for c in cs if c.ts).date()
                b0, b1 = last - timedelta(days=6), last
                a0, a1 = last - timedelta(days=13), last - timedelta(days=7)
            base = [c for c in cs if tx.in_window(c.ts, a0, a1)]
            per = [c for c in cs if tx.in_window(c.ts, b0, b1)]
            if not base or not per:
                raise tx.InputError(f"no API calls in the baseline {a0}..{a1} or the period {b0}..{b1}")
            return compare(base, per, (a0, a1), (b0, b1))

        args.compare_fn = compare_fn
        report = build(calls, args, stats, merged, rates)
        text = json.dumps(report, indent=2, default=str) + "\n" if fmt == "json" else render(report, fmt, args.top)
        tx.write_output(text, args.out)
    except tx.InputError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
