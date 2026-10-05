#!/usr/bin/env python3
"""Profile a CSV or TSV file: per-column type, nulls, distinct values, ranges, and data-quality warnings.

For each column: inferred type (integer, number, boolean, date, datetime, string, empty), null count (empty,
NULL, null, NA, N/A, None, -), distinct count, min and max (numeric or lexical), mean for numbers, mean length
for strings, the most common values, and whether the column is unique (a candidate key). File-level: delimiter
(sniffed unless --delimiter is given), header, row count, blank rows, ragged rows (wrong field count), duplicate
rows, and columns that are entirely empty or constant.

Usage:
    csv_profiler.py FILE [--json] [--delimiter ,] [--no-header] [--sample N] [--encoding utf-8] [--top N]

Exit codes: 0 profiled, 1 data-quality warnings found with --strict, 2 unreadable input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"
NULLS = {"", "null", "NULL", "Null", "NA", "N/A", "n/a", "None", "none", "-", "NaN", "nan", "#N/A"}
BOOLS = {"true", "false", "yes", "no", "t", "f", "y", "n", "0", "1"}
INT_RE = re.compile(r"^[-+]?\d{1,3}(,\d{3})+$|^[-+]?\d+$")
NUM_RE = re.compile(r"^[-+]?(\d{1,3}(,\d{3})+|\d+)?(\.\d+)?([eE][-+]?\d+)?$")
DATE_FORMATS = ["%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d", "%d-%m-%Y", "%d.%m.%Y", "%Y%m%d", "%b %d %Y", "%d %b %Y"]
DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")


def classify(value: str) -> str:
    v = value.strip()
    if v in NULLS:
        return "null"
    if INT_RE.match(v):
        return "integer"
    if NUM_RE.match(v) and any(ch.isdigit() for ch in v):
        return "number"
    if v.lower() in BOOLS:
        return "boolean"
    if DATETIME_RE.match(v):
        return "datetime"
    if len(v) <= 12:
        for fmt in DATE_FORMATS:
            try:
                dt.datetime.strptime(v, fmt)
                return "date"
            except ValueError:
                continue
    return "string"


def to_number(v: str) -> float:
    return float(v.strip().replace(",", ""))


def profile_column(name: str, values: list[str], top: int) -> dict:
    kinds = Counter(classify(v) for v in values)
    non_null = [v.strip() for v in values if v.strip() not in NULLS]
    nulls = len(values) - len(non_null)
    present = {k: c for k, c in kinds.items() if k != "null"}
    if not present:
        ctype = "empty"
    elif set(present) <= {"integer"}:
        ctype = "integer"
    elif set(present) <= {"integer", "number"}:
        ctype = "number"
    elif set(present) <= {"boolean"} or (set(present) <= {"boolean", "integer"} and all(v in {"0", "1"} for v in non_null)):
        ctype = "boolean"
    elif set(present) <= {"date"}:
        ctype = "date"
    elif set(present) <= {"date", "datetime"}:
        ctype = "datetime"
    else:
        ctype = "string"
    distinct = Counter(non_null)
    col = {"name": name, "type": ctype, "count": len(values), "nulls": nulls, "null_percent": round(100.0 * nulls / len(values), 1) if values else 0.0,
           "distinct": len(distinct), "unique": bool(non_null) and len(distinct) == len(non_null), "mixed_types": sorted(present) if len(present) > 1 and ctype == "string" else [],
           "top_values": [{"value": v[:60], "count": c} for v, c in distinct.most_common(top)]}
    if ctype in {"integer", "number"}:
        nums = [to_number(v) for v in non_null]
        col.update({"min": min(nums), "max": max(nums), "mean": round(statistics.fmean(nums), 4),
                    "median": statistics.median(nums), "stdev": round(statistics.pstdev(nums), 4) if len(nums) > 1 else 0.0,
                    "zeros": sum(1 for n in nums if n == 0), "negatives": sum(1 for n in nums if n < 0)})
    elif non_null:
        lengths = [len(v) for v in non_null]
        col.update({"min": min(non_null), "max": max(non_null), "min_length": min(lengths), "max_length": max(lengths), "mean_length": round(statistics.fmean(lengths), 1),
                    "leading_or_trailing_space": sum(1 for v in values if v != v.strip() and v.strip() not in NULLS)})
    return col


def profile(path: Path, delimiter: str | None, has_header: bool, sample: int | None, encoding: str, top: int) -> dict:
    text = path.read_text(encoding=encoding, errors="replace")
    if not text.strip():
        raise ValueError("file is empty")
    if delimiter is None:
        try:
            dialect = csv.Sniffer().sniff(text[:65536], delimiters=",;\t|")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = "\t" if text.count("\t") > text.count(",") else ","
    rows = list(csv.reader(text.splitlines(), delimiter=delimiter))
    blank = sum(1 for r in rows if not any(c.strip() for c in r))
    rows = [r for r in rows if any(c.strip() for c in r)]
    if not rows:
        raise ValueError("no data rows")
    if has_header:
        header, data = rows[0], rows[1:]
    else:
        header, data = [f"col{i + 1}" for i in range(len(rows[0]))], rows
    width = len(header)
    ragged = [i + (2 if has_header else 1) for i, r in enumerate(data) if len(r) != width]
    if sample:
        data = data[:sample]
    dup_rows = sum(c - 1 for c in Counter(tuple(r) for r in data).values() if c > 1)
    columns = []
    for i, name in enumerate(header):
        values = [r[i] if i < len(r) else "" for r in data]
        columns.append(profile_column(name or f"col{i + 1}", values, top))
    warnings: list[str] = []
    if ragged:
        warnings.append(f"{len(ragged)} rows have a field count different from the header (first at line {ragged[0]})")
    if dup_rows:
        warnings.append(f"{dup_rows} duplicate rows")
    if blank:
        warnings.append(f"{blank} blank rows skipped")
    dup_headers = [h for h, c in Counter(header).items() if c > 1]
    if dup_headers:
        warnings.append("duplicate header names: " + ", ".join(dup_headers))
    for c in columns:
        if c["type"] == "empty":
            warnings.append(f"column {c['name']} is entirely empty")
        elif c["distinct"] == 1 and c["nulls"] == 0 and c["count"] > 1:
            warnings.append(f"column {c['name']} is constant ({c['top_values'][0]['value']})")
        if c["mixed_types"]:
            warnings.append(f"column {c['name']} mixes types: {', '.join(c['mixed_types'])}")
        if c.get("leading_or_trailing_space"):
            warnings.append(f"column {c['name']} has {c['leading_or_trailing_space']} values with leading or trailing whitespace")
        if 0 < c["null_percent"] and c["null_percent"] >= 50:
            warnings.append(f"column {c['name']} is {c['null_percent']}% null")
    return {"version": VERSION, "file": str(path), "delimiter": delimiter, "header": has_header, "rows": len(data), "columns_count": width,
            "ragged_rows": ragged[:20], "duplicate_rows": dup_rows, "blank_rows": blank, "candidate_keys": [c["name"] for c in columns if c["unique"]],
            "columns": columns, "warnings": warnings}


def render_text(p: dict) -> str:
    d = {"\t": "TAB"}.get(p["delimiter"], p["delimiter"])
    lines = [f"csv-profiler {p['version']}: {p['file']}: {p['rows']} rows x {p['columns_count']} columns, delimiter '{d}', header={'yes' if p['header'] else 'no'}"]
    if p["candidate_keys"]:
        lines.append("candidate keys (unique, non-null): " + ", ".join(p["candidate_keys"]))
    lines.append(f"{'column':<24} {'type':<9} {'nulls':>6} {'distinct':>8}  range / stats")
    for c in p["columns"]:
        if c["type"] in {"integer", "number"}:
            extra = f"min={c['min']} max={c['max']} mean={c['mean']} median={c['median']}"
        elif c["type"] == "empty":
            extra = ""
        else:
            extra = f"len {c['min_length']}-{c['max_length']}; top: " + ", ".join(f"{t['value']!r} x{t['count']}" for t in c["top_values"][:3])
        lines.append(f"{c['name'][:24]:<24} {c['type']:<9} {c['nulls']:>6} {c['distinct']:>8}  {extra}")
    if p["warnings"]:
        lines.append("warnings:")
        lines += [f"  - {w}" for w in p["warnings"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--delimiter", help="field delimiter (sniffed when omitted; use 'tab' for TSV)")
    ap.add_argument("--no-header", action="store_true")
    ap.add_argument("--sample", type=int, help="profile only the first N data rows")
    ap.add_argument("--encoding", default="utf-8")
    ap.add_argument("--top", type=int, default=5, help="most common values to keep per column")
    ap.add_argument("--strict", action="store_true", help="exit 1 when any warning is produced")
    args = ap.parse_args(argv)
    p = Path(args.file)
    if not p.is_file():
        print(f"error: not a file: {p}", file=sys.stderr)
        return 2
    delim = {"tab": "\t", "\\t": "\t"}.get(args.delimiter, args.delimiter) if args.delimiter else None
    try:
        rep = profile(p, delim, not args.no_header, args.sample, args.encoding, args.top)
    except (ValueError, LookupError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2, default=str) if args.json else render_text(rep))
    return 1 if (args.strict and rep["warnings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
