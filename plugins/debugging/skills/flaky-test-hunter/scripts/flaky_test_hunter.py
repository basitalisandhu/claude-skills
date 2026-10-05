#!/usr/bin/env python3
"""Find flaky tests by comparing outcomes across several JUnit XML reports.

Give it the reports from several runs of the same suite (one file per run, or directories of them). A test is
flaky when it both passed and failed across the runs. The report lists every flaky test with its pass and fail
counts, the runs it failed in, the most common failure message, and the durations, plus tests that failed in
every run (consistently broken, not flaky) and tests that appear in only some runs (new, deleted or skipped).

Reads the JUnit XML dialects produced by pytest, Jest (jest-junit), Maven Surefire, Gradle, Go (go-junit-report),
and .NET; the common elements are <testsuite>, <testcase classname= name= time=> and <failure>, <error>, <skipped>.
Pytest's rerunfailures plugin writes a <rerun> element; a test with a rerun counts as flaky even within one run.

Usage:
    flaky_test_hunter.py PATH [PATH ...] [--json] [--min-runs N] [--fail-on-flaky]

Exit codes: 0 no flaky tests (or --fail-on-flaky not given), 1 flaky tests found with --fail-on-flaky, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "0.1.0"


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += sorted(x for x in p.rglob("*.xml") if x.is_file())
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(raw)
    return files


def parse_report(path: Path) -> list[dict]:
    """Return one record per testcase: {id, status, message, time, reruns}."""
    tree = ET.parse(path)
    root = tree.getroot()
    cases: list[dict] = []
    for tc in root.iter("testcase"):
        classname = tc.get("classname") or ""
        name = tc.get("name") or ""
        file_attr = tc.get("file") or ""
        test_id = f"{classname}::{name}" if classname else (f"{file_attr}::{name}" if file_attr else name)
        status = "passed"
        message = None
        reruns = 0
        for child in tc:
            tag = child.tag.split("}")[-1]
            if tag in ("failure", "error"):
                status = "failed"
                message = (child.get("message") or (child.text or "").strip().splitlines()[0:1] or [""])[0] if child.get("message") is None else child.get("message")
            elif tag == "skipped":
                status = "skipped"
                message = child.get("message")
            elif tag in ("rerunFailure", "rerunError", "flakyFailure", "flakyError", "rerun"):
                reruns += 1
        try:
            t = float(tc.get("time") or 0.0)
        except ValueError:
            t = 0.0
        cases.append({"id": test_id, "status": status, "message": (message or "").strip()[:200], "time": t, "reruns": reruns})
    return cases


def analyse(files: list[Path], min_runs: int) -> dict:
    runs: list[dict] = []
    outcomes: dict[str, list[tuple[int, str, str, float, int]]] = defaultdict(list)
    for i, f in enumerate(files):
        try:
            cases = parse_report(f)
        except ET.ParseError as exc:
            runs.append({"file": str(f), "error": str(exc), "tests": 0})
            continue
        runs.append({"file": str(f), "tests": len(cases), "failed": sum(c["status"] == "failed" for c in cases),
                     "skipped": sum(c["status"] == "skipped" for c in cases)})
        for c in cases:
            outcomes[c["id"]].append((i, c["status"], c["message"], c["time"], c["reruns"]))
    valid_runs = [r for r in runs if "error" not in r]
    flaky: list[dict] = []
    always_failing: list[dict] = []
    partial: list[dict] = []
    for test_id, recs in sorted(outcomes.items()):
        statuses = [s for _, s, _, _, _ in recs if s != "skipped"]
        passed = statuses.count("passed")
        failed = statuses.count("failed")
        reruns = sum(r for _, _, _, _, r in recs)
        times = [t for _, _, _, t, _ in recs]
        messages = Counter(m for _, s, m, _, _ in recs if s == "failed" and m)
        rec = {"id": test_id, "runs_seen": len(recs), "passed": passed, "failed": failed, "reruns": reruns,
               "failed_in": [files[i].name for i, s, _, _, _ in recs if s == "failed"],
               "top_message": messages.most_common(1)[0][0] if messages else "",
               "distinct_messages": len(messages),
               "time_min": round(min(times), 3) if times else 0.0, "time_max": round(max(times), 3) if times else 0.0}
        if (passed and failed) or (reruns and passed):
            rec["flake_rate"] = round(failed / max(1, passed + failed), 3)
            flaky.append(rec)
        elif failed and not passed and len(statuses) >= min_runs:
            always_failing.append(rec)
        if 0 < len(recs) < len(valid_runs):
            partial.append({"id": test_id, "runs_seen": len(recs), "runs_total": len(valid_runs)})
    flaky.sort(key=lambda r: (-r["failed"], r["id"]))
    return {"version": VERSION, "runs": runs, "tests": len(outcomes), "flaky": flaky, "always_failing": always_failing,
            "partial_presence": partial, "min_runs": min_runs}


def render_text(rep: dict) -> str:
    lines = [f"flaky-test-hunter {rep['version']}: {len(rep['runs'])} runs, {rep['tests']} distinct tests, {len(rep['flaky'])} flaky, {len(rep['always_failing'])} always failing"]
    for r in rep["runs"]:
        lines.append(f"  run {r['file']}: " + (f"parse error: {r['error']}" if "error" in r else f"{r['tests']} tests, {r['failed']} failed, {r['skipped']} skipped"))
    if rep["flaky"]:
        lines.append("flaky (passed and failed across runs):")
        for t in rep["flaky"]:
            lines.append(f"  {t['id']}  pass={t['passed']} fail={t['failed']} rate={t['flake_rate']} reruns={t['reruns']} time={t['time_min']}-{t['time_max']}s")
            if t["top_message"]:
                lines.append(f"      {t['top_message'][:120]}")
    if rep["always_failing"]:
        lines.append("always failing (not flaky, broken):")
        for t in rep["always_failing"]:
            lines.append(f"  {t['id']}  fail={t['failed']}  {t['top_message'][:100]}")
    if rep["partial_presence"]:
        lines.append(f"present in only some runs: {len(rep['partial_presence'])} tests (collection differences, new or removed tests)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="JUnit XML files or directories containing them")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min-runs", type=int, default=2, help="runs a test must appear in before it is called always-failing")
    ap.add_argument("--fail-on-flaky", action="store_true")
    args = ap.parse_args(argv)
    try:
        files = collect_files(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("error: no XML files found", file=sys.stderr)
        return 2
    rep = analyse(files, args.min_runs)
    print(json.dumps(rep, indent=2) if args.json else render_text(rep))
    return 1 if (args.fail_on_flaky and rep["flaky"]) else 0


if __name__ == "__main__":
    sys.exit(main())
