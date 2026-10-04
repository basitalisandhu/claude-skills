#!/usr/bin/env python3
"""Parse a crontab, explain each schedule in plain words, compute the next runs, and flag common mistakes.

Accepts user crontabs (5 fields + command), system crontabs with a user field (--system or auto-detected when
the sixth field looks like a user name), @reboot/@hourly/@daily/@weekly/@monthly/@yearly macros, environment
assignments (MAILTO=, PATH=, SHELL=) and comments.

Checks (id, severity):
  CRON-001 error   invalid field (wrong count, out-of-range value, bad step or name)
  CRON-002 warn    job runs every minute
  CRON-003 warn    no output redirection (cron mails or drops stdout and stderr)
  CRON-004 error   unescaped % in the command (cron turns it into a newline and feeds the rest to stdin)
  CRON-005 info    command is a relative path and no PATH= line is set (cron's default PATH is /usr/bin:/bin)
  CRON-006 warn    both day-of-month and day-of-week restricted (cron runs when EITHER matches)
  CRON-007 info    no MAILTO line (errors go to the local mailbox nobody reads)
  CRON-008 warn    duplicate schedule and command
  CRON-009 info    several jobs start in the same minute
  CRON-010 error   file does not end with a newline (cron ignores the last line)
  CRON-011 warn    job scheduled between 01:00 and 03:59 on a daily schedule (DST transitions can skip or repeat it)
  CRON-012 warn    job without a lock (flock, run-one, systemd) that runs more often than hourly and may overlap

Usage:
    cron_doctor.py [FILE] [--json] [--system] [--now ISO8601] [--next N]      (stdin when no file)

Exit codes: 0 no errors, 1 at least one CRON error, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import calendar
import datetime as dt
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
MACROS = {"@reboot": None, "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
          "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}
MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_abbr) if m}
DAYS = {d.lower(): i for i, d in enumerate(calendar.day_abbr)}  # mon=0 ... sun=6 (calendar); cron uses sun=0
CRON_DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
FIELD_SPECS = [("minute", 0, 59, {}), ("hour", 0, 23, {}), ("day-of-month", 1, 31, {}), ("month", 1, 12, MONTHS), ("day-of-week", 0, 7, CRON_DAYS)]
ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
LOCK_RE = re.compile(r"\b(flock|run-one|lockfile|lockrun|setlock|systemd-run|chronic)\b")


class CronError(ValueError):
    pass


def parse_field(spec: str, name: str, lo: int, hi: int, names: dict[str, int]) -> set[int]:
    values: set[int] = set()
    for part in spec.split(","):
        if not part:
            raise CronError(f"{name}: empty list item in {spec!r}")
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            if not step_s.isdigit() or int(step_s) == 0:
                raise CronError(f"{name}: bad step {step_s!r}")
            step = int(step_s)
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = to_int(a, name, names), to_int(b, name, names)
            if start > end:
                raise CronError(f"{name}: range {part!r} runs backwards")
        else:
            start = to_int(part, name, names)
            end = hi if "/" in spec and step > 1 and part != spec else start
        if start < lo or end > hi:
            raise CronError(f"{name}: {part!r} outside {lo}-{hi}")
        values.update(range(start, end + 1, step))
    if name == "day-of-week" and 7 in values:
        values.discard(7)
        values.add(0)
    return values


def to_int(token: str, name: str, names: dict[str, int]) -> int:
    t = token.strip().lower()
    if t in names:
        return names[t]
    if t.isdigit():
        return int(t)
    raise CronError(f"{name}: {token!r} is not a number or a known name")


def describe(fields: list[set[int]], raw: list[str]) -> str:
    minute, hour, dom, month, dow = fields
    rm, rh, rdom, rmon, rdow = raw
    def every(spec: str, unit: str, values: set[int], lo: int) -> str | None:
        m = re.match(r"^\*/(\d+)$", spec)
        if m:
            return f"every {m.group(1)} {unit}s" if m.group(1) != "1" else f"every {unit}"
        return None
    parts: list[str] = []
    if rm == "*" and rh == "*":
        parts.append("every minute")
    elif rh == "*" and len(minute) == 1:
        parts.append(f"at minute {next(iter(minute))} of every hour")
    elif every(rm, "minute", minute, 0) and rh == "*":
        parts.append(every(rm, "minute", minute, 0))
    elif every(rh, "hour", hour, 0) and len(minute) == 1:
        parts.append(f"{every(rh, 'hour', hour, 0)} at minute {next(iter(minute))}")
    elif len(minute) == 1 and len(hour) == 1:
        parts.append(f"at {next(iter(hour)):02d}:{next(iter(minute)):02d}")
    elif len(hour) == 1 and every(rm, "minute", minute, 0):
        parts.append(f"{every(rm, 'minute', minute, 0)} during hour {next(iter(hour)):02d}")
    else:
        parts.append(f"at minutes {rm} of hours {rh}")
    inv_days = {v: k for k, v in CRON_DAYS.items()}
    if rdom != "*" and rdow != "*":
        parts.append(f"on day-of-month {rdom} OR on {', '.join(inv_days[d] for d in sorted(dow))}")
    elif rdow != "*":
        parts.append("on " + ", ".join(inv_days[d] for d in sorted(dow)))
    elif rdom != "*":
        parts.append(f"on day {rdom} of the month")
    else:
        parts.append("every day")
    if rmon != "*":
        parts.append("in " + ", ".join(calendar.month_abbr[m] for m in sorted(month)))
    return " ".join(parts)


def next_runs(fields: list[set[int]], raw: list[str], now: dt.datetime, count: int) -> list[str]:
    minute, hour, dom, month, dow = fields
    dom_star, dow_star = raw[2] == "*", raw[4] == "*"
    out: list[str] = []
    t = (now.replace(second=0, microsecond=0) + dt.timedelta(minutes=1))
    day = t.date()
    limit = day + dt.timedelta(days=366 * 2)
    first_day = True
    while day < limit and len(out) < count:
        if day.month in month:
            cron_dow = (day.weekday() + 1) % 7
            day_ok = (day.day in dom) if dow_star else (cron_dow in dow) if dom_star else (day.day in dom or cron_dow in dow)
            if day_ok:
                for h in sorted(hour):
                    for m in sorted(minute):
                        cand = dt.datetime.combine(day, dt.time(h, m), tzinfo=now.tzinfo)
                        if first_day and cand < t:
                            continue
                        out.append(cand.isoformat(timespec="minutes"))
                        if len(out) >= count:
                            return out
        first_day = False
        day += dt.timedelta(days=1)
    return out


def parse_crontab(text: str, system: bool | None, now: dt.datetime, next_count: int) -> dict:
    jobs: list[dict] = []
    env: dict[str, str] = {}
    findings: list[dict] = []

    def add(fid, sev, line, title, fix):
        findings.append({"id": fid, "severity": sev, "line": line, "title": title, "fix": fix})

    if text and not text.endswith("\n"):
        add("CRON-010", "error", text.count("\n") + 1, "File does not end with a newline; cron ignores the last line", "Add a trailing newline.")
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ENV_LINE_RE.match(line)
        if m and not line.startswith("@") and not line[0].isdigit() and not line.startswith("*"):
            env[m.group(1)] = m.group(2).strip().strip("\"'")
            continue
        job = {"line": no, "raw": line, "schedule": None, "user": None, "command": "", "valid": True, "description": "", "next": []}
        if line.startswith("@"):
            macro, _, rest = line.partition(" ")
            if macro not in MACROS:
                add("CRON-001", "error", no, f"Unknown macro {macro}", "Use @reboot, @hourly, @daily, @weekly, @monthly or @yearly.")
                job["valid"] = False
                jobs.append(job)
                continue
            spec = MACROS[macro]
            tokens = rest.split(None, 1)
            if system is None:
                system_here = len(tokens) == 2 and USER_RE.match(tokens[0]) and not tokens[0].startswith("/") and "=" not in tokens[0]
            else:
                system_here = system
            if system_here and tokens:
                job["user"] = tokens[0]
                job["command"] = tokens[1] if len(tokens) > 1 else ""
            else:
                job["command"] = rest
            job["schedule"] = macro
            if spec is None:
                job["description"] = "at system boot"
                jobs.append(job)
                continue
            fields_raw = spec.split()
        else:
            tokens = line.split()
            if len(tokens) < 6:
                add("CRON-001", "error", no, f"Expected 5 time fields and a command, found {len(tokens)} tokens", "Format: minute hour day-of-month month day-of-week command")
                job["valid"] = False
                jobs.append(job)
                continue
            fields_raw = tokens[:5]
            rest_tokens = tokens[5:]
            if system is None:
                system_here = len(rest_tokens) >= 2 and USER_RE.match(rest_tokens[0]) is not None and "=" not in rest_tokens[0] and "/" not in rest_tokens[0]
            else:
                system_here = system
            if system_here:
                job["user"] = rest_tokens[0]
                job["command"] = line.split(None, 6)[6] if len(rest_tokens) > 1 else ""
            else:
                job["command"] = line.split(None, 5)[5]
            job["schedule"] = " ".join(fields_raw)
        try:
            fields = [parse_field(f, name, lo, hi, names) for f, (name, lo, hi, names) in zip(fields_raw, FIELD_SPECS)]
        except CronError as exc:
            add("CRON-001", "error", no, f"Invalid schedule: {exc}", "Fix the field; see `man 5 crontab`.")
            job["valid"] = False
            jobs.append(job)
            continue
        job["description"] = describe(fields, fields_raw)
        job["next"] = next_runs(fields, fields_raw, now, next_count)
        minute, hour, dom, month, dow = fields
        cmd = job["command"]
        if fields_raw[0] == "*" and fields_raw[1] == "*":
            add("CRON-002", "warn", no, "Runs every minute", "Confirm this is intended; a slow run will overlap the next one.")
        if not re.search(r"(>>?|\|)\s*\S", cmd) and "2>&1" not in cmd:
            add("CRON-003", "warn", no, "No output redirection", "Append >> /var/log/<job>.log 2>&1 (or | logger -t <job>) so output is kept and mail is not generated.")
        if re.search(r"(?<!\\)%", cmd):
            add("CRON-004", "error", no, "Unescaped % in command", "Escape it as \\% or move the command into a script; cron converts % to a newline.")
        first = cmd.split()[0] if cmd.split() else ""
        if first and not first.startswith(("/", "$", "~", ".")) and "PATH" not in env and first not in {"cd", "sh", "bash", "echo", "test", "[", "export"}:
            add("CRON-005", "info", no, f"Command {first!r} relies on PATH, which cron sets to /usr/bin:/bin", "Use an absolute path or add a PATH= line at the top of the crontab.")
        if fields_raw[2] != "*" and fields_raw[4] != "*":
            add("CRON-006", "warn", no, "Both day-of-month and day-of-week are restricted", "cron runs when either field matches, not both; use one of them or check the day inside the script.")
        if len(hour) == 1 and 1 <= next(iter(hour)) <= 3 and fields_raw[2] == "*" and fields_raw[3] == "*":
            add("CRON-011", "warn", no, "Daily job between 01:00 and 03:59", "DST changes can skip or repeat this hour; prefer 04:00 or later, or run cron in UTC.")
        if len(minute) * len(hour) > 24 and not LOCK_RE.search(cmd):
            add("CRON-012", "warn", no, "Frequent job without a lock", "Wrap it: flock -n /tmp/<job>.lock <command>, so runs cannot overlap.")
        jobs.append(job)
    if "MAILTO" not in env and any(j["valid"] for j in jobs):
        add("CRON-007", "info", 0, "No MAILTO line", "Set MAILTO=ops@example.com (or MAILTO=\"\" to disable mail) so failures reach someone.")
    seen: dict[tuple[str, str], int] = {}
    for j in jobs:
        key = (j["schedule"] or "", j["command"])
        if j["valid"] and key in seen:
            add("CRON-008", "warn", j["line"], f"Duplicate of line {seen[key]}", "Remove one of them.")
        seen.setdefault(key, j["line"])
    by_minute: dict[str, list[int]] = {}
    for j in jobs:
        if j["valid"] and j["schedule"] and not j["schedule"].startswith("@"):
            f = j["schedule"].split()
            if "*" not in (f[0], f[1]) and "/" not in f[0] and "," not in f[0] and "-" not in f[0]:
                by_minute.setdefault(f"{f[1]}:{f[0]}", []).append(j["line"])
    for when, lines in by_minute.items():
        if len(lines) > 1:
            add("CRON-009", "info", lines[0], f"{len(lines)} jobs start at the same time ({when}): lines {', '.join(map(str, lines))}", "Stagger them by a few minutes to spread load.")
    sev_order = {"error": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: (sev_order[f["severity"]], f["line"]))
    return {"version": VERSION, "env": {k: ("<set>" if k in {"MAILTO", "PATH", "SHELL", "HOME"} and False else v) for k, v in env.items()}, "jobs": jobs, "findings": findings,
            "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in ("error", "warn", "info")}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="crontab file (stdin when omitted; `crontab -l | cron_doctor.py`)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--system", action="store_true", help="lines have a user field after the schedule (/etc/crontab, /etc/cron.d)")
    ap.add_argument("--now", help="ISO 8601 time used for the next-run computation (default: now, local time)")
    ap.add_argument("--next", type=int, default=3, help="how many next runs to compute per job")
    args = ap.parse_args(argv)
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"error: not a file: {args.file}", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()
    try:
        now = dt.datetime.fromisoformat(args.now) if args.now else dt.datetime.now()
    except ValueError:
        print("error: --now must be ISO 8601, for example 2026-03-01T12:00", file=sys.stderr)
        return 2
    rep = parse_crontab(text, True if args.system else None, now, args.next)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        c = rep["counts"]
        print(f"cron-doctor {VERSION}: {len(rep['jobs'])} jobs, {c['error']} errors, {c['warn']} warnings, {c['info']} notes")
        for j in rep["jobs"]:
            status = "ok " if j["valid"] else "BAD"
            print(f"  line {j['line']:>3} [{status}] {j['schedule'] or '?':<16} {j['description']}")
            print(f"            {j['command'][:100]}")
            if j["next"]:
                print(f"            next: {', '.join(j['next'])}")
        for f in rep["findings"]:
            print(f"  [{f['severity']:<5}] {f['id']} line {f['line']}: {f['title']}\n          fix: {f['fix']}")
    return 1 if rep["counts"]["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
