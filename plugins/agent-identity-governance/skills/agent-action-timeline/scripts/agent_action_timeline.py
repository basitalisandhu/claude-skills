#!/usr/bin/env python3
"""Build one ordered timeline of what an agent identity did, from saved audit exports, and flag unusual actions.

usage: agent_action_timeline.py --identity VALUE [--identity VALUE ...] [--entra-signins FILE] [--entra-audit FILE]
                                [--cloudtrail FILE] [--github-audit FILE] [--app-log FILE] [--since T] [--until T]
                                [--allow-list FILE] [--baseline FILE] [--burst-count N] [--burst-window SECONDS]
                                [--json] [--out FILE]

Every input option can be repeated. Formats:
  --entra-signins  Graph /auditLogs/signIns (service principal sign-ins): createdDateTime, appId, servicePrincipalId
  --entra-audit    Graph /auditLogs/directoryAudits: activityDateTime, activityDisplayName, initiatedBy.app or .user
  --cloudtrail     aws cloudtrail lookup-events output ({"Events": [...]} with CloudTrailEvent) or log files
                   ({"Records": [...]})
  --github-audit   gh api /orgs/ORG/audit-log output: @timestamp (epoch milliseconds), action, actor
  --app-log        JSON lines; the time is read from timestamp, time, ts, @timestamp or datetime, the action from
                   action, event, tool, operation or name, the identity from agent, agent_id, identity, actor,
                   principal, client_id or user

An event belongs to the identity when any identity field equals one of the --identity values (ignoring case): appId,
service principal id or name, user principal name, IAM ARN, principal id, access key id, user or role name,
session issuer, GitHub actor or app log identity. Give every value the agent is known by.

Action names: signin:<resource>, entra:<activity>, <aws service>:<eventName> (for example s3:GetObject),
github:<action>, app:<action>. Timestamps are normalised to UTC and events ordered by time, then source and action.

Flags:
  burst                at least --burst-count events (20) within --burst-window seconds (60)
  first-seen           with --baseline (a file of known action names, one per line): an action not in it; without
                       a baseline, the first occurrence of each action in this window is marked first-in-window
  outside-allow-list   with --allow-list (one fnmatch pattern per line, # for comments): an action no pattern allows
  failed               the source recorded an error or failure (informational)

Access key ids are shown as their last four characters.

Exit codes: 0 nothing flagged, 1 a burst, an action outside the allow list, or (with --baseline) a first-seen
action, 2 bad input.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

TIME_KEYS = ("timestamp", "time", "ts", "@timestamp", "datetime")
ACTION_KEYS = ("action", "event", "tool", "operation", "name")
ID_KEYS = ("agent", "agent_id", "identity", "actor", "principal", "client_id", "user")


class InputError(Exception):
    """Bad input: exit code 2."""


# ---- shared event readers ----------------------------------------------------------------------------------------


def parse_dt(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000 if value > 10**11 else value, tz=timezone.utc)
    text = str(value).strip()
    if re.fullmatch(r"\d{10,13}", text):
        return parse_dt(int(text))
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00").replace("z", "+00:00"))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def mask(value) -> str:
    text = str(value or "").strip()
    return "****" + text[-4:] if text else ""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def rows_of(data, *keys: str) -> list[dict]:
    names = ("value", *keys)
    if isinstance(data, dict):
        for k in names:
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
        return []
    out: list[dict] = []
    for x in data if isinstance(data, list) else []:
        if isinstance(x, list):  # gh api --paginate --slurp gives a list of pages
            out += rows_of(x, *keys)
        elif isinstance(x, dict) and any(isinstance(x.get(k), list) for k in names):
            out += rows_of(x, *keys)
        elif isinstance(x, dict):
            out.append(x)
    return out


def event(source, when, action, ids, target="", ip="", failed=False, key_id="", file="", index=0) -> dict | None:
    dt = parse_dt(when)
    if dt is None:
        return None
    return {
        "time": iso(dt),
        "source": source,
        "action": action,
        "ids": sorted({str(i).strip().lower() for i in ids if i}),
        "target": str(target or ""),
        "ip": str(ip or ""),
        "failed": bool(failed),
        "key_id": mask(key_id),
        "file": file,
        "index": index,
    }


def read_entra_signins(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        status = r.get("status") or {}
        out.append(
            event(
                "entra-signin",
                r.get("createdDateTime"),
                f"signin:{r.get('resourceDisplayName') or r.get('resourceId') or 'unknown'}",
                [
                    r.get("appId"),
                    r.get("servicePrincipalId"),
                    r.get("servicePrincipalName"),
                    r.get("userPrincipalName"),
                    r.get("userId"),
                ],
                r.get("resourceDisplayName"),
                r.get("ipAddress"),
                str(status.get("errorCode", 0)) not in ("0", "None"),
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_entra_audit(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        by = r.get("initiatedBy") or {}
        app, user = by.get("app") or {}, by.get("user") or {}
        targets = [t.get("displayName") or t.get("id") for t in r.get("targetResources") or [] if isinstance(t, dict)]
        out.append(
            event(
                "entra-audit",
                r.get("activityDateTime"),
                f"entra:{r.get('activityDisplayName') or 'unknown'}",
                [
                    app.get("appId"),
                    app.get("servicePrincipalId"),
                    app.get("servicePrincipalName"),
                    app.get("displayName"),
                    user.get("id"),
                    user.get("userPrincipalName"),
                ],
                ", ".join(str(t) for t in targets if t),
                user.get("ipAddress"),
                str(r.get("result", "success")).lower() not in ("success", ""),
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_cloudtrail(path: Path) -> list[dict]:
    data = load_json(path)
    records = []
    for r in rows_of(data, "Events", "Records"):
        inner = r.get("CloudTrailEvent")
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}: a CloudTrailEvent is not valid JSON: {exc}") from exc
        if isinstance(inner, dict):
            records.append(inner)
        elif "eventTime" in r or "EventTime" in r:
            records.append(
                {
                    "eventTime": r.get("eventTime") or r.get("EventTime"),
                    "eventSource": r.get("eventSource") or r.get("EventSource"),
                    "eventName": r.get("eventName") or r.get("EventName"),
                    "userIdentity": r.get("userIdentity")
                    or {"userName": r.get("Username"), "accessKeyId": r.get("AccessKeyId")},
                }
            )
    out = []
    for n, r in enumerate(records):
        who = r.get("userIdentity") or {}
        issuer = ((who.get("sessionContext") or {}).get("sessionIssuer")) or {}
        arn = str(who.get("arn") or "")
        role = arn.split("/")[1] if ":assumed-role/" in arn and arn.count("/") >= 2 else ""
        service = str(r.get("eventSource") or "unknown").split(".")[0]
        resources = [x.get("ARN") or x.get("arn") for x in r.get("resources") or [] if isinstance(x, dict)]
        out.append(
            event(
                "cloudtrail",
                r.get("eventTime"),
                f"{service}:{r.get('eventName') or 'unknown'}",
                [
                    arn,
                    who.get("principalId"),
                    who.get("accessKeyId"),
                    who.get("userName"),
                    issuer.get("arn"),
                    issuer.get("userName"),
                    role,
                ],
                ", ".join(str(x) for x in resources if x),
                r.get("sourceIPAddress"),
                bool(r.get("errorCode")),
                who.get("accessKeyId"),
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_github_audit(path: Path) -> list[dict]:
    out = []
    for n, r in enumerate(rows_of(load_json(path))):
        out.append(
            event(
                "github-audit",
                r.get("@timestamp") or r.get("created_at"),
                f"github:{r.get('action') or 'unknown'}",
                [r.get("actor"), r.get("user"), r.get("oauth_application_name"), r.get("integration")],
                r.get("repo") or r.get("repository") or r.get("org"),
                r.get("actor_ip"),
                False,
                "",
                path.name,
                n,
            )
        )
    return [e for e in out if e]


def read_app_log(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path.name}: line {n} is not JSON: {exc}") from exc
        if not isinstance(r, dict):
            raise InputError(f"{path.name}: line {n} is not a JSON object")
        when = next((r[k] for k in TIME_KEYS if r.get(k) not in (None, "")), None)
        action = next((r[k] for k in ACTION_KEYS if r.get(k) not in (None, "")), "unknown")
        level = str(r.get("level") or r.get("status") or "").lower()
        e = event(
            "app-log",
            when,
            f"app:{action}",
            [r.get(k) for k in ID_KEYS],
            r.get("target") or r.get("resource"),
            r.get("ip"),
            level in ("error", "failed", "failure", "denied"),
            "",
            path.name,
            n,
        )
        if e:
            out.append(e)
    return out


READERS = {
    "entra_signins": read_entra_signins,
    "entra_audit": read_entra_audit,
    "cloudtrail": read_cloudtrail,
    "github_audit": read_github_audit,
    "app_log": read_app_log,
}


def collect(args) -> list[dict]:
    events: list[dict] = []
    given = False
    for option, reader in READERS.items():
        for f in getattr(args, option) or []:
            given = True
            events += reader(Path(f))
    if not given:
        raise InputError(
            "give at least one export (--entra-signins, --entra-audit, --cloudtrail, --github-audit, --app-log)"
        )
    return events


# ---- timeline ----------------------------------------------------------------------------------------------------


def read_lines(path: str | None) -> list[str] | None:
    if not path:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def bound(value: str | None, end: bool) -> datetime | None:
    if not value:
        return None
    dt = parse_dt(value)
    if dt is None:
        raise InputError(f"{value!r} is not a date or time")
    if end and len(value.strip()) == 10:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt


def build(args) -> dict:
    wanted = {v.strip().lower() for v in args.identity if v.strip()}
    if not wanted:
        raise InputError("--identity is empty")
    since, until = bound(args.since, False), bound(args.until, True)
    allow = read_lines(args.allow_list)
    baseline = set(read_lines(args.baseline) or []) if args.baseline else None
    events = [e for e in collect(args) if wanted & set(e["ids"])]
    events = [
        e for e in events if (not since or parse_dt(e["time"]) >= since) and (not until or parse_dt(e["time"]) <= until)
    ]
    events.sort(key=lambda e: (e["time"], e["source"], e["action"], e["file"], e["index"]))
    seen: set[str] = set()
    for e in events:
        e["flags"] = []
        if baseline is not None:
            if e["action"] not in baseline and e["action"] not in seen:
                e["flags"].append("first-seen")
        elif e["action"] not in seen:
            e["flags"].append("first-in-window")
        seen.add(e["action"])
        if allow is not None and not any(fnmatch.fnmatchcase(e["action"], p) for p in allow):
            e["flags"].append("outside-allow-list")
        if e["failed"]:
            e["flags"].append("failed")
        e.pop("ids")
    bursts = find_bursts(events, args.burst_count, args.burst_window)
    counts = {
        "events": len(events),
        "by_source": {s: sum(1 for e in events if e["source"] == s) for s in sorted({e["source"] for e in events})},
        "outside_allow_list": sum(1 for e in events if "outside-allow-list" in e["flags"]),
        "first_seen": sum(1 for e in events if "first-seen" in e["flags"]),
        "failed": sum(1 for e in events if e["failed"]),
        "bursts": len(bursts),
    }
    return {
        "identity": sorted(wanted),
        "window": {"since": iso(since) if since else None, "until": iso(until) if until else None},
        "allow_list": allow is not None,
        "baseline": baseline is not None,
        "summary": counts,
        "bursts": bursts,
        "events": events,
    }


def find_bursts(events: list[dict], count: int, window: int) -> list[dict]:
    times = [parse_dt(e["time"]) for e in events]
    bursts: list[dict] = []
    i = 0
    while i < len(events):
        j = i
        while j + 1 < len(events) and (times[j + 1] - times[i]).total_seconds() <= window:
            j += 1
        if j - i + 1 >= count:
            end = j
            while end + 1 < len(events) and (times[end + 1] - times[end - count + 2]).total_seconds() <= window:
                end += 1
            for e in events[i : end + 1]:
                e["flags"].append("burst")
            bursts.append({"start": events[i]["time"], "end": events[end]["time"], "events": end - i + 1})
            i = end + 1
        else:
            i += 1
    return bursts


def render(doc: dict) -> str:
    s = doc["summary"]
    lines = [
        "# Agent action timeline",
        "",
        f"Identity: {', '.join(doc['identity'])}. {s['events']} events "
        f"({', '.join(f'{k} {v}' for k, v in s['by_source'].items()) or 'none'}). Window: "
        f"{doc['window']['since'] or 'start of exports'} to {doc['window']['until'] or 'end of exports'}.",
        "",
        "- Outside the allow list: "
        + (str(s["outside_allow_list"]) if doc["allow_list"] else "not checked (no --allow-list)"),
        f"- First seen against the baseline: {s['first_seen'] if doc['baseline'] else 'not checked (no --baseline)'}",
        f"- Bursts: {s['bursts']}"
        + "".join(f"; {b['events']} events {b['start']} to {b['end']}" for b in doc["bursts"]),
        f"- Failed or denied: {s['failed']}",
        "",
        "| Time (UTC) | Source | Action | Target | IP | Key | Flags |",
        "|---|---|---|---|---|---|---|",
    ]
    for e in doc["events"]:
        lines.append(
            f"| {e['time']} | {e['source']} | {e['action']} | {e['target'] or '-'} | {e['ip'] or '-'} | "
            f"{e['key_id'] or '-'} | {', '.join(e['flags']) or '-'} |"
        )
    if not doc["events"]:
        lines.append("| - | - | no event matched these identity values | - | - | - | - |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agent_action_timeline.py",
        description="One ordered timeline of what an agent identity did, from saved audit exports.",
        epilog="Exit codes: 0 nothing flagged, 1 burst, outside allow list or first-seen with a baseline, 2 bad input.",
    )
    ap.add_argument("--identity", action="append", required=True, help="a value the agent is known by (repeatable)")
    ap.add_argument("--entra-signins", action="append", help="Graph sign-in log export (repeatable)")
    ap.add_argument("--entra-audit", action="append", help="Graph directory audit export (repeatable)")
    ap.add_argument("--cloudtrail", action="append", help="CloudTrail lookup-events output or log file (repeatable)")
    ap.add_argument("--github-audit", action="append", help="GitHub organisation audit log export (repeatable)")
    ap.add_argument("--app-log", action="append", help="application log in JSON lines (repeatable)")
    ap.add_argument("--since", help="keep events at or after this date or time (UTC)")
    ap.add_argument("--until", help="keep events at or before this date or time (UTC)")
    ap.add_argument("--allow-list", help="file of allowed action patterns, one per line")
    ap.add_argument("--baseline", help="file of action names seen before, one per line")
    ap.add_argument("--burst-count", type=int, default=20, help="events that make a burst (20)")
    ap.add_argument("--burst-window", type=int, default=60, help="seconds a burst must fit in (60)")
    ap.add_argument("--json", action="store_true", help="print the timeline as JSON")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        if args.burst_count < 2 or args.burst_window < 1:
            raise InputError("--burst-count must be at least 2 and --burst-window at least 1")
        doc = build(args)
    except InputError as exc:
        print(f"agent_action_timeline.py: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(doc, indent=2) + "\n" if args.json else render(doc)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    s = doc["summary"]
    return 1 if s["outside_allow_list"] or s["bursts"] or s["first_seen"] else 0


if __name__ == "__main__":
    sys.exit(main())
