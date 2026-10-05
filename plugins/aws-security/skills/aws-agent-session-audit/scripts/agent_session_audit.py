#!/usr/bin/env python3
"""Audit what an AI coding agent did in an AWS account, from saved CloudTrail events filtered to its role session.

Inputs (files or folders, any mix; folders are read for *.json, *.jsonl and *.json.gz):
  * `aws cloudtrail lookup-events --output json` output {"Events": [{"EventName", "EventTime", "EventSource",
    "Username", "Resources", "CloudTrailEvent": "<JSON string>"}]}; the embedded CloudTrailEvent is used when present
  * CloudTrail log files as delivered to S3 {"Records": [...]}, gzipped or not
  * a list of CloudTrail records, or JSON lines with one record per line (for example an Athena or CloudTrail Lake
    query result saved as JSON)

Filter: --session-name keeps records whose assumed-role ARN ends in /<session-name>, whose principalId ends in
:<session-name>, or whose lookup-events Username equals it. --role-name narrows to that role. Without either, every
record in the input counts.

Report: the time window, actions by service with reads, writes and errors, resources touched, errors by code, and
these findings (id, default severity):
  AGENT-LOGGING-TAMPER     critical  a call that stops or weakens CloudTrail, GuardDuty, Config, Security Hub or
                                     CloudWatch Logs (for example cloudtrail:StopLogging, guardduty:DeleteDetector)
  AGENT-IAM-WRITE          high      a successful IAM write, a role assumed from the session, or a federation token
  AGENT-DESTRUCTIVE        high      a successful Delete*, Terminate*, Remove*, Purge*, Detach* or Disable* call
  AGENT-OUTSIDE-ALLOWLIST  high      an action (successful or not) that is not on --allow-list
  AGENT-CONSOLE            medium    a console sign-in or a sign-in token request from the session
  AGENT-DENIED-BURST       medium    --denied-burst or more access-denied errors (default 10): the agent was probing
  AGENT-OTHER-REGION       low       a call in a region not listed in --regions

Remove these permissions: with --granted (an IAM policy document, `aws iam get-policy-version` output or
`aws iam get-role-policy` output), every explicitly granted action the session never called is listed for removal,
and every wildcard grant is listed with the actions the session used under it. Without --granted the report lists
the actions the session used successfully, as a starting point for an allow list. Read and write are classified by
the record's readOnly field, or by verb prefix (Get, List, Describe and similar count as read).

Output: Markdown (default) or --json, to stdout or --out. Access key ids, request parameters and response elements
are never printed; secret-shaped strings are masked. --redact also replaces account ids, source IP addresses and
e-mail addresses with stable tokens.

Exit codes: 0 no finding at or above --fail-on (default high), 1 findings at or above --fail-on (a person should
review the session), 2 bad input. Standard library only. Reads files; never calls AWS.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
READ_PREFIXES = ("get", "list", "describe", "head", "view", "search", "query", "scan", "select", "lookup", "batchget")
DESTRUCTIVE_PREFIXES = ("delete", "terminate", "remove", "purge", "detach", "disable", "deregister", "revoke")
LOGGING_TAMPER = {
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors",
    "cloudtrail:DeleteEventDataStore",
    "guardduty:DeleteDetector",
    "guardduty:UpdateDetector",
    "guardduty:DisassociateFromMasterAccount",
    "guardduty:DisassociateFromAdministratorAccount",
    "guardduty:CreateFilter",
    "config:StopConfigurationRecorder",
    "config:DeleteConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "securityhub:DisableSecurityHub",
    "securityhub:BatchDisableStandards",
    "securityhub:DisableImportFindingsForProduct",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "logs:PutRetentionPolicy",
}
IAM_ESCALATION = {"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:GetFederationToken", "iam:PassRole"}
CONSOLE = {"signin:ConsoleLogin", "signin:GetSigninToken", "sts:GetFederationToken"}
DENIED_CODES = re.compile(r"(?i)(accessdenied|unauthorized|forbidden|notauthorized)")
ACCOUNT_RE = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
RESOURCE_KEYS = (
    "bucketName",
    "roleName",
    "userName",
    "policyArn",
    "functionName",
    "tableName",
    "stackName",
    "secretId",
    "name",
    "logGroupName",
    "key",
)
MAX_BYTES = 200 * 1024 * 1024


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise InputError(f"{path.name}: larger than {MAX_BYTES // (1024 * 1024)} MB")
        raw = path.read_bytes()
        if path.suffix == ".gz":
            raw = gzip.decompress(raw)
        return raw.decode("utf-8-sig")
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path.name}: not UTF-8 text") from exc


def records_in(path: Path) -> list[dict]:
    text = read_text(path)
    try:
        docs = [json.loads(text)]
    except json.JSONDecodeError:
        docs = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise InputError(f"{path.name}:{n}: not JSON: {exc.msg}") from exc
    out: list[dict] = []
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("Events"), list):
            for ev in doc["Events"]:
                out.append(from_lookup(ev, path.name))
        elif isinstance(doc, dict) and isinstance(doc.get("Records"), list):
            out += [r for r in doc["Records"] if isinstance(r, dict)]
        elif isinstance(doc, list):
            out += [r for r in doc if isinstance(r, dict)]
        elif isinstance(doc, dict) and "eventName" in doc:
            out.append(doc)
        else:
            raise InputError(f"{path.name}: expected lookup-events output, a CloudTrail log file, a list of records or JSON lines")
    for r in out:
        if not isinstance(r.get("eventName"), str) or not isinstance(r.get("eventSource"), str):
            raise InputError(f"{path.name}: a record has no eventName or eventSource")
    return out


def from_lookup(ev: dict, where: str) -> dict:
    """A lookup-events entry, using the embedded CloudTrailEvent when it is there."""
    if not isinstance(ev, dict):
        raise InputError(f"{where}: Events entries must be objects")
    raw = ev.get("CloudTrailEvent")
    if isinstance(raw, str) and raw.strip():
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise InputError(f"{where}: CloudTrailEvent of {ev.get('EventId', '?')} is not JSON") from exc
        rec.setdefault("_username", ev.get("Username"))
        return rec
    ro = ev.get("ReadOnly")
    return {
        "eventName": ev.get("EventName"),
        "eventSource": ev.get("EventSource"),
        "eventTime": ev.get("EventTime"),
        "readOnly": None if ro is None else str(ro).lower() == "true",
        "resources": [{"ARN": r.get("ResourceName"), "type": r.get("ResourceType")} for r in ev.get("Resources") or []],
        "_username": ev.get("Username"),
    }


def collect(paths: list[str]) -> list[dict]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.is_file() and (f.name.endswith((".json", ".jsonl", ".json.gz"))))
        elif p.is_file():
            files.append(p)
        else:
            raise InputError(f"{p}: not found")
    if not files:
        raise InputError("no input files found")
    out: list[dict] = []
    for f in files:
        out += records_in(f)
    return out


def session_of(r: dict) -> tuple[str, str]:
    """(role name, session name) from userIdentity, or ('', username) for lookup-events entries without detail."""
    ui = r.get("userIdentity") or {}
    arn = str(ui.get("arn") or "")
    m = re.search(r":assumed-role/([^/]+)/(.+)$", arn)
    if m:
        return m.group(1), m.group(2)
    pid = str(ui.get("principalId") or "")
    if ":" in pid:
        return "", pid.split(":", 1)[1]
    return "", str(r.get("_username") or "")


def action(r: dict) -> str:
    return f"{r['eventSource'].split('.', 1)[0]}:{r['eventName']}"


def is_read(r: dict) -> bool:
    ro = r.get("readOnly")
    if isinstance(ro, bool):
        return ro
    if isinstance(ro, str):
        return ro.lower() == "true"
    return r["eventName"].lower().startswith(READ_PREFIXES)


def resources_of(r: dict) -> set[str]:
    out = {str(x.get("ARN") or x.get("arn")) for x in r.get("resources") or [] if isinstance(x, dict) and (x.get("ARN") or x.get("arn"))}
    params = r.get("requestParameters")
    if isinstance(params, dict):
        for k in RESOURCE_KEYS:
            v = params.get(k)
            if isinstance(v, str) and v:
                out.add(f"{r['eventSource'].split('.', 1)[0]}:{k}={v}")
    return out


def load_list(path: str) -> list[str]:
    """Actions from a JSON list, text lines, or an IAM policy document (Allow statements)."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if isinstance(doc, list) and all(isinstance(x, str) for x in doc):
        return doc
    return granted_actions(doc, path)


def policy_document(doc, where: str) -> dict:
    if isinstance(doc, dict):
        if isinstance(doc.get("PolicyVersion"), dict):
            doc = doc["PolicyVersion"].get("Document")
        elif "PolicyDocument" in doc:
            doc = doc["PolicyDocument"]
    if isinstance(doc, str):
        from urllib.parse import unquote

        try:
            doc = json.loads(unquote(doc))
        except json.JSONDecodeError as exc:
            raise InputError(f"{where}: policy document is not JSON") from exc
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise InputError(f"{where}: expected a list of actions or an IAM policy document")
    return doc


def granted_actions(doc, where: str) -> list[str]:
    stmts = policy_document(doc, where)["Statement"]
    stmts = [stmts] if isinstance(stmts, dict) else stmts
    out: list[str] = []
    for s in stmts:
        if not isinstance(s, dict) or s.get("Effect") != "Allow":
            continue
        acts = s.get("Action", [])
        out += [acts] if isinstance(acts, str) else [a for a in acts if isinstance(a, str)]
    return out


def matches(act: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(act.lower(), p.lower()) for p in patterns)


def finding(fid: str, sev: str, title: str, evidence: str, actions: list[str]) -> dict:
    return {"id": fid, "severity": sev, "title": title, "evidence": evidence, "actions": sorted(actions)}


def audit(records: list[dict], args) -> dict:
    allow = load_list(args.allow_list) if args.allow_list else None
    granted = None
    if args.granted:
        try:
            gdoc = json.loads(Path(args.granted).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InputError(f"{args.granted}: cannot read policy: {exc}") from exc
        granted = granted_actions(gdoc, args.granted)
    kept = []
    for r in records:
        role, sess = session_of(r)
        if args.session_name and sess != args.session_name:
            continue
        if args.role_name and role != args.role_name:
            continue
        kept.append(r)
    if not kept:
        raise InputError("no records match the session filter")
    kept.sort(key=lambda r: str(r.get("eventTime") or ""))
    by_service: dict[str, Counter] = defaultdict(Counter)
    acts: Counter = Counter()
    ok_acts: set[str] = set()
    errors: Counter = Counter()
    denied: Counter = Counter()
    resources: Counter = Counter()
    regions: Counter = Counter()
    sources: Counter = Counter()
    sessions: Counter = Counter()
    writes: set[str] = set()
    for r in kept:
        a = action(r)
        svc = a.split(":", 1)[0]
        failed = bool(r.get("errorCode"))
        acts[a] += 1
        by_service[svc]["calls"] += 1
        by_service[svc]["reads" if is_read(r) else "writes"] += 1
        if failed:
            by_service[svc]["errors"] += 1
            errors[str(r["errorCode"])] += 1
            if DENIED_CODES.search(str(r["errorCode"])):
                denied[a] += 1
        else:
            ok_acts.add(a)
            if not is_read(r):
                writes.add(a)
        for res in resources_of(r):
            resources[res] += 1
        if r.get("awsRegion"):
            regions[str(r["awsRegion"])] += 1
        if r.get("sourceIPAddress"):
            sources[str(r["sourceIPAddress"])] += 1
        role, sess = session_of(r)
        sessions[f"{role}/{sess}" if role else sess] += 1
    findings: list[dict] = []
    tamper = sorted(a for a in acts if a in LOGGING_TAMPER)
    if tamper:
        findings.append(finding("AGENT-LOGGING-TAMPER", "critical", "Calls that stop or weaken logging or detection", ", ".join(tamper), tamper))
    iam = sorted(a for a in ok_acts if (a.startswith("iam:") and a in writes) or a in IAM_ESCALATION)
    if iam:
        findings.append(finding("AGENT-IAM-WRITE", "high", "IAM changes or role assumption from the agent session", ", ".join(iam), iam))
    destructive = sorted(a for a in ok_acts if a.split(":", 1)[1].lower().startswith(DESTRUCTIVE_PREFIXES) and a not in LOGGING_TAMPER)
    if destructive:
        findings.append(finding("AGENT-DESTRUCTIVE", "high", "Destructive calls that succeeded", ", ".join(destructive), destructive))
    if allow is not None:
        outside = sorted(a for a in acts if not matches(a, allow))
        if outside:
            ev = ", ".join(f"{a} x{acts[a]}" + (" (failed)" if a not in ok_acts else "") for a in outside)
            findings.append(finding("AGENT-OUTSIDE-ALLOWLIST", "high", "Actions outside the declared allow list", ev, outside))
    console = sorted(a for a in acts if a in CONSOLE)
    if console:
        findings.append(finding("AGENT-CONSOLE", "medium", "Console sign-in or sign-in token from the session", ", ".join(console), console))
    total_denied = sum(denied.values())
    if total_denied >= args.denied_burst:
        top = ", ".join(f"{a} x{n}" for a, n in denied.most_common(5))
        findings.append(
            finding(
                "AGENT-DENIED-BURST",
                "medium",
                "Many access-denied errors: the agent was probing",
                f"{total_denied} denied calls; {top}",
                list(denied),
            )
        )
    if args.regions:
        other = sorted(set(regions) - set(args.regions))
        if other:
            findings.append(finding("AGENT-OTHER-REGION", "low", "Calls in regions outside the declared list", ", ".join(other), []))
    findings.sort(key=lambda f: (RANK[f["severity"]], f["id"]))
    if granted is not None:
        explicit = sorted({g for g in granted if "*" not in g})
        unused = [g for g in explicit if not any(a.lower() == g.lower() for a in acts)]
        wild = sorted({g for g in granted if "*" in g})
        narrow = {g: sorted(a for a in ok_acts if fnmatchcase(a.lower(), g.lower())) for g in wild}
        removal = {
            "basis": "granted policy",
            "remove": unused,
            "replace_wildcards": [{"grant": g, "used": u} for g, u in narrow.items()],
        }
    else:
        removal = {"basis": "actions used", "remove": [], "replace_wildcards": [], "allow_list_draft": sorted(ok_acts)}
    first, last = str(kept[0].get("eventTime") or ""), str(kept[-1].get("eventTime") or "")
    return {
        "tool": "agent_session_audit",
        "filter": {"session_name": args.session_name, "role_name": args.role_name},
        "window": {"first": first, "last": last, "records": len(kept), "read_from_input": len(records)},
        "sessions": dict(sessions.most_common()),
        "source_ips": dict(sources.most_common()),
        "regions": dict(sorted(regions.items())),
        "services": {s: dict(c) for s, c in sorted(by_service.items())},
        "actions": dict(sorted(acts.items())),
        "writes": sorted(writes),
        "errors": dict(errors.most_common()),
        "resources": dict(sorted(resources.items())),
        "findings": findings,
        "remove_permissions": removal,
        "note": "Findings come from the saved CloudTrail events only. Confirm each one before changing any permission; the script changed nothing.",
    }


def token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def scrub(text: str, redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = ACCOUNT_RE.sub(lambda m: f"acct-{token(m.group(0))}", text)
        text = IP_RE.sub(lambda m: f"ip-{token(m.group(0))}", text)
        text = EMAIL_RE.sub(lambda m: f"user-{token(m.group(0).lower())}@redacted.invalid", text)
    return text


def cell(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("\n", " ")


def render(rep: dict) -> str:
    w = rep["window"]
    lines = [
        "## Agent session audit",
        "",
        f"**Window:** {w['first']} to {w['last']}, {w['records']} events matched (of {w['read_from_input']} read).",
        f"**Sessions:** {', '.join(cell(s) for s in rep['sessions'])}. **Source IPs:** {', '.join(cell(s) for s in rep['source_ips']) or '-'}.",
        "",
        "### Findings",
        "",
    ]
    if rep["findings"]:
        lines += ["| Severity | Check | Finding | Evidence |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {f['id']} | {cell(f['title'])} | {cell(f['evidence'])} |" for f in rep["findings"]]
    else:
        lines.append("No findings at or above the selected severity.")
    lines += ["", "### Actions by service", "", "| Service | Calls | Reads | Writes | Errors |", "|---|---|---|---|---|"]
    for s, c in rep["services"].items():
        lines.append(f"| {cell(s)} | {c.get('calls', 0)} | {c.get('reads', 0)} | {c.get('writes', 0)} | {c.get('errors', 0)} |")
    lines += ["", f"**Writes that succeeded:** {', '.join(rep['writes']) or 'none'}."]
    if rep["errors"]:
        lines.append("**Errors:** " + ", ".join(f"{cell(k)} x{n}" for k, n in rep["errors"].items()) + ".")
    lines += ["", "### Resources touched", ""]
    lines += [f"- {cell(r)} ({n})" for r, n in rep["resources"].items()] or ["- none recorded"]
    rp = rep["remove_permissions"]
    lines += ["", "### Remove these permissions (proposal, review before any change)", ""]
    if rp["basis"] == "granted policy":
        lines += [f"- remove `{a}`: granted, never called in this window" for a in rp["remove"]] or ["- every explicit grant was used"]
        for w_ in rp["replace_wildcards"]:
            used = ", ".join(f"`{a}`" for a in w_["used"]) or "nothing (remove the grant)"
            lines.append(f"- replace `{w_['grant']}` with {used}")
    else:
        lines.append(
            "No --granted policy given. Actions used successfully, as a draft allow list: "
            + (", ".join(f"`{a}`" for a in rp["allow_list_draft"]) or "none")
        )
    lines += ["", rep["note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="CloudTrail export files or folders")
    ap.add_argument("--session-name", help="role session name of the agent, for example agent@operator")
    ap.add_argument("--role-name", help="role the agent assumed")
    ap.add_argument("--allow-list", help="declared allow list: JSON list of actions, text lines, or an IAM policy document")
    ap.add_argument("--granted", help="the policy the agent role holds, for the remove-these-permissions proposal")
    ap.add_argument("--regions", nargs="*", default=[], help="regions the agent was meant to use")
    ap.add_argument("--denied-burst", type=int, default=10, help="access-denied errors that raise AGENT-DENIED-BURST (default 10)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    ap.add_argument(
        "--fail-on", choices=SEVERITIES + ["none"], default="high", help="exit 1 when a finding is at or above this severity (default high)"
    )
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace account ids, source IPs and e-mail addresses with tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    if args.denied_burst < 1:
        print("error: --denied-burst must be at least 1", file=sys.stderr)
        return 2
    try:
        rep = audit(collect(args.inputs), args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep["findings"] = [f for f in rep["findings"] if RANK[f["severity"]] <= RANK[args.min_severity]]
    code = 0 if args.fail_on == "none" else int(any(RANK[f["severity"]] <= RANK[args.fail_on] for f in rep["findings"]))
    text = scrub(json.dumps(rep, indent=2) if args.json else render(rep), args.redact)
    try:
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
