#!/usr/bin/env python3
"""Flag security-relevant lines added by a saved unified diff (`git diff` or `gh pr diff` output).

Only added lines are scanned, and each is reported with its file and its line number in the new version, so a
reviewer can open the surrounding code. The patterns are structural (a call, a flag, a setting), not exploit
strings, and every hit is a lead for review, not a verdict.

Rules (id, severity):
  net-call             medium  new outbound network call (requests, urllib, httpx, fetch, axios, http.Get, curl,
                               sockets)
  shell-exec           high    shell command built at run time (shell=True, os.system, os.popen, execSync,
                               Runtime.exec)
  process-exec         medium  new child process without a shell (subprocess, spawn, exec.Command, ProcessBuilder)
  code-eval            high    eval, exec or new Function on a string
  unsafe-deserialise   high    pickle, marshal, yaml.load without a safe loader, ObjectInputStream,
                               BinaryFormatter, unserialize
  sql-from-string      high    SQL statement built with an f-string, format, % or + concatenation, or ${...}
  secret-literal       high    credential-shaped literal: a password, token or key assigned a quoted value, an
                               AWS key id, a private key header (evidence is redacted)
  tls-disabled         high    certificate or host name checks switched off (verify=False, rejectUnauthorized
                               false, CERT_NONE, InsecureSkipVerify, curl -k, sslmode=disable)
  workflow-permission  high    GitHub Actions: write-all, pull_request_target, or a new `<scope>: write` permission
  privileged-runtime   high    privileged containers, host namespaces, privilege escalation, USER root
  wildcard-iam         high    IAM statement granting Action "*" or Resource "*"
  install-hook         medium  package.json install hook, Android <uses-permission>, browser extension permission

Suppress a line with a trailing comment containing `diff-security-review: ignore`.

Usage:
    diff_security_scan.py DIFF_FILE [--json] [--out FILE] [--fail-on SEVERITY] [--exclude GLOB ...]
    git diff main...HEAD | diff_security_scan.py -

Exit codes: 0 no finding at or above --fail-on (default: low), 1 findings for a human to review, 2 bad input.
Standard library only. Read-only (writes only --out). No network.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["high", "medium", "low"]
IGNORE_RE = re.compile(r"diff-security-review:\s*ignore", re.I)
HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")
PLACEHOLDER_RE = re.compile(
    r"(?i)(xxx|your[_-]|example|placeholder|redacted|changeme|change-me|<[^>]+>|\.\.\.|\*\*\*|dummy|sample|fake|"
    r"todo|tbd|\$\{|\{\{|%s|os\.environ|getenv|process\.env)"
)
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")

# (rule, severity, pattern, path filter or None). The first matching rule per line wins, so order is specific first.
RULES: list[tuple[str, str, re.Pattern[str], re.Pattern[str] | None]] = [
    (
        "tls-disabled",
        "high",
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0|"
            r"InsecureSkipVerify\s*:\s*true|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|"
            r"\bcurl\b.*(\s-k\b|--insecure)|\bwget\b.*--no-check-certificate|strict-ssl\s*[=:]\s*false|"
            r"sslmode=disable|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts",
            re.I,
        ),
        None,
    ),
    (
        "workflow-permission",
        "high",
        re.compile(r"permissions\s*:\s*write-all|\bpull_request_target\b|^\s*[a-z-]+\s*:\s*write\s*(#.*)?$"),
        WORKFLOW_RE,
    ),
    (
        "privileged-runtime",
        "high",
        re.compile(
            r"privileged\s*:\s*true|host(Network|PID|IPC)\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|"
            r"--privileged\b|^\s*USER\s+root\s*$|network_mode\s*:\s*[\"']?host"
        ),
        None,
    ),
    (
        "wildcard-iam",
        "high",
        re.compile(
            r"[\"'](Action|Resource)[\"']\s*:\s*\[?\s*[\"']\*[\"']|\b(actions|resources)\s*=\s*\[\s*\"\*\"\s*\]"
        ),
        None,
    ),
    (
        "unsafe-deserialise",
        "high",
        re.compile(
            r"\b(c?[Pp]ickle|dill|marshal)\.loads?\(|\bshelve\.open\(|jsonpickle\.decode\(|yaml\.(unsafe_load|full_load)\(|"
            r"\byaml\.load\((?![^)]*Safe)|ObjectInputStream|\.readObject\(\)|BinaryFormatter|NetDataContractSerializer|"
            r"\bunserialize\(|Marshal\.load\(|node-serialize"
        ),
        None,
    ),
    (
        "shell-exec",
        "high",
        re.compile(
            r"shell\s*=\s*True|\bos\.(system|popen)\(|\bexecSync\(|child_process[\"']?\)?\.exec\(|"
            r"Runtime\.getRuntime\(\)\.exec\(|\b(shell_exec|passthru|proc_open)\(|\bsh\s+-c\b|\bbash\s+-c\b"
        ),
        None,
    ),
    (
        "code-eval",
        "high",
        re.compile(r"(?<![\w.])(eval|exec)\s*\(|\bnew Function\(|setTimeout\(\s*[\"'`]|setInterval\(\s*[\"'`]"),
        None,
    ),
    (
        "process-exec",
        "medium",
        re.compile(
            r"\bsubprocess\.(run|call|Popen|check_output|check_call)\(|\bspawn(Sync)?\(|\bexecFile(Sync)?\(|"
            r"\bexec\.Command\(|\bProcessBuilder\(|\bos\.exec[lv]p?e?\("
        ),
        None,
    ),
    (
        "net-call",
        "medium",
        re.compile(
            r"\brequests\.(get|post|put|patch|delete|head|request|Session)\b|\burlopen\(|\burllib\.request\b|"
            r"\bhttp\.client\.|\bhttpx\.|aiohttp\.ClientSession|(?<![\w.])fetch\(|\baxios(\.\w+)?\(|XMLHttpRequest|"
            r"\bhttps?\.(get|request)\(|\bhttp\.(Get|Post|NewRequest)\(|\bHttpClient\b|\bWebClient\b|"
            r"\bsocket\.(socket|create_connection)\(|\bnet\.Dial\(|\bnew WebSocket\(|^\s*(RUN\s+)?(curl|wget)\s"
        ),
        None,
    ),
    (
        "install-hook",
        "medium",
        re.compile(r"\"(pre|post)?install\"\s*:"),
        re.compile(r"(^|/)package\.json$"),
    ),
    ("install-hook", "medium", re.compile(r"<uses-permission\b"), re.compile(r"AndroidManifest\.xml$")),
    (
        "install-hook",
        "medium",
        re.compile(r"\"(host_)?permissions\"\s*:"),
        re.compile(r"(^|/)manifest\.json$"),
    ),
]

SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b\w*?(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")
SQL_RE = re.compile(r"(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b")
SQL_BUILD_RE = re.compile(r"(?i)(\bf[\"']|[\"']\s*%\s*[\w(]|\.format\(|[\"'`]\s*\+\s*\w|\w\s*\+\s*[\"'`]|\$\{|#\{)")


def redact_value(value: str) -> str:
    return value[:4] + "****" if len(value) > 8 else "****"


def redact_line(text: str) -> str:
    text = AWS_KEY_RE.sub(lambda m: redact_value(m.group(0)), text)
    text = SECRET_ASSIGN_RE.sub(lambda m: m.group(0).replace(m.group(2), redact_value(m.group(2))), text)
    text = LONG_TOKEN_RE.sub(lambda m: redact_value(m.group(0)), text)
    text = text.strip()
    return text if len(text) <= 160 else text[:157] + "..."


def secret_hit(line: str) -> bool:
    if AWS_KEY_RE.search(line) or KEY_HEADER_RE.search(line):
        return True
    for m in SECRET_ASSIGN_RE.finditer(line):
        if not PLACEHOLDER_RE.search(m.group(2)):
            return True
    return False


def classify(path: str, line: str) -> tuple[str, str] | None:
    """Return (rule, severity) for one added line, or None."""
    if secret_hit(line):
        return "secret-literal", "high"
    for rule, severity, pattern, path_filter in RULES:
        if path_filter is not None and not path_filter.search(path):
            continue
        if pattern.search(line):
            return rule, severity
    if SQL_RE.search(line) and SQL_BUILD_RE.search(line):
        return "sql-from-string", "high"
    return None


def parse_diff(text: str) -> tuple[list[tuple[str, int, str]], list[str]]:
    """Return ([(path, new line number, added text)], files touched). Raise ValueError when it is not a diff."""
    added: list[tuple[str, int, str]] = []
    files: list[str] = []
    path: str | None = None
    new_no = 0
    old_left = new_left = 0
    saw_header = False
    for raw in text.splitlines():
        in_hunk = old_left > 0 or new_left > 0
        if not in_hunk and raw.startswith("diff "):
            saw_header = True
            continue
        if raw.startswith("+++ ") and not in_hunk:
            target = raw[4:].split("\t")[0].strip().strip('"')
            saw_header = True
            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith(("b/", "w/", "i/")) else target
                if path not in files:
                    files.append(path)
            continue
        if raw.startswith("--- ") and not in_hunk:
            continue
        m = HUNK_RE.match(raw) if not in_hunk else None
        if m:
            old_left = int(m.group(1) if m.group(1) is not None else 1)
            new_no = int(m.group(2))
            new_left = int(m.group(3) if m.group(3) is not None else 1)
            continue
        if not in_hunk:
            continue
        if raw.startswith("+"):
            if path is not None:
                added.append((path, new_no, raw[1:]))
            new_no += 1
            new_left -= 1
        elif raw.startswith("-"):
            old_left -= 1
        elif raw.startswith("\\"):
            continue
        else:  # context line (a blank context line may have lost its leading space)
            new_no += 1
            new_left -= 1
            old_left -= 1
    if not saw_header:
        raise ValueError("not a unified diff: no 'diff --git' or '+++' file headers")
    return added, files


def scan(text: str, excludes: list[str]) -> dict:
    added, files = parse_diff(text)
    findings: list[dict] = []
    scanned = 0
    for path, no, line in added:
        if any(fnmatch.fnmatch(path, g) for g in excludes):
            continue
        scanned += 1
        if IGNORE_RE.search(line):
            continue
        hit = classify(path, line)
        if hit:
            rule, severity = hit
            findings.append(
                {"file": path, "line": no, "rule": rule, "severity": severity, "evidence": redact_line(line)}
            )
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["file"], f["line"]))
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    return {
        "version": VERSION,
        "files": len(files),
        "added_lines_scanned": scanned,
        "findings": findings,
        "by_rule": dict(sorted(by_rule.items())),
    }


def render(report: dict) -> str:
    lines = [
        f"diff-security-review {report['version']}: {report['files']} files,"
        f" {report['added_lines_scanned']} added lines scanned, {len(report['findings'])} findings"
    ]
    for f in report["findings"]:
        lines.append(f"  [{f['severity']}] {f['rule']} {f['file']}:{f['line']}: {f['evidence']}")
    if report["by_rule"]:
        lines.append("by rule: " + ", ".join(f"{k} {v}" for k, v in report["by_rule"].items()))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__
    )
    ap.add_argument("diff", help="unified diff file, or - for stdin")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="low", help="lowest severity that makes the exit code 1")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching this glob")
    args = ap.parse_args(argv)
    if args.diff == "-":
        text = sys.stdin.read()
    else:
        p = Path(args.diff)
        if not p.is_file():
            print(f"error: diff file not found: {p}", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
    try:
        report = scan(text, args.exclude)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = json.dumps(report, indent=2) + "\n" if args.json else render(report)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    limit = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f["severity"]) <= limit for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
