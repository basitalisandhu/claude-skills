#!/usr/bin/env python3
"""Scan a directory (or the files staged in git) for secrets that should not be committed.

Patterns: cloud and SaaS API keys (AWS, Google, GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, Mailgun, npm,
PyPI, Hugging Face, OpenAI-style), private key blocks, JSON Web Tokens, connection strings and URLs with embedded
passwords, and generic `key = value` assignments whose value is long and high-entropy. Evidence is always
redacted (first four characters, then stars). Also reports .env files that are not ignored by .gitignore, and
.env.example values that look real.

Suppress a line with a trailing comment containing `secrets-hygiene: ignore` or `pragma: allowlist secret`.
A baseline file (--baseline) lists fingerprints of accepted findings; --write-baseline creates one from the
current findings so only new secrets fail the build. Fingerprints are SHA-256 of path, rule and match; the
secret itself is never written.

Usage:
    secrets_scan.py [PATH] [--staged] [--json] [--fail-on SEVERITY] [--exclude DIR ...] [--baseline FILE] [--write-baseline FILE]

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 bad input.
Standard library only. Read-only (except --write-baseline). Runs git locally for --staged. No network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
DEFAULT_EXCLUDES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "coverage", ".next", "target", "vendor", ".idea", ".vscode"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".tar", ".jar", ".war", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".class", ".lock", ".svg", ".min.js", ".map"}
MAX_FILE_BYTES = 1024 * 1024
ALLOW_RE = re.compile(r"(secrets-hygiene:\s*ignore|pragma:\s*allowlist\s+secret|nosec|gitleaks:allow)", re.I)
PLACEHOLDER_RE = re.compile(r"(?i)(xxxx|your[_-]|example|placeholder|redacted|changeme|change-me|<[^>]+>|\.\.\.|\*\*\*|dummy|sample|test[-_]?key|fake|insert|replace|todo|tbd|\$\{|%s|\{\{)")

PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws-access-key-id", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("aws-secret-key", "critical", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b")),
    ("github-token", "critical", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("gitlab-token", "critical", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", "critical", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", "high", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("google-api-key", "critical", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("google-oauth-secret", "high", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b")),
    ("stripe-key", "critical", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("sendgrid-key", "critical", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("twilio-key", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("mailgun-key", "high", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("npm-token", "critical", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", "critical", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b")),
    ("huggingface-token", "critical", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("openai-style-key", "critical", re.compile(r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{32,}\b")),
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url-with-password", "high", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{4,})@[^\s/]+", re.I)),
    ("basic-auth-header", "high", re.compile(r"(?i)authorization[\"']?\s*[:=]\s*[\"']?basic\s+[A-Za-z0-9+/=]{16,}")),
    ("bearer-token-literal", "high", re.compile(r"(?i)authorization[\"']?\s*[:=]\s*[\"']?bearer\s+[A-Za-z0-9._-]{20,}")),
    ("generic-secret-assignment", "high", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|private[_-]?key|password|passwd|secret|token)\b[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']")),
    ("generic-secret-env", "medium", re.compile(r"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)\s*=\s*[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?\s*$")),
]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def redact(s: str) -> str:
    return s[:4] + "*" * min(12, max(4, len(s) - 4)) if len(s) > 8 else "*" * len(s)


def iter_files(root: Path, excludes: set[str]):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in excludes for part in p.relative_to(root).parts[:-1]):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES or p.name.endswith(".min.js"):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def staged_files(root: Path) -> list[Path]:
    proc = subprocess.run(["git", "-C", str(root), "diff", "--cached", "--name-only", "--diff-filter=ACMR"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git diff failed")
    return [root / line for line in proc.stdout.splitlines() if line and (root / line).is_file()]


def scan_text(path: str, text: str) -> list[dict]:
    """One finding per line at most: the first (most specific) rule that matches wins."""
    findings: list[dict] = []
    for no, line in enumerate(text.splitlines(), 1):
        if ALLOW_RE.search(line):
            continue
        for rule, sev, rx in PATTERNS:
            hit = None
            for m in rx.finditer(line):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if rule in {"generic-secret-assignment", "generic-secret-env", "url-with-password"}:
                    if PLACEHOLDER_RE.search(value) or entropy(value) < 3.0 or value.lower() in {"true", "false", "none", "null"}:
                        continue
                    if rule != "url-with-password" and re.match(r"^[a-z_]+$", value):
                        continue
                if rule == "openai-style-key" and PLACEHOLDER_RE.search(value):
                    continue
                hit = (m, value)
                break
            if hit:
                m, value = hit
                fp = hashlib.sha256(f"{path}\n{rule}\n{m.group(0)}".encode()).hexdigest()[:16]
                findings.append({"rule": rule, "severity": sev, "file": path, "line": no, "evidence": redact(value), "fingerprint": fp})
                break
    return findings


def check_env_hygiene(root: Path) -> list[dict]:
    out: list[dict] = []
    if not root.is_dir():
        return out
    gitignore = (root / ".gitignore").read_text(encoding="utf-8", errors="replace") if (root / ".gitignore").is_file() else ""
    ignores_env = any(re.match(r"^\s*(\.env(\*|\.\*|\.local)?|\*\*/\.env\*?|\.env/?)\s*$", l) for l in gitignore.splitlines())
    for env in sorted(root.rglob(".env*")):
        if not env.is_file() or any(part in DEFAULT_EXCLUDES for part in env.relative_to(root).parts[:-1]):
            continue
        if env.name in {".env.example", ".env.sample", ".env.template", ".env.dist"}:
            continue
        if not ignores_env:
            out.append({"rule": "env-file-not-ignored", "severity": "high", "file": str(env.relative_to(root)), "line": 0, "evidence": "no .env rule in .gitignore", "fingerprint": hashlib.sha256(f"{env.relative_to(root)}\nenv-file-not-ignored".encode()).hexdigest()[:16]})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--staged", action="store_true", help="scan only files staged in git (pre-commit use)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR")
    ap.add_argument("--baseline", help="JSON file of accepted fingerprints to ignore")
    ap.add_argument("--write-baseline", metavar="FILE", help="write the current fingerprints to FILE and exit 0")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    try:
        files = staged_files(root) if args.staged else list(iter_files(root, DEFAULT_EXCLUDES | set(args.exclude)))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings: list[dict] = []
    for f in files:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8000]:
            continue
        rel = str(f.relative_to(root)) if root.is_dir() else str(f)
        findings += scan_text(rel, data.decode("utf-8", errors="replace"))
    findings += check_env_hygiene(root)
    baseline: set[str] = set()
    if args.baseline:
        bp = Path(args.baseline)
        if not bp.is_file():
            print(f"error: baseline not found: {bp}", file=sys.stderr)
            return 2
        try:
            baseline = set(json.loads(bp.read_text(encoding="utf-8")).get("fingerprints", []))
        except (json.JSONDecodeError, AttributeError):
            print("error: baseline must be a JSON object with a fingerprints list", file=sys.stderr)
            return 2
    suppressed = [x for x in findings if x["fingerprint"] in baseline]
    findings = [x for x in findings if x["fingerprint"] not in baseline]
    if args.write_baseline:
        Path(args.write_baseline).write_text(json.dumps({"tool": f"secrets-hygiene {VERSION}", "fingerprints": sorted({x["fingerprint"] for x in findings} | baseline)}, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {len(findings)} fingerprints to {args.write_baseline}")
        return 0
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda x: (order[x["severity"]], x["file"], x["line"]))
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITIES}
    report = {"version": VERSION, "root": str(root), "files_scanned": len(files), "findings": findings, "suppressed_by_baseline": len(suppressed), "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"secrets-hygiene {VERSION}: {len(files)} files, {len(findings)} findings " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]) + (f", {len(suppressed)} suppressed by baseline" if suppressed else ""))
        for x in findings:
            print(f"  [{x['severity']:<8}] {x['rule']:<26} {x['file']}:{x['line']}  {x['evidence']}  fp={x['fingerprint']}")
        if findings:
            print("Rotate anything real, then remove it from history (git filter-repo) and add the path to .gitignore.")
    worst = min((order[x["severity"]] for x in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
