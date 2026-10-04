#!/usr/bin/env python3
"""Check the security headers of a captured HTTP response and grade them.

Input: the raw response as saved from `curl -sI https://example.com > resp.txt` or `curl -si` (status line and
headers; a body is ignored), or a JSON object of header names to values. Nothing is fetched by this script.

Checks (id, severity):
  HDR-001 high      Strict-Transport-Security missing, max-age under one year, or no includeSubDomains (HTTPS responses)
  HDR-002 high      Content-Security-Policy missing; medium for 'unsafe-inline' or 'unsafe-eval' in script-src/default-src,
                    wildcard sources, missing object-src 'none' or base-uri; info when only Report-Only is set
  HDR-003 medium    X-Content-Type-Options not nosniff
  HDR-004 medium    no clickjacking protection (X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors)
  HDR-005 low       Referrer-Policy missing or unsafe-url / no-referrer-when-downgrade
  HDR-006 low       Permissions-Policy missing
  HDR-007 high      Set-Cookie without Secure or HttpOnly; medium without SameSite; info on __Host- prefix opportunity
  HDR-008 low       Server or X-Powered-By reveals software and version
  HDR-009 critical  Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true
  HDR-010 info      X-XSS-Protection present (deprecated; remove or set to 0), Expect-CT or Public-Key-Pins present (deprecated)
  HDR-011 low       Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy missing (process isolation)
  HDR-012 low       text/html response without charset
  HDR-013 medium    Cache-Control allows caching of a response that sets a cookie or is marked --sensitive

Grade: A no findings above low, B one medium, C several medium, D any high, F any critical.

Usage:
    headers_check.py FILE [--json] [--http] [--sensitive] [--fail-on SEVERITY]      (FILE: raw response or headers JSON; '-' stdin)

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 unreadable input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
ONE_YEAR = 31536000


def parse_response(text: str) -> tuple[dict[str, list[str]], str | None]:
    """Return (headers as lower-name -> [values], status line)."""
    stripped = text.strip()
    if stripped.startswith("{"):
        doc = json.loads(stripped)
        headers: dict[str, list[str]] = {}
        for k, v in doc.items():
            headers.setdefault(k.lower(), []).extend(v if isinstance(v, list) else [str(v)])
        return headers, None
    # keep the last response when curl followed redirects (several header blocks)
    blocks = re.split(r"\r?\n\r?\n", text)
    header_blocks = [b for b in blocks if re.match(r"^HTTP/\d", b.strip())]
    block = header_blocks[-1] if header_blocks else blocks[0]
    lines = block.strip().splitlines()
    status = lines[0].strip() if lines and lines[0].startswith("HTTP/") else None
    headers = {}
    for line in lines[1:] if status else lines:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers, status


def check(headers: dict[str, list[str]], https: bool, sensitive: bool) -> list[dict]:
    findings: list[dict] = []

    def add(fid, sev, header, title, fix):
        findings.append({"id": fid, "severity": sev, "header": header, "title": title, "fix": fix})

    def first(name: str) -> str | None:
        v = headers.get(name)
        return v[0] if v else None

    hsts = first("strict-transport-security")
    if https:
        if not hsts:
            add("HDR-001", "high", "Strict-Transport-Security", "Missing", "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < ONE_YEAR:
                add("HDR-001", "high", "Strict-Transport-Security", f"max-age below one year ({hsts})", "Set max-age=31536000 or more.")
            if "includesubdomains" not in hsts.lower():
                add("HDR-001", "medium", "Strict-Transport-Security", "No includeSubDomains", "Add includeSubDomains once every subdomain serves HTTPS.")
    csp = first("content-security-policy")
    csp_ro = first("content-security-policy-report-only")
    frame_protected = False
    if not csp:
        if csp_ro:
            add("HDR-002", "info", "Content-Security-Policy", "Only Report-Only is set; nothing is enforced", "Promote the policy to Content-Security-Policy once the reports are clean.")
        add("HDR-002", "high", "Content-Security-Policy", "Missing", "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    else:
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if part:
                name, *vals = part.split()
                directives[name.lower()] = [v.strip("'\"").lower() for v in vals]
        script = directives.get("script-src", directives.get("default-src", []))
        if "unsafe-inline" in script and not any(v.startswith(("nonce-", "sha256-", "sha384-", "sha512-")) for v in script):
            add("HDR-002", "medium", "Content-Security-Policy", "'unsafe-inline' in script-src without nonces or hashes", "Use nonces or hashes and drop 'unsafe-inline'.")
        if "unsafe-eval" in script:
            add("HDR-002", "medium", "Content-Security-Policy", "'unsafe-eval' in script-src", "Remove eval and new Function from the bundle, then drop 'unsafe-eval'.")
        if "*" in script or any(v in {"http:", "https:", "data:"} for v in script):
            add("HDR-002", "medium", "Content-Security-Policy", "Wildcard or scheme-only source in script-src", "List exact origins.")
        if "object-src" not in directives and "none" not in directives.get("default-src", []):
            add("HDR-002", "low", "Content-Security-Policy", "No object-src 'none'", "Add object-src 'none' (plugins are a bypass vector).")
        if "base-uri" not in directives:
            add("HDR-002", "low", "Content-Security-Policy", "No base-uri", "Add base-uri 'self'.")
        if "frame-ancestors" in directives:
            frame_protected = True
    if (first("x-content-type-options") or "").lower() != "nosniff":
        add("HDR-003", "medium", "X-Content-Type-Options", "Missing or not nosniff", "X-Content-Type-Options: nosniff")
    xfo = (first("x-frame-options") or "").upper()
    if xfo in {"DENY", "SAMEORIGIN"}:
        frame_protected = True
    if not frame_protected:
        add("HDR-004", "medium", "X-Frame-Options", "No clickjacking protection", "Add CSP frame-ancestors 'none' (or 'self'), plus X-Frame-Options: DENY for older browsers.")
    rp = (first("referrer-policy") or "").lower()
    if not rp:
        add("HDR-005", "low", "Referrer-Policy", "Missing", "Referrer-Policy: strict-origin-when-cross-origin")
    elif rp in {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}:
        add("HDR-005", "low", "Referrer-Policy", f"Leaky policy ({rp})", "Use strict-origin-when-cross-origin or no-referrer.")
    if not first("permissions-policy"):
        add("HDR-006", "low", "Permissions-Policy", "Missing", "Permissions-Policy: camera=(), microphone=(), geolocation=()")
    for cookie in headers.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        if https and "secure" not in [a.strip() for a in low.split(";")]:
            add("HDR-007", "high", "Set-Cookie", f"Cookie {name} without Secure", "Add Secure.")
        if "httponly" not in low:
            add("HDR-007", "high", "Set-Cookie", f"Cookie {name} without HttpOnly", "Add HttpOnly unless JavaScript must read it.")
        if "samesite=" not in low:
            add("HDR-007", "medium", "Set-Cookie", f"Cookie {name} without SameSite", "Add SameSite=Lax (or Strict).")
        elif "samesite=none" in low and "secure" not in low:
            add("HDR-007", "high", "Set-Cookie", f"Cookie {name} SameSite=None without Secure", "Browsers reject it; add Secure.")
        if https and not name.startswith("__Host-") and "path=/" in low and "domain=" not in low and "secure" in low:
            add("HDR-007", "info", "Set-Cookie", f"Cookie {name} could use the __Host- prefix", "Prefix the name with __Host- to bind it to this host and path.")
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        v = first(h)
        if v and (h != "server" or re.search(r"\d", v)):
            add("HDR-008", "low", h, f"Reveals software: {v}", "Remove the header or strip the version.")
    acao = first("access-control-allow-origin")
    acac = (first("access-control-allow-credentials") or "").lower()
    if acao == "*" and acac == "true":
        add("HDR-009", "critical", "Access-Control-Allow-Origin", "Wildcard origin with credentials", "Echo an allowlisted origin instead of *, or drop Allow-Credentials.")
    elif acao == "*" and sensitive:
        add("HDR-009", "medium", "Access-Control-Allow-Origin", "Wildcard origin on a sensitive response", "Restrict to the origins that need it.")
    if first("x-xss-protection") not in (None, "0"):
        add("HDR-010", "info", "X-XSS-Protection", "Deprecated header enabled", "Remove it or set X-XSS-Protection: 0; rely on CSP.")
    for h in ("expect-ct", "public-key-pins", "public-key-pins-report-only"):
        if first(h):
            add("HDR-010", "info", h, "Deprecated header", "Remove it.")
    if not first("cross-origin-opener-policy"):
        add("HDR-011", "low", "Cross-Origin-Opener-Policy", "Missing", "Cross-Origin-Opener-Policy: same-origin")
    if not first("cross-origin-resource-policy"):
        add("HDR-011", "low", "Cross-Origin-Resource-Policy", "Missing", "Cross-Origin-Resource-Policy: same-origin (or same-site)")
    ct = (first("content-type") or "").lower()
    if ct.startswith("text/html") and "charset" not in ct:
        add("HDR-012", "low", "Content-Type", "text/html without charset", "Content-Type: text/html; charset=utf-8")
    cc = (first("cache-control") or "").lower()
    if (headers.get("set-cookie") or sensitive) and "no-store" not in cc:
        add("HDR-013", "medium", "Cache-Control", "Response with cookies or sensitive data is cacheable", "Cache-Control: no-store (and Pragma: no-cache for old proxies).")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["header"]))
    return findings


def grade(findings: list[dict]) -> str:
    sev = [f["severity"] for f in findings]
    if "critical" in sev:
        return "F"
    if "high" in sev:
        return "D"
    mediums = sev.count("medium")
    return "A" if mediums == 0 else "B" if mediums == 1 else "C"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="captured response ('-' for stdin)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--http", action="store_true", help="the response was served over plain HTTP (skips HSTS and Secure-cookie checks)")
    ap.add_argument("--sensitive", action="store_true", help="the response carries personal or authenticated data")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = ap.parse_args(argv)
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")
        headers, status = parse_response(text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read response: {exc}", file=sys.stderr)
        return 2
    if not headers:
        print("error: no headers found (expected 'Name: value' lines or a JSON object)", file=sys.stderr)
        return 2
    findings = check(headers, not args.http, args.sensitive)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    report = {"version": VERSION, "status": status, "https": not args.http, "headers_present": sorted(headers), "grade": grade(findings), "findings": findings, "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"http-security-headers {VERSION}: grade {report['grade']}, {len(findings)} findings " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]) + (f" ({status})" if status else ""))
        for f in findings:
            print(f"  [{f['severity']:<8}] {f['id']} {f['header']}: {f['title']}\n      fix: {f['fix']}")
    worst = min((order[f["severity"]] for f in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
