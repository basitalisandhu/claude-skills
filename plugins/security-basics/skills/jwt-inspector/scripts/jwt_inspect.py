#!/usr/bin/env python3
"""Decode a JSON Web Token without verifying it, explain the claims, and flag unsafe settings.

The signature is NOT checked: this tool has no key and makes no attempt. Every report says so. Use it to see
what a token says and whether its shape is sound; verification belongs in the application with its key.

Checks (id, severity):
  JWT-001 critical  alg is none, or the signature segment is empty
  JWT-002 high      exp missing; info when the token has expired; medium when the lifetime (exp - iat) exceeds 24 hours, high beyond 30 days
  JWT-003 high      header carries jku or x5u (key fetched from a URL the token chooses) or an odd kid (path or SQL characters)
  JWT-004 medium    alg is a symmetric HMAC (HS256/384/512): the verifier holds the same secret as the issuer
  JWT-005 low       iss, aud or sub missing (hard to scope the token)
  JWT-006 medium    nbf or iat in the future relative to --now (clock skew or forged)
  JWT-007 high      sensitive-looking claims in the payload (password, secret, ssn, card number); info for e-mail or phone
  JWT-008 low       token larger than 4 KB (cookie and header limits)
  JWT-009 info      five segments: this is a JWE (encrypted); only the header is readable
  JWT-010 low       typ missing in the header, or cty/typ set to something unusual

Usage:
    jwt_inspect.py TOKEN [--json] [--now ISO8601] [--fail-on SEVERITY]      ('-' reads the token from stdin; a 'Bearer ' prefix is stripped)

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 not a JWT.
Standard library only. No network. Never verifies.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SENSITIVE_RE = re.compile(r"(?i)^(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|ssn|social[_-]?security|card[_-]?number|cc[_-]?number|cvv|pin)$")
PII_RE = re.compile(r"(?i)^(email|e-mail|phone|mobile|address|dob|birth[_-]?date|name|given[_-]?name|family[_-]?name)$")
CLAIM_HELP = {"iss": "issuer", "sub": "subject (the principal)", "aud": "audience (who may accept it)", "exp": "expires at", "nbf": "not valid before", "iat": "issued at", "jti": "token id", "scope": "granted scopes", "scp": "granted scopes", "roles": "roles", "azp": "authorised party", "nonce": "replay nonce", "sid": "session id", "client_id": "client"}


def b64url_decode(seg: str) -> bytes:
    seg = seg.strip()
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode(token: str) -> dict:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) not in (3, 5):
        raise ValueError(f"expected 3 (JWS) or 5 (JWE) dot-separated segments, found {len(parts)}")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"header is not base64url JSON: {exc}")
    out = {"segments": len(parts), "header": header, "payload": None, "signature_present": bool(parts[-1]), "size": len(token)}
    if len(parts) == 3:
        try:
            payload_bytes = b64url_decode(parts[1])
            out["payload"] = json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"payload is not base64url JSON: {exc}")
        if not isinstance(out["payload"], dict):
            raise ValueError("payload is not a JSON object")
    return out


def fmt_time(ts, now: dt.datetime) -> str:
    try:
        when = dt.datetime.fromtimestamp(int(ts), tz=dt.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return f"{ts!r} (not a unix timestamp)"
    delta = when - now
    secs = int(delta.total_seconds())
    rel = f"in {human(secs)}" if secs >= 0 else f"{human(-secs)} ago"
    return f"{when.isoformat(timespec='seconds')} ({rel})"


def human(secs: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit}" + (f" {(secs % size) // (size // 24 if unit == 'd' else 60)}{'h' if unit == 'd' else 'm'}" if secs % size and unit != "m" else "")
    return f"{secs}s"


def analyse(tok: dict, now: dt.datetime) -> list[dict]:
    findings: list[dict] = []

    def add(fid, sev, title, fix):
        findings.append({"id": fid, "severity": sev, "title": title, "fix": fix})

    h = tok["header"]
    alg = str(h.get("alg", "")).strip()
    if not alg or alg.lower() == "none":
        add("JWT-001", "critical", f"alg is {alg or 'missing'}", "Reject tokens whose alg is none; pin the expected algorithm in the verifier.")
    if not tok["signature_present"] and tok["segments"] == 3:
        add("JWT-001", "critical", "Signature segment is empty", "An unsigned token must never be accepted.")
    if alg.upper().startswith("HS"):
        add("JWT-004", "medium", f"Symmetric algorithm {alg}", "Fine for a single issuer-verifier pair with a long random secret; use RS256/ES256 when several services verify.")
    for k in ("jku", "x5u"):
        if k in h:
            add("JWT-003", "high", f"Header {k} points the verifier at a URL: {str(h[k])[:80]}", "Ignore jku/x5u in the verifier and use a pinned key set.")
    kid = h.get("kid")
    if isinstance(kid, str) and re.search(r"(\.\./|/|\\|'|\"|;|--|\s)", kid):
        add("JWT-003", "high", f"kid contains path or query characters: {kid[:60]!r}", "Treat kid as an opaque lookup key, never as a path or query fragment.")
    if "typ" not in h:
        add("JWT-010", "low", "Header has no typ", "Set typ: JWT (or at+jwt for access tokens) so verifiers can reject other token types.")
    elif str(h.get("typ")).upper() not in {"JWT", "AT+JWT", "JOSE", "ID-TOKEN", "LOGOUT+JWT", "SECEVENT+JWT", "DPOP+JWT"}:
        add("JWT-010", "low", f"Unusual typ {h.get('typ')!r}", "Confirm the verifier expects this type.")
    if tok["segments"] == 5:
        add("JWT-009", "info", "Five segments: JWE (encrypted) token", "Only the header is readable without the key; decrypt in the application to inspect claims.")
    if tok["size"] > 4096:
        add("JWT-008", "low", f"Token is {tok['size']} bytes", "Keep tokens under 4 KB; cookies and some proxies cap header size.")
    p = tok["payload"]
    if p is None:
        return findings
    now_ts = int(now.timestamp())
    exp, iat, nbf = p.get("exp"), p.get("iat"), p.get("nbf")
    if exp is None:
        add("JWT-002", "high", "No exp claim", "Issue tokens with an expiry; without one a leaked token lives forever.")
    else:
        try:
            exp_i = int(exp)
            if exp_i < now_ts:
                add("JWT-002", "info", f"Token expired {human(now_ts - exp_i)} ago", "Expected if this is an old token; the verifier must reject it.")
            if iat is not None:
                life = exp_i - int(iat)
                if life > 30 * 86400:
                    add("JWT-002", "high", f"Lifetime is {life // 86400} days", "Access tokens should live minutes to hours; use refresh tokens for longer sessions.")
                elif life > 86400:
                    add("JWT-002", "medium", f"Lifetime is {round(life / 3600)} hours", "Shorten to a few hours unless the token is a refresh token.")
        except (TypeError, ValueError):
            add("JWT-002", "high", f"exp is not a number: {exp!r}", "exp must be a NumericDate (seconds since epoch).")
    for name in ("nbf", "iat"):
        v = p.get(name)
        if v is not None:
            try:
                if int(v) > now_ts + 300:
                    add("JWT-006", "medium", f"{name} is in the future ({fmt_time(v, now)})", "Check clock skew between issuer and verifier; verifiers should allow at most a few minutes of leeway.")
            except (TypeError, ValueError):
                add("JWT-006", "medium", f"{name} is not a number: {v!r}", "Use NumericDate.")
    for name in ("iss", "aud", "sub"):
        if name not in p:
            add("JWT-005", "low", f"No {name} claim", {"iss": "Set iss so verifiers can pin the issuer.", "aud": "Set aud so a token for one service is rejected by another.", "sub": "Set sub to identify the principal."}[name])
    for k in p:
        if SENSITIVE_RE.match(str(k)):
            add("JWT-007", "high", f"Sensitive claim {k!r} in the payload (readable by anyone holding the token)", "Remove it; a JWS payload is only base64, not encrypted.")
        elif PII_RE.match(str(k)):
            add("JWT-007", "info", f"Personal data claim {k!r} in the payload", "Keep PII out of access tokens unless the consumer needs it; consider a JWE or an opaque token.")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["id"]))
    return findings


def render_text(tok: dict, findings: list[dict], now: dt.datetime) -> str:
    lines = [f"jwt-inspector {VERSION}: SIGNATURE NOT VERIFIED (no key; decode only)", "header:"]
    for k, v in tok["header"].items():
        lines.append(f"  {k}: {json.dumps(v)}")
    if tok["payload"] is not None:
        lines.append("payload:")
        for k, v in tok["payload"].items():
            shown = fmt_time(v, now) if k in {"exp", "nbf", "iat", "auth_time"} else json.dumps(v)
            help_text = f"  ({CLAIM_HELP[k]})" if k in CLAIM_HELP else ""
            lines.append(f"  {k}: {shown}{help_text}")
    lines.append(f"signature: {'present' if tok['signature_present'] else 'EMPTY'}; size {tok['size']} bytes; segments {tok['segments']}")
    if findings:
        lines.append("findings:")
        for f in findings:
            lines.append(f"  [{f['severity']:<8}] {f['id']} {f['title']}\n      fix: {f['fix']}")
    else:
        lines.append("findings: none")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("token", help="the token, or '-' to read it from stdin")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--now", help="ISO 8601 reference time (default: current UTC time)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = ap.parse_args(argv)
    token = sys.stdin.read() if args.token == "-" else args.token
    try:
        now = dt.datetime.fromisoformat(args.now).astimezone(dt.timezone.utc) if args.now else dt.datetime.now(dt.timezone.utc)
        if args.now and dt.datetime.fromisoformat(args.now).tzinfo is None:
            now = dt.datetime.fromisoformat(args.now).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        print("error: --now must be ISO 8601", file=sys.stderr)
        return 2
    try:
        tok = decode(token)
    except ValueError as exc:
        print(f"error: not a JWT: {exc}", file=sys.stderr)
        return 2
    findings = analyse(tok, now)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    if args.json:
        print(json.dumps({"version": VERSION, "verified": False, "header": tok["header"], "payload": tok["payload"], "signature_present": tok["signature_present"],
                          "segments": tok["segments"], "size": tok["size"], "findings": findings,
                          "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}, "fail_on": args.fail_on}, indent=2))
    else:
        print(render_text(tok, findings, now))
    worst = min((order[f["severity"]] for f in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
