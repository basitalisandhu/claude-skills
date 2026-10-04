#!/usr/bin/env python3
"""PreToolUse hook (matcher: Bash): ask before `curl`/`wget` targets a raw IP or a non-HTTPS URL.

Reads the Claude Code hook JSON on stdin and, when it finds something risky, prints a JSON decision
with `permissionDecision: "ask"` so the user confirms the call with the reason in front of them.
Exit codes follow the hooks reference: 0 with JSON on stdout for a decision, 0 with no output for
"no opinion", 1 (non-blocking) when the input could not be read.

It warns on:
  * a plain `http://` URL to a non-loopback host (credentials and content travel in clear text)
  * a URL whose host is a raw IPv4 or IPv6 address (no name to pin, often a C2 or a metadata endpoint);
    the cloud metadata address 169.254.169.254 is called out by name
  * a bare host with no scheme (`curl example.com`), because curl and wget default to HTTP
  * certificate checks turned off: curl `-k`/`--insecure`/`--proxy-insecure`, wget `--no-check-certificate`
  * remote content piped into an interpreter in the same pipeline (`curl ... | sh`, `wget -O- ... | python3`)

Loopback targets (localhost, 127.0.0.0/8, ::1, 0.0.0.0, *.localhost) are allowed without a prompt
unless AGENT_SECURITY_WARN_LOOPBACK=1 is set in the environment Claude Code runs in.

Standard library only. No network. No file writes.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _shellwords import Segment, segments  # noqa: E402

FETCHERS = {"curl", "wget", "curlie", "http", "https", "xh", "aria2c", "fetch"}
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "python", "python3", "python2", "node", "perl",
                "ruby", "php", "pwsh", "powershell", "deno", "bun", "osascript", "source", "eval", "exec"}
# options that take a value which must not be mistaken for a URL
CURL_VALUE_OPTS = {"-o", "--output", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
                   "-H", "--header", "-u", "--user", "-X", "--request", "-A", "--user-agent", "-e", "--referer",
                   "--cacert", "--cert", "--key", "--capath", "-T", "--upload-file", "-F", "--form", "--form-string",
                   "-b", "--cookie", "-c", "--cookie-jar", "-x", "--proxy", "--proxy-user", "-m", "--max-time",
                   "--connect-timeout", "--retry", "--retry-delay", "--limit-rate", "-r", "--range", "-w",
                   "--write-out", "-K", "--config", "--url", "-E", "--interface", "--resolve", "--dns-servers",
                   "--max-redirs", "--max-filesize", "-C", "--continue-at", "--oauth2-bearer", "--aws-sigv4",
                   "--unix-socket", "--abstract-unix-socket", "--output-dir", "--create-file-mode", "--json",
                   "--variable", "--expand-url", "--etag-save", "--etag-compare", "--stderr", "--trace",
                   "--trace-ascii", "--dump-header", "-D", "--pinnedpubkey", "--tls-max", "--ciphers", "--netrc-file"}
WGET_VALUE_OPTS = {"-O", "--output-document", "-P", "--directory-prefix", "--header", "--post-data", "--post-file",
                   "-U", "--user-agent", "-i", "--input-file", "-o", "--output-file", "-a", "--append-output",
                   "--load-cookies", "--save-cookies", "--user", "--password", "--http-user", "--http-password",
                   "-T", "--timeout", "-t", "--tries", "-w", "--wait", "--limit-rate", "-e", "--execute", "-B",
                   "--base", "--ca-certificate", "--certificate", "--private-key", "--referer", "--method",
                   "--body-data", "--body-file", "-A", "--accept", "-R", "--reject", "-D", "--domains",
                   "--exclude-domains", "-l", "--level", "--bind-address", "--local-encoding", "--remote-encoding"}
INSECURE_FLAGS = {"-k", "--insecure", "--proxy-insecure", "--no-check-certificate", "--ssl-no-revoke", "--doh-insecure",
                  "--no-verify", "--verify=no", "--verify=false"}
COMMON_TLDS = {"com", "net", "org", "io", "dev", "ai", "co", "app", "cloud", "me", "info", "xyz", "gov", "edu", "mil",
               "int", "uk", "de", "fr", "jp", "cn", "ru", "in", "au", "ca", "br", "nl", "se", "no", "fi", "dk", "pl",
               "it", "es", "ch", "at", "be", "cz", "eu", "us", "tech", "site", "online", "store", "shop", "biz", "tv",
               "cc", "pk", "ae", "sg", "hk", "kr", "tw", "nz", "ie", "pt", "gr", "tr", "za", "mx", "ar", "cl", "id",
               "ph", "vn", "th", "my", "il", "sa", "eg", "ng", "ke", "ua", "ro", "hu", "sk", "lt", "lv", "ee", "is",
               "lu", "li", "ly", "to", "gg", "im", "io", "sh", "ws", "fm", "am", "network", "systems", "software",
               "tools", "zone", "works", "live", "news", "blog", "page", "run", "codes", "digital", "security"}
URL_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://")
IPV4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/.*)?$")
BARE_HOST_RE = re.compile(r"^(?P<host>(?:[A-Za-z0-9-]+\.)+(?P<tld>[A-Za-z]{2,}))(?::\d+)?(?P<rest>/.*)?$")
LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "host.docker.internal", "0.0.0.0"}


def _is_loopback(host: str) -> bool:
    h = host.strip("[]").lower()
    if h in LOOPBACK_NAMES or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        return False


def _ip_kind(host: str) -> str | None:
    h = host.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None
    if h == "169.254.169.254" or (ip.version == 6 and h.lower().startswith("fd00:ec2::254")):
        return "a raw IP address: the cloud instance metadata endpoint"
    if ip.is_link_local:
        return "a raw IP address: link-local"
    if ip.is_private:
        return "a raw IP address: private network or reserved range"
    return "a raw IP address: public"


def _targets(seg: Segment) -> list[str]:
    """URL-like positional arguments of a curl/wget segment."""
    value_opts = CURL_VALUE_OPTS if seg.program in {"curl", "curlie"} else WGET_VALUE_OPTS if seg.program == "wget" else CURL_VALUE_OPTS | WGET_VALUE_OPTS
    out: list[str] = []
    skip = False
    for a in seg.args:
        if skip:
            skip = False
            continue
        if a in value_opts:
            skip = True
            continue
        if a.startswith("-"):
            continue
        if a in {">", ">>", "<", "2>&1", "|", "&"}:
            continue
        out.append(a)
    return out


def _check_target(token: str, warn_loopback: bool) -> str | None:
    m = URL_RE.match(token)
    if m:
        scheme = m.group("scheme").lower()
        try:
            host = urlsplit(token).hostname or ""
        except ValueError:
            host = ""
        if not host:
            return None
        if _is_loopback(host) and not warn_loopback:
            return None
        kind = _ip_kind(host)
        reasons = []
        if scheme in {"http", "ftp", "ws"}:
            reasons.append(f"plain {scheme.upper()} to {host} (no encryption, no server identity)")
        if kind:
            reasons.append(f"{token} targets {kind}")
        return "; ".join(reasons) if reasons else None
    if IPV4_RE.match(token) or token.startswith("["):
        host = token.split("/")[0].split(":")[0] if not token.startswith("[") else token.split("]")[0]
        if _is_loopback(host) and not warn_loopback:
            return None
        kind = _ip_kind(host) or "a raw IP address"
        return f"{token} targets {kind}, with no scheme, so plain HTTP is used"
    bm = BARE_HOST_RE.match(token)
    if bm and bm.group("tld").lower() in COMMON_TLDS and not os.path.exists(token):
        return f"`{token}` has no scheme, so curl/wget will use plain HTTP"
    return None


def analyse(command: str) -> list[str]:
    warn_loopback = os.environ.get("AGENT_SECURITY_WARN_LOOPBACK") == "1"
    reasons: list[str] = []
    segs = segments(command)
    fetch_in_pipeline = False
    for seg in segs:
        if seg.operator != "|":
            fetch_in_pipeline = False
        if seg.program in FETCHERS:
            for flag in seg.args:
                if flag in INSECURE_FLAGS or flag.startswith("--verify="):
                    reasons.append(f"`{seg.program} {flag}` disables certificate verification")
                    break
            for t in _targets(seg):
                r = _check_target(t, warn_loopback)
                if r:
                    reasons.append(r)
            fetch_in_pipeline = True
        elif seg.program in INTERPRETERS and seg.operator == "|" and fetch_in_pipeline:
            reasons.append(f"remote content is piped straight into `{seg.program}`; download to a file, read it, then run it")
    seen: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    return seen


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001
        print(f"warn-insecure-fetch: could not read hook input ({exc})", file=sys.stderr)
        return 1
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not isinstance(command, str) or not command.strip():
        return 0
    reasons = analyse(command)
    if not reasons:
        return 0
    reason = "warn-insecure-fetch (agent-security plugin): " + " | ".join(reasons)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
