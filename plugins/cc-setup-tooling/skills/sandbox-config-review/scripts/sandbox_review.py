#!/usr/bin/env python3
"""sandbox_review.py: review the Claude Code sandbox settings of a project across settings scopes, say what is
actually enforced, and flag the settings that leave the boundary open.

The sandbox is the boundary the operating system enforces around Bash, PowerShell and Monitor commands and the
processes they start. Its rules come from https://code.claude.com/docs/en/sandboxing (read 2026-10-16); this script
applies only the key names, defaults and merge rules stated there.

Scopes read (offline, local files only):
  * --project DIR: DIR/.claude/settings.json (project, committed with the repository) and
    DIR/.claude/settings.local.json (local);
  * --user FILE: your user settings, normally ~/.claude/settings.json (not read unless given);
  * --managed FILE: a managed settings file.
The --settings command-line flag and server-managed settings are not read.

Merge rules (from the page):
  * Boolean keys: a managed value wins; otherwise local, then project, then user. allowUnsandboxedCommands false in
    user or managed settings holds even when a project sets true.
  * Array keys (excludedCommands, filesystem.*, network.allowedDomains, network.deniedDomains, credentials entries,
    permission rules) are merged across scopes, keeping the scope of each entry.
  * Only user and managed settings are honoured for filesystem.disabled, network.strictAllowlist, allowAppleEvents,
    credentials mask entries and network.tlsTerminate. When managed settings configure sandbox.filesystem or list a
    credentials.files deny entry, only managed settings can set filesystem.disabled. allowManagedDomainsOnly is read
    from managed settings only.
  * Admin-required sandbox (managed allowUnsandboxedCommands false, or managed allowManagedDomainsOnly true): the
    repository's excludedCommands, network.allowedDomains, network.allowUnixSockets, filesystem.allowWrite,
    WebFetch(domain:...) allow rules, proxy ports, and true values of the weaker-isolation keys are ignored, as is a
    repository false for enabled or failIfUnavailable when user settings set true.
  * network.strictAllowlist true in user or managed settings: the repository's allowedDomains, WebFetch(domain:...)
    allow rules and proxy ports are ignored. allowManagedDomainsOnly: only managed domain entries count.
  * WebFetch(domain:...) allow rules add hosts to the sandbox allowlist; only an exact host, a leading "*." or a bare
    "*" affect the sandbox. WebFetch(domain:...) deny rules join the denied domains.

Rules (severity):
  sandbox-off (high)                  sandbox.enabled is not true (off by default)
  windows-native-unsandboxed (high)   --platform windows: Claude Code runs commands unsandboxed there
  fail-open (medium)                  failIfUnavailable is not true, so a missing dependency means no sandbox
  escape-hatch-open (medium)          allowUnsandboxedCommands is not false and no Bash(dangerouslyDisableSandbox:true)
                                      ask rule exists
  excluded-command-broad (high, or medium when narrowed to more words) an excludedCommands entry for a shell,
                                      interpreter, network tool, package manager, container tool or command runner
  domain-wildcard-broad (high for "*" or a top-level domain, medium for the publishable-host list)
  allow-deny-conflict (low)           an allowed domain that a denied entry also covers (deny wins)
  credentials-readable (medium)       no denyRead, credentials or Read deny entry covers ~/.ssh, ~/.aws, ~/.config/gh,
                                      ~/.netrc or .env files
  filesystem-disabled (high with autoAllowBashIfSandboxed, else medium)
  unix-sockets-all (high)             network.allowAllUnixSockets is true
  weaker-isolation (medium)           enableWeakerNestedSandbox, enableWeakerNetworkIsolation, allowLocalBinding or
                                      allowAppleEvents is true
  proxy-port-set (medium)             httpProxyPort or socksProxyPort applies, so the built-in domain checks stop
  repo-loosens (high if honoured, low if ignored) a loosening value in the committed .claude/settings.json
  strict-allowlist-ignored-scope (medium) strictAllowlist set in project or local settings, where it has no effect
The active-sandbox checks (fail-open, escape-hatch-open, credentials-readable) are skipped while the sandbox is off
or the platform is native Windows; the configuration checks still run.

Output: Markdown (default) or JSON (--format json, or --json): the effective values with their source scope, the
effective allowed and denied domains (WebFetch rules marked), the findings, and a list of curl commands to run as
sandboxed commands in a session to confirm enforcement. The commands are printed, never run.

Exit codes: 0 no finding at or above --fail-on (default high), 1 at least one, 2 bad input (a file missing, invalid
JSON, or a wrong type such as a string where an array is required).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

DOC_URL = "https://code.claude.com/docs/en/sandboxing"
SCOPES = ("user", "project", "local", "managed")  # display order
PRECEDENCE = ("managed", "local", "project", "user")  # first set value wins for a Boolean key
REPO = ("project", "local")
TRUSTED = ("user", "managed")
SEVERITIES = {"low": 1, "medium": 2, "high": 3}

BOOL_KEYS = (
    "enabled",
    "failIfUnavailable",
    "allowUnsandboxedCommands",
    "autoAllowBashIfSandboxed",
    "filesystem.disabled",
    "network.strictAllowlist",
    "network.allowManagedDomainsOnly",
    "network.allowAllUnixSockets",
    "network.allowLocalBinding",
    "enableWeakerNestedSandbox",
    "enableWeakerNetworkIsolation",
    "allowAppleEvents",
)
# Defaults the page states. Keys without a stated default show "not set".
DEFAULTS = {
    "enabled": False,
    "failIfUnavailable": False,
    "allowUnsandboxedCommands": True,
    "autoAllowBashIfSandboxed": True,
    "filesystem.disabled": False,
}
LIST_KEYS = (
    "excludedCommands",
    "filesystem.allowWrite",
    "filesystem.denyWrite",
    "filesystem.denyRead",
    "filesystem.allowRead",
    "network.allowedDomains",
    "network.deniedDomains",
    "network.allowUnixSockets",
)
INT_KEYS = ("network.httpProxyPort", "network.socksProxyPort")
WEAKER = ("network.allowAllUnixSockets", "network.allowLocalBinding", "enableWeakerNestedSandbox")
WEAKER += ("enableWeakerNetworkIsolation",)
ONLY_TRUSTED_BOOLS = ("filesystem.disabled", "network.strictAllowlist", "allowAppleEvents")
REPO_IGNORED_WHEN_ADMIN = ("excludedCommands", "network.allowedDomains", "network.allowUnixSockets")
REPO_IGNORED_WHEN_ADMIN += ("filesystem.allowWrite", "webfetch-allow")
ESCAPE_ASK_RULE = "Bash(dangerouslyDisableSandbox:true)"

# excludedCommands: first words that hand Claude a general-purpose tool outside the sandbox.
BROAD_COMMANDS = {
    "shell": {"bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "pwsh", "powershell", "cmd"},
    "interpreter": {"python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "osascript", "Rscript"},
    "network tool": {"curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "ftp"},
    "package manager": {"npm", "npx", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "uvx", "poetry", "gem", "bundle"}
    | {"cargo", "go", "brew", "apt", "apt-get", "dnf", "yum", "composer"},
    "container tool": {"docker", "podman", "kubectl"},
    "command runner": {"env", "xargs", "sudo", "eval", "exec", "make", "*"},
}
# The skill's default list of wildcard suffixes where anyone can publish content (documented in SKILL.md).
PUBLISHABLE = (
    "githubusercontent.com",
    "github.io",
    "gitlab.io",
    "amazonaws.com",
    "cloudfront.net",
    "blob.core.windows.net",
    "web.core.windows.net",
    "azurewebsites.net",
    "azureedge.net",
    "googleapis.com",
    "googleusercontent.com",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "pastebin.com",
    "glitch.me",
    "onrender.com",
    "fly.dev",
)
TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in"}
TWO_LABEL_SUFFIXES |= {"co.za", "com.br", "com.cn", "com.pk", "com.sg"}
CREDENTIAL_TARGETS = (
    ("~/.ssh", "SSH keys"),
    ("~/.aws", "AWS credentials"),
    ("~/.config/gh", "GitHub CLI token"),
    ("~/.netrc", "netrc passwords"),
    (".env", ".env files in the project"),
)
REFUSE_CANDIDATES = ("example.com", "example.org", "example.net")


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


# ----------------------------------------------------------------------------------------------------------- loading


def load_settings(path: Path, label: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"{label}: cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{label}: invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{label}: {path.name} must hold a JSON object")
    return data


def get(block: dict, dotted: str):
    cur = block
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def check_types(data: dict, label: str) -> None:
    """Raise InputError for a value of the wrong type in the keys this script reads."""
    sandbox = data.get("sandbox", {})
    if not isinstance(sandbox, dict):
        raise InputError(f"{label}: sandbox must be an object")
    for sub in ("filesystem", "network", "credentials"):
        if sub in sandbox and not isinstance(sandbox[sub], dict):
            raise InputError(f"{label}: sandbox.{sub} must be an object")
    for key in BOOL_KEYS:
        value = get(sandbox, key)
        if value is not None and not isinstance(value, bool):
            raise InputError(f"{label}: sandbox.{key} must be true or false, not {type(value).__name__}")
    for key in LIST_KEYS:
        value = get(sandbox, key)
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
            raise InputError(f"{label}: sandbox.{key} must be an array of strings")
    for key in INT_KEYS:
        value = get(sandbox, key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise InputError(f"{label}: sandbox.{key} must be a whole number")
    for key, field in (("credentials.files", "path"), ("credentials.envVars", "name")):
        value = get(sandbox, key)
        if value is None:
            continue
        if not isinstance(value, list):
            raise InputError(f"{label}: sandbox.{key} must be an array of objects")
        for i, entry in enumerate(value):
            if not isinstance(entry, dict) or not isinstance(entry.get(field), str):
                raise InputError(f"{label}: sandbox.{key}[{i}] needs a string {field!r}")
            if entry.get("mode") not in ("deny", "mask"):
                raise InputError(f'{label}: sandbox.{key}[{i}].mode must be "deny" or "mask"')
    perms = data.get("permissions", {})
    if not isinstance(perms, dict):
        raise InputError(f"{label}: permissions must be an object")
    for key in ("allow", "ask", "deny"):
        value = perms.get(key)
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
            raise InputError(f"{label}: permissions.{key} must be an array of strings")
    value = perms.get("blockReadsOutsideWorkingDirectories")
    if value is not None and not isinstance(value, bool):
        raise InputError(f"{label}: permissions.blockReadsOutsideWorkingDirectories must be true or false")


# ---------------------------------------------------------------------------------------------------------- helpers


def host_of(entry: str) -> str:
    """The host part of a domain entry, lower case, without a port."""
    e = entry.strip().lower()
    if e.startswith("["):
        return e.split("]", 1)[0] + "]"
    head, sep, port = e.rpartition(":")
    return head if sep and port.isdigit() else e


def domain_covers(pattern: str, host: str, apex: bool = False) -> bool:
    """True when the domain entry pattern admits host (exact, bare "*", or a leading "*.").

    The page does not say whether "*.example.com" admits "example.com" itself; apex=True assumes it does, which is
    the cautious reading when choosing a host that should be refused."""
    p, h = host_of(pattern), host_of(host)
    if p == "*" or p == h:
        return True
    if p.startswith("*."):
        suffix = p[1:]
        return h.endswith(suffix) or (apex and h == suffix[1:])
    return False


def wildcard_risk(entry: str) -> tuple[str, str] | None:
    host = host_of(entry)
    if host == "*":
        return "high", "allows every host"
    if not host.startswith("*."):
        return None
    suffix = host[2:]
    if "." not in suffix or suffix in TWO_LABEL_SUFFIXES:
        return "high", f"allows every host under the top-level domain .{suffix}"
    for p in PUBLISHABLE:
        if suffix == p or suffix.endswith("." + p):
            return "medium", f"covers hosts anyone can publish to ({p}, in the default list)"
    return None


def webfetch_domain(rule: str) -> str | None:
    r = rule.strip()
    if r.startswith("WebFetch(domain:") and r.endswith(")"):
        return r[len("WebFetch(domain:") : -1].strip()
    return None


def sandbox_form(domain: str) -> bool:
    """WebFetch domain forms the sandbox honours: an exact host, a leading "*." or a bare "*"."""
    host = host_of(domain)
    return host == "*" or "*" not in (host[2:] if host.startswith("*.") else host)


def norm_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    for tail in ("/**", "/*"):
        while s.endswith(tail):
            s = s[: -len(tail)]
    s = s.rstrip("/") if len(s) > 1 else s
    if s.startswith("./"):
        s = s[2:]
    return s or "/"


def path_covers(entry: str, target: str) -> bool:
    e, t = norm_path(entry), norm_path(target)
    if e in ("/", "//"):
        return True
    if t == ".env":
        last = e.rsplit("/", 1)[-1]
        return fnmatch.fnmatchcase(".env", last)
    return t == e or t.startswith(e + "/") or fnmatch.fnmatchcase(t, e)


def read_rule_path(rule: str) -> str | None:
    r = rule.strip()
    if r.startswith("Read(") and r.endswith(")"):
        inner = r[5:-1].strip()
        if inner.startswith("//"):
            return inner[1:]
        return inner
    return None


def command_words(entry: str) -> list[str]:
    return [w for w in entry.replace(":*", " *").split() if w]


def broad_command(entry: str) -> tuple[str, str] | None:
    words = command_words(entry)
    if not words:
        return None
    first = words[0]
    for kind, names in BROAD_COMMANDS.items():
        if first in names:
            narrowed = len([w for w in words[1:] if w != "*"]) > 0
            sev = "medium" if narrowed and first != "*" else "high"
            article = "an" if kind[0] in "aeiou" else "a"
            what = "every command" if first == "*" else f"{article} {kind} ({first})"
            return sev, f"runs {what} outside the sandbox with your full access"
    return None


# ---------------------------------------------------------------------------------------------------------- review


class Review:
    def __init__(self, scopes: dict[str, dict | None], paths: dict[str, str], platform: str):
        self.data = {k: (v or {}) for k, v in scopes.items()}
        self.present = {k: v is not None for k, v in scopes.items()}
        self.paths = paths
        self.platform = platform
        self.findings: list[dict] = []
        managed_sb = self.sb("managed")
        self.admin_reasons = []
        if get(managed_sb, "allowUnsandboxedCommands") is False:
            self.admin_reasons.append("managed allowUnsandboxedCommands is false")
        if get(managed_sb, "network.allowManagedDomainsOnly") is True:
            self.admin_reasons.append("managed allowManagedDomainsOnly is true")
        self.admin_required = bool(self.admin_reasons)
        self.managed_domains_only = get(managed_sb, "network.allowManagedDomainsOnly") is True
        self.strict_lock = any(get(self.sb(s), "network.strictAllowlist") is True for s in TRUSTED)
        self.managed_fs_lock = isinstance(managed_sb.get("filesystem"), dict) or any(
            e.get("mode") == "deny" for e in (get(managed_sb, "credentials.files") or [])
        )

    def sb(self, scope: str) -> dict:
        return self.data[scope].get("sandbox", {}) or {}

    def perms(self, scope: str, key: str) -> list[str]:
        return list((self.data[scope].get("permissions", {}) or {}).get(key, []) or [])

    def add(self, rule: str, severity: str, scope: str, item: str, detail: str) -> None:
        self.findings.append({"rule": rule, "severity": severity, "scope": scope, "item": item, "detail": detail})

    # ------------------------------------------------------------------------------------------- honoured values

    def bool_honoured(self, scope: str, key: str, value: bool) -> tuple[bool, str]:
        if key == "network.allowManagedDomainsOnly" and scope != "managed":
            return False, "read from managed settings only"
        if key in ONLY_TRUSTED_BOOLS and scope in REPO:
            return False, "not honoured from project or local settings"
        if key == "filesystem.disabled" and self.managed_fs_lock and scope != "managed":
            return False, "managed settings configure the filesystem, so only they can set this"
        if self.admin_required and scope in REPO:
            if key in WEAKER and value is True:
                return False, "admin-required sandbox ignores a repository true"
            if key in ("enabled", "failIfUnavailable") and value is False and get(self.sb("user"), key) is True:
                return False, "admin-required sandbox ignores a repository false when user settings set true"
        return True, ""

    def effective_bool(self, key: str) -> dict:
        ignored = []
        managed = get(self.sb("managed"), key)
        if isinstance(managed, bool):
            return {"value": managed, "source": "managed", "ignored": ignored}
        if key == "allowUnsandboxedCommands" and get(self.sb("user"), key) is False:
            for s in REPO:
                if get(self.sb(s), key) is True:
                    ignored.append({"scope": s, "value": True, "reason": "a user false holds against a project true"})
            return {"value": False, "source": "user", "ignored": ignored}
        for scope in PRECEDENCE[1:]:
            value = get(self.sb(scope), key)
            if not isinstance(value, bool):
                continue
            ok, why = self.bool_honoured(scope, key, value)
            if ok:
                return {"value": value, "source": scope, "ignored": ignored}
            ignored.append({"scope": scope, "value": value, "reason": why})
        return {"value": DEFAULTS.get(key), "source": "default" if key in DEFAULTS else None, "ignored": ignored}

    def list_honoured(self, scope: str, key: str) -> tuple[bool, str]:
        if scope in REPO and self.admin_required and key in REPO_IGNORED_WHEN_ADMIN:
            return False, "admin-required sandbox (" + "; ".join(self.admin_reasons) + ") ignores repository entries"
        if key in ("network.allowedDomains", "webfetch-allow"):
            if self.managed_domains_only and scope != "managed":
                return False, "managed allowManagedDomainsOnly honours managed entries only"
            if self.strict_lock and scope in REPO:
                return False, "strictAllowlist in user or managed settings ignores repository entries"
        if key in INT_KEYS:
            if self.managed_domains_only and scope != "managed":
                return False, "with allowManagedDomainsOnly only managed settings can set a proxy port"
            managed_deny = get(self.sb("managed"), "network.deniedDomains") or any(
                webfetch_domain(r) for r in self.perms("managed", "deny")
            )
            if scope in REPO and (self.admin_required or self.strict_lock or managed_deny):
                return False, "a network lock ignores repository proxy ports"
        return True, ""

    def entries(self, key: str) -> list[dict]:
        out = []
        for scope in SCOPES:
            raw = get(self.sb(scope), key)
            for value in raw if isinstance(raw, list) else ([] if raw is None else [raw]):
                ok, why = self.list_honoured(scope, key)
                out.append({"value": value, "scope": scope, "honoured": ok, "reason": why})
        return out

    # ------------------------------------------------------------------------------------------------- domains

    def domains(self) -> tuple[list[dict], list[dict]]:
        allowed, denied = [], []
        for e in self.entries("network.allowedDomains"):
            allowed.append({"host": e["value"], "scope": e["scope"], "via": "allowedDomains", **_hr(e)})
        for scope in SCOPES:
            for rule in self.perms(scope, "allow"):
                d = webfetch_domain(rule)
                if d is None:
                    continue
                ok, why = self.list_honoured(scope, "webfetch-allow")
                if ok and not sandbox_form(d):
                    ok, why = False, "this wildcard form matches fetches but has no effect on sandboxed commands"
                allowed.append({"host": d, "scope": scope, "via": "WebFetch(domain:) allow rule", "honoured": ok})
                allowed[-1]["reason"] = why
        for e in self.entries("network.deniedDomains"):
            denied.append({"host": e["value"], "scope": e["scope"], "via": "deniedDomains", "honoured": True})
            denied[-1]["reason"] = ""
        for scope in SCOPES:
            for rule in self.perms(scope, "deny"):
                d = webfetch_domain(rule)
                if d is not None:
                    denied.append(
                        {
                            "host": d,
                            "scope": scope,
                            "via": "WebFetch(domain:) deny rule",
                            "honoured": True,
                            "reason": "",
                        }
                    )
        for a in allowed:
            a["denied_by"] = next((n["host"] for n in denied if domain_covers(n["host"], a["host"])), None)
        return allowed, denied

    # ------------------------------------------------------------------------------------------------- the checks

    def run(self) -> dict:
        eff = {k: self.effective_bool(k) for k in BOOL_KEYS}
        lists = {k: self.entries(k) for k in LIST_KEYS}
        ports = {k: self.entries(k) for k in INT_KEYS}
        allowed, denied = self.domains()
        enabled = eff["enabled"]["value"] is True
        windows = self.platform == "windows"
        active = enabled and not windows

        if windows:
            self.add(
                "windows-native-unsandboxed",
                "high",
                "platform",
                "windows",
                "on native Windows Claude Code runs commands unsandboxed; run it inside WSL2 to use the sandbox"
                + (
                    ", and with failIfUnavailable true it exits at startup" if eff["failIfUnavailable"]["value"] else ""
                ),
            )
        if not enabled:
            src = eff["enabled"]["source"]
            how = "not set (the sandbox is off by default)" if src == "default" else f"set to false in {src} settings"
            self.add("sandbox-off", "high", src or "default", "sandbox.enabled", how)

        if active:
            if eff["failIfUnavailable"]["value"] is not True:
                self.add(
                    "fail-open",
                    "medium",
                    eff["failIfUnavailable"]["source"] or "default",
                    "sandbox.failIfUnavailable",
                    "if the sandbox cannot start (missing dependency, unsupported platform) commands run unsandboxed",
                )
            has_ask = any(r.replace(" ", "") == ESCAPE_ASK_RULE for s in SCOPES for r in self.perms(s, "ask"))
            if eff["allowUnsandboxedCommands"]["value"] is not False and not has_ask:
                self.add(
                    "escape-hatch-open",
                    "medium",
                    eff["allowUnsandboxedCommands"]["source"] or "default",
                    "sandbox.allowUnsandboxedCommands",
                    "Claude can retry a failed command unsandboxed (no prompt in bypassPermissions mode, or when an "
                    f"allow rule matches); set it to false, or add the ask rule {ESCAPE_ASK_RULE}",
                )
            self.check_credentials(eff, lists)

        for e in lists["excludedCommands"]:
            risk = broad_command(e["value"])
            if risk:
                sev = risk[0] if e["honoured"] else "low"
                note = "" if e["honoured"] else f" (ignored now: {e['reason']})"
                self.add("excluded-command-broad", sev, e["scope"], e["value"], risk[1] + note)

        for d in allowed:
            risk = wildcard_risk(d["host"])
            if risk:
                sev = risk[0] if d["honoured"] else "low"
                note = "" if d["honoured"] else f" (ignored now: {d['reason']})"
                self.add("domain-wildcard-broad", sev, d["scope"], f"{d['host']} ({d['via']})", risk[1] + note)
        for a in (d for d in allowed if d["honoured"]):
            for n in denied:
                if domain_covers(n["host"], a["host"]):
                    self.add(
                        "allow-deny-conflict",
                        "low",
                        a["scope"],
                        a["host"],
                        f"allowed in {a['scope']} ({a['via']}) and denied by {n['host']} in {n['scope']} "
                        f"({n['via']}); the deny wins, so the allow entry has no effect",
                    )
                    break

        if eff["filesystem.disabled"]["value"] is True:
            auto = eff["autoAllowBashIfSandboxed"]["value"] is not False
            self.add(
                "filesystem-disabled",
                "high" if auto else "medium",
                eff["filesystem.disabled"]["source"],
                "sandbox.filesystem.disabled",
                "sandboxed commands can read and write the whole filesystem; denyRead and credentials file deny "
                "entries are not enforced"
                + (
                    ", and with autoAllowBashIfSandboxed they run without prompts and can write files that widen their "
                    "own access (shell startup files, $PATH executables, ~/.claude/settings.json)"
                    if auto
                    else ""
                ),
            )
        if eff["network.allowAllUnixSockets"]["value"] is True:
            self.add(
                "unix-sockets-all",
                "high",
                eff["network.allowAllUnixSockets"]["source"],
                "sandbox.network.allowAllUnixSockets",
                "every Unix socket is open to sandboxed commands; a socket such as /var/run/docker.sock gives access "
                "to the host",
            )
        for key in ("enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "network.allowLocalBinding"):
            if eff[key]["value"] is True:
                self.add("weaker-isolation", "medium", eff[key]["source"], f"sandbox.{key}", "weakens the sandbox")
        if eff["allowAppleEvents"]["value"] is True:
            self.add(
                "weaker-isolation",
                "medium",
                eff["allowAppleEvents"]["source"],
                "sandbox.allowAppleEvents",
                "removes code-execution isolation on macOS: sandboxed commands can launch other applications "
                "unsandboxed",
            )
        for key, entries in ports.items():
            for e in entries:
                if e["honoured"]:
                    self.add(
                        "proxy-port-set",
                        "medium",
                        e["scope"],
                        f"sandbox.{key} = {e['value']}",
                        "your own proxy now filters this traffic; allowedDomains, deniedDomains, strictAllowlist "
                        "and approval prompts stop applying to it",
                    )
        for scope in REPO:
            if get(self.sb(scope), "network.strictAllowlist") is not None:
                self.add(
                    "strict-allowlist-ignored-scope",
                    "medium",
                    scope,
                    "sandbox.network.strictAllowlist",
                    "has no effect in project or local settings; set it in user or managed settings",
                )
        self.check_repo(lists, ports, allowed)

        order = {k: i for i, k in enumerate(SCOPES + ("platform", "default"))}
        self.findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["rule"], order.get(f["scope"], 9), f["item"]))
        return {
            "doc": DOC_URL,
            "platform": self.platform,
            "scopes": [{"scope": s, "file": self.paths.get(s), "present": self.present.get(s, False)} for s in SCOPES],
            "admin_required": self.admin_required,
            "admin_required_because": self.admin_reasons,
            "active_checks": active,
            "effective": eff,
            "lists": {**lists, **ports},
            "domains": {"allowed": allowed, "denied": denied},
            "findings": self.findings,
            "verify": verify_commands(allowed, denied, any(e["honoured"] for v in ports.values() for e in v)),
        }

    def check_credentials(self, eff: dict, lists: dict) -> None:
        fs_off = eff["filesystem.disabled"]["value"] is True
        covers: list[tuple[str, str]] = []  # (path, where)
        mac_mask: list[tuple[str, str]] = []
        for e in lists["filesystem.denyRead"]:
            covers.append((e["value"], f"{e['scope']} denyRead"))
        for scope in SCOPES:
            for entry in get(self.sb(scope), "credentials.files") or []:
                if entry["mode"] == "deny":
                    covers.append((entry["path"], f"{scope} credentials deny"))
                elif scope in TRUSTED:
                    covers.append((entry["path"], f"{scope} credentials mask"))
                    if self.platform == "macos":
                        mac_mask.append((entry["path"], f"{scope} credentials mask"))
            for rule in self.perms(scope, "deny"):
                p = read_rule_path(rule)
                if p:
                    covers.append((p, f"{scope} {rule}"))
        block = next(
            (
                s
                for s in ("managed", "local", "project", "user")
                if (self.data[s].get("permissions", {}) or {}).get("blockReadsOutsideWorkingDirectories") is True
            ),
            None,
        )
        allow_read = [e["value"] for e in lists["filesystem.allowRead"]]
        for target, what in CREDENTIAL_TARGETS:
            pool = mac_mask if fs_off else covers
            hit = None
            for path, where in pool:
                if not path_covers(path, target):
                    continue
                reopened = any(path_covers(a, target) and len(norm_path(a)) > len(norm_path(path)) for a in allow_read)
                if not reopened:
                    hit = where
                    break
            if hit is None and block and not fs_off and target.startswith("~"):
                hit = f"{block} blockReadsOutsideWorkingDirectories"
            if hit is None:
                why = (
                    "filesystem isolation is off, so read blocks are not enforced"
                    if fs_off
                    else "reads of most of the machine are allowed by default and nothing denies this path"
                )
                self.add("credentials-readable", "medium", "default", target, f"{what}: {why}")

    def check_repo(self, lists: dict, ports: dict, allowed: list[dict]) -> None:
        """Loosening values in the committed project .claude/settings.json, which a cloned repository can ship."""
        items: list[tuple[str, bool, str]] = []
        for key in ("excludedCommands", "filesystem.allowWrite", "network.allowUnixSockets"):
            for e in lists[key]:
                if e["scope"] == "project":
                    items.append((f"{key}: {e['value']}", e["honoured"], e["reason"]))
        for d in allowed:
            if d["scope"] == "project" and host_of(d["host"]).startswith("*"):
                items.append((f"{d['via']}: {d['host']}", d["honoured"], d["reason"]))
        for key, entries in ports.items():
            for e in entries:
                if e["scope"] == "project":
                    items.append((f"{key}: {e['value']}", e["honoured"], e["reason"]))
        sb = self.sb("project")
        loosening = {"enabled": False, "failIfUnavailable": False, "allowUnsandboxedCommands": True}
        loosening.update({k: True for k in WEAKER + ("filesystem.disabled", "allowAppleEvents")})
        for key, bad in loosening.items():
            if get(sb, key) is bad:
                ok, why = self.bool_honoured("project", key, bad)
                if ok and key == "allowUnsandboxedCommands" and get(self.sb("user"), key) is False:
                    ok, why = False, "a user false holds against a project true"
                if ok and isinstance(get(self.sb("managed"), key), bool):
                    ok, why = False, "managed settings set this key"
                items.append((f"{key}: {json.dumps(bad)}", ok, why))
        for item, ok, why in items:
            detail = (
                "set in the committed .claude/settings.json, so anyone who clones the repository gets it"
                if ok
                else f"set in the committed .claude/settings.json but ignored here: {why}"
            )
            self.add("repo-loosens", "high" if ok else "low", "project", item, detail)


def _hr(e: dict) -> dict:
    return {"honoured": e["honoured"], "reason": e["reason"]}


def verify_commands(allowed: list[dict], denied: list[dict], proxy_port: bool = False) -> list[dict]:
    out = [
        {"command": "touch ~/sandbox-probe", "expect": "fails (Operation not permitted or Read-only file system)"},
        {"command": "curl --noproxy '*' https://example.com", "expect": "fails with Could not resolve host"},
    ]
    seen = set()
    live = [d for d in allowed if d["honoured"] and not d.get("denied_by")]
    for d in live:
        host = host_of(d["host"])
        if host in seen or host == "*":
            continue
        seen.add(host)
        if host.startswith("*."):
            out.append(
                {
                    "command": f'curl -sS -o /dev/null -w "%{{http_code}}" https://<a host under {host[2:]}>',
                    "expect": "connects (any HTTP status from the server, not a proxy 403)",
                }
            )
            continue
        target = d["host"].strip()
        out.append(
            {
                "command": f'curl -sS -o /dev/null -w "%{{http_code}}" https://{target}',
                "expect": "connects (any HTTP status from the server, not a proxy 403)",
            }
        )
    every = any(host_of(d["host"]) == "*" for d in live)
    refuse = next((h for h in REFUSE_CANDIDATES if not any(domain_covers(d["host"], h, apex=True) for d in live)), None)
    if refuse and not every:
        out.append(
            {
                "command": f'curl -sS -o /dev/null -w "%{{http_code}}" https://{refuse}',
                "expect": "refused: a 403 from the sandbox proxy or a network prompt (decline it)",
            }
        )
    for n in denied:
        host = host_of(n["host"])
        if "*" not in host:
            out.append(
                {
                    "command": f'curl -sS -o /dev/null -w "%{{http_code}}" https://{n["host"].strip()}',
                    "expect": "refused in every permission mode (deniedDomains)",
                }
            )
            break
    if proxy_port:
        for v in out[2:]:
            v["expect"] += "; but a proxy port applies, so your own proxy decides"

    return out


# ---------------------------------------------------------------------------------------------------------- output


def fmt_value(entry: dict) -> tuple[str, str]:
    value, source = entry["value"], entry["source"]
    if source is None:
        return "not set", "-"
    shown = json.dumps(value)
    return (f"{shown} (default)" if source == "default" else shown), source


def render(rep: dict) -> str:
    out = ["# Sandbox configuration review", ""]
    files = []
    for s in rep["scopes"]:
        if s["file"] is None:
            files.append(f"{s['scope']} (not given)")
        else:
            files.append(f"{s['scope']} `{s['file']}`" + ("" if s["present"] else " (not present)"))
    out.append(f"Platform: {rep['platform']}. Scopes read: {', '.join(files)}.")
    out.append("")
    if rep["admin_required"]:
        out.append(f"Admin-required sandbox: yes ({'; '.join(rep['admin_required_because'])}).")
    else:
        out.append("Admin-required sandbox: no.")
    if not rep["active_checks"]:
        out.append("")
        out.append("The sandbox does not run here, so the checks for an active sandbox were skipped.")
    out += [
        "",
        f"Rules from {rep['doc']}.",
        "",
        "## Effective settings",
        "",
        "| Key | Value | Source |",
        "|---|---|---|",
    ]
    for key, entry in rep["effective"].items():
        value, source = fmt_value(entry)
        ignored = "; ".join(f"{i['scope']} {json.dumps(i['value'])} ignored: {i['reason']}" for i in entry["ignored"])
        out.append(f"| `sandbox.{key}` | {value} | {source}{' (' + ignored + ')' if ignored else ''} |")
    for key, entries in rep["lists"].items():
        if not entries:
            continue
        out += ["", f"### sandbox.{key}", ""]
        for e in entries:
            note = "" if e["honoured"] else f" (ignored: {e['reason']})"
            out.append(f"- `{e['value']}` ({e['scope']}){note}")
    out += ["", "## Domains", ""]
    allowed = rep["domains"]["allowed"]
    live = [d for d in allowed if d["honoured"] and not d.get("denied_by")]
    out.append(f"### Allowed ({len(live)} applied)")
    out.append("")
    if not allowed:
        out.append("None: the allowed domains start empty, so every host needs approval or is refused.")
    for d in allowed:
        note = "" if d["honoured"] else f" (ignored: {d['reason']})"
        if d["honoured"] and d.get("denied_by"):
            note = f" (no effect: denied by {d['denied_by']})"
        out.append(f"- `{d['host']}` ({d['scope']}, {d['via']}){note}")
    out += ["", f"### Denied ({len(rep['domains']['denied'])})", ""]
    out += [f"- `{d['host']}` ({d['scope']}, {d['via']})" for d in rep["domains"]["denied"]] or ["None."]
    out += ["", "## Findings", ""]
    out += [f"- {f['severity']} {f['rule']} ({f['scope']}) `{f['item']}`: {f['detail']}" for f in rep["findings"]] or [
        "None."
    ]
    out += [
        "",
        "## Verify enforcement",
        "",
        "Printed, not run. Ask Claude to run each line as a sandboxed Bash command in a session (a line typed at the "
        "`!` prompt usually runs outside the sandbox), and decline any offer to retry outside the sandbox.",
        "",
        "```bash",
    ]
    for v in rep["verify"]:
        out.append(f"{v['command']}  # {v['expect']}")
    out += ["```", ""]
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------------------- main


def default_platform() -> str:
    """macos, windows or linux from the running interpreter; WSL2 reports linux (pass --platform wsl to say so)."""
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sandbox_review.py",
        description="Review Claude Code sandbox settings across user, project, local and managed scopes, show what "
        "is enforced and flag the settings that leave it open. Reads local files only.",
        epilog=f"Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 bad input. Rules from {DOC_URL}.",
    )
    p.add_argument(
        "--project", default=None, help="project folder: reads .claude/settings.json and settings.local.json"
    )
    p.add_argument("--user", default=None, help="user settings file, normally ~/.claude/settings.json (default: none)")
    p.add_argument("--managed", default=None, help="managed settings file (default: none)")
    p.add_argument(
        "--platform",
        choices=("macos", "linux", "wsl", "windows"),
        default=None,
        help="platform to judge for (default: the one this runs on; WSL2 shows as linux)",
    )
    p.add_argument("--format", choices=("markdown", "json"), default="markdown", help="output format")
    p.add_argument("--json", action="store_true", help="same as --format json")
    p.add_argument("--fail-on", choices=("high", "medium", "low"), default="high", help="exit 1 at this severity")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not (args.project or args.user or args.managed):
            raise InputError("give --project DIR, --user FILE or --managed FILE")
        scopes: dict[str, dict | None] = {s: None for s in SCOPES}
        paths: dict[str, str] = {}
        if args.project:
            root = Path(args.project)
            if not root.is_dir():
                raise InputError(f"--project {root}: not a folder")
            for scope, name in (("project", "settings.json"), ("local", "settings.local.json")):
                paths[scope] = f".claude/{name}"
                f = root / ".claude" / name
                if f.is_file():
                    scopes[scope] = load_settings(f, scope)
        for scope, value in (("user", args.user), ("managed", args.managed)):
            if value:
                f = Path(value)
                if not f.is_file():
                    raise InputError(f"--{scope} {f}: not found")
                paths[scope] = f.name
                scopes[scope] = load_settings(f, scope)
        for scope, data in scopes.items():
            if data is not None:
                check_types(data, f"{scope} {paths[scope]}")
    except InputError as exc:
        print(f"sandbox_review.py: {exc}", file=sys.stderr)
        return 2
    rep = Review(scopes, paths, args.platform or default_platform()).run()
    counts = {s: sum(1 for f in rep["findings"] if f["severity"] == s) for s in SEVERITIES}
    rep["counts"] = counts
    as_json = args.json or args.format == "json"
    text = json.dumps(rep, indent=2) + "\n" if as_json else render(rep)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    threshold = SEVERITIES[args.fail_on]
    return 1 if any(SEVERITIES[f["severity"]] >= threshold for f in rep["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
