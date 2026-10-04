#!/usr/bin/env python3
"""PreToolUse hook (matcher: Bash): block commands that print or export likely secrets.

Reads the Claude Code hook JSON on stdin. Exit codes follow the hooks reference:
  0  no decision, the normal permission flow applies
  2  block the tool call; the reason on stderr is shown to the model
  1  the hook itself could not run (bad input); non-blocking, first stderr line is shown as a notice

What it blocks (see README for the full list and the reasoning):
  * whole-environment dumps: bare `env`, `printenv`, `export`/`export -p`, `declare -x`/`-p`, bare `set`,
    `/proc/*/environ`, `print(os.environ)`, `console.log(process.env)`
  * printing a secret-named variable: `echo $OPENAI_API_KEY`, `printf '%s' "$DB_PASSWORD"`,
    `printenv GITHUB_TOKEN`, `declare -p AWS_SECRET_ACCESS_KEY`
  * reading secret files with a display or transfer program: `cat .env`, `less ~/.aws/credentials`,
    `base64 id_rsa`, `scp .env host:`, `tail ~/.config/gh/hosts.yml`
  * credential-printing subcommands: `gh auth token`, `gcloud auth print-access-token`,
    `az account get-access-token`, `aws configure export-credentials`, `kubectl get secret ... -o`,
    `vault kv get`, `op read`, `security find-generic-password -w`, `heroku config`, `doppler secrets`

What it allows on purpose: `env FOO=bar cmd`, `printenv HOME`, `export FOO=bar`, `[ -n "$TOKEN" ]`,
`echo "${TOKEN:+set}"`, `echo ${#TOKEN}`, `cat .env.example`, `source .env`, `ls ~/.ssh`,
`curl -H "Authorization: Bearer $TOKEN"` (using a secret is not printing it).

Standard library only. No network. No file writes.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _shellwords import Segment, basename_of, expand_home, segments  # noqa: E402

SECRET_SEGMENTS = {
    "key", "keys", "secret", "secrets", "token", "tokens", "password", "passwd", "pass", "pwd_hash",
    "credential", "credentials", "creds", "auth", "apikey", "api_key", "bearer", "dsn", "pat", "jwt",
    "cookie", "session", "private", "signing", "oauth", "refresh", "access", "client_secret", "passphrase",
    "webhook",
}
NON_SECRET_SEGMENTS = {"public", "pub", "id", "name", "path", "file", "dir", "url", "type", "mode", "count", "max", "min", "ttl", "size", "len", "length"}
SECRET_VAR_NAMES = {
    "database_url", "db_url", "redis_url", "mongo_url", "mongodb_uri", "mongo_uri", "postgres_url", "postgresql_url",
    "mysql_url", "amqp_url", "rabbitmq_url", "connection_string", "conn_str", "service_account_json",
    "google_application_credentials_json", "npm_token", "pypi_token", "hisar_agent_key", "hisar_admin_token",
}
# access/refresh alone are too generic; only treat them as secrets with a token-ish companion segment
WEAK_SEGMENTS = {"access", "refresh", "session", "cookie", "auth", "private", "signing", "oauth", "pass", "webhook"}

VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)([^}\s\"']*)\}?")
PRINTERS = {"echo", "printf", "print"}
READERS = {
    "cat", "less", "more", "most", "head", "tail", "bat", "batcat", "nl", "tac", "strings", "base64", "base32",
    "xxd", "od", "hexdump", "hd", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "cut", "tr",
    "jq", "yq", "view", "vim", "vi", "nvim", "nano", "emacs", "code", "subl", "open", "xdg-open", "tee", "curl",
    "wget", "scp", "rsync", "sftp", "nc", "ncat", "netcat", "mail", "mailx", "sendmail", "pbcopy", "xclip",
    "xsel", "wl-copy", "clip", "column", "paste", "fold", "pr", "uniq", "sort", "rev", "iconv", "openssl",
    "python", "python3", "node", "ruby", "perl", "php",
}
INTERPRETER_DUMP_RE = re.compile(
    r"(print|pprint|dump|dumps|write|log|puts|echo)\s*\(?[^()]*\b(os\.environ\b(?![\[.(])|dict\(os\.environ\)|os\.environ\.items\(\)|process\.env\b(?![\[.A-Za-z_])|ENV\.to_h|ENV\.each|\$_ENV|getenv\(\))",
    re.I,
)
INTERPRETER_SECRET_RE = re.compile(
    r"(print|pprint|log|puts|echo|stdout)[^;\n]*?(process\.env\.([A-Za-z_][A-Za-z0-9_]*)|os\.environ(?:\.get)?[\[(]\s*['\"]([A-Za-z_][A-Za-z0-9_]*)|ENV\[['\"]([A-Za-z_][A-Za-z0-9_]*)|getenv\(['\"]([A-Za-z_][A-Za-z0-9_]*))",
    re.I,
)

SECRET_FILE_BASENAMES = {
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass", ".my.cnf", ".boto", ".s3cfg",
    ".htpasswd", "shadow", "gshadow", ".vault-token", ".terraformrc", "terraform.rc", "credentials",
    "credentials.json", "client_secret.json", "client_secrets.json", "application_default_credentials.json",
    "adc.json", "secrets.json", "secrets.yaml", "secrets.yml", "secret.yaml", "secret.yml", "secrets.env",
    "secrets.toml", ".secrets", "kubeconfig", "secring.gpg", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_ed25519_sk", "id_ecdsa_sk", "admin-token", "hosts.yml", "config.json", "accessTokens.json",
    "msal_token_cache.json", "credentials.db", "access_tokens.db", ".credentials.json", "token.json",
    "tokens.json", "auth.json", "cookies.txt", "cookies.sqlite", "Login Data", "logins.json", "key3.db",
    "key4.db", "keychain-db", "wallet.dat", ".hisar", "service-account.json",
}
SECRET_DIR_HINTS = (".ssh/", ".aws/", ".gnupg/", ".kube/", ".docker/", ".config/gh/", ".config/gcloud/", ".azure/",
                    ".hisar/", ".vault/", ".netlify/", ".config/doppler/", ".railway/", ".fly/", ".terraform.d/",
                    ".password-store/", "private-keys-v1.d/", "/proc/self/", "/proc/")
SECRET_FILE_RE = re.compile(
    r"(^|/)(\.env(\.[A-Za-z0-9_.-]+)?|[^/]*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|asc|gpg|ovpn|secret|secrets|cred|creds|token))$",
    re.I,
)
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".schema", ".defaults", ".example.local", ".md", ".txt", ".d.ts", ".ts", ".js", ".json", ".yaml", ".yml", ".sh")
PEM_SAFE_HINTS = ("cert", "chain", "fullchain", "ca", "cacert", "public", "pub", "bundle", "root", "trust", "csr")
CONFIG_JSON_SECRET_DIRS = (".docker/", "Claude/", ".claude/", "gcloud/", ".azure/")

CREDENTIAL_SUBCOMMANDS: list[tuple[str, re.Pattern[str], str]] = [
    ("gh", re.compile(r"^auth\s+token\b"), "`gh auth token` prints your GitHub token"),
    ("gcloud", re.compile(r"^(auth\s+(application-default\s+)?print-(access|identity)-token|auth\s+print-)"), "gcloud prints an access token"),
    ("az", re.compile(r"^account\s+get-access-token\b|^keyvault\s+secret\s+show\b"), "az prints a credential"),
    ("aws", re.compile(r"^configure\s+(get\s+\S*(secret|token|key)\S*|export-credentials)|^sts\s+get-session-token|^secretsmanager\s+get-secret-value|^ssm\s+get-parameters?\b.*--with-decryption"), "aws prints a credential"),
    ("kubectl", re.compile(r"^(get|view)\s+secrets?\b.*(-o|--output)\b"), "kubectl prints secret contents"),
    ("vault", re.compile(r"^(kv\s+get|read)\b"), "vault prints a secret"),
    ("op", re.compile(r"^(read|item\s+get\b.*(--reveal|--fields|password))"), "1Password CLI prints a secret"),
    ("security", re.compile(r"^find-(generic|internet)-password\b.*(-w|-g)"), "macOS keychain password would be printed"),
    ("heroku", re.compile(r"^config(:get)?\b"), "heroku prints config vars"),
    ("doppler", re.compile(r"^secrets\b"), "doppler prints secrets"),
    ("railway", re.compile(r"^variables\b"), "railway prints variables"),
    ("vercel", re.compile(r"^env\s+(pull|ls)\b"), "vercel prints or writes env values"),
    ("flyctl", re.compile(r"^ssh\s+console\b.*env"), "fly console env dump"),
    ("docker", re.compile(r"^(inspect\b|run\b.*\benv\b|exec\b.*\b(env|printenv)\b)"), "docker would print container environment"),
    ("git", re.compile(r"^config\b.*credential"), "git credential configuration may hold a token"),
    ("ssh-add", re.compile(r"^-L\b"), "ssh-add -L prints public keys only; use -l to list fingerprints"),
]


def _is_secret_name(name: str) -> bool:
    low = name.lower()
    if low in SECRET_VAR_NAMES:
        return True
    if low.endswith(("_pat", "_jwt", "apikey", "api_key", "_secret", "_token", "_password", "_passwd")):
        return True
    parts = [p for p in re.split(r"[_\-.]+", low) if p]
    if any(p in NON_SECRET_SEGMENTS for p in parts) and not any(p in {"secret", "token", "password", "passwd", "apikey", "api_key", "key"} for p in parts):
        return False
    strong = [p for p in parts if p in SECRET_SEGMENTS and p not in WEAK_SEGMENTS]
    if strong:
        # `KEY` alone or with anything, `TOKEN`, `SECRET`, `PASSWORD` ... are secrets
        if "key" in strong and {"public", "pub"} & set(parts):
            return False
        return True
    weak = [p for p in parts if p in WEAK_SEGMENTS]
    return len(weak) >= 2  # e.g. ACCESS_SESSION, AUTH_COOKIE


def _var_refs(text: str) -> list[tuple[str, str]]:
    """(name, modifier) for every $NAME / ${NAME...} reference."""
    refs = []
    for m in VAR_REF_RE.finditer(text):
        refs.append((m.group(1), m.group(2) or ""))
    return refs


def _secret_file(token: str) -> str | None:
    """Return a reason if the token names a file that commonly holds secrets."""
    tok = expand_home(token).replace("\\", "/")
    base = basename_of(tok)
    low = tok.lower()
    if low.startswith("/proc/") and low.endswith("environ"):
        return f"{token} (a process environment dump)"
    if base.startswith(".env"):
        if any(base.endswith(s) for s in SAFE_ENV_SUFFIXES) or base in {".envrc", ".env.d"}:
            return None
        return f"{token} (a dotenv file)"
    if "*" in tok or "?" in tok:
        if any(h in low for h in SECRET_DIR_HINTS) or base.startswith(".env"):
            return f"{token} (a glob over a credential directory)"
        return None
    if base in {"config.json", "hosts.yml", "credentials", "config", "accessTokens.json", "credentials.db", "token.json", "tokens.json", "auth.json"}:
        if base == "config" and ".ssh/" in low:
            return None  # ~/.ssh/config holds host aliases, not keys
        if any(h in low for h in SECRET_DIR_HINTS) or any(h.lower() in low for h in CONFIG_JSON_SECRET_DIRS):
            return f"{token} (a credential store)"
        return None
    if base in SECRET_FILE_BASENAMES:
        return f"{token} (a file that commonly holds credentials)"
    m = SECRET_FILE_RE.match(tok)
    if m:
        ext = (m.group(4) or "").lower()
        if ext == "pem" and any(h in base for h in PEM_SAFE_HINTS) and not any(h in base for h in ("key", "priv", "secret")):
            return None
        if ext == "key" and ("pub" in base or base.endswith(".pub.key")):
            return None
        return f"{token} (a private key or secret file)"
    if any(h in low for h in (".ssh/", ".aws/credentials", ".gnupg/", ".kube/config", ".hisar/", ".password-store/", "private-keys-v1.d/")):
        if base.endswith(".pub") or base in {"known_hosts", "known_hosts.old", "config", "authorized_keys"} and ".ssh/" in low:
            return None
        return f"{token} (inside a credential directory)"
    return None


def check_segment(seg: Segment) -> str | None:
    prog, args = seg.program, seg.args
    raw_lower = seg.raw.lower()
    joined = " ".join(args)

    if not prog:
        return None

    # 1. whole-environment dumps
    if prog in {"env", "printenv"}:
        positional = [a for a in args if not a.startswith("-") and "=" not in a]
        if not positional:
            return f"`{prog}` prints the whole environment, including any secrets in it"
        if prog == "printenv":
            for name in positional:
                if _is_secret_name(name):
                    return f"`printenv {name}` would print a secret"
    if prog == "export":
        if not args or args == ["-p"] or all(a.startswith("-") for a in args):
            return "`export` with no assignment prints every exported variable"
        for a in args:
            if "=" not in a and not a.startswith("-") and _is_secret_name(a):
                pass  # `export NAME` re-exports an existing variable; it prints nothing
    if prog in {"declare", "typeset"}:
        flags = [a for a in args if a.startswith("-")]
        names = [a for a in args if not a.startswith("-") and "=" not in a]
        if any(f in {"-x", "-p", "-xp", "-px"} for f in flags):
            if not names:
                return f"`{prog} {' '.join(flags)}` prints every exported variable"
            for n in names:
                if _is_secret_name(n):
                    return f"`{prog} -p {n}` would print a secret"
    if prog == "set" and not args:
        return "bare `set` prints every shell variable"
    if prog in {"compgen"} and "-A" in args and "export" in args:
        return None

    # 2. printing a secret-named variable
    if prog in PRINTERS:
        for name, modifier in _var_refs(joined):
            if not _is_secret_name(name):
                continue
            if modifier.startswith(":+") or modifier.startswith("+"):
                continue  # ${X:+set} prints a marker, not the value
            return f"`{prog}` would print the value of ${name}"
        if re.search(r"\$\{#\w+\}", joined):
            pass
    if prog in {"[", "[[", "test"}:
        return None

    # 3. reading or transferring secret files
    if prog in READERS or prog in {"cp", "mv", "install", "zip", "tar", "7z", "gzip", "split", "ln"}:
        transfer = prog in {"curl", "wget", "scp", "rsync", "sftp", "nc", "ncat", "netcat", "mail", "mailx", "sendmail", "cp", "mv", "install", "zip", "tar", "7z", "gzip", "split", "ln"}
        for a in args:
            if a.startswith("-") and not a.startswith("-/"):
                continue
            if a in {">", ">>", "<", "<<", "<<<", "|", "&", "2>&1"}:
                continue
            if "://" in a and prog in {"curl", "wget"}:
                continue
            if "@" in a and prog in {"curl", "wget"}:
                a = a.split("@", 1)[1]  # -F name=@file, -d @file, --data-binary @file
                if not a:
                    continue
            reason = _secret_file(a)
            if reason:
                if transfer and prog in {"cp", "mv", "install", "ln"}:
                    # copying a credential file inside the machine is not printing it; only flag transfers
                    continue
                verb = "transfer" if transfer else "print"
                return f"`{prog}` would {verb} {reason}"
    if prog in {"python", "python3", "node", "ruby", "perl", "php"} or prog in SECRET_SEGMENTS:
        pass

    # 4. credential-printing subcommands
    for name, pattern, why in CREDENTIAL_SUBCOMMANDS:
        if prog == name and pattern.search(joined):
            return why

    # 5. interpreter one-liners that dump the environment
    if INTERPRETER_DUMP_RE.search(seg.raw):
        return "this one-liner prints the whole process environment"
    m = INTERPRETER_SECRET_RE.search(seg.raw)
    if m:
        var = next((g for g in m.groups()[2:] if g), "")
        if var and _is_secret_name(var):
            return f"this one-liner prints the value of {var}"
    if "/proc/" in raw_lower and "environ" in raw_lower:
        return "/proc/*/environ (a process environment dump) would be read"
    return None


def decide(command: str) -> str | None:
    for seg in segments(command):
        reason = check_segment(seg)
        if reason:
            return reason
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001
        print(f"block-secret-exposure: could not read hook input ({exc})", file=sys.stderr)
        return 1
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not isinstance(command, str) or not command.strip():
        return 0
    reason = decide(command)
    if reason is None:
        return 0
    print(
        "block-secret-exposure (agent-security plugin): blocked this command because "
        f"{reason}. Secrets must not be printed into the transcript. If you need to check that a variable "
        "is set, use `[ -n \"$NAME\" ] && echo set`; to inspect a config file, open it with a redacting viewer "
        "or ask the user to confirm the value out of band.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
