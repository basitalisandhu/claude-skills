"""Shared helpers for the compliance-evidence scripts, standard library only.

Every skill folder carries an identical copy of this file so that each skill stays self-contained when copied on
its own. tests/test_shared_helpers.py fails when the copies drift apart.

What it provides:
  * The three result states (supported, contradicted, not assessable) and evidence_row(), which refuses to build a
    supported or contradicted row without a cited evidence file and field.
  * The disclaimer every output carries: preparation for a human assessor, not an opinion or attestation.
  * load_json(), items_of() and error_body(): read saved exports and recognise saved API error responses (a GitHub
    403 or 404 body, for example), so that "the API could not tell" is never read as "the control is absent".
  * parse_dt / as_of_datetime / days_between: tolerant ISO 8601 parsing.
  * sha256_file(): the integrity hash used by evidence packs.
  * redact(): replaces user identifiers (e-mail addresses, IAM user and role names inside ARNs, and any extra names
    the caller passes, such as GitHub logins) with stable tokens. Tokens are the first 8 hex characters of a SHA-256
    of the lower-cased value, so the same person gets the same token across one report.
  * load_config(): YAML (via _miniyaml) or JSON with a key allow-list.
  * cell() and render_rows(): Markdown output that keeps untrusted export text inside its table cell.

Nothing here opens a socket, runs a subprocess or calls any API.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from _miniyaml import YAMLError
from _miniyaml import load as yaml_load

SUPPORTED = "supported"
CONTRADICTED = "contradicted"
NOT_ASSESSABLE = "not assessable"
STATES = (SUPPORTED, CONTRADICTED, NOT_ASSESSABLE)
STATE_ORDER = {CONTRADICTED: 0, NOT_ASSESSABLE: 1, SUPPORTED: 2}

DISCLAIMER = ("Preparation for a human assessor: this is not an audit opinion, an attestation or a certification, "
              "and not legal advice. Every result comes from exported files and needs review by the assessor.")

EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
ARN_PRINCIPAL_RE = re.compile(r"(arn:aws[a-z-]*:(?:iam|sts)::\d{12}:(?:user|role|assumed-role)/)([A-Za-z0-9+=,.@_/-]+)")
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


class InputError(Exception):
    """Bad or unreadable input. Scripts exit 2."""


# ---- result rows ------------------------------------------------------------------------------------------------

def citation(file: str, field: str, value) -> dict:
    """One citation: the evidence file (path inside the pack or export folder), the field read, and its value."""
    if not file or not field:
        raise ValueError("a citation needs a file and a field")
    return {"file": file, "field": field, "value": value}


def evidence_row(check: str, controls: dict[str, list[str]], state: str, statement: str,
                 citations: list[dict] | None = None, gaps: list[str] | None = None) -> dict:
    """One evidence row. supported and contradicted rows must cite at least one file and field."""
    if state not in STATES:
        raise ValueError(f"unknown state {state!r}; use one of {', '.join(STATES)}")
    citations = list(citations or [])
    if state != NOT_ASSESSABLE and not citations:
        raise ValueError(f"{check}: a {state} row needs at least one citation (file and field)")
    for c in citations:
        if not c.get("file") or not c.get("field"):
            raise ValueError(f"{check}: every citation needs a file and a field")
    return {"check": check, "controls": controls, "state": state, "statement": statement,
            "citations": citations, "gaps": list(gaps or [])}


def worst_state(states) -> str:
    """contradicted beats not assessable beats supported; an empty list is not assessable."""
    states = list(states)
    if not states:
        return NOT_ASSESSABLE
    return min(states, key=lambda s: STATE_ORDER[s])


def state_counts(rows: list[dict]) -> dict[str, int]:
    return {s: sum(1 for r in rows if r["state"] == s) for s in STATES}


def fail_exit(rows: list[dict], fail_on: str) -> int:
    if fail_on == "contradicted":
        return 1 if any(r["state"] == CONTRADICTED for r in rows) else 0
    if fail_on == "not-assessable":
        return 1 if any(r["state"] != SUPPORTED for r in rows) else 0
    return 0


# ---- reading exports --------------------------------------------------------------------------------------------

def load_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc


def items_of(data, where: str = "input") -> list[dict]:
    """Return the list of objects in a response: {"value": [...]}, a bare list, or a single object."""
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]
    elif isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise InputError(f"{where}: expected a JSON object, a list, or {{\"value\": [...]}}")
    out = [x for x in data if isinstance(x, dict)]
    if len(out) != len(data):
        raise InputError(f"{where}: every entry must be a JSON object")
    return out


def error_body(data) -> dict | None:
    """Recognise a saved API error response and return {"status": "...", "message": "..."}, else None.

    GitHub (gh api) saves {"message": ..., "documentation_url": ..., "status": "403"}; Microsoft Graph saves
    {"error": {"code": ..., "message": ...}}; the AWS CLI writes errors to stderr, which the skills save as a .err file.
    """
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("error"), dict) and ("code" in data["error"] or "message" in data["error"]):
        e = data["error"]
        return {"status": str(e.get("code", "")), "message": str(e.get("message", ""))}
    keys = set(data)
    if "message" in keys and keys <= {"message", "documentation_url", "status", "errors"} and (
            "documentation_url" in keys or "status" in keys):
        return {"status": str(data.get("status", "")), "message": str(data.get("message", ""))}
    return None


def is_denied(err: dict | None) -> bool:
    """True when an error says the caller could not see the data (permissions, plan or licence)."""
    if not err:
        return False
    text = f"{err.get('status', '')} {err.get('message', '')}".lower()
    return any(k in text for k in ("403", "401", "forbidden", "not accessible", "access denied", "accessdenied",
                                   "unauthorized", "upgrade to github", "must have admin", "requires authentication",
                                   "authorization_requestdenied", "not authorized"))


def resolve_path(data, path: str) -> list[tuple[str, object]]:
    """Resolve a dotted path with [] fan-out. Returns [(concrete path, value)]; an empty list when nothing matches."""
    parts = [p for p in path.split(".") if p] if path else []
    current: list[tuple[str, object]] = [("", data)]
    for part in parts:
        fan = part.endswith("[]")
        key = part[:-2] if fan else part
        nxt: list[tuple[str, object]] = []
        for where, value in current:
            if key:
                if not isinstance(value, dict) or key not in value:
                    continue
                where = f"{where}.{key}" if where else key
                value = value[key]
            if fan:
                if not isinstance(value, list):
                    continue
                nxt.extend((f"{where}[{i}]", v) for i, v in enumerate(value))
            else:
                nxt.append((where, value))
        current = nxt
    return current


# ---- dates ------------------------------------------------------------------------------------------------------

def parse_dt(value) -> datetime | None:
    """Parse an ISO 8601 timestamp. Returns an aware UTC datetime, or None for empty or unparseable values."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _FRACTION_RE.sub(r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt.year <= 1:
        return None
    return dt.astimezone(UTC)


def as_of_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = parse_dt(value if "T" in value else value + "T00:00:00Z")
    if dt is None:
        raise InputError(f"--as-of: cannot parse {value!r}; use YYYY-MM-DD")
    return dt


def days_between(earlier, later: datetime) -> int | None:
    dt = parse_dt(earlier)
    if dt is None:
        return None
    return (later - dt).days


# ---- integrity --------------------------------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    return h.hexdigest()


# ---- privacy ----------------------------------------------------------------------------------------------------

def token(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:8]


def redact(obj, names: set[str] | None = None):
    """Return a copy of obj with user identifiers replaced by stable tokens.

    Covers e-mail addresses, IAM user and role names inside ARNs, and every name in `names` (GitHub logins, IAM
    user names from a credential report, display names) as a whole word. Dictionary keys are left alone.
    """
    ordered = sorted((n for n in (names or set()) if n and len(n.strip()) > 1), key=len, reverse=True)
    patterns = [(re.compile(r"(?<![\w.@-])" + re.escape(n) + r"(?![\w@-])"), f"user-{token(n)}") for n in ordered]

    def _s(s: str) -> str:
        s = EMAIL_RE.sub(lambda m: f"user-{token(m.group(0))}@redacted.invalid", s)
        s = ARN_PRINCIPAL_RE.sub(lambda m: m.group(1) + f"user-{token(m.group(2))}", s)
        for rx, tok in patterns:
            s = rx.sub(tok, s)
        return s

    def _walk(o):
        if isinstance(o, str):
            return _s(o)
        if isinstance(o, list):
            return [_walk(x) for x in o]
        if isinstance(o, tuple):
            return tuple(_walk(x) for x in o)
        if isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        return o

    return _walk(obj)


# ---- config -----------------------------------------------------------------------------------------------------

def load_yaml_or_json(path: str | Path):
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"{p}: cannot read: {exc}") from exc
    try:
        return json.loads(text) if p.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise InputError(f"{p}: cannot parse: {exc}") from exc


def load_config(path: str | None, allowed: set[str]) -> dict:
    if not path:
        return {}
    cfg = load_yaml_or_json(path)
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise InputError(f"{path}: config must be a mapping")
    unknown = set(cfg) - allowed
    if unknown:
        raise InputError(f"{path}: unknown config keys: {', '.join(sorted(unknown))}")
    return cfg


def cfg_number(cfg: dict, key: str, default: float, minimum: float = 0) -> float:
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value < minimum:
        raise InputError(f"config {key} must be a number of at least {minimum}")
    return value


# ---- output -----------------------------------------------------------------------------------------------------

def cell(value) -> str:
    """Export text is untrusted: keep it inside its Markdown table cell."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")


def short(value, limit: int = 80) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def cite_text(c: dict) -> str:
    return f"{c['file']}#{c['field']} = {short(c.get('value'), 160)}"


def render_rows(rows: list[dict], framework_key: str | None = None) -> list[str]:
    if not rows:
        return ["No rows."]
    head = "| # | State | Check | Controls | Statement | Evidence (file#field = value) | Gaps |"
    lines = [head, "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        ctrl = r.get("controls") or {}
        if framework_key:
            ids = ", ".join(ctrl.get(framework_key, []))
        else:
            ids = "; ".join(f"{k}: {', '.join(v)}" for k, v in ctrl.items() if v)
        ev = "<br>".join(cell(cite_text(c)) for c in r["citations"]) or "none"
        gaps = "<br>".join(cell(g) for g in r["gaps"]) or ""
        lines.append(f"| {i} | {r['state']} | {r['check']} | {cell(ids)} | {cell(r['statement'])} | {ev} | {gaps} |")
    return lines


def add_common_args(ap, fail_on: bool = True) -> None:
    ap.add_argument("--as-of", help="evaluate dates as of this day (YYYY-MM-DD); default today")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true",
                    help="replace user identifiers (e-mail addresses, IAM user names, GitHub logins) with stable tokens")
    if fail_on:
        ap.add_argument("--fail-on", choices=["contradicted", "not-assessable", "none"], default="none",
                        help="exit 1 when a row is contradicted (or, with not-assessable, anything short of supported); default none")


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=False, default=str)
