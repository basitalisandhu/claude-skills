"""Shared helpers for reading saved GitHub exports (gh pr list --json, gh issue view --json, gh api).

This file is copied, byte for byte, into every skill's scripts/ folder so each skill folder stays self-contained.
tests/test_shared_helpers.py fails if the copies differ. Standard library only; nothing here touches the network.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path


class InputError(Exception):
    """Bad input: a missing folder, a file that is not JSON, or JSON of the wrong shape. Scripts exit 2 on it."""


def parse_time(value: object) -> datetime | None:
    """Parse a GitHub timestamp ('2026-09-30T12:00:00Z') or a date ('2026-09-30', read as midnight UTC)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00+00:00"
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def iso(moment: datetime | None) -> str | None:
    """Format a time as 2026-09-30T12:00:00Z, or None."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def hours_between(start: datetime, end: datetime) -> float:
    return round((end - start).total_seconds() / 3600, 1)


def human_hours(hours: float | None) -> str:
    """Render a number of hours as '45m', '5.2h' or '5.1d (122.0h)'."""
    if hours is None:
        return "n/a"
    if hours < 1:
        return f"{round(hours * 60)}m"
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d ({hours:.1f}h)"


def human_delta(delta: timedelta) -> str:
    minutes = round(delta.total_seconds() / 60)
    sign = "-" if minutes < 0 else ""
    minutes = abs(minutes)
    if minutes < 60:
        return f"{sign}{minutes}m"
    hours, rest = divmod(minutes, 60)
    if hours < 48:
        return f"{sign}{hours}h{rest:02d}m"
    days, hours = divmod(hours, 24)
    return f"{sign}{days}d{hours:02d}h"


def median(values: list[float]) -> float | None:
    """Median; with an even count, the mean of the two middle values."""
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[mid], 1)
    return round((ordered[mid - 1] + ordered[mid]) / 2, 1)


def percentile_nearest_rank(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile: the value at rank ceil(pct/100 * n) in ascending order. No interpolation."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return round(ordered[rank - 1], 1)


def load_json(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            raise InputError(f"{path}: the file is empty; re-run the export command in SKILL.md")
        return json.loads(text)
    except FileNotFoundError as exc:
        raise InputError(f"{path}: not found") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: not valid JSON: {exc}") from exc


def row_number(row: dict) -> int | None:
    """The row's number as an int ('12' is accepted), or None when it is missing, a bool or not a whole number."""
    value = row.get("number")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def check_rows(rows: list, source: object, kind: str = "row", required: tuple[str, ...] = ("createdAt",),
               optional: tuple[str, ...] = ()) -> None:
    """Raise InputError unless every row is an object with a whole number, parseable `required` times and, when
    present and not null, parseable `optional` times. Catches exports made with the wrong --json fields or edited by
    hand, which would otherwise crash or be read as "nothing to report"."""
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise InputError(f"{source}: item {index} is not an object; expected {kind}s from gh --json")
        number = row_number(row)
        if number is None:
            raise InputError(f"{source}: item {index} has number {row.get('number')!r}; expected a whole number")
        for field in required:
            if parse_time(row.get(field)) is None:
                raise InputError(f"{source}: {kind} #{number} has {field} {row.get(field)!r}; expected an ISO time "
                                 f"such as 2026-09-30T12:00:00Z (re-run the export with the --json fields in SKILL.md)")
        for field in optional:
            value = row.get(field)
            if value not in (None, "") and parse_time(value) is None:
                raise InputError(f"{source}: {kind} #{number} has {field} {value!r}; expected an ISO time or null")


def find_file(folder: Path, stem: str) -> Path | None:
    """Find '<stem>.json' or '<anything>-<stem>.json' (for example prs.json or fixture-prs.json) in folder."""
    exact = folder / f"{stem}.json"
    if exact.is_file():
        return exact
    matches = sorted(p for p in folder.glob(f"*-{stem}.json") if p.is_file())
    return matches[0] if matches else None


def stem_files(folder: Path, stem: str) -> list[Path]:
    """Every '<stem>.json', '<stem>-<part>.json' or '<prefix>-<stem>[-<part>].json' in folder, for exports split
    over several files (for example issues-open.json and issues-closed.json). Numbered files are left out."""
    pattern = re.compile(rf"(?:^|-){re.escape(stem)}(?:-[a-z][a-z0-9-]*)?\.json$")
    return sorted(p for p in folder.glob("*.json") if p.is_file() and pattern.search(p.name))


def merge_rows(paths: list[Path], kind: str = "row", required: tuple[str, ...] = (),
               optional: tuple[str, ...] = ()) -> list[dict]:
    """Concatenate exported rows from several files; a number seen twice keeps the row from the later file.
    Each file's rows are checked with check_rows for `required` and `optional` times."""
    rows: dict[object, dict] = {}
    for path in paths:
        data = load_rows(path)
        for row in data:
            if not isinstance(row, dict) or "number" not in row:
                raise InputError(f"{path}: expected a list of objects with a 'number' field")
        check_rows(data, path, kind, required, optional)
        for row in data:
            rows[row_number(row)] = row
    return list(rows.values())


def load_rows(path: Path) -> list:
    """load_json then flatten_pages, naming the file when it does not hold a JSON array."""
    data = load_json(path)
    try:
        return flatten_pages(data)
    except InputError as exc:
        kind = type(data).__name__.replace("dict", "object").replace("NoneType", "null")
        raise InputError(f"{path}: {exc}, found a JSON {kind}") from exc


def numbered_files(folder: Path, stem: str) -> dict[int, Path]:
    """Map N to the file '<stem>-N.json' or '<anything>-<stem>-N.json' in folder."""
    out: dict[int, Path] = {}
    pattern = re.compile(rf"(?:^|-){re.escape(stem)}-(\d+)\.json$")
    for path in sorted(folder.glob("*.json")):
        match = pattern.search(path.name)
        if match:
            out.setdefault(int(match.group(1)), path)
    return out


def flatten_pages(data: object) -> list:
    """`gh api --paginate` without --slurp concatenates arrays; with --slurp it nests them. Accept both."""
    if isinstance(data, list) and data and all(isinstance(x, list) for x in data):
        return [item for page in data for item in page]
    if isinstance(data, list):
        return data
    raise InputError("expected a JSON array")


def login_of(actor: object) -> str | None:
    """The login of a gh --json author ({'login': ...}) or a REST user object."""
    if isinstance(actor, dict):
        login = actor.get("login") or actor.get("name") or actor.get("slug")
        return str(login) if login else None
    if isinstance(actor, str) and actor:
        return actor
    return None


def is_bot(actor: object) -> bool:
    if isinstance(actor, dict):
        if actor.get("is_bot") or actor.get("type") == "Bot":
            return True
        login = actor.get("login") or ""
    else:
        login = actor or ""
    return isinstance(login, str) and (login.endswith("[bot]") or login.startswith("app/"))


def token(login: str) -> str:
    """A stable, non-reversible token for a login: user-<first 6 hex of sha256>."""
    return "user-" + hashlib.sha256(login.lower().encode("utf-8")).hexdigest()[:6]


class Redactor:
    """Replace known logins (and @mentions of them) in any string with a token or a role name.

    With enabled=False it returns values unchanged, so call sites do not branch.
    """

    def __init__(self, logins: set[str], enabled: bool, names: dict[str, str] | None = None) -> None:
        self.enabled = enabled
        self.names = {k.lower(): v for k, v in (names or {}).items()}
        ordered = sorted((x for x in logins if x and len(x) > 1), key=len, reverse=True)
        self.patterns = [
            (re.compile(r"(?<![\w-])@?" + re.escape(x) + r"(?![\w-])", re.IGNORECASE), x) for x in ordered
        ]

    def name(self, login: str | None) -> str | None:
        if login is None or not self.enabled:
            return login
        return self.names.get(login.lower(), token(login))

    def text(self, value: str | None) -> str | None:
        if not self.enabled or not isinstance(value, str):
            return value
        for rx, login in self.patterns:
            value = rx.sub(lambda _m, login=login: self.name(login) or "", value)
        return value


def md_cell(value: object) -> str:
    """Make a value safe for one Markdown table cell."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def short(text: str | None, limit: int = 90) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."
