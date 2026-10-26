"""_transcript.py: a defensive reader for Claude Code session transcripts (JSON lines). Standard library only.

Byte-identical copies sit in the scripts folder of every skill in this plugin that reads transcripts, so each skill
still works when it is copied on its own; tests/test_transcript_helper.py checks the copies match.

The transcript format is not documented. What this reader relies on was seen in local transcripts on 2026-10-26:
one JSON object per line, a `type` key (user, assistant, system, attachment and several bookkeeping types), and
`sessionId`, `timestamp` (ISO 8601), `cwd`, `isSidechain`, `uuid` on conversation lines. Lines that are not JSON
objects, or not UTF-8, are counted as unreadable and skipped; line types it does not know are counted and skipped.
Subagent transcripts sit under `<project>/<session id>/subagents/` and are read like any other file.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

CONVERSATION_TYPES = {"user", "assistant", "system", "attachment"}
# Bookkeeping line types seen in transcripts. They are known (so not reported as unknown) but carry nothing the
# skills read, apart from `pr-link`, which the compaction check uses.
BOOKKEEPING_TYPES = {
    "summary",
    "custom-title",
    "ai-title",
    "last-prompt",
    "file-history-snapshot",
    "file-history-delta",
    "queue-operation",
    "mode",
    "permission-mode",
    "agent-name",
    "pr-link",
    "cost-state",
    "relocated",
    "result",
    "started",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}


class InputError(Exception):
    """Bad input or usage: the script prints the message on one line and exits 2."""


@dataclass
class Record:
    path: Path
    line: int
    data: dict

    @property
    def type(self) -> str:
        t = self.data.get("type")
        return t if isinstance(t, str) else ""


@dataclass
class ReadStats:
    files: int = 0
    lines: int = 0
    unreadable: int = 0
    unreadable_files: int = 0
    records: int = 0
    unknown_types: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "lines": self.lines,
            "records": self.records,
            "unreadable_lines": self.unreadable,
            "unreadable_files": self.unreadable_files,
            "unknown_types": dict(sorted(self.unknown_types.items())),
        }

    def note(self) -> str:
        parts = [f"Read {self.files} file(s), {self.lines} line(s)"]
        if self.unreadable:
            parts.append(f"{self.unreadable} unreadable line(s) skipped")
        if self.unreadable_files:
            parts.append(f"{self.unreadable_files} unreadable file(s) skipped")
        unknown = sum(self.unknown_types.values())
        if unknown:
            parts.append(f"{unknown} line(s) of {len(self.unknown_types)} unknown type(s) skipped")
        return ", ".join(parts) + "."


def collect_files(paths: list[str]) -> list[Path]:
    """Expand the given paths: a file is read as it is, a folder is searched for *.jsonl files recursively."""
    if not paths:
        raise InputError("give at least one transcript file or folder")
    found: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            for f in sorted(p.rglob("*.jsonl")):
                if f.is_file() and not (set(f.relative_to(p).parts[:-1]) & SKIP_DIRS):
                    found.append(f)
        else:
            raise InputError(f"{raw}: no such file or folder")
    seen: set[str] = set()
    unique = []
    for f in found:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(f)
    if not unique:
        raise InputError("no .jsonl transcript files found in the given folders")
    return unique


def read_records(files: list[Path], stats: ReadStats) -> list[Record]:
    """Every readable JSON-object line of the given files, in file order. Problems are counted in stats."""
    out: list[Record] = []
    for path in files:
        try:
            raw = path.read_bytes()
        except OSError:
            stats.unreadable_files += 1
            continue
        stats.files += 1
        for number, chunk in enumerate(raw.splitlines(), start=1):
            if not chunk.strip():
                continue
            stats.lines += 1
            try:
                data = json.loads(chunk.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                stats.unreadable += 1
                continue
            if not isinstance(data, dict):
                stats.unreadable += 1
                continue
            rec = Record(path, number, data)
            if rec.type not in CONVERSATION_TYPES and rec.type not in BOOKKEEPING_TYPES:
                stats.unknown_types[rec.type or "(none)"] += 1
                continue
            stats.records += 1
            out.append(rec)
    return out


def parse_ts(value: object) -> datetime | None:
    """An ISO 8601 timestamp as an aware UTC datetime, or None."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_day(value: str, flag: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise InputError(f"{flag}: expected a date as YYYY-MM-DD, got {value!r}") from None


def parse_range(value: str, flag: str) -> tuple[date, date]:
    """A date range written A..B (both inclusive)."""
    if ".." not in value:
        raise InputError(f"{flag}: expected a range as YYYY-MM-DD..YYYY-MM-DD, got {value!r}")
    a, b = value.split("..", 1)
    start, end = parse_day(a, flag), parse_day(b, flag)
    if end < start:
        raise InputError(f"{flag}: the range ends before it starts")
    return start, end


def in_window(ts: datetime | None, since: date | None, until: date | None) -> bool:
    """True when the timestamp's UTC date is inside [since, until]; a line without a timestamp is kept only when
    no window is set."""
    if since is None and until is None:
        return True
    if ts is None:
        return False
    d = ts.date()
    return (since is None or d >= since) and (until is None or d <= until)


def session_id(rec: Record) -> str:
    sid = rec.data.get("sessionId")
    return sid if isinstance(sid, str) and sid else rec.path.stem


def is_subagent(rec: Record) -> bool:
    return rec.data.get("isSidechain") is True or "subagents" in rec.path.parts


def project_name(path: Path) -> str:
    """The project folder a transcript belongs to: the folder that holds `<session>.jsonl`, or, for a subagent
    transcript under `<project>/<session>/subagents/...`, the folder above the session folder."""
    parts = path.parts
    if "subagents" in parts:
        i = len(parts) - 1 - parts[::-1].index("subagents")
        if i >= 2:
            return parts[i - 2]
    return path.parent.name or "."


def content_blocks(message: object) -> list[dict]:
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def message_text(message: object) -> str:
    """The plain text of a message: a string content, or its text blocks joined with newlines."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    return "\n".join(b.get("text", "") for b in content_blocks(message) if b.get("type") == "text")


def tool_result_text(block: dict) -> str:
    """The text of a tool_result block: a string, or the text parts of a list."""
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(p.get("text", "")) for p in content if isinstance(p, dict) and p.get("type", "text") == "text"
        )
    return ""


def one_line(text: str, limit: int = 120) -> str:
    flat = re.sub(r"\s+", " ", text).strip()
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def write_output(text: str, out: str | None) -> None:
    if not out:
        sys.stdout.write(text)
        return
    try:
        Path(out).write_text(text, encoding="utf-8")
    except OSError as exc:
        raise InputError(f"--out {out}: cannot write ({exc.strerror or exc})") from None


def table(headers: list[str], rows: list[list[str]], fmt: str) -> list[str]:
    """A Markdown table, or for text an aligned plain table."""
    if fmt == "markdown":
        lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
        lines += ["| " + " | ".join(r) + " |" for r in rows]
        return lines
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    lines += ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    return lines
