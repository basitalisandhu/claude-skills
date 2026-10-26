#!/usr/bin/env python3
"""Seal an agent's audit log as a hash chain, verify it later, and check it recorded every action.

An agent audit log (one JSON object per line: a hook's activity log, an MCP gateway or proxy log, an agent
runtime's action log) is only evidence if nobody could edit, delete or reorder lines after the fact, and only
complete if every action the agent took is in it. This script does three things, offline:

  seal      add a chain record {"_chain": {"seq", "prev", "hash"}} to every line, where hash is SHA-256 (or
            HMAC-SHA256 with --key-file) over the previous hash and the line's canonical JSON. Prints the head
            (last sequence number and hash) to store somewhere the log writer cannot change.
  verify    recompute the chain and report edited lines, deleted, inserted or reordered lines, sequence gaps and
            duplicates, timestamps that go backwards, lines that are not JSON or carry no chain record, and a
            log that is shorter than or different from a stored head.
  coverage  compare the action ids in the log with the ids of the actions that happened (a Claude Code session
            log's tool_use ids, or a plain list) and report actions the log never recorded.

Usage:
  audit_chain.py seal actions.jsonl --out actions.sealed.jsonl
  audit_chain.py verify actions.sealed.jsonl --head 41:3f9c...
  audit_chain.py coverage actions.sealed.jsonl --transcript session.jsonl --id-field tool_use_id

Standard library only (hashlib, hmac, json); no network. A key file is read, never printed.

Exit codes: 0 sealed, intact or complete; 1 verify or coverage found a problem; 2 bad input (missing file, a file
that holds no JSON lines at all, a bad --head value, an empty key file, a log that is already sealed when sealing).
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
TIME_FIELDS = ("ts", "timestamp", "time", "@timestamp", "eventTime", "createdDateTime", "activityDateTime")
ID_FIELDS = ("tool_use_id", "toolUseId", "action_id", "id", "event_id", "eventID", "request_id")


class InputError(Exception):
    """Bad input: exit code 2."""


def guard_bad_shapes(main):
    """Decorate main(): a value of an unexpected type inside an input file (a number where a string belongs, a list
    where an object belongs) exits 2 with a message instead of a traceback."""

    @functools.wraps(main)
    def wrapper(*args, **kwargs):
        try:
            return main(*args, **kwargs)
        except (TypeError, AttributeError, KeyError, IndexError, ValueError, RecursionError) as exc:
            print(
                f"error: an input file holds a value of an unexpected type or shape ({type(exc).__name__}: {exc}); "
                "check that each file is the unchanged export or output named in --help, then run again",
                file=sys.stderr,
            )
            return 2

    return wrapper


def canonical(record: dict) -> bytes:
    body = {k: v for k, v in record.items() if k != "_chain"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def link(prev: str, record: dict, seq: int, key: bytes | None) -> str:
    material = f"{seq}:{prev}:".encode() + canonical(record)
    if key:
        return hmac.new(key, material, hashlib.sha256).hexdigest()
    return hashlib.sha256(material).hexdigest()


def read_key(path: str | None) -> bytes | None:
    if not path:
        return None
    try:
        key = Path(path).expanduser().read_bytes().strip()
    except OSError as exc:
        raise InputError(f"--key-file: cannot read {path}: {exc}") from exc
    if not key:
        raise InputError(f"--key-file: {path} is empty")
    return key


def read_lines(path: Path) -> list[tuple[int, str]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise InputError(f"{path} not found") from exc
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{path} is not UTF-8 text") from exc
    lines = [(n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    if not lines:
        raise InputError(f"{path} is empty")
    return lines


def parse(lines: list[tuple[int, str]], path: Path) -> list[tuple[int, dict | None, str]]:
    out, ok = [], 0
    for n, line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            out.append((n, None, line))
            continue
        if isinstance(rec, dict):
            ok += 1
            out.append((n, rec, line))
        else:
            out.append((n, None, line))
    if ok == 0:
        raise InputError(f"{path} holds no JSON object lines")
    return out


def when(rec: dict) -> datetime | None:
    for f in TIME_FIELDS:
        v = rec.get(f)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            secs = v / 1000 if v > 1e11 else v
            try:
                return datetime.fromtimestamp(secs, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):  # an epoch beyond what the platform can hold
                return None
        if isinstance(v, str) and v:
            s = v.strip().replace("Z", "+00:00")
            try:
                t = datetime.fromisoformat(s)
            except ValueError:
                continue
            return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return None


def parse_head(value: str | None) -> tuple[int, str] | None:
    if not value:
        return None
    m = re.fullmatch(r"(\d+):([0-9a-f]{64})", value.strip())
    if not m:
        raise InputError("--head must look like <seq>:<64 hex characters>, as seal prints it")
    return int(m.group(1)), m.group(2)


# ---------------------------------------------------------------- seal


def cmd_seal(args) -> int:
    path = Path(args.log)
    key = read_key(args.key_file)
    records = parse(read_lines(path), path)
    bad = [n for n, rec, _ in records if rec is None]
    if bad:
        raise InputError(f"{path}: line {bad[0]} is not a JSON object; fix or remove it before sealing")
    if any("_chain" in rec for _, rec, _ in records):
        raise InputError(f"{path} already carries _chain records; verify it instead of sealing it again")
    prev, out = GENESIS, []
    start = args.start_seq
    for i, (_, rec, _) in enumerate(records):
        seq = start + i
        h = link(prev, rec, seq, key)
        sealed = dict(rec)
        sealed["_chain"] = {"seq": seq, "prev": prev, "hash": h, "alg": "hmac-sha256" if key else "sha256"}
        out.append(json.dumps(sealed, ensure_ascii=False))
        prev = h
    text = "\n".join(out) + "\n"
    dest = Path(args.out) if args.out else None
    if dest:
        dest.write_text(text, encoding="utf-8")
    head = f"{start + len(records) - 1}:{prev}"
    summary = {"sealed": len(records), "head": head, "alg": "hmac-sha256" if key else "sha256", "out": args.out}
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        if not dest:
            sys.stdout.write(text)
            return 0
        print(f"Sealed {len(records)} lines into {dest.name} ({summary['alg']}).")
        print(f"Head: {head}")
        print("Store the head where the log writer cannot change it (a ticket, a signed commit, a WORM bucket).")
    return 0


# ---------------------------------------------------------------- verify


def verify(records, key: bytes | None, head, skew: float) -> tuple[list[dict], dict]:
    findings: list[dict] = []

    def add(kind: str, line: int | None, detail: str) -> None:
        findings.append({"kind": kind, "line": line, "detail": detail})

    prev_hash, prev_seq, prev_time = None, None, None
    seen_seq: dict[int, int] = {}
    hashes: dict[str, int] = {}
    last_hash, last_seq, chained = None, None, 0
    algs = set()
    for n, rec, _ in records:
        if rec is None:
            add("unparseable-line", n, "not a JSON object: the line was damaged or written by something else")
            prev_hash = None
            continue
        chain = rec.get("_chain")
        if not isinstance(chain, dict) or not {"seq", "prev", "hash"} <= set(chain):
            add("unsealed-line", n, "no _chain record: written after sealing, or inserted")
            prev_hash = None
            continue
        seq, prev, h = chain.get("seq"), chain.get("prev"), chain.get("hash")
        if not isinstance(seq, int) or not isinstance(prev, str) or not isinstance(h, str):
            add("bad-chain-record", n, "_chain fields have the wrong types")
            prev_hash = None
            continue
        chained += 1
        algs.add(chain.get("alg", "sha256"))
        if seq in seen_seq:
            add("duplicate-seq", n, f"sequence {seq} also on line {seen_seq[seq]}")
        seen_seq.setdefault(seq, n)
        expect = link(prev, rec, seq, key)
        if not hmac.compare_digest(expect, h):
            add("hash-mismatch", n, f"sequence {seq}: content does not match its hash (edited, or the wrong key)")
        if prev_seq is not None and seq != prev_seq + 1 and seq not in (prev_seq,):
            if seq > prev_seq + 1:
                add("seq-gap", n, f"sequence jumps from {prev_seq} to {seq}: {seq - prev_seq - 1} line(s) missing")
            else:
                add("seq-backwards", n, f"sequence goes back from {prev_seq} to {seq}: lines reordered or inserted")
        if prev_hash is not None and prev != prev_hash:
            if prev in hashes:
                add("prev-mismatch", n, f"links to line {hashes[prev]}, not the line before it: lines reordered")
            else:
                add("prev-mismatch", n, "does not link to the line before it: a line before it was removed or edited")
        elif prev_hash is None and prev_seq is None and prev != GENESIS:
            add("starts-mid-chain", n, f"first line links to an earlier hash (sequence {seq}): the start is missing")
        t = when(rec)
        if t is not None and prev_time is not None and (prev_time - t).total_seconds() > skew:
            add("time-backwards", n, f"timestamp {t.isoformat()} is before the previous line's {prev_time.isoformat()}")
        if t is not None:
            prev_time = t
        hashes[h] = n
        prev_hash, prev_seq, last_hash, last_seq = h, seq, h, seq
    if len(algs) > 1:
        add("mixed-algorithms", None, f"lines use {', '.join(sorted(algs))}")
    if "hmac-sha256" in algs and key is None:
        add("key-needed", None, "lines were sealed with HMAC; pass --key-file to check their hashes")
    if head is not None:
        hseq, hhash = head
        if last_seq is None:
            add("head-mismatch", None, "the stored head cannot be checked: no sealed line")
        elif last_seq < hseq:
            add("truncated", None, f"the stored head is sequence {hseq} but the log ends at {last_seq}")
        elif hhash not in hashes:
            add("head-mismatch", None, f"no line has the stored head hash (sequence {hseq})")
        elif last_seq > hseq:
            add("appended", None, f"{last_seq - hseq} line(s) after the stored head (information)")
    summary = {
        "lines": len(records),
        "chained": chained,
        "first_seq": min(seen_seq) if seen_seq else None,
        "last_seq": last_seq,
        "head": f"{last_seq}:{last_hash}" if last_hash else None,
    }
    return findings, summary


def cmd_verify(args) -> int:
    path = Path(args.log)
    key = read_key(args.key_file)
    head = parse_head(args.head)
    if args.head_file:
        try:
            head = parse_head(Path(args.head_file).read_text(encoding="utf-8").strip())
        except (OSError, UnicodeDecodeError) as exc:
            raise InputError(f"--head-file: cannot read {args.head_file}: {exc}") from exc
    records = parse(read_lines(path), path)
    findings, summary = verify(records, key, head, args.skew)
    problems = [f for f in findings if f["kind"] != "appended"]
    result = {"log": path.name, "intact": not problems, "summary": summary, "findings": findings}
    if args.json:
        text = json.dumps(result, indent=2) + "\n"
    else:
        lines = [
            "# Audit log integrity",
            "",
            f"Log: {path.name}. Lines: {summary['lines']}, sealed: {summary['chained']}, "
            f"sequence {summary['first_seq']} to {summary['last_seq']}.",
            f"Result: {'intact' if not problems else 'NOT intact'} ({len(problems)} problem(s)).",
            f"Head now: {summary['head']}",
            "",
            "## Findings",
            "",
        ]
        lines += [
            f"- {f['kind']}" + (f" (line {f['line']})" if f["line"] else "") + f": {f['detail']}" for f in findings
        ]
        if not findings:
            lines.append("None. Every line links to the one before it and matches its hash.")
        text = "\n".join(lines) + "\n"
    write(text, args.out)
    return 1 if problems else 0


# ---------------------------------------------------------------- coverage


def expected_ids(args) -> list[str]:
    ids: list[str] = []
    for t in args.transcript:
        for n, line in read_lines(Path(t)):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"--transcript {t}: line {n} is not JSON") from exc
            msg = rec.get("message") if isinstance(rec, dict) else None
            content = msg.get("content") if isinstance(msg, dict) else None
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                    ids.append(block["id"])
    for f in args.expected:
        for _, line in read_lines(Path(f)):
            ids.append(line.strip())
    if not ids:
        raise InputError("no expected action ids: give --transcript with tool calls or --expected with ids")
    return list(dict.fromkeys(ids))


def cmd_coverage(args) -> int:
    path = Path(args.log)
    records = parse(read_lines(path), path)
    expect = expected_ids(args)
    fields = [args.id_field] if args.id_field else list(ID_FIELDS)
    logged: dict[str, int] = {}
    for n, rec, _ in records:
        if rec is None:
            continue
        for f in fields:
            v = rec.get(f)
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                logged.setdefault(str(v), n)
                break
    missing = [i for i in expect if i not in logged]
    expected_set = set(expect)  # built once: rebuilding it per logged id made coverage quadratic
    extra = [i for i in logged if i not in expected_set]
    result = {
        "log": path.name,
        "expected": len(expect),
        "logged": len([i for i in expect if i in logged]),
        "missing": missing,
        "not_expected": extra,
        "complete": not missing,
    }
    if args.json:
        text = json.dumps(result, indent=2) + "\n"
    else:
        pct = 100 * result["logged"] / len(expect)
        lines = [
            "# Audit log coverage",
            "",
            f"Log: {path.name}. Expected actions: {len(expect)}. Recorded: {result['logged']} ({pct:.0f}%).",
            "",
            "## Actions the log never recorded",
            "",
        ]
        lines += [f"- `{i}`" for i in missing] or ["None."]
        lines += ["", "## Logged ids not in the expected list (information)", ""]
        lines += [f"- `{i}` (line {logged[i]})" for i in extra] or ["None."]
        text = "\n".join(lines) + "\n"
    write(text, args.out)
    return 1 if missing else 0


def write(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


@guard_bad_shapes
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="audit_chain.py",
        description="Seal an agent audit log (JSON lines) as a SHA-256 or HMAC hash chain, verify it later, and check "
        "that it recorded every action the agent took.",
        epilog="Exit codes: 0 sealed, intact or complete; 1 verify or coverage found a problem; 2 bad input.",
    )
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("seal", help="add a hash chain to every line")
    s.add_argument("log")
    s.add_argument("--out", help="write the sealed log here (default: standard output)")
    s.add_argument("--key-file", help="file holding an HMAC key; without it the chain is plain SHA-256")
    s.add_argument("--start-seq", type=int, default=0, help="first sequence number (default 0)")
    s.add_argument("--json", action="store_true", help="print the seal summary as JSON")
    v = sub.add_parser("verify", help="recompute the chain and report breaks")
    v.add_argument("log")
    v.add_argument("--head", help="the head printed by seal, <seq>:<hash>")
    v.add_argument("--head-file", help="a file holding the head")
    v.add_argument("--key-file", help="the HMAC key file used to seal")
    v.add_argument("--skew", type=float, default=5.0, help="seconds a timestamp may go back before it is flagged")
    v.add_argument("--json", action="store_true", help="JSON output")
    v.add_argument("--out", help="write the report to this file")
    c = sub.add_parser("coverage", help="list actions the log never recorded")
    c.add_argument("log")
    c.add_argument("--transcript", action="append", default=[], help="Claude Code session log: its tool_use ids")
    c.add_argument("--expected", action="append", default=[], help="a file with one expected action id per line")
    c.add_argument(
        "--id-field", help=f"field holding the action id in the log (default: first of {', '.join(ID_FIELDS)})"
    )
    c.add_argument("--json", action="store_true", help="JSON output")
    c.add_argument("--out", help="write the report to this file")
    args = ap.parse_args(argv)
    try:
        return {"seal": cmd_seal, "verify": cmd_verify, "coverage": cmd_coverage}[args.command](args)
    except InputError as exc:
        print(f"audit_chain.py {args.command}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
