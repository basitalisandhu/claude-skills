#!/usr/bin/env python3
"""Infer a JSON Schema (draft 2020-12) from one or more JSON sample documents.

Input: a JSON file holding one object, an array of objects (each element is a sample), or NDJSON (one document
per line); several files are merged. The schema records, per property: the union of observed types, whether it
was present in every sample (`required`), null-ability, string formats it recognises in every value (date,
date-time, email, uuid, uri, ipv4), small fixed vocabularies as `enum` (when --enum-max distinct values cover
every sample and there are at least --enum-min-samples values), numeric minimum and maximum, and string
minLength and maxLength. Arrays get an `items` schema merged across every element. Observed example values are
added as `examples` (first two) unless --no-examples.

The output is a starting point for a hand-finished schema, which is what the json-schema-author skill does with it.

Usage:
    json_schema_infer.py FILE [FILE ...] [--title NAME] [--no-examples] [--enum-max 10] [--enum-min-samples 5]
                         [--no-bounds] [--json]   (output is always JSON; --json keeps the flag uniform with the other scripts)

Exit codes: 0 schema written, 2 unreadable or invalid input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
FORMATS = [
    ("date-time", re.compile(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("time", re.compile(r"^\d{2}:\d{2}:\d{2}(\.\d+)?$")),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
    ("uri", re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.I)),
    ("ipv4", re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")),
]


class Node:
    """Accumulates observations for one position in the document tree."""

    def __init__(self):
        self.types: set[str] = set()
        self.count = 0
        self.nullable = False
        self.props: dict[str, Node] = {}
        self.prop_presence: dict[str, int] = {}
        self.object_count = 0
        self.items: Node | None = None
        self.strings: list[str] = []
        self.numbers: list[float] = []
        self.examples: list = []
        self.all_ints = True

    def observe(self, value) -> None:
        self.count += 1
        if len(self.examples) < 2 and value not in self.examples and not isinstance(value, (dict, list)):
            self.examples.append(value)
        if value is None:
            self.nullable = True
            self.types.add("null")
        elif isinstance(value, bool):
            self.types.add("boolean")
        elif isinstance(value, int):
            self.types.add("integer")
            self.numbers.append(value)
        elif isinstance(value, float):
            self.types.add("number")
            self.all_ints = self.all_ints and value.is_integer()
            self.numbers.append(value)
        elif isinstance(value, str):
            self.types.add("string")
            self.strings.append(value)
        elif isinstance(value, list):
            self.types.add("array")
            if self.items is None:
                self.items = Node()
            for v in value:
                self.items.observe(v)
        elif isinstance(value, dict):
            self.types.add("object")
            self.object_count += 1
            for k, v in value.items():
                self.props.setdefault(k, Node()).observe(v)
                self.prop_presence[k] = self.prop_presence.get(k, 0) + 1

    def schema(self, opts: dict) -> dict:
        types = set(self.types)
        if "integer" in types and "number" in types:
            types.discard("integer")
        out: dict = {}
        if not types:
            return out
        if len(types) == 1:
            out["type"] = next(iter(types))
        else:
            out["type"] = sorted(types)
        if "object" in types:
            props = {k: n.schema(opts) for k, n in sorted(self.props.items())}
            out["properties"] = props
            required = sorted(k for k, c in self.prop_presence.items() if c == self.object_count)
            if required:
                out["required"] = required
            out["additionalProperties"] = False
        if "array" in types and self.items is not None:
            out["items"] = self.items.schema(opts)
        if "string" in types and self.strings:
            for name, rx in FORMATS:
                if all(rx.match(s) for s in self.strings):
                    out["format"] = name
                    break
            distinct = sorted(set(self.strings))
            if "format" not in out and len(self.strings) >= opts["enum_min_samples"] and 1 < len(distinct) <= opts["enum_max"] and len(distinct) < len(self.strings):
                out["enum"] = distinct + ([None] if self.nullable else [])
            if opts["bounds"] and "enum" not in out and "format" not in out:
                lengths = [len(s) for s in self.strings]
                out["minLength"] = min(lengths)
                out["maxLength"] = max(lengths)
        if self.numbers and opts["bounds"]:
            out["minimum"] = min(self.numbers)
            out["maximum"] = max(self.numbers)
        if opts["examples"] and self.examples and "enum" not in out:
            out["examples"] = [e for e in self.examples if e is not None][:2] or self.examples[:1]
        return out


def load_samples(path: Path) -> list:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        raise ValueError(f"{path}: empty file")
    try:
        doc = json.loads(stripped)
        return doc if isinstance(doc, list) else [doc]
    except json.JSONDecodeError:
        pass
    samples = []
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{no}: not JSON and not NDJSON: {exc.msg}")
    return samples


def infer(samples: list, title: str | None, opts: dict) -> dict:
    root = Node()
    for s in samples:
        root.observe(s)
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
    if title:
        schema["title"] = title
    schema.update(root.schema(opts))
    schema["x-inferred-from"] = {"samples": len(samples), "tool": f"json-schema-author {VERSION}", "note": "Inferred; review required, enum, bounds and additionalProperties by hand."}
    return schema


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--title")
    ap.add_argument("--json", action="store_true", help="accepted for uniformity; output is always JSON")
    ap.add_argument("--no-examples", action="store_true")
    ap.add_argument("--no-bounds", action="store_true", help="omit minimum/maximum and minLength/maxLength")
    ap.add_argument("--enum-max", type=int, default=10)
    ap.add_argument("--enum-min-samples", type=int, default=5)
    args = ap.parse_args(argv)
    samples: list = []
    for f in args.files:
        p = Path(f)
        if not p.is_file():
            print(f"error: not a file: {f}", file=sys.stderr)
            return 2
        try:
            samples += load_samples(p)
        except (ValueError, UnicodeDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if not samples:
        print("error: no samples", file=sys.stderr)
        return 2
    opts = {"examples": not args.no_examples, "bounds": not args.no_bounds, "enum_max": args.enum_max, "enum_min_samples": args.enum_min_samples}
    print(json.dumps(infer(samples, args.title, opts), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
