#!/usr/bin/env python3
"""Map source modules to the test files that cover them by name, and list the modules with no test.

Conventions recognised (case-insensitive, any directory):
  Python       foo.py        <->  test_foo.py, foo_test.py, tests/test_foo.py, tests/<pkg>/test_foo.py
  JS/TS        foo.ts        <->  foo.test.ts, foo.spec.ts, __tests__/foo.ts, __tests__/foo.test.ts, test/foo.test.ts
  Go           foo.go        <->  foo_test.go (same directory)
  Ruby         foo.rb        <->  foo_spec.rb, foo_test.rb, test_foo.rb
  Rust         foo.rs        <->  inline #[cfg(test)] module, or tests/foo.rs
A test file also "covers" a module when it imports it (Python `import x`/`from x import`, JS `from './x'`,
`require('./x')`), so a differently named test still counts. A module counts as covered when either rule matches.
Entry points and config files (app.py, main.py, index.ts, settings.py and similar) and __init__.py are not counted as
modules; the report says how many were skipped so an all-entry-point project does not read as fully covered.

Usage:
    test_gap_finder.py PATH [--json] [--min PERCENT] [--exclude DIR ...] [--include-init]

Exit codes: 0 coverage-by-file at or above --min (default 0), 1 below --min, 2 bad input (not a directory, --min
outside 0-100, or no source modules found).
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_EXCLUDES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "coverage", ".next", "target", "migrations", "vendor"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".go", ".rb", ".rs"}
TEST_DIRS = {"tests", "test", "__tests__", "spec", "specs", "testing"}
TEST_NAME_RE = re.compile(r"^(test_.*|.*_test|.*\.test|.*\.spec|.*_spec|conftest|setup_tests?)$", re.I)
NON_MODULE_NAMES = {"setup", "conf", "config", "settings", "__main__", "manage", "wsgi", "asgi", "urls", "constants",
                    "types", "index", "main", "app", "server", "vite.config", "jest.config", "webpack.config",
                    "tailwind.config", "next.config", "babel.config", "eslint.config", "rollup.config", "tsup.config",
                    "mod", "lib", "build", "gulpfile", "gruntfile", "rakefile"}
FROM_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^\n#)]+)", re.M)
IMPORT_RES = [
    re.compile(r"^\s*import\s+([\w.]+)", re.M),
    re.compile(r"""(?:from|require\(|import\()\s*['"]([^'"]+)['"]""", re.M),
    re.compile(r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", re.M),
    re.compile(r"^\s*(?:use|mod)\s+([\w:]+)", re.M),
]


def is_test_path(p: Path, root: Path) -> bool:
    rel = p.relative_to(root) if root.is_dir() else p
    if any(part.lower() in TEST_DIRS for part in rel.parts[:-1]):
        return True
    stem = p.name[:-len(p.suffix)] if p.suffix else p.name
    return bool(TEST_NAME_RE.match(stem))


def iter_sources(root: Path, excludes: set[str]):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in SOURCE_SUFFIXES:
            continue
        if p.name.endswith(".d.ts") or p.name.endswith(".min.js"):
            continue
        if any(part in excludes for part in p.relative_to(root).parts[:-1]):
            continue
        yield p


def module_key(p: Path) -> str:
    stem = p.name[:-len(p.suffix)]
    return stem.lower()


def candidate_test_keys(stem: str) -> set[str]:
    keys: set[str] = set()
    # a private module (_parser.py) is usually tested as test_parser.py, so try the name without leading underscores too
    for s in {stem.lower(), stem.lower().lstrip("_")} - {""}:
        keys |= {f"test_{s}", f"{s}_test", f"{s}.test", f"{s}.spec", f"{s}_spec", s}
    return keys


def analyse(root: Path, excludes: set[str], include_init: bool) -> dict:
    sources: list[Path] = []
    tests: list[Path] = []
    for p in iter_sources(root, excludes):
        (tests if is_test_path(p, root) else sources).append(p)
    test_keys: dict[str, list[Path]] = {}
    test_imports: dict[Path, set[str]] = {}
    for t in tests:
        stem = t.name[:-len(t.suffix)]
        test_keys.setdefault(stem.lower(), []).append(t)
        text = t.read_text(encoding="utf-8", errors="replace")
        names: set[str] = set()
        for rx in IMPORT_RES:
            for m in rx.finditer(text):
                raw = m.group(1)
                names.add(raw.split("/")[-1].split(".")[-1].split("::")[-1].lower())
                names.add(raw.split("/")[-1].lower())
                names.add(raw.lower())
        for m in FROM_IMPORT_RE.finditer(text):
            base = m.group(1).lower()
            names.add(base)
            names.add(base.split(".")[-1])
            for item in m.group(2).split(","):
                item = item.strip().split(" as ")[0].strip().lower()
                if item:
                    names.add(item)
                    names.add(f"{base}.{item}")
        test_imports[t] = names
    modules: list[dict] = []
    skipped: list[str] = []
    for s in sources:
        stem = s.name[:-len(s.suffix)]
        if (stem == "__init__" and not include_init) or stem.lower() in NON_MODULE_NAMES or stem.startswith("."):
            skipped.append(s.relative_to(root).as_posix())
            continue
        covered_by: list[str] = []
        for key in candidate_test_keys(stem):
            for t in test_keys.get(key, []):
                if t != s:
                    covered_by.append(t.relative_to(root).as_posix())
        if s.suffix == ".rs":
            text = s.read_text(encoding="utf-8", errors="replace")
            if "#[cfg(test)]" in text:
                covered_by.append(f"{s.relative_to(root).as_posix()} (inline #[cfg(test)])")
        if not covered_by:
            mod_names = {stem.lower()}
            parts = s.relative_to(root).with_suffix("").parts
            for i in range(len(parts)):
                mod_names.add(".".join(parts[i:]).lower())
                mod_names.add("/".join(parts[i:]).lower())
            for t, names in test_imports.items():
                if names & mod_names:
                    covered_by.append(t.relative_to(root).as_posix())
        modules.append({"module": s.relative_to(root).as_posix(), "language": s.suffix.lstrip("."), "covered": bool(covered_by),
                        "tests": sorted(set(covered_by))})
    uncovered = [m for m in modules if not m["covered"]]
    return {"version": VERSION, "root": str(root), "source_modules": len(modules), "test_files": len(tests),
            "covered": len(modules) - len(uncovered),
            "percent": round(100.0 * (len(modules) - len(uncovered)) / len(modules), 1) if modules else 100.0,
            "modules": modules, "uncovered": [m["module"] for m in uncovered], "skipped_entry_points": skipped,
            "note": "Name and import based. A module listed as covered may still have weak tests; one listed as uncovered may be exercised indirectly."}


def percent_arg(text: str) -> float:
    """argparse type for a percentage between 0 and 100."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a percentage, got {text!r}") from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"must be a percentage between 0 and 100, got {value:g}")
    return value


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min", type=percent_arg, default=0.0, help="exit 1 when the share of modules with a test is below this percent")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR")
    ap.add_argument("--include-init", action="store_true", help="count __init__.py files as modules")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    report = analyse(root, DEFAULT_EXCLUDES | set(args.exclude), args.include_init)
    if not report["source_modules"]:
        where = f" ({len(report['skipped_entry_points'])} entry-point or config file(s) skipped, such as {report['skipped_entry_points'][0]})" if report["skipped_entry_points"] else ""
        print(f"error: no source modules found under {root}{where}; suffixes read: {', '.join(sorted(SOURCE_SUFFIXES))}", file=sys.stderr)
        return 2
    report["min"] = args.min
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        skipped = len(report["skipped_entry_points"])
        print(f"test-gap-finder {VERSION}: {report['covered']}/{report['source_modules']} modules have a test by name or import ({report['percent']}%), {report['test_files']} test files"
              + (f", {skipped} entry-point or config file(s) not counted" if skipped else ""))
        for m in report["uncovered"]:
            print(f"  no test: {m}")
        print(report["note"])
    return 1 if report["percent"] < args.min else 0


if __name__ == "__main__":
    sys.exit(main())
