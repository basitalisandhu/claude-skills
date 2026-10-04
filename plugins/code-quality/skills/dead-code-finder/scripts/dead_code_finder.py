#!/usr/bin/env python3
"""Find probably-unused functions, classes and exports in a Python or JavaScript/TypeScript tree.

Python: every top-level or class-level def/class is a candidate. A candidate is "unused" when its name does not
appear anywhere else in the tree (any file, any position) apart from its own definition. Names that start with an
underscore, dunder methods, test functions, decorated entry points (such as @app.route handlers) and names listed
in an __all__ are skipped, because they are used by convention or by a framework.

JavaScript/TypeScript: every `export function|class|const|let|var NAME` and `export { a, b }` is a candidate. A
candidate is "unused" when NAME is not imported or referenced in any other file. `export default` and files named
index.* are skipped (they are entry points by convention).

This is a name-based heuristic, not a call graph: dynamic access (getattr, globals()[name], string-keyed registries,
reflection) is invisible to it. Treat the output as a list of things to confirm, not a list of things to delete.

Usage:
    dead_code_finder.py PATH [--json] [--include-private] [--exclude DIR ...] [--fail-on-findings]

Exit codes: 0 no findings (or findings without --fail-on-findings), 1 findings with --fail-on-findings, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_EXCLUDES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", "coverage", ".next", "target"}
PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MAX_FILE_BYTES = 2 * 1024 * 1024

FRAMEWORK_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "task", "command", "fixture", "receiver",
                        "register", "listener", "on", "event", "hook", "api", "websocket", "middleware", "validator",
                        "field_validator", "model_validator", "property", "cached_property", "overload", "main",
                        "cli", "group", "option", "argument", "pytest", "app", "router", "bp", "blueprint", "celery"}
JS_EXPORT_RE = re.compile(r"^\s*export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var|enum|interface|type|abstract\s+class)\s+([A-Za-z_$][\w$]*)", re.M)
JS_EXPORT_LIST_RE = re.compile(r"^\s*export\s*\{([^}]*)\}\s*(?:;|$)", re.M)
JS_EXPORT_DEFAULT_RE = re.compile(r"^\s*export\s+default\b", re.M)
WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")


def iter_files(root: Path, excludes: set[str]):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in excludes for part in p.relative_to(root).parts[:-1]):
            continue
        if p.suffix in PY_SUFFIXES or p.suffix in JS_SUFFIXES:
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_test_file(p: Path) -> bool:
    name = p.name
    return (name.startswith("test_") or name.endswith("_test.py") or ".test." in name or ".spec." in name
            or "tests" in p.parts or "__tests__" in p.parts or "test" in p.parts)


def decorator_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for d in getattr(node, "decorator_list", []):
        target = d.func if isinstance(d, ast.Call) else d
        while isinstance(target, ast.Attribute):
            names.add(target.attr)
            target = target.value
        if isinstance(target, ast.Name):
            names.add(target.id)
    return names


def python_candidates(path: Path, tree: ast.Module, include_private: bool) -> list[dict]:
    out: list[dict] = []
    exported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                exported |= {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}

    def visit(body, owner: str | None):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
                kind = "class" if isinstance(node, ast.ClassDef) else ("method" if owner else "function")
                skip = (name in exported or name.startswith("__") and name.endswith("__")
                        or (name.startswith("_") and not include_private)
                        or name.startswith("test") and is_test_file(path)
                        or decorator_names(node) & FRAMEWORK_DECORATORS
                        or (owner and name in {"setUp", "tearDown", "setUpClass", "tearDownClass", "get_queryset", "save",
                                               "clean", "validate", "render", "dispatch", "handle", "run", "forward"}))
                if not skip:
                    out.append({"file": str(path), "line": node.lineno, "name": name, "kind": kind,
                                "qualname": f"{owner}.{name}" if owner else name, "language": "python"})
                if isinstance(node, ast.ClassDef):
                    visit(node.body, name)
    visit(tree.body, None)
    return out


def js_candidates(path: Path, text: str) -> list[dict]:
    out: list[dict] = []
    if path.stem == "index" or JS_EXPORT_DEFAULT_RE.search(text) and path.suffix in {".jsx", ".tsx"}:
        return out
    for m in JS_EXPORT_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"file": str(path), "line": line, "name": m.group(1), "kind": "export", "qualname": m.group(1), "language": "javascript"})
    for m in JS_EXPORT_LIST_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        for part in m.group(1).split(","):
            part = part.strip()
            if not part or part.startswith("type "):
                continue
            name = part.split(" as ")[-1].strip()
            if name and name != "default":
                out.append({"file": str(path), "line": line, "name": name, "kind": "export", "qualname": name, "language": "javascript"})
    return out


def analyse(root: Path, include_private: bool, excludes: set[str]) -> dict:
    files = list(iter_files(root, excludes))
    candidates: list[dict] = []
    word_counts: Counter[str] = Counter()
    per_file_words: dict[str, Counter[str]] = {}
    parse_errors: list[str] = []
    for p in files:
        text = read(p)
        words = Counter(WORD_RE.findall(text))
        per_file_words[str(p)] = words
        word_counts.update(words)
        if p.suffix in PY_SUFFIXES:
            try:
                tree = ast.parse(text, filename=str(p))
            except SyntaxError as exc:
                parse_errors.append(f"{p}:{exc.lineno}: {exc.msg}")
                continue
            candidates += python_candidates(p, tree, include_private)
        else:
            candidates += js_candidates(p, text)
    findings: list[dict] = []
    for c in candidates:
        total = word_counts[c["name"]]
        own = per_file_words.get(c["file"], Counter())[c["name"]]
        elsewhere = total - own
        # A definition references its own name once (def NAME / class NAME / export NAME). Other mentions inside the
        # same file count as use (recursion, local calls); for JS exports only other-file references count.
        if c["language"] == "python":
            used = elsewhere > 0 or own > 1
        else:
            used = elsewhere > 0
        if not used:
            c = dict(c, references_elsewhere=elsewhere)
            try:
                c["file"] = str(Path(c["file"]).relative_to(root)) if root.is_dir() else c["file"]
            except ValueError:
                pass
            findings.append(c)
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return {
        "version": VERSION,
        "root": str(root),
        "files_scanned": len(files),
        "candidates": len(candidates),
        "findings": findings,
        "parse_errors": parse_errors,
        "note": "Name-based heuristic. Dynamic access (getattr, registries, reflection, templates) is not visible; confirm before deleting.",
    }


def render_text(report: dict) -> str:
    lines = [f"dead-code-finder {report['version']}: {report['files_scanned']} files, {report['candidates']} candidates, {len(report['findings'])} probably unused"]
    for f in report["findings"]:
        lines.append(f"  {f['file']}:{f['line']}  {f['kind']} {f['qualname']}")
    for e in report["parse_errors"]:
        lines.append(f"  parse error: {e}")
    lines.append(report["note"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="directory or file to scan")
    ap.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    ap.add_argument("--include-private", action="store_true", help="also report names that start with an underscore")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR", help="directory name to skip (repeatable)")
    ap.add_argument("--fail-on-findings", action="store_true", help="exit 1 when anything is reported")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    report = analyse(root, args.include_private, DEFAULT_EXCLUDES | set(args.exclude))
    print(json.dumps(report, indent=2) if args.json else render_text(report))
    return 1 if (args.fail_on_findings and report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
