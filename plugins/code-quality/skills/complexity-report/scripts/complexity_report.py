#!/usr/bin/env python3
"""Report cyclomatic complexity, length and nesting depth per function for Python and JavaScript/TypeScript.

Python is parsed with ast: complexity = 1 + if/elif/for/while/except/with/assert/comprehension-if/boolean operator
branches/ternaries/match cases. JavaScript and TypeScript use a tokenizer that strips strings and comments, finds
function-like declarations (function f, const f = () =>, method shorthand, class methods) by brace matching, and
counts if/else if/for/while/case/catch/&&/||/??/?: inside each body. Both are approximations in the same spirit as
radon and eslint's complexity rule; the point is to rank functions, not to produce a certified number.

Usage:
    complexity_report.py PATH [--json] [--max-complexity N] [--max-length N] [--top N] [--exclude DIR ...]

Exit codes: 0 nothing over the thresholds, 1 at least one function over --max-complexity or --max-length, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_EXCLUDES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "coverage", ".next", "target"}
PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def iter_files(root: Path, excludes: set[str]):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and (p.suffix in PY_SUFFIXES or p.suffix in JS_SUFFIXES):
            if any(part in excludes for part in p.relative_to(root).parts[:-1]):
                continue
            try:
                if p.stat().st_size <= MAX_FILE_BYTES:
                    yield p
            except OSError:
                continue


# ---- Python -------------------------------------------------------------------------------------------------
class _PyVisitor(ast.NodeVisitor):
    def __init__(self):
        self.complexity = 1
        self.max_depth = 0
        self._depth = 0

    def _branch(self, node, nested=True):
        self.complexity += 1
        if nested:
            self._depth += 1
            self.max_depth = max(self.max_depth, self._depth)
            self.generic_visit(node)
            self._depth -= 1
        else:
            self.generic_visit(node)

    def visit_If(self, node):
        self._branch(node)

    def visit_For(self, node):
        self._branch(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self._branch(node)

    def visit_ExceptHandler(self, node):
        self._branch(node)

    def visit_With(self, node):
        self._depth += 1
        self.max_depth = max(self.max_depth, self._depth)
        self.generic_visit(node)
        self._depth -= 1

    visit_AsyncWith = visit_With

    def visit_Try(self, node):
        self._depth += 1
        self.max_depth = max(self.max_depth, self._depth)
        self.generic_visit(node)
        self._depth -= 1

    def visit_Assert(self, node):
        self._branch(node, nested=False)

    def visit_IfExp(self, node):
        self._branch(node, nested=False)

    def visit_BoolOp(self, node):
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_comprehension(self, node):
        self.complexity += 1 + len(node.ifs)
        self.generic_visit(node)

    def visit_match_case(self, node):
        self._branch(node)

    def visit_FunctionDef(self, node):
        # nested functions are measured on their own; do not descend
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_ClassDef(self, node):
        return


def python_functions(path: Path, text: str) -> tuple[list[dict], str | None]:
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [], f"{path}:{exc.lineno}: {exc.msg}"
    out: list[dict] = []

    def walk(body, owner):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                v = _PyVisitor()
                for child in node.body:
                    v.visit(child)
                end = getattr(node, "end_lineno", node.lineno)
                out.append({"file": str(path), "name": f"{owner}.{node.name}" if owner else node.name, "line": node.lineno,
                            "length": end - node.lineno + 1, "complexity": v.complexity, "max_depth": v.max_depth,
                            "params": len(node.args.args) + len(node.args.kwonlyargs) + len(node.args.posonlyargs)
                            + (1 if node.args.vararg else 0) + (1 if node.args.kwarg else 0), "language": "python"})
                walk(node.body, f"{owner}.{node.name}" if owner else node.name)
            elif isinstance(node, ast.ClassDef):
                walk(node.body, f"{owner}.{node.name}" if owner else node.name)
    walk(tree.body, "")
    return out, None


# ---- JavaScript / TypeScript --------------------------------------------------------------------------------
def _strip_js(text: str) -> str:
    """Replace comments and string/template contents with spaces, keeping newlines and length."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif c != "`" and text[j] == "\n":
                    break
                j += 1
            j = min(j + 1, n)
            out.append(c + re.sub(r"[^\n]", " ", text[i + 1:j - 1]) + (c if j - 1 < n else ""))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


JS_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:default\s+)?(?:async\s+)?\bfunction\s*\*?\s*(?P<fname>[A-Za-z_$][\w$]*)?\s*(?:<[^>()]*>)?\s*\("
    r"|\b(?:const|let|var)\s+(?P<vname>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?\s*=>"
    r"|\b(?:const|let|var)\s+(?P<vname2>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b"
    r"|^[ \t]*(?:(?:public|private|protected|static|async|readonly|override)\s+)*(?P<mname>[A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\([^;{}]*\)\s*(?::\s*[^{;=]+)?\s*\{",
    re.M)
JS_KEYWORD_METHODS = {"if", "for", "while", "switch", "catch", "function", "return", "else", "do", "try", "with", "constructor"}
JS_BRANCH_RE = re.compile(r"\b(if|for|while|case|catch)\b|&&|\|\||\?\?|\?[^.:?]")


def _find_body(text: str, start: int) -> tuple[int, int] | None:
    """From index start, find the first '{' outside a parameter list and return (open, close) indexes."""
    i = start
    depth_paren = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth_paren += 1
        elif c == ")":
            depth_paren -= 1
        elif c == "{" and depth_paren <= 0:
            break
        elif c == ";" and depth_paren <= 0:
            return None
        elif c == "\n" and depth_paren <= 0 and not text[i + 1:].lstrip().startswith("{"):
            return None
        i += 1
    if i >= n:
        return None
    depth = 0
    j = i
    while j < n:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return i, j
        j += 1
    return None


def js_functions(path: Path, text: str) -> list[dict]:
    clean = _strip_js(text)
    out: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for m in JS_FUNC_RE.finditer(clean):
        name = m.group("fname") or m.group("vname") or m.group("vname2") or m.group("mname")
        if m.group("mname") and name in JS_KEYWORD_METHODS:
            continue
        name = name or "<anonymous>"
        if m.group("mname"):
            body = _find_body(clean, m.start())
        elif m.group("fname") is not None or (m.group("vname") is None and m.group("vname2") is None):
            body = _find_body(clean, m.end() - 1)
        else:
            body = _find_body(clean, m.end())
        if not body:
            continue
        if body in seen:
            continue
        seen.add(body)
        inner = clean[body[0] + 1:body[1]]
        complexity = 1 + len(JS_BRANCH_RE.findall(inner))
        # nesting depth from braces inside the body
        depth = max_depth = 0
        for ch in inner:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth -= 1
        line = clean.count("\n", 0, m.start()) + 1
        length = clean.count("\n", body[0], body[1]) + 1
        out.append({"file": str(path), "name": name, "line": line, "length": length, "complexity": complexity,
                    "max_depth": max_depth, "params": None, "language": "javascript"})
    return out


def analyse(root: Path, excludes: set[str]) -> dict:
    functions: list[dict] = []
    errors: list[str] = []
    files = 0
    for p in iter_files(root, excludes):
        files += 1
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix in PY_SUFFIXES:
            fns, err = python_functions(p, text)
            if err:
                errors.append(err)
            functions += fns
        else:
            functions += js_functions(p, text)
    for f in functions:
        if root.is_dir():
            try:
                f["file"] = str(Path(f["file"]).relative_to(root))
            except ValueError:
                pass
    return {"version": VERSION, "root": str(root), "files_scanned": files, "functions": functions, "parse_errors": errors}


def grade(c: int) -> str:
    return "A" if c <= 5 else "B" if c <= 10 else "C" if c <= 20 else "D" if c <= 30 else "F"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-complexity", type=int, default=10, help="threshold that marks a function as over (default 10)")
    ap.add_argument("--max-length", type=int, default=60, help="line-count threshold (default 60)")
    ap.add_argument("--top", type=int, default=20, help="rows to print in text mode")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    report = analyse(root, DEFAULT_EXCLUDES | set(args.exclude))
    fns = report["functions"]
    for f in fns:
        f["grade"] = grade(f["complexity"])
        f["over"] = f["complexity"] > args.max_complexity or f["length"] > args.max_length
    fns.sort(key=lambda f: (-f["complexity"], -f["length"], f["file"], f["line"]))
    over = [f for f in fns if f["over"]]
    report["thresholds"] = {"max_complexity": args.max_complexity, "max_length": args.max_length}
    report["summary"] = {"functions": len(fns), "over_threshold": len(over),
                         "mean_complexity": round(sum(f["complexity"] for f in fns) / len(fns), 2) if fns else 0.0,
                         "max_complexity": max((f["complexity"] for f in fns), default=0)}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"complexity-report {VERSION}: {report['files_scanned']} files, {s['functions']} functions, mean {s['mean_complexity']}, max {s['max_complexity']}, {s['over_threshold']} over threshold")
        print(f"{'CC':>4} {'G':>1} {'len':>4} {'depth':>5}  function")
        for f in fns[:args.top]:
            flag = "*" if f["over"] else " "
            print(f"{f['complexity']:>4} {f['grade']:>1} {f['length']:>4} {f['max_depth']:>5} {flag} {f['file']}:{f['line']} {f['name']}")
        for e in report["parse_errors"]:
            print(f"parse error: {e}")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
