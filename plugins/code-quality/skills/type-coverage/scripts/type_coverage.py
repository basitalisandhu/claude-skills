#!/usr/bin/env python3
"""Measure type annotation coverage for Python and TypeScript sources.

Python (ast): for every function, each parameter (except self/cls) and the return value is a slot; a slot is
covered when it has an annotation. Files with `from __future__ import annotations` are handled the same way.
TypeScript (tokenizer): each parameter of a function, arrow function or method is a slot, covered when it has a
`: type` annotation; explicit `any` annotations are counted separately because they are typed in name only.
Plain JavaScript files are listed but not measured.

Usage:
    type_coverage.py PATH [--json] [--min PERCENT] [--exclude DIR ...] [--top N]

Exit codes: 0 overall coverage at or above --min (default 0, so informational), 1 below --min, 2 bad input.
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
MAX_FILE_BYTES = 2 * 1024 * 1024


def iter_files(root: Path, excludes: set[str]):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in {".py", ".ts", ".tsx"} and not p.name.endswith(".d.ts"):
            if any(part in excludes for part in p.relative_to(root).parts[:-1]):
                continue
            try:
                if p.stat().st_size <= MAX_FILE_BYTES:
                    yield p
            except OSError:
                pass


def python_file(path: Path, text: str) -> dict:
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return {"file": str(path), "language": "python", "error": f"line {exc.lineno}: {exc.msg}", "slots": 0, "covered": 0, "functions": 0, "untyped": []}
    slots = covered = functions = 0
    untyped: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions += 1
            params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            if node.args.vararg:
                params.append(node.args.vararg)
            if node.args.kwarg:
                params.append(node.args.kwarg)
            missing: list[str] = []
            for a in params:
                if a.arg in {"self", "cls"}:
                    continue
                slots += 1
                if a.annotation is not None:
                    covered += 1
                else:
                    missing.append(a.arg)
            slots += 1
            if node.returns is not None or node.name == "__init__":
                covered += 1
            else:
                missing.append("return")
            if missing:
                untyped.append({"name": node.name, "line": node.lineno, "missing": missing})
    return {"file": str(path), "language": "python", "slots": slots, "covered": covered, "functions": functions, "untyped": untyped}


def _strip_ts(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        c = text[i]
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
                j += 1
            j = min(j + 1, n)
            out.append(c + re.sub(r"[^\n]", " ", text[i + 1:j - 1]) + c)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


TS_FUNC_RE = re.compile(
    r"\bfunction\s*\*?\s*(?P<fname>[A-Za-z_$][\w$]*)?\s*(?:<[^>]*>)?\s*\("
    r"|(?:const|let|var)\s+(?P<vname>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?=\s*(?:async\s*)?(?:<[^>]*>)?\s*\((?P<arrowparams>[^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::\s*[^=]+?)?=>"
    r"|^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+|async\s+|readonly\s+|override\s+)*(?P<mname>[A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\((?P<mparams>[^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::\s*[^{;=]+)?\s*\{",
    re.M)
TS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "else", "do", "try", "with"}


def _params_at(text: str, open_paren: int) -> str:
    depth = 0
    for j in range(open_paren, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:j]
    return ""


def _split_params(params: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in params:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def ts_file(path: Path, text: str) -> dict:
    clean = _strip_ts(text)
    slots = covered = functions = any_count = 0
    untyped: list[dict] = []
    for m in TS_FUNC_RE.finditer(clean):
        name = m.group("fname") or m.group("vname") or m.group("mname") or "<anonymous>"
        if m.group("mname") and name in TS_KEYWORDS:
            continue
        if m.group("fname") is not None or (m.group("fname") is None and m.group("vname") is None and m.group("mname") is None):
            params = _params_at(clean, m.end() - 1)
        elif m.group("vname"):
            params = m.group("arrowparams")
        else:
            params = m.group("mparams")
        functions += 1
        missing: list[str] = []
        for p in _split_params(params):
            if p.startswith("..."):
                p = p[3:]
            if p.startswith("this:"):
                continue
            slots += 1
            if ":" in p and not p.lstrip().startswith("{") and not p.lstrip().startswith("["):
                covered += 1
                if re.search(r":\s*any\b", p):
                    any_count += 1
            elif p.lstrip().startswith(("{", "[")) and re.search(r"[}\]]\s*:", p):
                covered += 1
            else:
                missing.append(p.split("=")[0].strip() or "?")
        if missing:
            untyped.append({"name": name, "line": clean.count("\n", 0, m.start()) + 1, "missing": missing})
    any_count += len(re.findall(r"\bas\s+any\b", clean))
    return {"file": str(path), "language": "typescript", "slots": slots, "covered": covered, "functions": functions, "any": any_count, "untyped": untyped}


def analyse(root: Path, excludes: set[str]) -> dict:
    files: list[dict] = []
    for p in iter_files(root, excludes):
        text = p.read_text(encoding="utf-8", errors="replace")
        rec = python_file(p, text) if p.suffix == ".py" else ts_file(p, text)
        if root.is_dir():
            try:
                rec["file"] = str(p.relative_to(root))
            except ValueError:
                pass
        rec["percent"] = round(100.0 * rec["covered"] / rec["slots"], 1) if rec["slots"] else 100.0
        files.append(rec)
    slots = sum(f["slots"] for f in files)
    covered = sum(f["covered"] for f in files)
    return {"version": VERSION, "root": str(root), "files": files,
            "summary": {"files": len(files), "functions": sum(f["functions"] for f in files), "slots": slots, "covered": covered,
                        "percent": round(100.0 * covered / slots, 1) if slots else 100.0,
                        "any_annotations": sum(f.get("any", 0) for f in files)}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min", type=float, default=0.0, help="fail (exit 1) when overall coverage is below this percent")
    ap.add_argument("--top", type=int, default=15, help="least-covered files to list in text mode")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    report = analyse(root, DEFAULT_EXCLUDES | set(args.exclude))
    report["min"] = args.min
    s = report["summary"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"type-coverage {VERSION}: {s['percent']}% of {s['slots']} slots annotated across {s['files']} files ({s['functions']} functions, {s['any_annotations']} explicit any)")
        worst = sorted((f for f in report["files"] if f["slots"]), key=lambda f: (f["percent"], -f["slots"]))[:args.top]
        for f in worst:
            print(f"  {f['percent']:>5}%  {f['covered']:>4}/{f['slots']:<4} {f['file']}")
            for u in f["untyped"][:3]:
                print(f"           line {u['line']} {u['name']}: {', '.join(u['missing'])}")
    return 1 if s["percent"] < args.min else 0


if __name__ == "__main__":
    sys.exit(main())
