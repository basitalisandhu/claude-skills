#!/usr/bin/env python3
"""Extract API documentation from source: Python docstrings (via ast) and JavaScript/TypeScript JSDoc blocks.

For each module it lists public functions, classes and methods with their signature, the first paragraph of
the docstring, and (for Python) parsed Google, NumPy or reST style parameter and return sections; for JS/TS the
JSDoc @param, @returns, @throws, @deprecated and @example tags. Undocumented public symbols are listed separately
so the gaps are visible. Output is Markdown (default) or JSON.

Usage:
    extract_docs.py PATH [--json] [--include-private] [--exclude DIR ...] [--min-coverage PERCENT]

Exit codes: 0 extracted, 1 documentation coverage below --min-coverage, 2 bad input.
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
DEFAULT_EXCLUDES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "tests", "test", "__tests__", ".tox", "coverage"}
JSDOC_RE = re.compile(r"/\*\*(?P<doc>.*?)\*/\s*(?P<decl>(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*(?P<fname>[\w$]+)\s*(?:<[^>]*>)?\s*\((?P<fparams>[^)]*)\)|class\s+(?P<cname>[\w$]+)|(?:const|let|var)\s+(?P<vname>[\w$]+)\s*=\s*(?:async\s*)?(?:\((?P<aparams>[^)]*)\)|[\w$]+)\s*(?::[^=]+)?=>|(?P<mname>[\w$]+)\s*\((?P<mparams>[^)]*)\)\s*(?::[^{]+)?\{))", re.S)
PY_PARAM_SECTION_RE = re.compile(r"^(Args|Arguments|Parameters|Params|Keyword Args|Returns|Return|Yields|Raises|Attributes|Examples?|Notes?)\s*:?\s*$", re.M)


def iter_files(root: Path, excludes: set[str]):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"} and not p.name.endswith(".d.ts"):
            if any(part in excludes for part in p.relative_to(root).parts[:-1]):
                continue
            yield p


def parse_py_docstring(doc: str) -> dict:
    """Split a docstring into summary, body and parameter/return sections (Google, NumPy, reST)."""
    doc = doc.strip()
    if not doc:
        return {"summary": "", "params": {}, "returns": "", "raises": []}
    paragraphs = re.split(r"\n\s*\n", doc, maxsplit=1)
    summary = " ".join(paragraphs[0].split())
    params: dict[str, str] = {}
    returns = ""
    raises: list[str] = []
    for m in re.finditer(r"^\s*:param\s+(?:\w+\s+)?(\w+):\s*(.*)$", doc, re.M):
        params[m.group(1)] = m.group(2).strip()
    rm = re.search(r"^\s*:returns?:\s*(.*)$", doc, re.M)
    if rm:
        returns = rm.group(1).strip()
    for m in re.finditer(r"^\s*:raises?\s+(\w+):", doc, re.M):
        raises.append(m.group(1))
    sections = PY_PARAM_SECTION_RE.split(doc)
    for i in range(1, len(sections) - 1, 2):
        name, body = sections[i], sections[i + 1]
        body = re.sub(r"^\s*-{3,}\s*$", "", body, flags=re.M)
        if name in {"Args", "Arguments", "Parameters", "Params", "Keyword Args"}:
            for pm in re.finditer(r"^\s*(\*{0,2}\w+)\s*(?:\(([^)]*)\))?\s*:\s*(.*)$", body, re.M):
                params[pm.group(1)] = pm.group(3).strip()
            for pm in re.finditer(r"^(\w+)\s*:\s*[^\n]+\n\s+(.*)$", body, re.M):  # NumPy "name : type\n    desc"
                params.setdefault(pm.group(1), pm.group(2).strip())
        elif name in {"Returns", "Return", "Yields"}:
            returns = returns or " ".join(body.strip().split())[:200]
        elif name == "Raises":
            raises += re.findall(r"^\s*(\w+(?:\.\w+)*)\s*:", body, re.M)
    return {"summary": summary, "params": params, "returns": returns, "raises": sorted(set(raises))}


def py_signature(node) -> str:
    a = node.args
    parts: list[str] = []

    def fmt(arg, default=None, prefix=""):
        text = prefix + arg.arg
        if arg.annotation is not None:
            text += f": {ast.unparse(arg.annotation)}"
        if default is not None:
            text += f" = {ast.unparse(default)}" if arg.annotation is not None else f"={ast.unparse(default)}"
        return text

    positional = a.posonlyargs + a.args
    defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
    for i, (arg, d) in enumerate(zip(positional, defaults)):
        parts.append(fmt(arg, d))
        if a.posonlyargs and i == len(a.posonlyargs) - 1:
            parts.append("/")
    if a.vararg:
        parts.append(fmt(a.vararg, prefix="*"))
    elif a.kwonlyargs:
        parts.append("*")
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        parts.append(fmt(arg, d))
    if a.kwarg:
        parts.append(fmt(a.kwarg, prefix="**"))
    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
    return f"{prefix}{node.name}({', '.join(parts)}){ret}"


def extract_python(path: Path, text: str, include_private: bool) -> dict:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return {"file": str(path), "language": "python", "error": f"line {exc.lineno}: {exc.msg}", "symbols": []}
    module_doc = ast.get_docstring(tree) or ""
    symbols: list[dict] = []

    def visible(name: str) -> bool:
        return include_private or not name.startswith("_") or (name.startswith("__") and name.endswith("__") and name == "__init__")

    def visit(body, owner: str | None):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and visible(node.name):
                doc = ast.get_docstring(node) or ""
                parsed = parse_py_docstring(doc)
                symbols.append({"kind": "method" if owner else "function", "name": f"{owner}.{node.name}" if owner else node.name, "line": node.lineno,
                                "signature": py_signature(node), "documented": bool(doc.strip()), **parsed})
            elif isinstance(node, ast.ClassDef) and visible(node.name):
                doc = ast.get_docstring(node) or ""
                parsed = parse_py_docstring(doc)
                bases = ", ".join(ast.unparse(b) for b in node.bases)
                symbols.append({"kind": "class", "name": node.name, "line": node.lineno, "signature": f"class {node.name}({bases})" if bases else f"class {node.name}", "documented": bool(doc.strip()), **parsed})
                visit(node.body, node.name)
    visit(tree.body, None)
    return {"file": str(path), "language": "python", "module_doc": " ".join(module_doc.strip().split("\n\n")[0].split()) if module_doc else "", "symbols": symbols}


def parse_jsdoc(doc: str) -> dict:
    lines = [re.sub(r"^\s*\*\s?", "", l) for l in doc.strip().splitlines()]
    text = "\n".join(lines).strip()
    chunks = re.split(r"(?:^|\s)(?=@[a-zA-Z]+\b)", text)
    description = chunks[0].strip() if chunks else ""
    params: dict[str, str] = {}
    returns = ""
    raises: list[str] = []
    deprecated = None
    examples: list[str] = []
    for chunk in chunks[1:]:
        chunk = chunk.strip()
        tag, _, rest = chunk.partition(" ") if "\n" not in chunk.split(" ", 1)[0] else (chunk.split("\n", 1)[0], "", chunk.split("\n", 1)[1])
        rest = rest.strip()
        if tag in {"@param", "@arg", "@argument"}:
            m = re.match(r"(?:\{[^}]*\}\s*)?\[?([\w$.]+)(?:=[^\]]*)?\]?\s*-?\s*(.*)$", " ".join(rest.split()), re.S)
            if m:
                params[m.group(1)] = m.group(2).strip()
        elif tag in {"@returns", "@return"}:
            returns = re.sub(r"^\{[^}]*\}\s*-?\s*", "", " ".join(rest.split())).strip()
        elif tag in {"@throws", "@exception"}:
            tm = re.match(r"^\{([^}]*)\}", rest)
            raises.append((tm.group(1) if tm else "Error").strip())
        elif tag == "@deprecated":
            deprecated = " ".join(rest.split()) or "yes"
        elif tag == "@example":
            if rest:
                examples.append(rest)
    summary = " ".join(description.split("\n\n")[0].split())
    return {"summary": summary.split(". ")[0] + ("." if ". " in summary else "") if summary else "", "params": params, "returns": returns, "raises": raises, "deprecated": deprecated, "examples": examples}


def extract_js(path: Path, text: str, include_private: bool) -> dict:
    symbols: list[dict] = []
    documented_spans: set[int] = set()
    for m in JSDOC_RE.finditer(text):
        name = m.group("fname") or m.group("cname") or m.group("vname") or m.group("mname")
        if not name or name in {"if", "for", "while", "switch", "catch", "return"}:
            continue
        if name.startswith("_") and not include_private:
            continue
        params = m.group("fparams") or m.group("aparams") or m.group("mparams") or ""
        kind = "class" if m.group("cname") else ("method" if m.group("mname") else "function")
        parsed = parse_jsdoc(m.group("doc"))
        line = text.count("\n", 0, m.start("decl")) + 1
        documented_spans.add(line)
        symbols.append({"kind": kind, "name": name, "line": line, "signature": f"{name}({' '.join(params.split())})" if kind != "class" else f"class {name}", "documented": bool(parsed["summary"] or parsed["params"]), **parsed})
    for m in re.finditer(r"^\s*export\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*([\w$]+)|class\s+([\w$]+)|(?:const|let|var)\s+([\w$]+))", text, re.M):
        name = m.group(1) or m.group(2) or m.group(3)
        line = text.count("\n", 0, m.start()) + 1
        if line not in documented_spans and (include_private or not name.startswith("_")):
            symbols.append({"kind": "class" if m.group(2) else "function", "name": name, "line": line, "signature": name, "documented": False, "summary": "", "params": {}, "returns": "", "raises": []})
    symbols.sort(key=lambda s: s["line"])
    return {"file": str(path), "language": "javascript", "module_doc": "", "symbols": symbols}


def render_markdown(report: dict) -> str:
    out = [f"# API reference", "", f"Generated by api-docs-from-code {report['version']} from `{report['root']}`: {report['summary']['symbols']} public symbols, {report['summary']['documented']} documented ({report['summary']['percent']}%).", ""]
    for mod in report["modules"]:
        if not mod["symbols"] and not mod.get("error"):
            continue
        out.append(f"## `{mod['file']}`")
        out.append("")
        if mod.get("error"):
            out.append(f"Parse error: {mod['error']}")
            out.append("")
            continue
        if mod.get("module_doc"):
            out.append(mod["module_doc"])
            out.append("")
        for s in mod["symbols"]:
            out.append(f"### `{s['signature']}`")
            out.append("")
            if s.get("deprecated"):
                out.append(f"**Deprecated:** {s['deprecated']}")
                out.append("")
            out.append(s["summary"] if s["summary"] else "_Undocumented._")
            out.append("")
            if s["params"]:
                out.append("| Parameter | Description |")
                out.append("|---|---|")
                out += [f"| `{k}` | {v or ''} |" for k, v in s["params"].items()]
                out.append("")
            if s["returns"]:
                out.append(f"Returns: {s['returns']}")
                out.append("")
            if s["raises"]:
                out.append("Raises: " + ", ".join(f"`{r}`" for r in s["raises"]))
                out.append("")
            for ex in s.get("examples") or []:
                out += ["```", ex, "```", ""]
    gaps = [f"{m['file']}:{s['line']} {s['name']}" for m in report["modules"] for s in m["symbols"] if not s["documented"]]
    if gaps:
        out.append("## Undocumented public symbols")
        out.append("")
        out += [f"- {g}" for g in gaps]
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--include-private", action="store_true")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR")
    ap.add_argument("--min-coverage", type=float, default=0.0, help="exit 1 when fewer than this percent of public symbols are documented")
    args = ap.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    modules: list[dict] = []
    for p in iter_files(root, DEFAULT_EXCLUDES | set(args.exclude)):
        text = p.read_text(encoding="utf-8", errors="replace")
        rec = extract_python(p, text, args.include_private) if p.suffix == ".py" else extract_js(p, text, args.include_private)
        if root.is_dir():
            rec["file"] = str(p.relative_to(root))
        modules.append(rec)
    total = sum(len(m["symbols"]) for m in modules)
    documented = sum(1 for m in modules for s in m["symbols"] if s["documented"])
    report = {"version": VERSION, "root": str(root), "modules": modules,
              "summary": {"files": len(modules), "symbols": total, "documented": documented, "percent": round(100.0 * documented / total, 1) if total else 100.0}}
    print(json.dumps(report, indent=2) if args.json else render_markdown(report))
    return 1 if report["summary"]["percent"] < args.min_coverage else 0


if __name__ == "__main__":
    sys.exit(main())
