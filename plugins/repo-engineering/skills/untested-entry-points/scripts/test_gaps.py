#!/usr/bin/env python3
"""Map public functions and CLI entry points to the tests that mention them, and rank what is untested.

Units:
  Python      module-level public functions and classes (ast), names not starting with "_"
  JS and TS   exported functions, classes and consts (regex: export function/class/const, export { a, b })
  Entry       pyproject [project.scripts] targets, package.json "bin", and the main() of any Python file with an
              if __name__ == "__main__" guard; entry points are ranked before everything else

A unit counts as tested when any test file mentions its name as a whole word. That is a name reference, not
coverage: a mention proves nothing ran. Size is the unit's line span; fan-in is the number of non-test source
files, other than its own, that mention the name. Untested units are ranked by entry point first, then by
size x (1 + fan-in).

--stubs prints characterisation test stubs in the detected framework (pytest, unittest, jest, vitest, node:test);
--stubs-dir writes them as new files and never overwrites an existing one. Stubs are skipped or todo tests: they
pass nothing until someone records the current behaviour in them.

Exit codes: 0 ok (or untested count within --max-untested), 1 more untested units than --max-untested, 2 bad input.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import tomllib
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__", ".tox", "target",
             ".next", "coverage", ".mypy_cache", ".ruff_cache", ".pytest_cache"}
PY_TEST_RE = re.compile(r"(^|/)(tests?)/|(^|/)test_[^/]+\.py$|_test\.py$|(^|/)conftest\.py$")
JS_TEST_RE = re.compile(r"(^|/)(__tests__|tests?)/|\.(test|spec)\.[cm]?[jt]sx?$")
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")
MAX_FILE_BYTES = 1_000_000


def walk(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            if f.endswith((".py",) + JS_SUFFIXES) and not f.endswith(".d.ts"):
                out.append((Path(dirpath) / f).relative_to(root).as_posix())
    return out


def read(root: Path, rel: str) -> str | None:
    p = root / rel
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_test(rel: str) -> bool:
    return bool(PY_TEST_RE.search(rel)) if rel.endswith(".py") else bool(JS_TEST_RE.search(rel))


def py_module(rel: str) -> str:
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
        parts = parts[1:]
    return ".".join(parts)


def python_units(rel: str, text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    units = []
    has_guard = bool(re.search(r"^if __name__ == ['\"]__main__['\"]", text, re.MULTILINE))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            params = []
            if kind == "function":
                params = [a.arg for a in node.args.args + node.args.kwonlyargs if a.arg not in {"self", "cls"}]
            units.append({"name": node.name, "kind": kind, "lang": "python", "path": rel, "line": node.lineno,
                          "size": end - node.lineno + 1, "params": params,
                          "entry_point": has_guard and node.name == "main", "module": py_module(rel)})
    return units


def js_block_end(lines: list[str], start: int) -> int:
    depth, seen = 0, False
    for i in range(start, min(len(lines), start + 2000)):
        line = re.sub(r"(\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`|//.*$)", "", lines[i])
        depth += line.count("{") - line.count("}")
        if "{" in line:
            seen = True
        if seen and depth <= 0:
            return i
        if not seen and line.rstrip().endswith(";"):
            return i
    return start


def js_units(rel: str, text: str) -> list[dict]:
    lines = text.splitlines()
    units = []
    decl = re.compile(r"^\s*export\s+(?:default\s+)?(?:async\s+)?(function\*?|class|const|let|var)\s+"
                      r"([A-Za-z_$][\w$]*)\s*(\([^)]*\))?")
    for i, line in enumerate(lines):
        m = decl.match(line)
        if not m:
            continue
        end = js_block_end(lines, i)
        kind = "class" if m.group(1) == "class" else "function"
        params = []
        sig = m.group(3) or ""
        if not sig:
            am = re.search(r"=\s*(?:async\s*)?\(([^)]*)\)\s*=>", line)
            sig = f"({am.group(1)})" if am else ""
        if sig:
            params = [p.strip().split("=")[0].split(":")[0].strip() for p in sig.strip("()").split(",") if p.strip()]
        units.append({"name": m.group(2), "kind": kind, "lang": "js", "path": rel, "line": i + 1,
                      "size": end - i + 1, "params": params, "entry_point": False, "module": rel})
    for m in re.finditer(r"^\s*export\s*\{([^}]*)\}", text, re.MULTILINE):
        line = text[: m.start()].count("\n") + 1
        for part in m.group(1).split(","):
            local = part.strip().split(" as ")[0].strip()
            name = part.strip().split(" as ")[-1].strip()
            if not name or any(u["name"] == name for u in units):
                continue
            dm = re.search(rf"^\s*(?:async\s+)?(?:function\*?|class|const|let|var)\s+{re.escape(local)}\b", text,
                           re.MULTILINE)
            start = text[: dm.start()].count("\n") if dm else line - 1
            units.append({"name": name, "kind": "function", "lang": "js", "path": rel, "line": start + 1,
                          "size": js_block_end(lines, start) - start + 1, "params": [], "entry_point": False,
                          "module": rel})
    return units


def entry_targets(root: Path) -> list[tuple[str, str]]:
    """(module or path, function) pairs for declared CLI entry points."""
    out = []
    pp = root / "pyproject.toml"
    if pp.is_file():
        try:
            data = tomllib.loads(pp.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        for table in (data.get("project", {}).get("scripts", {}),
                      data.get("tool", {}).get("poetry", {}).get("scripts", {})):
            for target in (table or {}).values():
                if isinstance(target, str) and ":" in target:
                    mod, fn = target.split(":", 1)
                    out.append((mod.strip(), fn.strip().split(".")[0]))
    pj = root / "package.json"
    if pj.is_file():
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        bins = data.get("bin")
        if isinstance(bins, str):
            bins = {"bin": bins}
        for target in (bins or {}).values():
            if isinstance(target, str):
                out.append((target.lstrip("./"), "*"))
    return out


def detect_framework(root: Path, test_texts: dict[str, str], lang: str) -> str:
    if lang == "python":
        joined = "\n".join(t for r, t in test_texts.items() if r.endswith(".py"))
        pp = (root / "pyproject.toml")
        cfg = pp.read_text(encoding="utf-8", errors="replace") if pp.is_file() else ""
        if "pytest" in cfg or "import pytest" in joined or (root / "conftest.py").exists() or (
                root / "pytest.ini").exists():
            return "pytest"
        if "import unittest" in joined or "from unittest" in joined:
            return "unittest"
        return "pytest"
    pj = root / "package.json"
    deps = ""
    if pj.is_file():
        deps = pj.read_text(encoding="utf-8", errors="replace")
    if "vitest" in deps:
        return "vitest"
    if "jest" in deps:
        return "jest"
    return "node:test"


def stub(unit: dict, framework: str) -> tuple[str, str]:
    """Return (suggested file name, stub text)."""
    name = unit["name"]
    where = f"{unit['path']}:{unit['line']}"
    args = ", ".join(unit["params"])
    if unit["lang"] == "python":
        mod = unit["module"]
        placeholders = ", ".join(f"{p}=..." for p in unit["params"])
        call = f"{name}({placeholders})" if unit["kind"] == "function" else f"{name}(...)"
        head = (f'"""Characterisation test stub for {mod}.{name} ({where}).\n\n'
                "Record what the code does today before changing it: call it with real inputs, paste the observed\n"
                'output as the expected value, then remove the skip."""\n')
        if framework == "unittest":
            body = (f"{head}import unittest\n\nfrom {mod} import {name}\n\n\n"
                    f"class Test{name[:1].upper()}{name[1:]}Characterisation(unittest.TestCase):\n"
                    f'    @unittest.skip("characterisation stub: fill in real inputs and the observed output")\n'
                    f"    def test_current_behaviour(self):\n"
                    f"        result = {call}  # replace the arguments with real values\n"
                    f"        self.assertEqual(result, None)  # replace None with the observed output\n")
        else:
            body = (f"{head}import pytest\n\nfrom {mod} import {name}\n\n\n"
                    f'@pytest.mark.skip(reason="characterisation stub: fill in real inputs and the observed output")\n'
                    f"def test_{name.lower()}_current_behaviour():\n"
                    f"    result = {call}  # replace the arguments with real values\n"
                    f"    assert result == None  # noqa: E711  replace None with the observed output\n")
        return f"test_{name.lower()}_characterisation.py", body
    rel_import = "./" + os.path.splitext(unit["path"])[0]
    todo = f"{name}({args}) returns what it returns today; record real inputs and the observed output"
    ext = ".ts" if unit["path"].endswith((".ts", ".tsx", ".mts", ".cts")) else ".js"
    if framework in {"jest", "vitest"}:
        imp = 'import { test } from "vitest";\n' if framework == "vitest" else ""
        body = (f"// Characterisation test stub for {name} ({where}). Record current behaviour before changing it.\n"
                f'{imp}import {{ {name} }} from "{rel_import}";\n\n'
                f'test.todo("{todo}");\n')
    else:
        body = (f"// Characterisation test stub for {name} ({where}). Record current behaviour before changing it.\n"
                f'import {{ test }} from "node:test";\nimport {{ {name} }} from "{rel_import}";\n\n'
                f'test.todo("{todo}");\n')
    return f"{name}.characterisation.test{ext}", body


def analyse(root: Path, top: int) -> dict:
    files = walk(root)
    texts = {r: t for r in files if (t := read(root, r)) is not None}
    tests = {r: t for r, t in texts.items() if is_test(r)}
    sources = {r: t for r, t in texts.items() if r not in tests}
    units: list[dict] = []
    for rel, text in sources.items():
        units += python_units(rel, text) if rel.endswith(".py") else js_units(rel, text)
    entries = entry_targets(root)
    for u in units:
        for mod, fn in entries:
            if (u["lang"] == "python" and u["module"] == mod and u["name"] == fn) or (
                    u["lang"] == "js" and u["path"] == mod):
                u["entry_point"] = True
    word_cache: dict[str, re.Pattern] = {}
    for u in units:
        pat = word_cache.setdefault(u["name"], re.compile(rf"(?<![\w$]){re.escape(u['name'])}(?![\w$])"))
        refs = sorted(r for r, t in tests.items() if pat.search(t))
        u["tested_by"] = refs
        u["tested"] = bool(refs)
        u["fan_in"] = sum(1 for r, t in sources.items() if r != u["path"] and pat.search(t))
        u["score"] = u["size"] * (1 + u["fan_in"])
    untested = [u for u in units if not u["tested"]]
    untested.sort(key=lambda u: (not u["entry_point"], -u["score"], u["path"], u["line"]))
    langs = sorted({u["lang"] for u in units})
    frameworks = {lang: detect_framework(root, tests, lang) for lang in langs}
    return {
        "repo": str(root),
        "test_files": sorted(tests),
        "frameworks": frameworks,
        "units": len(units),
        "tested": len(units) - len(untested),
        "untested": len(untested),
        "entry_points_untested": sum(1 for u in untested if u["entry_point"]),
        "ranked_untested": [{k: u[k] for k in ("name", "kind", "lang", "path", "line", "size", "fan_in", "score",
                                               "entry_point", "module", "params")} for u in untested[:top]],
        "tested_units": [{"name": u["name"], "path": u["path"], "line": u["line"], "tested_by": u["tested_by"]}
                         for u in units if u["tested"]],
    }


def render(rep: dict) -> str:
    out = [f"Test gaps: {rep['repo']}",
           f"{rep['tested']} of {rep['units']} public units are mentioned by a test file "
           f"({len(rep['test_files'])} test files); {rep['untested']} are not, "
           f"{rep['entry_points_untested']} of them entry points.", ""]
    if rep["ranked_untested"]:
        out.append(f"{'RANK':<5}{'UNIT':<32}{'LOCATION':<36}{'SIZE':>5}{'FAN-IN':>8}  ENTRY")
        for i, u in enumerate(rep["ranked_untested"], 1):
            loc = f"{u['path']}:{u['line']}"
            out.append(f"{i:<5}{u['name'][:31]:<32}{loc[:35]:<36}{u['size']:>5}{u['fan_in']:>8}  "
                       f"{'yes' if u['entry_point'] else ''}")
    out.append("")
    out.append("Tested means a test file mentions the name; it does not mean the code ran. Confirm with a coverage "
               "tool before relying on it.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="test_gaps.py",
                                 description="Rank public functions and CLI entry points that no test mentions, and "
                                             "propose characterisation test stubs.")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--top", type=int, default=20, help="how many untested units to list (default: 20)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--stubs", action="store_true", help="print a characterisation test stub for each listed unit")
    ap.add_argument("--stubs-dir", metavar="DIR", help="write the stubs into DIR as new files (never overwrites)")
    ap.add_argument("--max-untested", type=int, help="exit 1 when more units than this are untested")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    rep = analyse(root, max(1, args.top))
    stubs = []
    if args.stubs or args.stubs_dir:
        for u in rep["ranked_untested"]:
            name, body = stub(u, rep["frameworks"].get(u["lang"], "pytest"))
            stubs.append({"unit": u["name"], "file": name, "content": body})
        rep["stubs"] = stubs
    if args.stubs_dir:
        out_dir = Path(args.stubs_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for s in stubs:
            target = out_dir / s["file"]
            if target.exists():
                s["written"] = False
                continue
            target.write_text(s["content"], encoding="utf-8")
            s["written"] = True
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(render(rep))
        if args.stubs:
            for s in stubs:
                print(f"\n# --- {s['file']} ---\n{s['content']}", end="")
        if args.stubs_dir:
            written = sum(1 for s in stubs if s.get("written"))
            print(f"\nWrote {written} stub file(s) to {args.stubs_dir}; skipped {len(stubs) - written} existing.")
    if args.max_untested is not None and rep["untested"] > args.max_untested:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
