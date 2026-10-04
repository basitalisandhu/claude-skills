#!/usr/bin/env python3
"""Lint an AGENTS.md or CLAUDE.md for lines that repeat what a parser can already read, or point at nothing.

Checks:
  CTX-MANIFEST  a command that a manifest already declares: "npm run X" / "pnpm X" / "yarn X" for a package.json
                script, "make X" for a Makefile target, "just X" for a justfile recipe, a pyproject console script
  CTX-DEPS      a line naming three or more dependencies that the manifests already list
  CTX-RUNTIME   a runtime version the manifest already pins (requires-python, engines.node, .nvmrc, .python-version)
  CTX-TREE      a directory tree listing; the agent can list files itself
  CTX-PATH      a path in backticks or a relative link that does not exist in the repository
  CTX-GENERIC   generic advice that applies to every repository ("write clean code", "follow best practices")
  CTX-BUDGET    the file is longer than the line or word budget

The file's length against the budget is always reported. Reads files only; runs nothing.
Exit codes: 0 no findings, 1 findings, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".tox", "target", ".next"}
PATH_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".toml", ".yml", ".yaml", ".md", ".txt",
    ".cfg", ".ini", ".sh", ".go", ".rs", ".rb", ".java", ".kt", ".sql", ".lock", ".env", ".example", ".html",
    ".css", ".tf", ".proto", ".graphql", ".mdx",
}
BARE_FILENAMES = {"Makefile", "Dockerfile", "LICENSE", "Procfile", "Justfile", "justfile", "Gemfile"}
GENERIC = [
    r"write clean(,)? (readable |maintainable )?code", r"follow (the )?best practices",
    r"meaningful (variable )?names", r"keep (functions|code) (small|simple)", r"write (good|comprehensive) tests",
    r"handle errors (properly|gracefully)",
    r"be consistent", r"use descriptive names", r"follow (the )?(existing )?coding (style|standards)",
    r"make sure (the )?code is (readable|maintainable)", r"(avoid|don't|do not) (write )?duplicate code",
    r"add comments where (necessary|needed)", r"follow solid principles",
]
SPAN_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
LINK_RE = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")


def read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None
    except OSError:
        return None


class Manifests:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.npm_scripts: set[str] = set()
        self.make_targets: set[str] = set()
        self.just_recipes: set[str] = set()
        self.console_scripts: set[str] = set()
        self.deps: set[str] = set()
        self.runtimes: list[tuple[str, str]] = []
        pj_text = read(root / "package.json")
        if pj_text:
            try:
                pj = json.loads(pj_text)
            except json.JSONDecodeError:
                pj = {}
            self.npm_scripts = set((pj.get("scripts") or {}).keys())
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                self.deps |= {d.split("/")[-1].lower() for d in (pj.get(key) or {})}
            node = (pj.get("engines") or {}).get("node")
            if isinstance(node, str):
                self.runtimes.append(("node", node))
        pp_text = read(root / "pyproject.toml")
        if pp_text:
            try:
                pp = tomllib.loads(pp_text)
            except tomllib.TOMLDecodeError:
                pp = {}
            proj = pp.get("project", {})
            self.console_scripts |= set((proj.get("scripts") or {}).keys())
            self.console_scripts |= set((pp.get("tool", {}).get("poetry", {}).get("scripts") or {}).keys())
            reqs = list(proj.get("dependencies") or [])
            for group in (proj.get("optional-dependencies") or {}).values():
                reqs += list(group)
            for group in (pp.get("dependency-groups") or {}).values():
                reqs += [r for r in group if isinstance(r, str)]
            poetry = pp.get("tool", {}).get("poetry", {})
            reqs += [k for k in (poetry.get("dependencies") or {}) if k != "python"]
            self.deps |= {req_name(r) for r in reqs if req_name(r)}
            if isinstance(proj.get("requires-python"), str):
                self.runtimes.append(("python", proj["requires-python"]))
        for req in sorted(root.glob("requirements*.txt")):
            for ln in (read(req) or "").splitlines():
                name = req_name(ln)
                if name:
                    self.deps.add(name)
        for f, lang in ((".nvmrc", "node"), (".python-version", "python")):
            v = read(root / f)
            if v and v.strip():
                self.runtimes.append((lang, v.strip()))
        mk = read(root / "Makefile") or read(root / "makefile")
        if mk:
            self.make_targets = set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", mk, re.MULTILINE))
        jf = read(root / "justfile") or read(root / "Justfile")
        if jf:
            self.just_recipes = set(re.findall(r"^@?([A-Za-z0-9_-]+)[^:\n=]*:(?!=)", jf, re.MULTILINE))
        self.deps = {d for d in self.deps if len(d) >= 3}


def req_name(line: str) -> str:
    line = line.split("#")[0].strip()
    if not line or line.startswith("-"):
        return ""
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
    return m.group(1).lower().replace("_", "-") if m else ""


class Tree:
    def __init__(self, root: Path) -> None:
        self.files: set[str] = set()
        self.dirs: set[str] = set()
        self.basenames: set[str] = set()
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            base = Path(dirpath).relative_to(root).as_posix()
            if base != ".":
                self.dirs.add(base)
            for f in filenames:
                rel = f if base == "." else f"{base}/{f}"
                self.files.add(rel)
                self.basenames.add(f)
                count += 1
            if count > 50_000:
                break

    def exists(self, rel: str) -> bool:
        rel = rel.strip("/")
        return rel in self.files or rel in self.dirs


def path_status(raw: str, tree: Tree, ctx_dir: str) -> str | None:
    """'ok', 'missing', or None when raw does not look like a repository path."""
    s = raw.strip()
    if not s or any(c in s for c in "<>*{}$ |'\"\\") or s.startswith(("~", "/", "-", "http:", "https:")):
        return None
    s = re.sub(r":\d+(?:-\d+)?$", "", s)
    s = s[2:] if s.startswith("./") else s
    last = s.rstrip("/").split("/")[-1]
    if not last or re.fullmatch(r"\.[A-Za-z0-9]{1,6}", s):
        return None
    has_ext = Path(last).suffix.lower() in PATH_SUFFIXES or last in BARE_FILENAMES or (
        last.startswith(".") and len(last) > 2)
    has_slash = "/" in s.rstrip("/")
    if not has_ext and not has_slash:
        return None
    if not has_slash:
        return "ok" if tree.exists(s) or s.rstrip("/") in tree.basenames else "missing"
    for cand in (s, os.path.normpath(os.path.join(ctx_dir, s)) if ctx_dir else s):
        if tree.exists(Path(cand).as_posix()):
            return "ok"
    if has_ext or tree.exists(s.split("/")[0]):
        return "missing"
    return None


def command_dupes(text: str, m: Manifests) -> list[str]:
    hits = []
    for cmd in re.finditer(r"\b(npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)", text):
        name = cmd.group(2)
        if name in m.npm_scripts:
            hits.append(f"{cmd.group(0)} (package.json scripts)")
    for cmd in re.finditer(r"\bmake\s+([A-Za-z0-9_.-]+)", text):
        if cmd.group(1) in m.make_targets:
            hits.append(f"make {cmd.group(1)} (Makefile target)")
    for cmd in re.finditer(r"\bjust\s+([A-Za-z0-9_-]+)", text):
        if cmd.group(1) in m.just_recipes:
            hits.append(f"just {cmd.group(1)} (justfile recipe)")
    for name in m.console_scripts:
        if re.search(rf"(?:^|`|\$ )\s*{re.escape(name)}(?:\s|`|$)", text):
            hits.append(f"{name} (pyproject console script)")
    return hits


def lint(ctx_path: Path, root: Path, max_lines: int, max_words: int) -> dict:
    text = read(ctx_path)
    if text is None:
        raise FileNotFoundError(str(ctx_path))
    m = Manifests(root)
    tree = Tree(root)
    try:
        ctx_dir = ctx_path.resolve().parent.relative_to(root.resolve()).as_posix()
        ctx_dir = "" if ctx_dir == "." else ctx_dir
    except ValueError:
        ctx_dir = ""
    findings: list[dict] = []

    def add(code: str, line: int, message: str, src: str) -> None:
        findings.append({"code": code, "line": line, "message": message, "text": src.strip()[:160]})

    lines = text.splitlines()
    in_fence = False
    fence_start = 0
    fence_body: list[str] = []
    for no, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r"^(```|~~~)", stripped):
            if not in_fence:
                in_fence, fence_start, fence_body = True, no, []
            else:
                in_fence = False
                tree_lines = [b for b in fence_body if re.search(r"[├└│]|^\s*[\w.-]+/\s*(#.*)?$", b)]
                if tree_lines and len(tree_lines) >= max(2, len(fence_body) // 2):
                    add("CTX-TREE", fence_start, "directory tree listing; the agent can list files itself",
                        fence_body[0] if fence_body else "")
            continue
        if in_fence:
            fence_body.append(line)
            for hit in command_dupes(line, m):
                add("CTX-MANIFEST", no, f"repeats a manifest command: {hit}", line)
            continue
        for hit in command_dupes(line, m):
            add("CTX-MANIFEST", no, f"repeats a manifest command: {hit}", line)
        low = line.lower()
        named = sorted({d for d in m.deps if re.search(rf"(?<![\w-]){re.escape(d)}(?![\w-])", low)})
        if len(named) >= 3:
            add("CTX-DEPS", no, f"lists dependencies the manifests already declare: {', '.join(named)}", line)
        for lang, spec in m.runtimes:
            vm = re.search(rf"\b{lang}(?:\.js)?\s*v?(\d+(?:\.\d+)?)", low)
            if vm and vm.group(1) in spec:
                add("CTX-RUNTIME", no, f"{lang} {vm.group(1)} is already pinned in the manifest ({spec})", line)
        for span in SPAN_RE.findall(line):
            if path_status(span, tree, ctx_dir) == "missing":
                add("CTX-PATH", no, f"`{span}` does not exist in the repository", line)
        for target in LINK_RE.findall(line):
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            t = unquote(target.split("#")[0])
            if t and path_status(t if "/" in t or "." in t else t + "/", tree, ctx_dir) == "missing":
                add("CTX-PATH", no, f"link target {t} does not exist in the repository", line)
        for pat in GENERIC:
            if re.search(pat, low):
                add("CTX-GENERIC", no, "generic advice; it applies to every repository and tells the agent nothing",
                    line)
                break
    nonempty = sum(1 for ln in lines if ln.strip())
    words = len(re.findall(r"\S+", text))
    if nonempty > max_lines or words > max_words:
        add("CTX-BUDGET", 1, f"{nonempty} non-empty lines and {words} words; budget is {max_lines} lines and "
                             f"{max_words} words", lines[0] if lines else "")
    findings.sort(key=lambda f: (f["line"], f["code"]))
    return {
        "file": str(ctx_path),
        "repo": str(root),
        "length": {"nonempty_lines": nonempty, "words": words, "max_lines": max_lines, "max_words": max_words,
                   "within_budget": nonempty <= max_lines and words <= max_words},
        "findings": findings,
        "counts": {code: sum(1 for f in findings if f["code"] == code)
                   for code in sorted({f["code"] for f in findings})},
    }


def render(rep: dict) -> str:
    out = [f"{f['code']:<13} line {f['line']:>4}  {f['message']}" for f in rep["findings"]]
    ln = rep["length"]
    out.append("")
    out.append(f"Length: {ln['nonempty_lines']}/{ln['max_lines']} non-empty lines, {ln['words']}/{ln['max_words']} "
               f"words ({'within' if ln['within_budget'] else 'over'} budget)")
    out.append(f"{len(rep['findings'])} finding(s)")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="context_lint.py",
                                 description="Flag AGENTS.md or CLAUDE.md lines that restate manifests or name "
                                             "missing files, and report length against a budget.")
    ap.add_argument("context_file", help="AGENTS.md, CLAUDE.md or another agent context file")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--max-lines", type=int, default=60, help="non-empty line budget (default: 60)")
    ap.add_argument("--max-words", type=int, default=600, help="word budget (default: 600)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    try:
        rep = lint(Path(args.context_file), root, args.max_lines, args.max_words)
    except FileNotFoundError:
        print(f"error: cannot read {args.context_file}", file=sys.stderr)
        return 2
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
