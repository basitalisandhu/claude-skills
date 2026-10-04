#!/usr/bin/env python3
"""Deterministic inventory of a repository: the facts an audit starts from.

Sections in the report:
  languages        file count and line count per language (by extension)
  entry_points     pyproject scripts, package.json bin/main/scripts, Python __main__ guards, Dockerfile
                   ENTRYPOINT/CMD, Makefile targets, conventional main files
  tests            test files by naming convention
  ci               CI configuration files (GitHub Actions, GitLab, CircleCI, Azure, Jenkins, Travis)
  manifests        dependency manifests, each with whether a lockfile sits next to it
  licence          licence files with the detected licence family
  largest_files    the largest source files by line count
  untested_files   source files whose module name no test file mentions

Reads files only; runs nothing. Exit codes: 0 ok, 2 bad input.
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

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__", ".tox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "target", ".next", ".cache", "coverage", "vendor",
}
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 50_000
LANGS = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".java": "Java",
    ".kt": "Kotlin", ".swift": "Swift", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".cs": "C#", ".php": "PHP", ".sh": "Shell", ".bash": "Shell", ".sql": "SQL", ".html": "HTML",
    ".css": "CSS", ".scss": "CSS", ".md": "Markdown", ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML",
    ".json": "JSON", ".tf": "Terraform", ".dockerfile": "Dockerfile",
}
SOURCE_LANGS = {"Python", "JavaScript", "TypeScript", "Go", "Rust", "Ruby", "Java", "Kotlin", "Swift", "C", "C++",
                "C#", "PHP", "Shell"}
MANIFESTS = {
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"],
    "setup.py": [], "setup.cfg": [],
    "Pipfile": ["Pipfile.lock"],
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
    "go.mod": ["go.sum"], "Cargo.toml": ["Cargo.lock"], "Gemfile": ["Gemfile.lock"],
    "pom.xml": [], "build.gradle": [], "build.gradle.kts": [], "composer.json": ["composer.lock"],
}
CI_PATTERNS = [
    re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"), re.compile(r"^\.gitlab-ci\.ya?ml$"),
    re.compile(r"^\.circleci/config\.ya?ml$"), re.compile(r"^azure-pipelines\.ya?ml$"),
    re.compile(r"^Jenkinsfile$"), re.compile(r"^\.travis\.ya?ml$"), re.compile(r"^bitbucket-pipelines\.ya?ml$"),
]
TEST_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$|_spec\.rb$")
MAIN_NAMES = {"main.py", "__main__.py", "manage.py", "app.py", "main.go", "index.js", "index.ts", "server.js",
              "server.ts", "main.rs", "cli.py"}
LICENCE_FAMILIES = [
    ("MIT", r"\bMIT License\b|Permission is hereby granted, free of charge"),
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
    ("GPL-3.0", r"GNU GENERAL PUBLIC LICENSE\s+Version 3"),
    ("GPL-2.0", r"GNU GENERAL PUBLIC LICENSE\s+Version 2"),
    ("LGPL", r"GNU LESSER GENERAL PUBLIC LICENSE"),
    ("AGPL-3.0", r"GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("MPL-2.0", r"Mozilla Public License,?\s+(v\.|Version)\s*2\.0"),
    ("BSD", r"Redistribution and use in source and binary forms"),
    ("ISC", r"\bISC License\b"),
    ("Unlicense", r"This is free and unencumbered software"),
]


def walk(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            out.append(Path(dirpath) / f)
            if len(out) >= MAX_FILES:
                return out
    return out


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def language(rel: str) -> str | None:
    name = rel.split("/")[-1]
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    if name in {"Makefile", "makefile"}:
        return "Make"
    return LANGS.get(Path(name).suffix.lower())


def collect(root: Path, top: int) -> dict:
    files = walk(root)
    texts: dict[str, str] = {}
    langs: dict[str, dict[str, int]] = {}
    sizes: list[tuple[int, str]] = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        lang = language(rel)
        if lang is None:
            continue
        text = read_text(p)
        if text is None:
            continue
        texts[rel] = text
        n = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        entry = langs.setdefault(lang, {"files": 0, "lines": 0})
        entry["files"] += 1
        entry["lines"] += n
        if lang in SOURCE_LANGS:
            sizes.append((n, rel))
    rels = {p.relative_to(root).as_posix() for p in files}

    tests = sorted(r for r in texts if TEST_RE.search(r) and language(r) in SOURCE_LANGS)
    test_text = "\n".join(texts[t] for t in tests)

    entry_points: list[dict] = []
    pyproject = texts.get("pyproject.toml")
    if pyproject:
        try:
            data = tomllib.loads(pyproject)
        except tomllib.TOMLDecodeError:
            data = {}
        for table in (data.get("project", {}).get("scripts", {}),
                      data.get("tool", {}).get("poetry", {}).get("scripts", {})):
            if isinstance(table, dict):
                for name, target in sorted(table.items()):
                    entry_points.append({"kind": "console_script", "name": name, "target": str(target),
                                         "source": "pyproject.toml"})
    pkg = texts.get("package.json")
    if pkg:
        try:
            pj = json.loads(pkg)
        except json.JSONDecodeError:
            pj = {}
        bins = pj.get("bin")
        if isinstance(bins, str):
            bins = {pj.get("name", "bin"): bins}
        for name, target in sorted((bins or {}).items()):
            entry_points.append({"kind": "npm_bin", "name": name, "target": target, "source": "package.json"})
        if isinstance(pj.get("main"), str):
            entry_points.append({"kind": "npm_main", "name": "main", "target": pj["main"], "source": "package.json"})
        for name, cmd in sorted((pj.get("scripts") or {}).items()):
            entry_points.append({"kind": "npm_script", "name": name, "target": str(cmd), "source": "package.json"})
    for rel, text in sorted(texts.items()):
        if rel.endswith(".py") and not TEST_RE.search(rel) and re.search(r"^if __name__ == ['\"]__main__['\"]", text,
                                                                         re.MULTILINE):
            line = text[: re.search(r"^if __name__", text, re.MULTILINE).start()].count("\n") + 1
            entry_points.append({"kind": "python_main_guard", "name": rel, "target": f"{rel}:{line}",
                                 "source": rel})
        name = rel.split("/")[-1]
        if language(rel) == "Dockerfile":
            for m in re.finditer(r"^(ENTRYPOINT|CMD)\s+(.+)$", text, re.MULTILINE):
                line = text[: m.start()].count("\n") + 1
                entry_points.append({"kind": "docker_" + m.group(1).lower(), "name": rel,
                                     "target": m.group(2).strip(), "source": f"{rel}:{line}"})
        elif name in {"Makefile", "makefile"} and "/" not in rel:
            for t in re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", text, re.MULTILINE):
                if not t.startswith("."):
                    entry_points.append({"kind": "make_target", "name": t, "target": t, "source": rel})
        elif name in MAIN_NAMES and not TEST_RE.search(rel) and not any(
                e["name"] == rel for e in entry_points):
            entry_points.append({"kind": "conventional_main", "name": rel, "target": rel, "source": rel})

    ci = sorted(r for r in rels if any(p.search(r) for p in CI_PATTERNS))
    manifests = []
    for rel in sorted(rels):
        name = rel.split("/")[-1]
        if name in MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.(txt|in)", name):
            parent = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
            locks = [lf for lf in MANIFESTS.get(name, []) if parent + lf in rels]
            pinned = None
            req_text = read_text(root / rel) if name.startswith("requirements") else None
            if req_text is not None:
                reqs = [ln.split("#")[0].strip() for ln in req_text.splitlines()]
                reqs = [r for r in reqs if r and not r.startswith("-")]
                pinned = {"total": len(reqs), "exact_pins": sum("==" in r for r in reqs)}
            manifests.append({"path": rel, "lockfiles": locks, "requirements_pins": pinned})
    licences = []
    for rel in sorted(rels):
        name = rel.split("/")[-1].upper()
        if "/" not in rel and (name.startswith(("LICENSE", "LICENCE", "COPYING"))):
            text = read_text(root / rel) or ""
            family = next((fam for fam, pat in LICENCE_FAMILIES if re.search(pat, text, re.IGNORECASE)), "unknown")
            licences.append({"path": rel, "family": family})

    sizes.sort(key=lambda x: (-x[0], x[1]))
    untested = []
    for n, rel in sizes:
        if TEST_RE.search(rel) or not rel.endswith((".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
            continue
        stem = Path(rel).stem
        if stem in {"__init__", "index", "conftest", "setup"} or stem.startswith("."):
            continue
        if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(stem)}(?![A-Za-z0-9_])", test_text):
            untested.append({"path": rel, "lines": n, "public_functions": public_count(rel, texts[rel])})
    return {
        "repo": str(root),
        "files_scanned": len(files),
        "languages": dict(sorted(langs.items(), key=lambda kv: (-kv[1]["lines"], kv[0]))),
        "entry_points": entry_points,
        "tests": {"count": len(tests), "files": tests},
        "ci": ci,
        "manifests": manifests,
        "licence": licences,
        "largest_files": [{"path": r, "lines": n} for n, r in sizes[:top]],
        "untested_files": untested[:top],
        "untested_files_total": len(untested),
    }


def public_count(rel: str, text: str) -> int | None:
    if rel.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return None
        return sum(1 for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                   and not n.name.startswith("_"))
    return len(re.findall(r"^\s*export\s", text, re.MULTILINE))


def render(rep: dict) -> str:
    out = [f"Repository facts: {rep['repo']} ({rep['files_scanned']} files scanned)", "", "Languages:"]
    for lang, v in rep["languages"].items():
        out.append(f"  {lang:<12} {v['files']:>6} files {v['lines']:>9} lines")
    out.append("")
    out.append(f"Entry points ({len(rep['entry_points'])}):")
    for e in rep["entry_points"]:
        out.append(f"  {e['kind']:<20} {e['name']}  ->  {e['target']}")
    out.append("")
    out.append(f"Test files: {rep['tests']['count']}")
    out.append(f"CI: {', '.join(rep['ci']) or 'none found'}")
    out.append("Manifests:")
    for m in rep["manifests"] or [{"path": "none found", "lockfiles": [], "requirements_pins": None}]:
        extra = f" lockfiles: {', '.join(m['lockfiles'])}" if m["lockfiles"] else ""
        if m["requirements_pins"]:
            p = m["requirements_pins"]
            extra += f" pins: {p['exact_pins']}/{p['total']} exact"
        out.append(f"  {m['path']}{extra}")
    lic = ", ".join(f"{x['path']} ({x['family']})" for x in rep["licence"]) or "none found"
    out.append(f"Licence: {lic}")
    out.append("")
    out.append("Largest source files:")
    for f in rep["largest_files"]:
        out.append(f"  {f['lines']:>7}  {f['path']}")
    out.append("")
    out.append(f"Source files no test mentions by name ({rep['untested_files_total']}, top shown):")
    for f in rep["untested_files"]:
        out.append(f"  {f['lines']:>7}  {f['path']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="repo_facts.py",
                                 description="Print the deterministic inventory a cited codebase audit starts from.")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--top", type=int, default=10, help="how many largest and untested files to list (default: 10)")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON to FILE")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    rep = collect(root, max(1, args.top))
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
