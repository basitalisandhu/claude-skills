#!/usr/bin/env python3
"""portability_check.py: find what in a skill folder breaks on another host or operating system, with a fix hint.

Input: one or more skill folders, plugin folders or SKILL.md files. Every file below a folder is read (except .git,
node_modules, caches and virtual environments).

Rules (each finding cites the file and line):
  * yaml-unsafe: a front matter value a strict YAML reader rejects, such as a plain value containing ': ';
  * hardcoded-home-path: /Users/<name>/, /home/<name>/ or C:\\Users\\<name>\\ written into a file;
  * platform-path: a path that exists on one platform only (Homebrew prefixes, the macOS Library and Applications
    folders, the Linux proc file system, the Windows APPDATA variable);
  * plugin-root-no-fallback: a SKILL.md that runs scripts through ${CLAUDE_PLUGIN_ROOT} and never says where the
    script is when the skill is copied without the plugin system (no ${CLAUDE_PLUGIN_ROOT:-...} default and no line
    naming the script's path relative to the skill folder);
  * env-no-default: Python indexing os.environ with a CLAUDE_ variable name (such as the plugin root) and no default;
  * non-portable-shell: GNU-only or BSD-only command options in .sh files and in bash or sh code blocks of Markdown
    (sed -i, readlink -f, date -d, stat -c, stat -f, grep -P, xargs -r, echo -e, base64 -w, find -printf);
  * bashism-in-sh: a #!/bin/sh script using [[, function, source, == or arrays;
  * shebang-hardcoded: #!/bin/bash or #!/usr/bin/python3 instead of #!/usr/bin/env ...;
  * open-no-encoding: Python open(), Path.open(), read_text() or write_text() in text mode without encoding=;
  * os-specific-call: Python calls or imports that exist on one family only (os.getuid, os.fork, pwd, fcntl,
    termios, winreg, msvcrt and similar) outside an `if` that checks os.name, sys.platform or hasattr;
  * windows-separator: a relative path written with backslashes as separators;
  * crlf: Windows line endings in SKILL.md, shell or Python files (a shebang line then fails);
  * symlink: a symbolic link inside the folder (lost or broken in zip and copy installs);
  * case-collision: two names in one folder that differ only by case.

--skip-rule RULE leaves a rule out, for a skill that is meant for one platform (repeatable).

Exit codes: 0 no findings, 1 at least one finding, 2 bad input (a path that does not exist).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _skillmd  # noqa: E402

SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".bash", ".json", ".yml", ".yaml", ".toml", ".txt", ".ps1", ".js", ".ts"}
HOME_RE = re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+/|[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._ -]+[\\/]")
# Assembled from parts so this file does not report itself.
PLATFORM_RE = re.compile(
    "|".join(
        [
            "/opt/" + r"homebrew\b",
            "/usr/local/" + r"Cellar\b",
            "~/" + "Library/",
            "/" + "Applications/",
            "/" + "proc/",
            "%" + "APPDATA%",
        ]
    )
)
SEP_RE = re.compile(r"(?<![\\\w])(?:\.{1,2}\\|[\w.-]+\\)+[\w.-]+\.(?:py|sh|md|json|txt|ya?ml|toml|js|ts)\b")
SHELL_RULES = [
    (re.compile(r"\bsed\s+-i\b"), "sed -i takes different arguments on GNU and BSD; write to a temp file instead"),
    (re.compile(r"\breadlink\s+-f\b"), "readlink -f is missing on older macOS; use realpath or Python"),
    (re.compile(r"\bdate\s+-d\b"), "date -d is GNU only; compute dates in Python"),
    (re.compile(r"\bstat\s+-c\b"), "stat -c is GNU only (BSD uses -f); use Python os.stat"),
    (re.compile(r"\bstat\s+-f\b"), "stat -f is BSD only (GNU uses -c); use Python os.stat"),
    (re.compile(r"\bgrep\s+(?:-\w*P|--perl-regexp)"), "grep -P is GNU only; use grep -E or Python re"),
    (re.compile(r"\bxargs\s+-r\b"), "xargs -r is GNU only"),
    (re.compile(r"\becho\s+-e\b"), "echo -e behaves differently across shells; use printf"),
    (re.compile(r"\bbase64\s+-w\b"), "base64 -w is GNU only"),
    (re.compile(r"\bfind\b.*\s-printf\b"), "find -printf is GNU only"),
]
BASHISMS = re.compile(r"\[\[|^\s*function\s+\w+|^\s*source\s+|\s==\s|^\s*\w+=\(")
OS_CALLS = {
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getpgid",
    "fork",
    "killpg",
    "setsid",
    "chown",
    "getlogin",
    "startfile",
}
OS_MODULES = {"pwd", "grp", "fcntl", "termios", "resource", "winreg", "msvcrt", "_winapi"}
NON_TEXT_OPENERS = {"os", "tarfile", "zipfile", "webbrowser", "shelve", "dbm", "wave", "sqlite3", "Image"}
FENCE_RE = re.compile(r"^```(bash|sh|shell|zsh)?[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
CLAUDE_ENV_RE = re.compile(r"os\.environ\[\s*['\"](CLAUDE_[A-Z_]+)['\"]\s*\]")


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def guarded(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.If, ast.IfExp)):
            test = ast.unparse(cur.test)
            if "platform" in test or "os.name" in test or "hasattr" in test:
                return True
        if isinstance(cur, ast.Try):
            return True
        cur = parents.get(cur)
    return False


def python_findings(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            kw = {k.arg for k in node.keywords}
            receiver = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
            text_call = (
                (name == "open" and receiver not in NON_TEXT_OPENERS)
                or (name == "read_text" and not node.args)
                or (name == "write_text" and len(node.args) == 1)
            )
            if text_call and "encoding" not in kw:
                mode_args = [a for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                mode_kw = [k.value for k in node.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)]
                modes = [m.value for m in mode_kw] + [
                    a.value for a in mode_args if re.fullmatch(r"[rwxabt+]+", a.value)
                ]
                if not any("b" in m for m in modes):
                    out.append(
                        (
                            node.lineno,
                            "open-no-encoding",
                            f"{name}() without encoding= uses the locale encoding (cp1252 on many Windows hosts); "
                            'add encoding="utf-8"',
                        )
                    )
            if (
                isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "os"
                and f.attr in OS_CALLS
                and not guarded(node, parents)
            ):
                out.append(
                    (
                        node.lineno,
                        "os-specific-call",
                        f"os.{f.attr} exists on one platform family only; guard it with os.name or hasattr",
                    )
                )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = (
                [a.name.split(".")[0] for a in node.names]
                if isinstance(node, ast.Import)
                else [(node.module or "").split(".")[0]]
            )
            for m in mods:
                if m in OS_MODULES and not guarded(node, parents):
                    out.append(
                        (
                            node.lineno,
                            "os-specific-call",
                            f"module {m} exists on one platform family only; import it inside a platform check",
                        )
                    )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for m in SEP_RE.finditer(node.value):
                out.append(
                    (
                        node.lineno,
                        "windows-separator",
                        f"{m.group(0)!r} uses backslashes; build paths with pathlib or '/'",
                    )
                )
    for m in CLAUDE_ENV_RE.finditer(text):
        out.append(
            (
                line_of(text, m.start()),
                "env-no-default",
                f"{m.group(1)} is unset outside a plugin install; use os.environ.get with a fallback",
            )
        )
    return out


def shell_findings(text: str, offset: int = 0) -> list[tuple[int, str, str]]:
    out = []
    for rx, hint in SHELL_RULES:
        for m in rx.finditer(text):
            out.append((line_of(text, m.start()) + offset, "non-portable-shell", hint))
    return out


def skill_md_findings(path: Path, text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    if path.name == "SKILL.md":
        for line, problem in _skillmd.parse(text).problems:
            out.append((line, "yaml-unsafe", problem))
        refs = list(re.finditer(r"\$\{CLAUDE_PLUGIN_ROOT\}/(?:skills/[\w.-]+/)?(scripts/[\w.-]+)", text))
        if refs and "${CLAUDE_PLUGIN_ROOT:-" not in text:
            scripts = {m.group(1) for m in refs}
            plain = [ln for ln in text.splitlines() if "CLAUDE_PLUGIN_ROOT" not in ln and any(s in ln for s in scripts)]
            if not plain:
                out.append(
                    (
                        line_of(text, refs[0].start()),
                        "plugin-root-no-fallback",
                        "say where the script is when the skill is copied without the plugin system, for "
                        "example 'from a copy install run scripts/<file> from the skill folder'",
                    )
                )
    for m in FENCE_RE.finditer(text):
        if m.group(1):
            out += shell_findings(m.group(2), line_of(text, m.start(2)) - 1)
    return out


def check_file(path: Path, rel: str) -> list[dict]:
    raw = path.read_bytes()
    if b"\0" in raw[:4096]:
        return []
    text = raw.decode("utf-8", errors="replace")
    found: list[tuple[int, str, str]] = []
    if b"\r\n" in raw and (path.suffix in (".py", ".sh", ".bash") or path.name == "SKILL.md"):
        found.append((1, "crlf", "Windows line endings; save with LF (add a .gitattributes rule: * text=auto eol=lf)"))
    text = text.replace("\r\n", "\n")
    for m in HOME_RE.finditer(text):
        found.append(
            (
                line_of(text, m.start()),
                "hardcoded-home-path",
                f"{m.group(0)!r} exists on one machine only; use ~, $HOME or a path relative to the skill",
            )
        )
    for m in PLATFORM_RE.finditer(text):
        found.append(
            (
                line_of(text, m.start()),
                "platform-path",
                f"{m.group(0)!r} exists on one platform only; detect it or make it an option",
            )
        )
    first = text.split("\n", 1)[0]
    if first.startswith("#!") and re.match(r"#!\s*/(?:usr/)?bin/(?:bash|zsh|python3?)\b", first):
        found.append((1, "shebang-hardcoded", f"{first!r}; use #!/usr/bin/env bash or #!/usr/bin/env python3"))
    if path.suffix == ".py":
        found += python_findings(text)
    elif path.suffix in (".sh", ".bash") or first.startswith("#!") and "sh" in first and path.suffix == "":
        found += shell_findings(text)
        if re.match(r"#!\s*/bin/sh\b", first):
            for n, ln in enumerate(text.split("\n"), start=1):
                if BASHISMS.search(ln):
                    found.append((n, "bashism-in-sh", "bash syntax in a /bin/sh script; use POSIX sh or bash"))
    elif path.suffix == ".md":
        found += skill_md_findings(path, text)
        for m in SEP_RE.finditer(text):
            found.append(
                (
                    line_of(text, m.start()),
                    "windows-separator",
                    f"{m.group(0)!r} uses backslashes; write paths with '/'",
                )
            )
    unique = sorted(set(found))
    return [{"file": rel, "line": n, "rule": r, "hint": h} for n, r, h in unique]


def walk(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out = []
    for p in sorted(root.rglob("*")):
        if SKIP & set(p.relative_to(root).parts):
            continue
        out.append(p)
    return out


def analyse(paths: list[Path], skip: set[str] | None = None) -> dict:
    findings: list[dict] = []
    files = 0
    for root in paths:
        base = root.parent if root.is_file() else root
        entries = walk(root)
        seen_case: dict[tuple[str, str], str] = {}
        for p in entries:
            rel = p.relative_to(base).as_posix() if p != base else p.name
            label = f"{base.name}/{rel}"
            key = (p.parent.as_posix(), p.name.lower())
            if key in seen_case and seen_case[key] != p.name:
                findings.append(
                    {
                        "file": label,
                        "line": 1,
                        "rule": "case-collision",
                        "hint": f"differs from {seen_case[key]!r} only by case; macOS and Windows merge them",
                    }
                )
            seen_case.setdefault(key, p.name)
            if p.is_symlink():
                findings.append(
                    {
                        "file": label,
                        "line": 1,
                        "rule": "symlink",
                        "hint": "symbolic links are dropped or broken by zip and copy installs; copy the file",
                    }
                )
                continue
            if p.is_file() and (p.suffix in TEXT_SUFFIXES or p.suffix == ""):
                files += 1
                findings += check_file(p, label)
    findings = [f for f in findings if f["rule"] not in (skip or set())]
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return {"files_checked": files, "skipped_rules": sorted(skip or []), "findings": findings}


def render(rep: dict) -> str:
    out = [
        "# Skill portability check",
        "",
        f"{rep['files_checked']} file(s) checked, {len(rep['findings'])} finding(s).",
    ]
    by_file: dict[str, list[dict]] = {}
    for f in rep["findings"]:
        by_file.setdefault(f["file"], []).append(f)
    for file, items in by_file.items():
        out += ["", f"## {file}", ""]
        out += [f"- line {f['line']} {f['rule']}: {f['hint']}" for f in items]
    if not by_file:
        out += ["", "No findings."]
    out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portability_check.py",
        description="Report what in a skill or plugin folder breaks on other hosts or operating systems, per file, "
        "with a fix hint.",
        epilog="Exit codes: 0 no findings, 1 at least one finding, 2 bad input.",
    )
    p.add_argument("paths", nargs="+", help="skill folders, plugin folders or SKILL.md files")
    p.add_argument("--skip-rule", action="append", default=[], help="rule to leave out, e.g. platform-path")
    p.add_argument("--json", action="store_true", help="print the computed data as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = [Path(p) for p in args.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"portability_check.py: not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    rep = analyse(paths, set(args.skip_rule))
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n" if args.json else render(rep)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
