#!/usr/bin/env python3
"""Verify the checkable claims in a repository's documentation against its working tree.

Claim kinds, and what counts as verified:
  path     a file or directory in backticks, or the script a documented command runs: it exists
  link     a relative Markdown link or image: the target exists
  flag     a --flag in a documented command or in backticks: the script (or any parser in the repo) declares it
  default  a documented CLI or environment-variable default equals its literal code default
  env      an ENVIRONMENT_VARIABLE in backticks: it is named in at least one non-documentation file
  symbol   a function, class, dotted name or config key in backticks: it is defined in code or config
  version  "<project>==X.Y.Z", "<project>@X.Y.Z", "<project> vX.Y.Z", or a line naming the project and
           "version X.Y.Z": it equals the version in pyproject.toml or package.json
  target   "npm run X" or "make X": the package.json script or Makefile target exists

Statuses: verified; missing (the thing named does not exist); stale (it exists but what the docs say about it
is wrong); unverified (recognised as a claim, but this checker cannot decide; never a failure).

Nothing is executed and nothing leaves the machine, unless --run-help is given: then scripts that have no
parseable option declarations are run once with --help (10 s timeout, minimal environment) to read their flags.

Exit codes: 0 no drift at the --fail-on level, 1 drift found, 2 bad input.
"""
from __future__ import annotations

import argparse
import ast
import builtins
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__", ".tox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "target", ".next", ".cache", "coverage",
}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
DOC_SUFFIXES = {".md", ".markdown", ".rst", ".txt", ".adoc"}
PATH_SUFFIXES = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".toml", ".yml", ".yaml", ".md",
    ".txt", ".cfg", ".ini", ".sh", ".bash", ".zsh", ".go", ".rs", ".rb", ".java", ".kt", ".c", ".h", ".cpp",
    ".hpp", ".cs", ".php", ".html", ".css", ".scss", ".sql", ".lock", ".env", ".example", ".csv", ".xml",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ipynb", ".tf", ".proto", ".graphql", ".rst", ".mdx",
}
BARE_FILENAMES = {"Makefile", "Dockerfile", "LICENSE", "LICENCE", "Procfile", "Justfile", "Gemfile", "Rakefile"}
SHELL_LANGS = {"", "bash", "sh", "shell", "console", "zsh", "terminal", "shell-session"}
STATUSES = ("verified", "missing", "stale", "unverified")

FLAG_RE = re.compile(r"(?<![\w-])(--[A-Za-z0-9][A-Za-z0-9_-]*)")
ENV_RE = re.compile(r"^\$?\{?([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])\}?$")
ENV_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])(?![A-Za-z0-9_])")
IDENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(\([^()]*\))?$")
SPAN_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
LINK_RE = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
SEMVER = r"v?(\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?)"
DEFAULT_RE = re.compile(
    r"\(?\bdefaults?\b\s*(?:is|to|of|=|:)?\s*(?:is\s+)?[`\"']?([^`\"'\s,;)]+)[`\"']?", re.IGNORECASE
)
PYTHON_RE = re.compile(r"^(?:python|python3|py)(?:\d+(?:\.\d+)?)?$")


@dataclass
class Claim:
    kind: str
    claim: str
    doc: str
    line: int
    status: str
    detail: str = ""

    @property
    def location(self) -> str:
        return f"{self.doc}:{self.line}"


@dataclass
class ScriptInfo:
    kind: str
    flags: set[str] = field(default_factory=set)
    defaults: dict[str, object] = field(default_factory=dict)
    parser_found: bool = False


UNKNOWN = object()


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


def walk(root: Path, excludes: list[str]) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            rel = (base / d).relative_to(root).as_posix()
            if d in SKIP_DIRS or is_excluded(rel, excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            p = base / f
            if is_excluded(p.relative_to(root).as_posix(), excludes):
                continue
            out.append(p)
            if len(out) >= MAX_FILES:
                return out
    return out


def is_excluded(rel: str, excludes: list[str]) -> bool:
    for pat in excludes:
        pat = pat.rstrip("/")
        if fnmatch.fnmatch(rel, pat) or rel == pat or rel.startswith(pat + "/"):
            return True
    return False


class Index:
    """What the working tree declares: files, symbols, config keys, option parsers, manifests."""

    def __init__(self, root: Path, excludes: list[str], run_help: bool = False) -> None:
        self.root = root
        self.run_help = run_help
        self.files = walk(root, excludes)
        self.rel_files = {p.relative_to(root).as_posix() for p in self.files}
        self.rel_dirs: set[str] = set()
        self.basenames: set[str] = set()
        for rel in self.rel_files:
            parts = rel.split("/")
            self.basenames.add(parts[-1])
            for i in range(1, len(parts)):
                self.rel_dirs.add("/".join(parts[:i]))
        self.symbols: set[str] = set()
        self.class_members: dict[str, set[str]] = {}
        self.modules: dict[str, str] = {}
        self.config_keys: set[str] = set()
        self.scripts: dict[str, ScriptInfo] = {}
        self.all_flags: set[str] = set()
        self.flag_defaults: dict[str, list[tuple[str, object]]] = {}
        self.env_defaults: dict[str, list[tuple[str, object]]] = {}
        self.code_texts: dict[str, str] = {}
        self.pyproject: dict = {}
        self.package_json: dict = {}
        self.npm_by_dir: dict[str, set[str]] = {}
        self.make_by_dir: dict[str, set[str]] = {}
        self._build()

    def _build(self) -> None:
        for p in self.files:
            rel = p.relative_to(self.root).as_posix()
            suffix = p.suffix.lower()
            if suffix in DOC_SUFFIXES and not p.name.startswith(".env"):
                continue
            text = read_text(p)
            if text is None:
                continue
            self.code_texts[rel] = text
            if suffix == ".py":
                self._index_python(rel, text)
            elif suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
                self._index_js(rel, text)
            elif suffix in {".sh", ".bash", ".zsh"} or (suffix == "" and text.startswith("#!") and "sh" in text[:40]):
                info = ScriptInfo(kind="shell", flags=set(FLAG_RE.findall(text)))
                info.parser_found = bool(info.flags)
                self.scripts[rel] = info
                self.all_flags |= info.flags
            if p.name == "pyproject.toml":
                self._index_config(rel, text, "toml")
                if rel == "pyproject.toml":
                    try:
                        self.pyproject = tomllib.loads(text)
                    except tomllib.TOMLDecodeError:
                        self.pyproject = {}
            elif p.name == "package.json":
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    data = {}
                data = data if isinstance(data, dict) else {}
                scripts = data.get("scripts")
                self.npm_by_dir[rel.rsplit("/", 1)[0] if "/" in rel else ""] = (
                    set(scripts) if isinstance(scripts, dict) else set())
                if rel == "package.json":
                    self.package_json = data
                self._index_config(rel, text, "json")
            elif suffix in {".toml", ".json", ".yml", ".yaml", ".ini", ".cfg"} or p.name.startswith(".env"):
                if p.name not in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}:
                    self._index_config(rel, text, suffix.lstrip(".") or "env")
            if p.name in {"Makefile", "makefile", "GNUmakefile"}:
                targets = set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", text, re.MULTILINE))
                self.make_by_dir.setdefault(rel.rsplit("/", 1)[0] if "/" in rel else "", set()).update(targets)

    def _index_python(self, rel: str, text: str) -> None:
        mod = rel[:-3].split("/")
        if mod[-1] == "__init__":
            mod = mod[:-1]
        if mod:
            self.modules[".".join(mod)] = rel
            if mod[0] == "src" and len(mod) > 1:
                self.modules[".".join(mod[1:])] = rel
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return
        info = ScriptInfo(kind="python")
        os_module_names = {"os"}
        environ_names: set[str] = set()
        getenv_names: set[str] = set()
        for imported in tree.body:
            if isinstance(imported, ast.Import):
                os_module_names.update(
                    alias.asname or alias.name
                    for alias in imported.names
                    if alias.name == "os"
                )
            elif isinstance(imported, ast.ImportFrom) and imported.module == "os":
                for alias in imported.names:
                    if alias.name == "environ":
                        environ_names.add(alias.asname or alias.name)
                    elif alias.name == "getenv":
                        getenv_names.add(alias.asname or alias.name)
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.symbols.add(t.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.symbols.add(node.target.id)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.symbols.add(node.name)
            elif isinstance(node, ast.ClassDef):
                self.symbols.add(node.name)
                members = self.class_members.setdefault(node.name, set())
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        members.add(item.name)
                    elif isinstance(item, ast.Assign):
                        members |= {t.id for t in item.targets if isinstance(t, ast.Name)}
                    elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        members.add(item.target.id)
            elif isinstance(node, ast.Call):
                fn = node.func
                env_name = None
                if (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "get"
                    and isinstance(fn.value, ast.Attribute)
                    and fn.value.attr == "environ"
                    and isinstance(fn.value.value, ast.Name)
                    and fn.value.value.id in os_module_names
                ):
                    env_name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                elif (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "get"
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id in environ_names
                ):
                    env_name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                elif (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "getenv"
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id in os_module_names
                ):
                    env_name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                elif isinstance(fn, ast.Name) and fn.id in getenv_names:
                    env_name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                if isinstance(env_name, str) and len(node.args) > 1:
                    try:
                        env_default = ast.literal_eval(node.args[1])
                    except (ValueError, SyntaxError, TypeError):
                        env_default = UNKNOWN
                    self.env_defaults.setdefault(env_name, []).append((rel, env_default))

                name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
                if name not in {"add_argument", "option"}:
                    continue
                opts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        and a.value.startswith("-")]
                if not opts:
                    continue
                info.parser_found = True
                default: object = UNKNOWN
                action = None
                for kw in node.keywords:
                    if kw.arg == "action" and isinstance(kw.value, ast.Constant):
                        action = kw.value.value
                for kw in node.keywords:
                    if kw.arg == "default":
                        try:
                            default = ast.literal_eval(kw.value)
                        except (ValueError, SyntaxError, TypeError):
                            default = UNKNOWN
                if default is UNKNOWN and action == "store_true":
                    default = False
                elif default is UNKNOWN and action == "store_false":
                    default = True
                elif default is UNKNOWN and name == "add_argument" and action is None:
                    default = None
                for o in opts:
                    info.flags.add(o)
                    info.defaults[o] = default
                    self.flag_defaults.setdefault(o, []).append((rel, default))
                    self.symbols.add(o.lstrip("-").replace("-", "_"))
        if info.parser_found or "ArgumentParser" in text:
            info.flags |= {"-h", "--help"}
            info.parser_found = True
        self.scripts[rel] = info
        self.all_flags |= info.flags

    def _index_js(self, rel: str, text: str) -> None:
        for m in re.finditer(
            r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var|interface|type|enum)\s+"
            r"([A-Za-z_$][\w$]*)", text):
            self.symbols.add(m.group(1))
        for m in re.finditer(r"\bexport\s*\{([^}]*)\}", text):
            for part in m.group(1).split(","):
                name = part.strip().split(" as ")[-1].strip()
                if name:
                    self.symbols.add(name)
        for m in re.finditer(r"\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=", text):
            self.symbols.add(m.group(1))
        for m in re.finditer(r"\b(?:function|class)\s+([A-Za-z_$][\w$]*)", text):
            self.symbols.add(m.group(1))
        flags = set(re.findall(r"[\"'`](--[A-Za-z0-9][A-Za-z0-9_-]*)", text))
        info = ScriptInfo(kind="js", flags=flags, parser_found=bool(flags))
        self.scripts[rel] = info
        self.all_flags |= flags

    def _index_config(self, rel: str, text: str, kind: str) -> None:
        def keys(obj: object) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    self.config_keys.add(str(k))
                    keys(v)
            elif isinstance(obj, list):
                for v in obj:
                    keys(v)

        if kind == "toml":
            try:
                keys(tomllib.loads(text))
            except tomllib.TOMLDecodeError:
                pass
        elif kind == "json":
            try:
                keys(json.loads(text))
            except json.JSONDecodeError:
                pass
        elif kind in {"yml", "yaml"}:
            self.config_keys |= set(re.findall(r"^\s*-?\s*([A-Za-z_][\w.-]*)\s*:", text, re.MULTILINE))
        else:
            self.config_keys |= set(re.findall(r"^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=", text, re.MULTILINE))

    # --- lookups -----------------------------------------------------------------------------------------------

    def exists(self, rel: str) -> bool:
        rel = rel.strip("/")
        return rel in self.rel_files or rel in self.rel_dirs or rel == ""

    def project(self) -> tuple[str, str]:
        proj = self.pyproject.get("project", {}) if isinstance(self.pyproject, dict) else {}
        poetry = self.pyproject.get("tool", {}).get("poetry", {}) if isinstance(self.pyproject, dict) else {}
        for src in (proj, poetry, self.package_json):
            if isinstance(src, dict) and src.get("name") and isinstance(src.get("version"), str):
                return str(src["name"]), src["version"]
        return "", ""

    def console_scripts(self) -> dict[str, str]:
        out: dict[str, str] = {}
        scripts = self.pyproject.get("project", {}).get("scripts", {}) if self.pyproject else {}
        poetry = self.pyproject.get("tool", {}).get("poetry", {}).get("scripts", {}) if self.pyproject else {}
        for table in (scripts, poetry):
            if isinstance(table, dict):
                for name, target in table.items():
                    if isinstance(target, str):
                        mod = target.split(":")[0].strip()
                        if mod in self.modules:
                            out[name] = self.modules[mod]
        bins = self.package_json.get("bin") if self.package_json else None
        if isinstance(bins, str) and self.package_json.get("name"):
            bins = {self.package_json["name"]: bins}
        if isinstance(bins, dict):
            for name, target in bins.items():
                if isinstance(target, str):
                    out[name] = target.lstrip("./")
        return out

    def mentions(self, name: str) -> str | None:
        """First code or config file that names `name` as a whole word, if any."""
        pat = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])")
        return next((rel for rel, text in self.code_texts.items() if pat.search(text)), None)

    def script_info(self, rel: str) -> ScriptInfo | None:
        info = self.scripts.get(rel)
        if info is None and rel in self.rel_files:
            info = ScriptInfo(kind="other")
            self.scripts[rel] = info
        if info is not None and not info.parser_found and self.run_help:
            info.flags |= self._help_flags(rel, info.kind)
            info.parser_found = bool(info.flags)
        return info

    def _help_flags(self, rel: str, kind: str) -> set[str]:
        path = self.root / rel
        if kind == "python":
            cmd = [sys.executable, str(path), "--help"]
        elif kind == "shell":
            cmd = ["bash", str(path), "--help"]
        elif os.access(path, os.X_OK):
            cmd = [str(path), "--help"]
        else:
            return set()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "NO_COLOR": "1"}
        try:
            proc = subprocess.run(cmd, cwd=self.root, env=env, capture_output=True, text=True, timeout=10,
                                  stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return set()
        return set(FLAG_RE.findall(proc.stdout + proc.stderr))


# --- claim extraction --------------------------------------------------------------------------------------------


def default_docs(index: Index) -> list[str]:
    out = []
    for rel in sorted(index.rel_files):
        name = rel.split("/")[-1]
        top = "/" not in rel
        if not rel.lower().endswith((".md", ".markdown")):
            continue
        if top and (name.upper().startswith(("README", "CONTRIBUTING")) or name in {"AGENTS.md", "CLAUDE.md"}):
            out.append(rel)
        elif rel.startswith("docs/"):
            out.append(rel)
    return out


def norm_value(v: object) -> str:
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip().strip("\"'").lower()


def norm_claimed(s: str) -> str:
    s = s.strip().strip("\"'`.").lower()
    if s in {"null", "nil", "none"}:
        return "none"
    try:
        f = float(s)
        return str(int(f)) if f.is_integer() else str(f)
    except ValueError:
        return s


class Checker:
    def __init__(self, index: Index) -> None:
        self.index = index
        self.claims: list[Claim] = []
        self._seen: set[tuple] = set()
        self.name, self.version = index.project()
        self.console = index.console_scripts()

    def add(self, kind: str, claim: str, doc: str, line: int, status: str, detail: str = "") -> None:
        key = (kind, claim, doc, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.claims.append(Claim(kind, claim, doc, line, status, detail))

    def check_doc(self, doc: str) -> None:
        text = read_text(self.index.root / doc)
        if text is None:
            return
        doc_dir = str(Path(doc).parent.as_posix()) if "/" in doc else ""
        is_changelog = "changelog" in doc.lower() or "history" in doc.lower()
        fence: str | None = None
        fence_lang = ""
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            m = re.match(r"^(`{3,}|~{3,})\s*([\w+-]*)", stripped)
            if m:
                if fence is None:
                    fence, fence_lang = m.group(1), m.group(2).lower()
                    continue
                if stripped.startswith(fence[0] * len(fence)):
                    fence = None
                    continue
            if fence is not None:
                if fence_lang in SHELL_LANGS:
                    self.check_command(stripped, doc, lineno)
                if not is_changelog:
                    self.check_versions(line, doc, lineno)
                continue
            for target in LINK_RE.findall(line):
                self.check_link(target, doc, doc_dir, lineno)
            for span in SPAN_RE.findall(line):
                self.check_span(span.strip(), doc, lineno)
            self.check_defaults(line, doc, lineno)
            if not is_changelog:
                self.check_versions(line, doc, lineno)

    # links and paths

    def check_link(self, target: str, doc: str, doc_dir: str, lineno: int) -> None:
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith(("#", "//")):
            return
        path = unquote(target.split("#")[0].split("?")[0])
        if not path:
            return
        rel = path.lstrip("/") if path.startswith("/") else os.path.normpath(os.path.join(doc_dir, path))
        rel = Path(rel).as_posix()
        if rel.startswith("../") or rel == "..":
            self.add("link", target, doc, lineno, "unverified", "points outside the repository")
        elif self.index.exists(rel):
            self.add("link", target, doc, lineno, "verified")
        else:
            self.add("link", target, doc, lineno, "missing", f"{rel} not found in the working tree")

    def path_claim(self, raw: str, doc: str, lineno: int) -> bool:
        """Record a path claim if raw looks like a repository path. Returns True when it was treated as a path."""
        s = raw.strip()
        if not s or any(c in s for c in "<>*{}$ |'\"\\") or s.startswith(("~", "/", "-", "http:", "https:")):
            return False
        s = re.sub(r"::.*$", "", s)
        s = re.sub(r":\d+(?:-\d+)?$", "", s)
        s = s[2:] if s.startswith("./") else s
        last = s.rstrip("/").split("/")[-1]
        if not last or last in {".", ".."}:
            return False
        if re.fullmatch(r"\.[A-Za-z0-9]{1,6}", s):
            return False
        suffix = Path(last).suffix.lower()
        has_ext = suffix in PATH_SUFFIXES or last in BARE_FILENAMES or (last.startswith(".") and len(last) > 2)
        has_slash = "/" in s.rstrip("/")
        if not has_ext and not has_slash and not s.endswith("/"):
            return False
        if not has_slash:
            target = s.rstrip("/")
            if self.index.exists(target) or target in self.index.basenames or any(
                    d.split("/")[-1] == target for d in self.index.rel_dirs):
                self.add("path", raw, doc, lineno, "verified")
            else:
                self.add("path", raw, doc, lineno, "unverified",
                         "no file with this name in the tree; a bare name may refer to files in other projects")
            return True
        doc_dir = doc.rsplit("/", 1)[0] if "/" in doc else ""
        local = Path(os.path.normpath(os.path.join(doc_dir, s))).as_posix() if doc_dir else s
        if self.index.exists(s) or self.index.exists(local):
            self.add("path", raw, doc, lineno, "verified")
            return True
        tail = "/" + s.rstrip("/")
        elsewhere = next((r for r in sorted(self.index.rel_files | self.index.rel_dirs) if r.endswith(tail)), None)
        if elsewhere:
            self.add("path", raw, doc, lineno, "unverified",
                     f"exists as {elsewhere}; the doc does not say what the path is relative to")
            return True
        first = s.split("/")[0]
        if has_ext or self.index.exists(first):
            parent = "/".join(s.rstrip("/").split("/")[:-1])
            detail = "not found in the working tree"
            if self.index.exists(parent):
                siblings = sorted(r.split("/")[-1] for r in self.index.rel_files if r.rsplit("/", 1)[0] == parent)
                stem = Path(last).stem.lower()
                close = [n for n in siblings if Path(n).suffix == suffix and (stem[:3] in n.lower())]
                if close:
                    detail += f"; same directory has {', '.join(close[:3])}"
            self.add("path", raw, doc, lineno, "missing", detail)
            return True
        return False

    # inline code spans

    def check_span(self, span: str, doc: str, lineno: int) -> None:
        if not span:
            return
        if re.search(r"\s", span):
            first = span.split()[0]
            if (PYTHON_RE.match(first) or first.startswith("./") or first in {"npm", "pnpm", "yarn", "bun", "make"}
                    or first in self.console or ("/" in first and self.index.exists(first.lstrip("./")))):
                self.check_command(span, doc, lineno)
            elif first.startswith("--") and FLAG_RE.fullmatch(first.split("=")[0]):
                self.check_flag(first.split("=")[0], doc, lineno)
            return
        if span.startswith("--"):
            flag = span.split("=")[0]
            if FLAG_RE.fullmatch(flag):
                self.check_flag(flag, doc, lineno)
            return
        m = ENV_RE.match(span)
        if m:
            self.check_env(m.group(1), span, doc, lineno)
            return
        if self.path_claim(span, doc, lineno):
            return
        m = IDENT_RE.match(span)
        if m:
            self.check_symbol(m.group(1), span, bool(m.group(2)), doc, lineno)

    def check_flag(self, flag: str, doc: str, lineno: int) -> None:
        if flag in self.index.all_flags:
            self.add("flag", flag, doc, lineno, "verified")
        else:
            self.add("flag", flag, doc, lineno, "missing", "no option parser or script in the tree declares it")

    def check_env(self, name: str, raw: str, doc: str, lineno: int) -> None:
        pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")
        for rel, text in self.index.code_texts.items():
            if pat.search(text):
                self.add("env", raw, doc, lineno, "verified", f"read in {rel}")
                return
        self.add("env", raw, doc, lineno, "missing", "not named in any code or config file")

    def check_symbol(self, name: str, raw: str, called: bool, doc: str, lineno: int) -> None:
        parts = name.split(".")
        qualifies = called or len(parts) > 1 or "_" in name.strip("_") or re.search(r"[a-z][A-Z]", name)
        if not qualifies or name.isupper():
            return
        idx = self.index
        known = idx.symbols | idx.config_keys

        def defined(n: str) -> bool:
            return n in known or n in idx.modules

        if len(parts) == 1:
            if defined(name):
                self.add("symbol", raw, doc, lineno, "verified")
            elif name in dir(builtins):
                return
            elif (where := idx.mentions(name)) is not None:
                self.add("symbol", raw, doc, lineno, "unverified",
                         f"named in {where} but not as a definition this checker parses")
            else:
                self.add("symbol", raw, doc, lineno, "missing", "not named in any code or config file")
            return
        if parts[0] in sys.stdlib_module_names and not defined(parts[0]):
            return
        if name in idx.modules:
            self.add("symbol", raw, doc, lineno, "verified", f"module {idx.modules[name]}")
            return
        owner, member = parts[-2], parts[-1]
        if owner in idx.class_members and member in idx.class_members[owner]:
            self.add("symbol", raw, doc, lineno, "verified")
            return
        head_known = defined(parts[0]) or any(m.split(".")[0] == parts[0] for m in idx.modules)
        if member in known and head_known:
            self.add("symbol", raw, doc, lineno, "verified")
        elif head_known or owner in idx.class_members:
            if (where := idx.mentions(member)) is not None:
                self.add("symbol", raw, doc, lineno, "unverified",
                         f"{member} is named in {where} but not as a definition this checker parses")
            else:
                self.add("symbol", raw, doc, lineno, "missing", f"{parts[0]} exists but {member} is not defined on it")
        # neither part is known: likely a name from another project; not a claim about this repository

    # commands

    def resolve_module(self, mod: str) -> str | None:
        rel = self.index.modules.get(mod)
        if rel and rel.endswith("__init__.py"):
            main = rel[: -len("__init__.py")] + "__main__.py"
            if main in self.index.rel_files:
                return main
        return rel

    def check_command(self, line: str, doc: str, lineno: int) -> None:
        line = re.sub(r"^(?:\$|%|>)\s+", "", line.strip())
        if not line or line.startswith("#"):
            return
        cwd: str | None = ""
        for seg in re.split(r"\s*(?:&&|\|\||;|\|)\s*", line):
            try:
                tokens = shlex.split(seg, comments=True)
            except ValueError:
                tokens = seg.split()
            while tokens and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0] in {"sudo", "exec"}):
                tokens = tokens[1:]
            if tokens and tokens[0] in {"cd", "pushd"}:
                dest = tokens[1] if len(tokens) > 1 else ""
                if cwd is None or not dest or dest.startswith(("/", "~", "$")):
                    cwd = None
                else:
                    cand = Path(os.path.normpath(os.path.join(cwd, dest))).as_posix()
                    cwd = "" if cand == "." else cand if self.index.exists(cand) else None
                continue
            if tokens:
                self.check_segment(tokens, doc, lineno, cwd)

    def manifest_target(self, kind: str, label: str, name: str, by_dir: dict[str, set[str]], cwd: str | None,
                        doc: str, lineno: int) -> None:
        manifest = "package.json" if kind == "npm" else "Makefile"
        if cwd is None:
            self.add("target", label, doc, lineno, "unverified", "the command runs in a directory the doc does not "
                                                                 "pin down")
            return
        where = f"{cwd}/{manifest}" if cwd else manifest
        names = by_dir.get(cwd)
        if names is not None:
            if name in names:
                self.add("target", label, doc, lineno, "verified", where)
            else:
                self.add("target", label, doc, lineno, "missing", f"not defined in {where}")
            return
        others = sorted(d for d, n in by_dir.items() if name in n)
        if others:
            self.add("target", label, doc, lineno, "unverified",
                     f"no {where}; defined in {others[0] + '/' if others[0] else ''}{manifest}, the doc does not "
                     "say to run it there")
        else:
            self.add("target", label, doc, lineno, "missing", f"no {where}, and no {manifest} defines it")

    def check_segment(self, tokens: list[str], doc: str, lineno: int, cwd: str | None = "") -> None:
        head, args = tokens[0], tokens[1:]
        script: str | None = None
        if cwd != "" and head not in {"npm", "pnpm", "yarn", "bun", "make"}:
            return
        if PYTHON_RE.match(head):
            if len(args) >= 2 and args[0] == "-m":
                script = self.resolve_module(args[1])
                if script is None:
                    return
                args = args[2:]
            elif args and not args[0].startswith("-"):
                target = args[0][2:] if args[0].startswith("./") else args[0]
                if "/" not in target and not target.endswith(".py"):
                    return
                if not self.path_claim(args[0], doc, lineno) or not self.index.exists(target):
                    return
                script, args = target, args[1:]
            else:
                return
        elif head in {"npm", "pnpm", "yarn", "bun"}:
            name = None
            if len(args) >= 2 and args[0] == "run":
                name = args[1]
            elif args and args[0] in {"test", "start"}:
                name = args[0]
            if name:
                self.manifest_target("npm", f"{head} run {name}", name, self.index.npm_by_dir, cwd, doc, lineno)
            return
        elif head == "make":
            for t in args:
                if t.startswith("-") or "=" in t:
                    continue
                self.manifest_target("make", f"make {t}", t, self.index.make_by_dir, cwd, doc, lineno)
            return
        elif head in self.console:
            script = self.console[head]
        elif head.startswith("./") or ("/" in head and not head.startswith("/")):
            if not self.path_claim(head, doc, lineno):
                return
            target = head[2:] if head.startswith("./") else head
            if not self.index.exists(target):
                return
            script = target
        else:
            return
        if script is None:
            return
        info = self.index.script_info(script)
        for a in args:
            if not a.startswith("--") or a == "--":
                continue
            flag = a.split("=")[0]
            if not FLAG_RE.fullmatch(flag):
                continue
            claim = f"{flag} ({script})"
            if info is None or not info.parser_found:
                self.add("flag", claim, doc, lineno, "unverified", "no option declarations found in the script")
            elif flag in info.flags:
                self.add("flag", claim, doc, lineno, "verified")
            else:
                self.add("flag", claim, doc, lineno, "missing", f"{script} does not declare it")

    # defaults and versions

    def check_defaults(self, line: str, doc: str, lineno: int) -> None:
        flags = list(FLAG_RE.finditer(line))
        for i, m in enumerate(flags):
            end = flags[i + 1].start() if i + 1 < len(flags) else len(line)
            window = re.split(r"(?<=[.!?])\s", line[m.end():min(end, m.end() + 100)])[0]
            dm = DEFAULT_RE.search(window)
            if not dm:
                continue
            flag, claimed = m.group(1), dm.group(1)
            if claimed.lower() in {"value", "is", "to", "of", "the", "a", "an"}:
                continue
            defs = self.index.flag_defaults.get(flag, [])
            known = [(rel, d) for rel, d in defs if d is not UNKNOWN]
            claim = f"{flag} default {claimed}"
            if not defs:
                continue
            if not known:
                self.add("default", claim, doc, lineno, "unverified", "the default is not a literal in the code")
                continue
            named = [(rel, d) for rel, d in known if rel.rsplit("/", 1)[-1] in line]
            known = named or known
            if any(norm_value(d) == norm_claimed(claimed) for _, d in known):
                self.add("default", claim, doc, lineno, "verified")
            elif len({rel for rel, _ in known}) > 1:
                self.add("default", claim, doc, lineno, "unverified",
                         f"{len({rel for rel, _ in known})} scripts declare {flag} with other defaults; the line "
                         "does not name the script")
            else:
                rel, d = known[0]
                self.add("default", claim, doc, lineno, "stale", f"code default is {d!r} in {rel}")

        for match in ENV_NAME_RE.finditer(line):
            name = match.group(1)
            window = re.split(r"(?<=[.!?])\s", line[match.end():match.end() + 100])[0]
            dm = DEFAULT_RE.search(window)
            if not dm:
                continue
            claimed = dm.group(1)
            if claimed.lower() in {"value", "is", "to", "of", "the", "a", "an"}:
                continue
            defs = self.index.env_defaults.get(name, [])
            if not defs:
                continue
            claim = f"{name} default {claimed}"
            if any(default is UNKNOWN for _, default in defs):
                self.add("default", claim, doc, lineno, "unverified", "at least one code default is not a literal")
                continue
            values = {norm_value(default) for _, default in defs}
            if len(values) > 1:
                self.add("default", claim, doc, lineno, "unverified", "code declares multiple defaults")
            elif next(iter(values)) == norm_claimed(claimed):
                self.add("default", claim, doc, lineno, "verified")
            else:
                rel, default = defs[0]
                self.add("default", claim, doc, lineno, "stale", f"code default is {default!r} in {rel}")

    def check_versions(self, line: str, doc: str, lineno: int) -> None:
        if not self.version or not self.name:
            return
        name = re.escape(self.name)
        found: list[str] = []
        found += re.findall(rf"(?<![\w-]){name}\s*(?:==|@|\s+v)" + SEMVER, line, re.IGNORECASE)
        if re.search(rf"(?<![\w-]){name}(?![\w-])", line, re.IGNORECASE):
            found += re.findall(r"\bversion\s*[:=]?\s*" + SEMVER, line, re.IGNORECASE)
        for v in dict.fromkeys(found):
            claim = f"{self.name} {v}"
            if v == self.version:
                self.add("version", claim, doc, lineno, "verified")
            else:
                self.add("version", claim, doc, lineno, "stale", f"manifest version is {self.version}")


def run(root: Path, docs: list[str] | None, excludes: list[str], run_help: bool) -> dict:
    index = Index(root, excludes, run_help=run_help)
    selected: list[str] = []
    if docs:
        for pat in docs:
            matches = sorted(r for r in index.rel_files if fnmatch.fnmatch(r, pat))
            if not matches and (root / pat).is_file():
                matches = [pat]
            selected += matches
    else:
        selected = default_docs(index)
    selected = list(dict.fromkeys(selected))
    checker = Checker(index)
    for doc in selected:
        checker.check_doc(doc)
    summary = {s: 0 for s in STATUSES}
    for c in checker.claims:
        summary[c.status] += 1
    summary["total"] = len(checker.claims)
    return {
        "repo": str(root),
        "docs": selected,
        "summary": summary,
        "claims": [asdict(c) | {"location": c.location} for c in checker.claims],
    }


def render_table(report: dict, only_failures: bool) -> str:
    rows = [c for c in report["claims"] if not only_failures or c["status"] in {"missing", "stale"}]
    order = {"stale": 0, "missing": 1, "unverified": 2, "verified": 3}
    rows.sort(key=lambda c: (order[c["status"]], c["doc"], c["line"]))
    head = ("STATUS", "KIND", "LOCATION", "CLAIM", "DETAIL")
    table = [head] + [(c["status"], c["kind"], c["location"], c["claim"], c["detail"]) for c in rows]
    widths = [min(max(len(r[i]) for r in table), 48) for i in range(4)]
    lines = []
    for r in table:
        cells = [r[i][:48].ljust(widths[i]) for i in range(4)]
        lines.append("  ".join(cells + [r[4]]).rstrip())
    s = report["summary"]
    lines.append("")
    lines.append(f"{s['total']} claims in {len(report['docs'])} documents: {s['verified']} verified, "
                 f"{s['missing']} missing, {s['stale']} stale, {s['unverified']} unverified")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="docs_truth_check.py",
        description="Check README and docs claims (paths, links, flags, defaults, env vars, symbols, versions, "
                    "npm and make targets) against the working tree.")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--docs", action="append", metavar="GLOB",
                    help="documentation files or globs relative to the repo (repeatable); default: README*, "
                         "CONTRIBUTING*, AGENTS.md, CLAUDE.md at the root and docs/**/*.md")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="paths to leave out of the index and the docs (repeatable)")
    ap.add_argument("--json", action="store_true", help="print the JSON report instead of the table")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON report to FILE")
    ap.add_argument("--only-failures", action="store_true", help="table shows only missing and stale claims")
    ap.add_argument("--fail-on", choices=["any", "stale", "none"], default="any",
                    help="exit 1 on any missing or stale claim (any), only on stale claims, or never (default: any)")
    ap.add_argument("--run-help", action="store_true",
                    help="run scripts with no parseable option declarations once with --help to read their flags")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    report = run(root, args.docs, args.exclude, args.run_help)
    if not report["docs"]:
        print("error: no documentation files found (use --docs)", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2) if args.json else render_table(report, args.only_failures))
    s = report["summary"]
    if args.fail_on == "any" and (s["missing"] or s["stale"]):
        return 1
    if args.fail_on == "stale" and s["stale"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
