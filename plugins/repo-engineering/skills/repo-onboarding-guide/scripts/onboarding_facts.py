#!/usr/bin/env python3
"""Collect the deterministic facts an onboarding guide must be built from, each with a citation.

Fact kinds (every fact has an id, a kind, a one-line text, the terms a guide may use for it, and a citation):
  project          name, version and runtime requirement from pyproject.toml and package.json
  entry_point      pyproject console scripts, package.json bin and main, Python __main__ guards,
                   Dockerfile ENTRYPOINT and CMD, Procfile processes
  command          package.json scripts, Makefile and justfile targets, CI workflow run steps
  test_command     the subset of commands that run tests, plus pytest configuration
  test_location    directories that hold test files, with a file count
  directory        top-level directories (and one level under src/) with a purpose taken from a package
                   docstring or a README heading when there is one, otherwise inferred from the name
  env_var          environment variables read by Python (os.environ, os.getenv), JS and TS (process.env),
                   or declared in .env.example style files and compose files
  external_service services inferred from env var names and compose images (PostgreSQL, Redis and so on)
  owner            CODEOWNERS rules (root, .github/ or docs/)

Citations are "path:line". A directory whose purpose is inferred from its name cites the directory itself
("path/") and says so in "basis". Reads files only; runs nothing. Exit codes: 0 ok, 2 bad input.
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
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
TEST_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$|_spec\.rb$")
TEST_CMD_RE = re.compile(r"\b(pytest|unittest|tox|nox|jest|vitest|mocha|go test|cargo test|npm test|"
                         r"npm run test|yarn test|pnpm test|rspec|phpunit|make test|node --test)\b")
NAME_PURPOSES = {
    "src": "source code", "lib": "library code", "app": "application code", "apps": "applications",
    "packages": "workspace packages", "pkg": "packages", "cmd": "command entry points", "internal": "internal packages",
    "tests": "tests", "test": "tests", "spec": "tests", "__tests__": "tests", "e2e": "end-to-end tests",
    "docs": "documentation", "doc": "documentation", "examples": "examples", "example": "examples",
    "scripts": "helper scripts", "bin": "executables", "tools": "tooling", "config": "configuration",
    "configs": "configuration", "deploy": "deployment configuration", "deployment": "deployment configuration",
    "infra": "infrastructure code", "terraform": "infrastructure code", "k8s": "Kubernetes manifests",
    "helm": "Helm charts", "migrations": "database migrations", "public": "static assets", "static": "static assets",
    "assets": "static assets", "web": "web front end", "frontend": "front end", "backend": "back end",
    "api": "API code", "server": "server code", "client": "client code", "fixtures": "test fixtures",
    ".github": "GitHub configuration and workflows", ".circleci": "CircleCI configuration",
    ".devcontainer": "dev container configuration", "benchmarks": "benchmarks", "plugins": "plugins",
}
SERVICES = [
    ("PostgreSQL", r"postgres|\bpg_|^PG[A-Z]*$|^PG_"), ("MySQL", r"mysql|mariadb"), ("Redis", r"redis"),
    ("MongoDB", r"mongo"), ("RabbitMQ", r"rabbit|amqp"), ("Kafka", r"kafka"), ("Elasticsearch", r"elastic"),
    ("AWS", r"^aws_|\bs3\b|_s3_|^s3_|dynamo|\bsqs\b|_sqs"), ("Google Cloud", r"^gcp_|^gcs_|google_cloud|bigquery"),
    ("Azure", r"azure"), ("Stripe", r"stripe"), ("Sentry", r"sentry"), ("SMTP mail", r"smtp|mailgun|sendgrid"),
    ("Slack", r"slack"), ("GitHub API", r"^github_|^gh_token"), ("SQLite", r"sqlite"),
]
ENV_PY_RE = re.compile(r"os\.(?:environ\.get|getenv|environ\.setdefault)\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]"
                       r"|os\.environ\[\s*['\"]([A-Z][A-Z0-9_]+)['\"]\s*\]")
ENV_JS_RE = re.compile(r"process\.env\.([A-Z][A-Z0-9_]+)|process\.env\[\s*['\"]([A-Z][A-Z0-9_]+)['\"]\s*\]"
                       r"|import\.meta\.env\.([A-Z][A-Z0-9_]+)")
ENV_FILE_RE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=")
ENV_FILE_NAMES = {".env.example", ".env.sample", ".env.template", "example.env", ".env.dist"}


def walk(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            out.append((Path(dirpath) / f).relative_to(root).as_posix())
            if len(out) >= MAX_FILES:
                return out
    return out


def read(root: Path, rel: str) -> str | None:
    p = root / rel
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def line_of(text: str, needle: str | re.Pattern, default: int = 1) -> int:
    if isinstance(needle, str):
        idx = text.find(needle)
    else:
        m = needle.search(text)
        idx = m.start() if m else -1
    return text[:idx].count("\n") + 1 if idx >= 0 else default


def cite(rel: str, text: str, needle: str | re.Pattern) -> str:
    return f"{rel}:{line_of(text, needle)}"


class Facts:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self._seen: set[tuple] = set()

    def add(self, kind: str, text: str, citation: str, terms: list[str], **extra) -> None:
        key = (kind, text, citation)
        if key in self._seen:
            return
        self._seen.add(key)
        terms = sorted({t for t in terms if t})
        self.items.append({"kind": kind, "text": text, "terms": terms, "citation": citation, **extra})


def collect(root: Path) -> dict:
    files = walk(root)
    fileset = set(files)
    facts = Facts()
    texts: dict[str, str] = {}
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if (Path(rel).suffix in CODE_EXT or name in {"pyproject.toml", "package.json", "Makefile", "makefile",
                                                     "justfile", "Procfile", "CODEOWNERS"}
                or name in ENV_FILE_NAMES or name.startswith(("Dockerfile", "docker-compose", "compose."))
                or rel.startswith(".github/workflows/") or name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}):
            text = read(root, rel)
            if text is not None:
                texts[rel] = text

    for rel, text in sorted(texts.items()):
        name = rel.rsplit("/", 1)[-1]
        base = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if name == "pyproject.toml":
            pyproject_facts(facts, rel, text)
        elif name == "package.json":
            package_facts(facts, rel, text, base)
        elif name in {"Makefile", "makefile", "justfile"}:
            tool = "make" if name != "justfile" else "just"
            pat = (r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:(?!=)" if tool == "make"
                   else r"^([A-Za-z0-9_][A-Za-z0-9_-]*)(?:\s+[^:\n]*)?:(?!=)")
            for m in re.finditer(pat, text, re.MULTILINE):
                target = m.group(1)
                cmd = f"{tool} {target}"
                prefix = f"cd {base.rstrip('/')} && " if base else ""
                kind = "test_command" if re.search(r"test|check", target) else "command"
                line = text[: m.start()].count("\n") + 1
                facts.add(kind, f"`{prefix}{cmd}` is a {tool} target", f"{rel}:{line}",
                          [cmd, target, prefix + cmd, rel], command=prefix + cmd)
        elif name == "Procfile":
            for i, ln in enumerate(text.splitlines(), 1):
                m = re.match(r"^([A-Za-z0-9_-]+):\s*(.+)$", ln)
                if m:
                    facts.add("entry_point", f"Procfile process `{m.group(1)}` runs `{m.group(2).strip()}`",
                              f"{rel}:{i}", [m.group(1), m.group(2).strip()], command=m.group(2).strip())
        elif name.startswith("Dockerfile"):
            for m in re.finditer(r"^(ENTRYPOINT|CMD)\s+(.+)$", text, re.MULTILINE):
                line = text[: m.start()].count("\n") + 1
                facts.add("entry_point", f"{rel} {m.group(1)} is `{m.group(2).strip()}`", f"{rel}:{line}",
                          [m.group(2).strip(), rel])
        elif rel.startswith(".github/workflows/") or name.startswith(".gitlab-ci"):
            ci_facts(facts, rel, text)
        elif name.startswith(("docker-compose", "compose.")):
            for m in re.finditer(r"^\s*image:\s*['\"]?([^\s'\"]+)", text, re.MULTILINE):
                line = text[: m.start()].count("\n") + 1
                image = m.group(1)
                for svc, pat in SERVICES:
                    if re.search(pat, image.split("/")[-1].split(":")[0], re.IGNORECASE):
                        facts.add("external_service", f"{svc} runs as compose image `{image}`", f"{rel}:{line}",
                                  [svc, image, image.split(":")[0], rel], service=svc, basis=f"compose image {image}")
            for i, ln in enumerate(text.splitlines(), 1):
                m = re.match(r"^\s*-?\s*([A-Z][A-Z0-9_]+)\s*[:=]", ln)
                if m and "_" in m.group(1):
                    env_fact(facts, m.group(1), rel, i)
        elif name in ENV_FILE_NAMES:
            for i, ln in enumerate(text.splitlines(), 1):
                m = ENV_FILE_RE.match(ln)
                if m:
                    env_fact(facts, m.group(1), rel, i)
        elif name == "CODEOWNERS" and rel in {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}:
            for i, ln in enumerate(text.splitlines(), 1):
                parts = ln.split("#", 1)[0].split()
                if len(parts) >= 2:
                    owners = [p for p in parts[1:] if p.startswith("@") or "@" in p]
                    facts.add("owner", f"`{parts[0]}` is owned by {', '.join(owners)}", f"{rel}:{i}",
                              [parts[0], parts[0].strip("/"), *owners], pattern=parts[0], owners=owners)
        if Path(rel).suffix in CODE_EXT:
            code_facts(facts, rel, text)

    test_location_facts(facts, files)
    directory_facts(facts, root, files, fileset)

    order = ["project", "entry_point", "command", "test_command", "test_location", "directory", "env_var",
             "external_service", "owner"]
    items = sorted(facts.items, key=lambda f: (order.index(f["kind"]), f["citation"], f["text"]))
    for n, f in enumerate(items, 1):
        f["id"] = f"F{n}"
    items = [{"id": f.pop("id"), **f} for f in items]
    counts: dict[str, int] = {}
    for f in items:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1
    return {"repo": str(root), "files_scanned": len(files), "counts": counts, "facts": items}


def env_fact(facts: Facts, name: str, rel: str, line: int) -> None:
    facts.add("env_var", f"`{name}` is read or declared in {rel}", f"{rel}:{line}", [name, rel], name=name)
    lowered = name.lower()
    for svc, pat in SERVICES:
        if re.search(pat, lowered if not pat.startswith("^PG") else name, re.IGNORECASE):
            facts.add("external_service", f"{svc} is suggested by the variable `{name}`", f"{rel}:{line}",
                      [svc, name, rel], service=svc, basis=f"env var {name}")


def pyproject_facts(facts: Facts, rel: str, text: str) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    proj = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    name = proj.get("name") or poetry.get("name")
    if isinstance(name, str):
        facts.add("project", f"Python project `{name}`", cite(rel, text, re.compile(r"^name\s*=", re.M)),
                  [name, rel], name=name)
    version = proj.get("version") or poetry.get("version")
    if isinstance(version, str):
        facts.add("project", f"version `{version}` in {rel}",
                  cite(rel, text, re.compile(r"^version\s*=", re.M)), [version])
    req = proj.get("requires-python")
    if isinstance(req, str):
        facts.add("project", f"requires Python `{req}`", cite(rel, text, "requires-python"),
                  [req, "Python " + req.lstrip("><=~^! ")])
    for table in (proj.get("scripts", {}), poetry.get("scripts", {})):
        if isinstance(table, dict):
            for script, target in table.items():
                facts.add("entry_point", f"console script `{script}` runs `{target}`",
                          cite(rel, text, re.compile(r"^\s*[\"']?" + re.escape(script) + r"[\"']?\s*=", re.M)),
                          [script, str(target), str(target).split(":")[0]], command=script)
    pytest_cfg = data.get("tool", {}).get("pytest", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(pytest_cfg, dict) and pytest_cfg:
        line = line_of(text, "[tool.pytest")
        paths = pytest_cfg.get("ini_options", {}).get("testpaths", [])
        facts.add("test_command", "pytest is configured" + (f" with testpaths {paths}" if paths else ""),
                  f"{rel}:{line}", ["pytest", "python -m pytest", "python3 -m pytest", *map(str, paths)],
                  command="pytest")


def package_facts(facts: Facts, rel: str, text: str, base: str) -> None:
    try:
        pj = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(pj, dict):
        return
    prefix = f"cd {base.rstrip('/')} && " if base else ""
    if isinstance(pj.get("name"), str):
        facts.add("project", f"npm package `{pj['name']}`" + (f" in {base.rstrip('/')}" if base else ""),
                  cite(rel, text, '"name"'), [pj["name"], rel])
    if isinstance(pj.get("version"), str):
        facts.add("project", f"version `{pj['version']}` in {rel}", cite(rel, text, '"version"'),
                  [pj["version"]])
    engines = pj.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("node"), str):
        facts.add("project", f"requires Node `{engines['node']}`", cite(rel, text, '"node"'),
                  [engines["node"], "Node " + engines["node"].lstrip("><=~^ ")])
    bins = pj.get("bin")
    if isinstance(bins, str):
        bins = {pj.get("name", "bin"): bins}
    if isinstance(bins, dict):
        for name, target in bins.items():
            facts.add("entry_point", f"npm bin `{name}` runs `{base}{target}`", cite(rel, text, '"bin"'),
                      [name, str(target), base + str(target).lstrip("./")], command=name)
    if isinstance(pj.get("main"), str):
        facts.add("entry_point", f"package main is `{base}{pj['main']}`", cite(rel, text, '"main"'),
                  [pj["main"], base + pj["main"].lstrip("./")])
    scripts = pj.get("scripts")
    if isinstance(scripts, dict):
        for name, cmd in scripts.items():
            short = {"test", "start", "stop", "restart"}
            forms = [f"npm run {name}", f"yarn {name}", f"pnpm {name}", f"pnpm run {name}", f"yarn run {name}",
                     f"bun run {name}"]
            if name in short:
                forms += [f"npm {name}"]
            if name == "test":
                forms += ["npm t"]
            forms += [prefix + f for f in forms] + [name, str(cmd)]
            kind = "test_command" if name.startswith("test") or TEST_CMD_RE.search(str(cmd)) else "command"
            facts.add(kind, f"`{prefix}npm run {name}` runs `{cmd}`",
                      cite(rel, text, json.dumps(name) + ":"), forms, command=f"{prefix}npm run {name}")


def ci_facts(facts: Facts, rel: str, text: str) -> None:
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", lines[i])
        if m:
            indent, first = len(m.group(1)), m.group(2).strip()
            cmds: list[tuple[int, str]] = []
            if first in {"|", ">", "|-", ">-"}:
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
                    if lines[j].strip() and not lines[j].strip().startswith("#"):
                        cmds.append((j + 1, lines[j].strip()))
                    j += 1
                i = j
            else:
                cmds.append((i + 1, first.strip("'\"")))
                i += 1
            for line, cmd in cmds:
                kind = "test_command" if TEST_CMD_RE.search(cmd) else "command"
                facts.add(kind, f"CI runs `{cmd}`", f"{rel}:{line}", [cmd], command=cmd, source="ci")
            continue
        i += 1


def code_facts(facts: Facts, rel: str, text: str) -> None:
    if rel.endswith(".py"):
        for m in ENV_PY_RE.finditer(text):
            env_fact(facts, m.group(1) or m.group(2), rel, text[: m.start()].count("\n") + 1)
        if not TEST_RE.search(rel):
            m = re.search(r"^if __name__ == ['\"]__main__['\"]", text, re.MULTILINE)
            if m:
                line = text[: m.start()].count("\n") + 1
                facts.add("entry_point", f"`{rel}` runs as a script (`__main__` guard)", f"{rel}:{line}",
                          [rel, f"python {rel}", f"python3 {rel}"])
            if rel.endswith("__main__.py"):
                pkg = rel.rsplit("/", 1)[0].replace("/", ".") if "/" in rel else ""
                if pkg:
                    mod = pkg.split(".", 1)[1] if pkg.startswith("src.") else pkg
                    facts.add("entry_point", f"`python -m {mod}` runs {rel}", f"{rel}:1",
                              [f"python -m {mod}", f"python3 -m {mod}", rel])
    else:
        for m in ENV_JS_RE.finditer(text):
            env_fact(facts, m.group(1) or m.group(2) or m.group(3), rel, text[: m.start()].count("\n") + 1)


def test_location_facts(facts: Facts, files: list[str]) -> None:
    groups: dict[str, list[str]] = {}
    for rel in files:
        if Path(rel).suffix in CODE_EXT | {".go", ".rb", ".rs"} and TEST_RE.search(rel):
            m = re.search(r"(^|.*/)(tests?|__tests__|spec)/", rel)
            key = (m.group(0) if m else (rel.rsplit("/", 1)[0] + "/" if "/" in rel else "./"))
            groups.setdefault(key, []).append(rel)
    for key, members in sorted(groups.items()):
        facts.add("test_location", f"{len(members)} test file(s) under `{key}`", f"{members[0]}:1",
                  [key, key.rstrip("/"), *members], count=len(members))


def docstring_purpose(root: Path, rel: str) -> tuple[str, int] | None:
    text = read(root, rel)
    if text is None:
        return None
    if rel.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return None
        doc = ast.get_docstring(tree)
        if doc:
            return doc.strip().splitlines()[0].strip(), 1
        return None
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        if not s:
            continue
        if rel.endswith(".md"):
            return re.sub(r"^#+\s*", "", s)[:160], i
        m = re.match(r"^(?://+|/\*+|\*)\s*(.*?)\s*(?:\*/)?$", s)
        return (m.group(1)[:160], i) if m and m.group(1) else None
    return None


def directory_facts(facts: Facts, root: Path, files: list[str], fileset: set[str]) -> None:
    dirs: set[str] = set()
    for rel in files:
        parts = rel.split("/")
        if len(parts) > 1:
            dirs.add(parts[0])
        if len(parts) > 2 and parts[0] in {"src", "packages", "apps", "lib"}:
            dirs.add("/".join(parts[:2]))
    for d in sorted(dirs):
        count = sum(1 for r in files if r.startswith(d + "/"))
        purpose = None
        for cand in (f"{d}/__init__.py", f"{d}/README.md", f"{d}/readme.md", f"{d}/index.ts", f"{d}/index.js"):
            if cand in fileset:
                got = docstring_purpose(root, cand)
                if got:
                    purpose = got
                    facts.add("directory", f"`{d}/`: {purpose[0]}", f"{cand}:{purpose[1]}", [d, d + "/"],
                              path=d + "/", purpose=purpose[0], basis=f"first line of {cand}", files=count)
                    break
        if purpose is None:
            name = d.rsplit("/", 1)[-1]
            guess = NAME_PURPOSES.get(name.lower())
            text = f"`{d}/`: {guess} (inferred from the name)" if guess else f"`{d}/`: purpose not stated"
            facts.add("directory", text, f"{d}/", [d, d + "/"], path=d + "/", purpose=guess,
                      basis="directory name" if guess else "none", files=count)


def render(rep: dict) -> str:
    out = [f"Onboarding facts: {rep['repo']} ({rep['files_scanned']} files scanned)", ""]
    kind = None
    for f in rep["facts"]:
        if f["kind"] != kind:
            kind = f["kind"]
            out.append(f"{kind} ({rep['counts'][kind]}):")
        out.append(f"  {f['id']:<5} {f['text']}  [{f['citation']}]")
    if not rep["facts"]:
        out.append("No facts found.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="onboarding_facts.py",
                                 description="Print the cited facts an onboarding guide must be written from.")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON to FILE")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    rep = collect(root)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
