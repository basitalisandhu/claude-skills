#!/usr/bin/env python3
"""Offline repository hygiene checks with a severity per finding, a table, JSON or SARIF, and a CI exit code.

Rules (severity in brackets):
  HYG-LOCK        [medium] a dependency manifest with no lockfile next to it ([low] for pyproject.toml and
                  Cargo.toml, where libraries often leave the lock out on purpose)
  HYG-LOCKDRIFT   [medium] lockfile drift signals: a package.json dependency missing from package-lock.json or with
                  a different range there; a pyproject dependency absent from poetry.lock or uv.lock; two
                  different JS lockfiles side by side ([low])
  HYG-DUPDEP      [medium] the same dependency declared with different version specs in several workspace manifests
  HYG-LICENSE     [medium] no licence file at the root
  HYG-SPDX        [low] a manifest without a licence field, or one that is not an SPDX-style identifier; [medium]
                  when it disagrees with the licence file's family
  HYG-SECRET      [high] secret-shaped strings (cloud access key ids, GitHub, Slack, Stripe and Google API tokens,
                  private key blocks); [medium] generic "password/secret/token = '<long literal>'" assignments.
                  Values are never printed in full.
  HYG-PIN         [medium] a GitHub Actions step that uses an action by tag or branch instead of a full commit SHA
  HYG-PERMS       [high] a workflow or job with "permissions: write-all"; [low] a workflow with no permissions key
  HYG-SECURITY    [low] no SECURITY.md (root, .github/ or docs/)
  HYG-COC         [low] no CODE_OF_CONDUCT.md (root, .github/ or docs/)
  HYG-LARGE       [medium] a file larger than --max-file-kb (default 1024)
  HYG-GENERATED   [low] a generated or build output path committed (dist/, build/, node_modules/, __pycache__/,
                  *.pyc, *.egg-info/, coverage output, .DS_Store)

Files come from "git ls-files" when the folder is a git work tree (so only committed or staged files count) and
from a directory walk otherwise. No network. Exit codes: 0 nothing at or above --fail-on, 1 findings at or above
it, 2 bad input.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

SEVERITIES = ["low", "medium", "high"]
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
CONTENT_SKIP = {"node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__", "coverage", ".git",
                "target", ".next"}
TEXT_LIMIT = 1_000_000
LOCKS = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock",
                     "npm-shrinkwrap.json"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"],
    "Pipfile": ["Pipfile.lock"], "Cargo.toml": ["Cargo.lock"], "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"], "composer.json": ["composer.lock"],
}
GENERATED_RE = re.compile(r"(^|/)(dist|build|node_modules|__pycache__|coverage|htmlcov|\.pytest_cache|"
                          r"[^/]+\.egg-info)/|\.pyc$|(^|/)\.DS_Store$|(^|/)\.coverage$")
SECRET_RULES = [
    ("cloud access key id", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", "high", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", "high", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private key block", "high", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
]
GENERIC_SECRET = re.compile(
    r"""(?i)\b([\w-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[\w-]*)\s*[:=]\s*"""
    r"""(['"])([^'"\s]{12,})\2""")
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|changeme|example|placeholder|dummy|test|fake|sample|your[_-].*|<.*>|"
                         r"\$\{.*\}|\{\{.*\}\})$|example|placeholder|changeme|dummy|xxxx")
SPDX_RE = re.compile(r"^(?:\(?[A-Za-z0-9.+-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*\)?)$")
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


class Report:
    def __init__(self) -> None:
        self.findings: list[dict] = []

    def add(self, rule: str, severity: str, path: str, line: int, message: str) -> None:
        self.findings.append({"rule": rule, "severity": severity, "path": path, "line": line, "message": message})


def list_files(root: Path) -> tuple[list[str], str]:
    if (root / ".git").exists() and shutil.which("git"):
        try:
            proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached"], capture_output=True,
                                  timeout=60, check=False)
            if proc.returncode == 0:
                files = sorted(f for f in proc.stdout.decode("utf-8", "replace").split("\0") if f)
                return [f for f in files if (root / f).is_file()], "git ls-files"
        except (OSError, subprocess.TimeoutExpired):
            pass
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for f in sorted(filenames):
            out.append((Path(dirpath) / f).relative_to(root).as_posix())
    return out, "directory walk"


def read(root: Path, rel: str) -> str | None:
    try:
        p = root / rel
        if p.stat().st_size > TEXT_LIMIT:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text[:i].count("\n") + 1 if i >= 0 else 1


def redact(value: str) -> str:
    return f"{value[:4]}... ({len(value)} chars)"


def js_deps(pj: dict) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if isinstance(pj.get(key), dict):
            deps.update({k: str(v) for k, v in pj[key].items()})
    return deps


def py_deps(data: dict) -> dict[str, str]:
    deps: dict[str, str] = {}
    for spec in data.get("project", {}).get("dependencies", []) or []:
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", str(spec))
        if m:
            deps[m.group(1).lower().replace("_", "-")] = m.group(3).split(";")[0].strip()
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry, dict):
        for k, v in poetry.items():
            if k.lower() != "python":
                deps[k.lower().replace("_", "-")] = v if isinstance(v, str) else str(v.get("version", ""))
    return deps


def check_manifests(root: Path, files: list[str], rep: Report, licence_family: str | None) -> None:
    fileset = set(files)
    declared: dict[str, list[tuple[str, str, int]]] = {}
    for rel in files:
        name = PurePosixPath(rel).name
        if name not in LOCKS or any(part in CONTENT_SKIP for part in PurePosixPath(rel).parts[:-1]):
            continue
        base = rel[: -len(name)]
        locks = [lf for lf in LOCKS[name] if base + lf in fileset]
        text = read(root, rel) or ""
        deps: dict[str, str] = {}
        licence = None
        has_deps = True
        if name == "package.json":
            try:
                pj = json.loads(text)
            except json.JSONDecodeError:
                rep.add("HYG-LOCK", "medium", rel, 1, "package.json does not parse")
                continue
            deps = js_deps(pj)
            has_deps = bool(deps)
            licence = pj.get("license") if isinstance(pj.get("license"), str) else None
            if not pj.get("private") or licence is not None:
                spdx_check(rep, rel, text, licence, "license", licence_family)
            for k, v in deps.items():
                declared.setdefault(k, []).append((rel, v, line_of(text, f'"{k}"')))
            js_locks = [lf for lf in locks if lf != "npm-shrinkwrap.json"]
            if len(js_locks) > 1:
                rep.add("HYG-LOCKDRIFT", "low", rel, 1,
                        f"several lockfiles next to {rel}: {', '.join(js_locks)}; installs may disagree")
            if base + "package-lock.json" in fileset and deps:
                lock_drift_npm(root, base + "package-lock.json", deps, rep)
            workspace_root = isinstance(pj.get("workspaces"), (list, dict))
            if not locks and has_deps and not workspace_lock_above(rel, fileset):
                rep.add("HYG-LOCK", "medium", rel, 1, "dependencies declared but no lockfile committed next to it"
                        + (" (workspace root)" if workspace_root else ""))
            continue
        if name == "pyproject.toml":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            deps = py_deps(data)
            has_deps = bool(deps)
            proj = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
            lic = proj.get("license") or data.get("tool", {}).get("poetry", {}).get("license")
            if isinstance(lic, dict):
                lic = lic.get("text") or lic.get("file")
            if proj.get("license-expression"):
                lic = proj["license-expression"]
            if proj or data.get("tool", {}).get("poetry"):
                spdx_check(rep, rel, text, lic if isinstance(lic, str) else None, "license", licence_family)
            for k, v in deps.items():
                declared.setdefault(k, []).append((rel, v, line_of(text, k)))
            for lock in locks:
                if lock in {"poetry.lock", "uv.lock", "pdm.lock"}:
                    lock_text = (read(root, base + lock) or "").lower().replace("_", "-")
                    for dep in sorted(deps):
                        if f'name = "{dep}"' not in lock_text:
                            rep.add("HYG-LOCKDRIFT", "medium", rel, line_of(text, dep),
                                    f"{dep} is declared here but not in {base + lock}; the lock is older than the "
                                    f"manifest")
            if not locks and has_deps:
                rep.add("HYG-LOCK", "low", rel, 1, "dependencies declared but no lockfile (fine for a library, not "
                                                   "for an application)")
            continue
        if name == "Cargo.toml":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            pkg = data.get("package", {})
            if pkg:
                spdx_check(rep, rel, text, pkg.get("license") if isinstance(pkg.get("license"), str) else None,
                           "license", licence_family)
            if not locks and data.get("dependencies"):
                rep.add("HYG-LOCK", "low", rel, 1, "dependencies declared but no Cargo.lock")
            continue
        if not locks:
            rep.add("HYG-LOCK", "medium", rel, 1, f"{name} without its lockfile ({' or '.join(LOCKS[name])})")
    for dep, uses in sorted(declared.items()):
        specs = {v for _, v, _ in uses}
        if len(uses) > 1 and len(specs) > 1:
            where = ", ".join(f"{r} ({v})" for r, v, _ in uses)
            rep.add("HYG-DUPDEP", "medium", uses[0][0], uses[0][2],
                    f"{dep} is declared with {len(specs)} different version specs: {where}")


def workspace_lock_above(rel: str, fileset: set[str]) -> bool:
    parts = PurePosixPath(rel).parts[:-1]
    for n in range(len(parts) - 1, -1, -1):
        base = "/".join(parts[:n]) + ("/" if n else "")
        if any(base + lf in fileset for lf in LOCKS["package.json"]):
            return True
    return False


def lock_drift_npm(root: Path, lock_rel: str, deps: dict[str, str], rep: Report) -> None:
    try:
        lock = json.loads(read(root, lock_rel) or "")
    except json.JSONDecodeError:
        rep.add("HYG-LOCKDRIFT", "medium", lock_rel, 1, "package-lock.json does not parse")
        return
    top = lock.get("packages", {}).get("", {}) if isinstance(lock.get("packages"), dict) else {}
    locked = js_deps(top) if top else {}
    installed = lock.get("packages", {}) if isinstance(lock.get("packages"), dict) else {}
    legacy = lock.get("dependencies", {}) if isinstance(lock.get("dependencies"), dict) else {}
    for dep, spec in sorted(deps.items()):
        present = f"node_modules/{dep}" in installed or dep in legacy
        if not present:
            rep.add("HYG-LOCKDRIFT", "medium", lock_rel, 1, f"{dep} is in package.json but not in {lock_rel}")
        elif locked and locked.get(dep) not in {None, spec}:
            rep.add("HYG-LOCKDRIFT", "medium", lock_rel, 1,
                    f"{dep} is {spec} in package.json but {locked[dep]} in {lock_rel}")


def spdx_check(rep: Report, rel: str, text: str, licence: str | None, key: str, family: str | None) -> None:
    if not licence:
        rep.add("HYG-SPDX", "low", rel, 1, f"no {key} field with an SPDX identifier")
        return
    line = line_of(text, licence)
    if not SPDX_RE.match(licence.strip()) or licence.strip().upper() in {"SEE LICENSE IN LICENSE", "UNLICENSED"}:
        if licence.strip().upper() != "UNLICENSED":
            rep.add("HYG-SPDX", "low", rel, line, f"{key} {licence!r} is not an SPDX identifier")
        return
    if family and family not in {"unknown"}:
        ids = re.findall(r"[A-Za-z0-9.+-]+", licence)
        fam = family.split("-")[0].upper()
        if not any(i.upper().startswith(fam) for i in ids if i.upper() not in {"AND", "OR", "WITH"}):
            rep.add("HYG-SPDX", "medium", rel, line, f"{key} is {licence} but the licence file reads as {family}")


def check_secrets(root: Path, files: list[str], rep: Report) -> None:
    for rel in files:
        parts = PurePosixPath(rel).parts
        if any(p in CONTENT_SKIP for p in parts[:-1]) or PurePosixPath(rel).name.endswith((".lock", "-lock.json",
                                                                                         "lock.yaml")):
            continue
        text = read(root, rel)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if "hygiene: ignore" in line:
                continue
            hit = False
            for label, sev, rx in SECRET_RULES:
                m = rx.search(line)
                if m:
                    shown = "private key header" if label == "private key block" else redact(m.group(0))
                    rep.add("HYG-SECRET", sev, rel, i, f"{label}: {shown}")
                    hit = True
                    break
            if hit:
                continue
            m = GENERIC_SECRET.search(line)
            if m and not PLACEHOLDER.search(m.group(3)) and not re.fullmatch(r"[a-z_]+(\.[a-z_]+)+", m.group(3)):
                rep.add("HYG-SECRET", "medium", rel, i, f"{m.group(1)} is assigned a literal: {redact(m.group(3))}")


def check_workflows(root: Path, files: list[str], rep: Report) -> None:
    for rel in files:
        if not re.match(r"^\.github/workflows/[^/]+\.ya?ml$", rel):
            continue
        text = read(root, rel) or ""
        has_perms = False
        for i, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^(\s*)(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)", line)
            if m:
                ref = m.group(2)
                if ref.startswith(("./", "docker://")):
                    continue
                if "@" not in ref:
                    rep.add("HYG-PIN", "medium", rel, i, f"{ref} has no ref at all")
                elif not re.fullmatch(r"[0-9a-f]{40}", ref.rsplit("@", 1)[1]):
                    rep.add("HYG-PIN", "medium", rel, i, f"{ref} is pinned to a tag or branch, not a commit SHA")
            pm = re.match(r"^(\s*)permissions:\s*(\S*)", line)
            if pm:
                if not pm.group(1):
                    has_perms = True
                if pm.group(2).strip("'\"") == "write-all":
                    rep.add("HYG-PERMS", "high", rel, i, "permissions: write-all gives the token every write scope")
        if not has_perms:
            rep.add("HYG-PERMS", "low", rel, 1, "no top-level permissions key; the token gets the repository default")


def check_files(root: Path, files: list[str], rep: Report, max_kb: int) -> str | None:
    lower = {f.lower() for f in files}
    for rule, name in (("HYG-SECURITY", "security.md"), ("HYG-COC", "code_of_conduct.md")):
        if not any(f"{d}{name}" in lower for d in ("", ".github/", "docs/")):
            rep.add(rule, "low", ".", 0, f"no {name.upper().replace('.MD', '.md')} at the root, in .github/ or docs/")
    licence_files = [f for f in files if "/" not in f and f.upper().startswith(("LICENSE", "LICENCE", "COPYING"))]
    family = None
    if not licence_files:
        rep.add("HYG-LICENSE", "medium", ".", 0, "no LICENSE, LICENCE or COPYING file at the root")
    else:
        text = read(root, licence_files[0]) or ""
        family = next((fam for fam, pat in LICENCE_FAMILIES if re.search(pat, text, re.IGNORECASE)), "unknown")
    reported_dirs: set[str] = set()
    for rel in files:
        try:
            size = (root / rel).stat().st_size
        except OSError:
            continue
        if size > max_kb * 1024:
            rep.add("HYG-LARGE", "medium", rel, 0, f"{size // 1024} KB (limit {max_kb} KB); consider Git LFS or a "
                                                   f"release asset")
        m = GENERATED_RE.search(rel)
        if m:
            key = rel[: m.end()] if m.group(2) else rel
            if key not in reported_dirs:
                reported_dirs.add(key)
                rep.add("HYG-GENERATED", "low", key, 0, "generated or build output is committed")
    return family


def excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or rel.startswith(p.rstrip("/*") + "/") for p in patterns)


def collect(root: Path, max_kb: int, exclude: list[str] | None = None) -> dict:
    files, source = list_files(root)
    files = [f for f in files if not excluded(f, exclude or [])]
    rep = Report()
    family = check_files(root, files, rep, max_kb)
    check_manifests(root, files, rep, family)
    check_secrets(root, files, rep)
    check_workflows(root, files, rep)
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    rep.findings.sort(key=lambda f: (order[f["severity"]], f["rule"], f["path"], f["line"]))
    counts = {s: sum(f["severity"] == s for f in rep.findings) for s in reversed(SEVERITIES)}
    return {"repo": str(root), "files": len(files), "file_source": source, "licence_family": family,
            "counts": counts, "findings": rep.findings}


def sarif(rep: dict) -> dict:
    rules = sorted({f["rule"] for f in rep["findings"]})
    results = []
    for f in rep["findings"]:
        loc = {"physicalLocation": {"artifactLocation": {"uri": f["path"] if f["path"] != "." else "."}}}
        if f["line"]:
            loc["physicalLocation"]["region"] = {"startLine": f["line"]}
        results.append({"ruleId": f["rule"], "level": SARIF_LEVEL[f["severity"]], "message": {"text": f["message"]},
                        "locations": [loc], "properties": {"severity": f["severity"]}})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "repo-hygiene-bundle", "informationUri":
                                      "https://github.com/basitalisandhu/repo-engineering-skills",
                                      "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules]}},
                  "results": results}],
    }


def render(rep: dict) -> str:
    c = rep["counts"]
    out = [f"Repository hygiene: {rep['repo']} ({rep['files']} files from {rep['file_source']})",
           f"{c['high']} high, {c['medium']} medium, {c['low']} low", ""]
    for f in rep["findings"]:
        loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
        out.append(f"{f['severity']:<7} {f['rule']:<14} {loc:<45} {f['message']}")
    if not rep["findings"]:
        out.append("No findings.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hygiene.py",
                                 description="Offline hygiene checks: lockfiles, licences, secrets, CI pinning and "
                                             "permissions, community files, large and generated files.")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="medium",
                    help="lowest severity that makes the exit code 1 (default: medium)")
    ap.add_argument("--max-file-kb", type=int, default=1024, help="size above which a file is flagged (default: 1024)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="leave matching paths out, for example tests/fixtures (repeatable)")
    ap.add_argument("--rule", action="append", default=[], metavar="ID", help="only report this rule (repeatable)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0 to FILE")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    rep = collect(root, max(1, args.max_file_kb), args.exclude)
    if args.rule:
        wanted = {r.upper() for r in args.rule}
        rep["findings"] = [f for f in rep["findings"] if f["rule"] in wanted]
        rep["counts"] = {s: sum(f["severity"] == s for f in rep["findings"]) for s in reversed(SEVERITIES)}
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(sarif(rep), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    if args.fail_on == "none":
        return 0
    floor = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f["severity"]) >= floor for f in rep["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
