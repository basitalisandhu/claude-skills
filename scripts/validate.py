#!/usr/bin/env python3
"""Validate the repository: plugin structure, SKILL.md front matter, marketplace,
generated files and house rules. Standard library only, offline.

    python3 scripts/validate.py
    python3 scripts/validate.py --allow-duplicate some-skill   # tolerate one known duplicate name
    python3 scripts/validate.py --strict-quality               # soft quality notes become errors

Vendored plugin content (plugins/) and the generated site (docs/) are exempt from the
house-style checks; their counts are reported so a change upstream is visible.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hublib as H  # noqa: E402

EM_DASH = chr(0x2014)
# Assembled at run time so this file does not contain the strings it forbids.
MODEL_NAMES = [
    "Claude " + "Opus",
    "Claude " + "Sonnet",
    "Claude " + "Haiku",
    "GP" + "T-",
    "Gem" + "ini",
]
SECRET_PATTERNS = [
    ("aws access key id", "AK" + "IA" + r"[0-9A-Z]{16}"),
    ("github token", "gh" + r"[pousr]_[A-Za-z0-9]{36,}"),
    ("github fine-grained token", "github_" + "pat_" + r"[A-Za-z0-9_]{40,}"),
    ("slack token", "xo" + r"x[baprs]-[A-Za-z0-9-]{10,}"),
    ("private key block", "-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |PGP )?" + "PRIVATE KEY" + "-----"),
    ("google api key", "AI" + "za" + r"[0-9A-Za-z_-]{35}"),
    ("openai-style key", r"\b" + "s" + "k-" + r"(?:proj-|live-)?[A-Za-z0-9]{32,}"),
    ("stripe live key", "sk_" + "live_" + r"[A-Za-z0-9]{20,}"),
]
ALLOWED_SECRET_LITERALS = {"AK" + "IA" + "IOSFODNN7EXAMPLE"}
TEXT_SUFFIXES = {".md", ".py", ".json", ".yml", ".yaml", ".txt", ".toml", ".cfg", ".ini", ".sh", ".js", ".ts",
                 ".mjs", ".cjs", ".html", ".css", ".xml", ".csv", ".tsv", ".tf", ".env", ""}
VENDORED = ("plugins/", "docs/")


class Report:
    def __init__(self) -> None:
        self.results: list[tuple[str, list[str], list[str]]] = []

    def add(self, name: str, problems: list[str], notes: list[str] | None = None) -> None:
        self.results.append((name, problems, notes or []))

    def print(self) -> int:
        failed = 0
        for name, problems, notes in self.results:
            print(f"{'ok  ' if not problems else 'FAIL'} {name}" + (f" ({len(problems)})" if problems else ""))
            for p in problems[:40]:
                print(f"     {p}")
            if len(problems) > 40:
                print(f"     ... and {len(problems) - 40} more")
            for n in notes:
                print(f"     note: {n}")
            failed += len(problems)
        print("validate: " + ("all checks passed" if not failed else f"{failed} problem(s)"))
        return 1 if failed else 0


def repo_files(root: Path) -> list[str]:
    """Tracked plus untracked, non-ignored files (git), or a plain walk without git."""
    try:
        out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=root,
                             capture_output=True, text=True, check=True).stdout
        files = [f for f in out.split("\0") if f and (root / f).is_file()]
        if files:
            return sorted(files)
    except (OSError, subprocess.CalledProcessError):
        pass
    skip = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv"}
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                  if p.is_file() and not any(part in skip for part in p.relative_to(root).parts))


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"LICENSE", ".gitignore", ".nojekyll"}:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def check_structure(root: Path) -> list[str]:
    problems = []
    dirs = H.plugin_dirs(root)
    if not dirs:
        return ["plugins/ is empty; run python3 scripts/sync.py"]
    for pdir in dirs:
        manifest_path = pdir / ".claude-plugin" / "plugin.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"{manifest_path.relative_to(root)}: missing or invalid JSON ({exc})")
            continue
        if manifest.get("name") != pdir.name:
            problems.append(f"{manifest_path.relative_to(root)}: name {manifest.get('name')!r} != directory {pdir.name!r}")
        if not H.skill_dirs(pdir):
            problems.append(f"plugins/{pdir.name}: no skills/*/SKILL.md")
        skills_dir = pdir / "skills"
        if skills_dir.is_dir():
            for d in skills_dir.iterdir():
                if d.is_dir() and not (d / "SKILL.md").is_file():
                    problems.append(f"plugins/{pdir.name}/skills/{d.name}: no SKILL.md")
    return problems


PLAIN_SCALAR_TRAPS = (": ", " #")


def strict_yaml_problems(text: str) -> list[str]:
    """Return problems a strict YAML reader would raise on top-level scalars in the front matter.

    Claude Code reads SKILL.md front matter leniently, but the skills CLI and other
    strict parsers reject an unquoted value that contains ": " or " #", or a quote
    that is never closed, and then skip the skill.
    """
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return []
    end = text.find("\n---", 4)
    block = text[4:end] if end != -1 else text[4:]
    out: list[str] = []
    for n, line in enumerate(block.split("\n"), start=2):
        if not line.strip() or line[0] in " \t" or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if not value or value in (">", ">-", "|", "|-", ">+", "|+"):
            continue
        if value[0] in "\"'":
            q = value[0]
            body = value[1:]
            closed = False
            i = 0
            while i < len(body):
                c = body[i]
                if q == '"' and c == "\\":
                    i += 2
                    continue
                if c == q:
                    if q == "'" and body[i + 1:i + 2] == "'":
                        i += 2
                        continue
                    closed = True
                    if body[i + 1:].strip() not in ("", "#") and not body[i + 1:].strip().startswith("#"):
                        out.append(f"line {n}: text after the closing quote of {key.strip()!r}")
                    break
                i += 1
            if not closed:
                out.append(f"line {n}: unclosed quote in {key.strip()!r}")
            continue
        for trap in PLAIN_SCALAR_TRAPS:
            if trap in value:
                out.append(f"line {n}: unquoted {key.strip()!r} contains {trap!r}; wrap the value in double quotes")
                break
        else:
            if value.endswith(":"):
                out.append(f"line {n}: unquoted {key.strip()!r} ends with ':'; wrap the value in double quotes")
    return out


def check_frontmatter(root: Path, allow_duplicates: set[str]) -> tuple[list[str], list[str], list[str]]:
    problems: list[str] = []
    dup_problems: list[str] = []
    notes: list[str] = []
    seen: dict[str, list[str]] = {}
    for pdir in H.plugin_dirs(root):
        for sdir in H.skill_dirs(pdir):
            rel = f"plugins/{pdir.name}/skills/{sdir.name}/SKILL.md"
            raw = (sdir / "SKILL.md").read_text(encoding="utf-8")
            fields, _, errors = H.parse_frontmatter(raw)
            problems += [f"{rel}: {err}" for err in errors]
            problems += [f"{rel}: {err} (strict YAML)" for err in strict_yaml_problems(raw)]
            name = fields.get("name")
            if not isinstance(name, str) or not name:
                problems.append(f"{rel}: missing name")
            else:
                if len(name) > 64:
                    problems.append(f"{rel}: name longer than 64 characters")
                if not H.NAME_RE.match(name):
                    problems.append(f"{rel}: name {name!r} must be lowercase letters, digits and single hyphens")
                if name != sdir.name:
                    problems.append(f"{rel}: name {name!r} does not equal its directory {sdir.name!r}")
                seen.setdefault(name, []).append(pdir.name)
            desc = fields.get("description")
            if not isinstance(desc, str) or not desc.strip():
                problems.append(f"{rel}: missing or empty description")
            elif len(desc) > 1024:
                problems.append(f"{rel}: description is {len(desc)} characters (limit 1024)")
            unknown = sorted(set(fields) - H.ALLOWED_FRONTMATTER)
            if unknown:
                problems.append(f"{rel}: unknown front matter keys {unknown}")
    for name, plugins in sorted(seen.items()):
        if len(plugins) > 1:
            msg = f"skill name {name!r} is used by plugins {plugins}; names must be unique across the repository"
            if name in allow_duplicates:
                notes.append(f"allowed duplicate: {msg}")
            else:
                dup_problems.append(msg)
    for name in sorted(allow_duplicates - {n for n, p in seen.items() if len(p) > 1}):
        notes.append(f"--allow-duplicate {name} is not needed (no duplicate found)")
    return problems, dup_problems, notes


def check_marketplace(root: Path) -> list[str]:
    path = root / ".claude-plugin" / "marketplace.json"
    data = H.load_json(path)
    if data is None:
        return [".claude-plugin/marketplace.json is missing"]
    problems = []
    if data.get("name") != H.MARKETPLACE_NAME:
        problems.append(f"marketplace name {data.get('name')!r} should be {H.MARKETPLACE_NAME!r}")
    if not data.get("owner", {}).get("name"):
        problems.append("marketplace owner.name is missing")
    entries = data.get("plugins", [])
    names = [p.get("name") for p in entries]
    dirs = [p.name for p in H.plugin_dirs(root)]
    if sorted(names) != sorted(dirs):
        problems.append(f"marketplace plugins {sorted(names)} != plugin directories {sorted(dirs)}")
    if len(set(names)) != len(names):
        problems.append("marketplace lists a plugin twice")
    for entry in entries:
        name = entry.get("name")
        if entry.get("source") != f"./plugins/{name}":
            problems.append(f"{name}: source {entry.get('source')!r} should be './plugins/{name}'")
        manifest = H.load_json(root / "plugins" / str(name) / ".claude-plugin" / "plugin.json", {}) or {}
        if manifest and manifest.get("name") != name:
            problems.append(f"{name}: marketplace name differs from plugin.json name {manifest.get('name')!r}")
        for key in ("description", "version", "repository", "license"):
            if not entry.get(key):
                problems.append(f"{name}: marketplace entry has no {key}")
    return problems


def check_sources(root: Path) -> list[str]:
    data = H.load_json(root / "SOURCES.json")
    if data is None:
        return ["SOURCES.json is missing"]
    problems = []
    plugins = data.get("plugins", {})
    dirs = {p.name: p for p in H.plugin_dirs(root)}
    if sorted(plugins) != sorted(dirs):
        problems.append(f"SOURCES.json plugins {sorted(plugins)} != plugin directories {sorted(dirs)}")
    for name, rec in sorted(plugins.items()):
        for key in ("repo", "url", "path", "commit", "synced_at", "upstream_version", "content_sha256"):
            if not rec.get(key):
                problems.append(f"SOURCES.json {name}: missing {key}")
        if name in dirs and rec.get("content_sha256") != H.tree_hash(dirs[name]):
            problems.append(f"plugins/{name} differs from the synced content recorded in SOURCES.json "
                            f"(edit skills in {rec.get('repo')}, then run scripts/sync.py)")
        manifest = H.load_json(dirs[name] / ".claude-plugin" / "plugin.json", {}) if name in dirs else {}
        if manifest and manifest.get("version") != rec.get("upstream_version"):
            problems.append(f"SOURCES.json {name}: upstream_version != plugin.json version")
    return problems


def check_generated(root: Path) -> tuple[list[str], list[str]]:
    expected = H.build_catalog(root)
    actual = H.load_json(root / "catalog.json")
    catalog_problems = []
    if actual != expected:
        catalog_problems.append("catalog.json does not match the plugins/ tree; run python3 scripts/sync.py --offline")
    readme_problems = []
    readme = (root / "README.md").read_text(encoding="utf-8")
    try:
        if H.render_readme(readme, expected) != readme:
            readme_problems.append("README catalog block or count badge does not match catalog.json; "
                                   "run python3 scripts/sync.py --offline")
    except ValueError as exc:
        readme_problems.append(str(exc))
    return catalog_problems, readme_problems


def check_quality_report(root: Path) -> list[str]:
    path = root / H.QUALITY_REPORT
    want = H.render_quality_report(H.quality_findings(root))
    if not path.is_file() or path.read_text(encoding="utf-8") != want:
        return [f"{H.QUALITY_REPORT} is missing or stale; run python3 scripts/sync.py --offline"]
    return []


NUMBER_WORDS = {"ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
                "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20}
COUNT_PHRASE_RE = re.compile(r"(?<![\w.%-])(\d+|" + "|".join(NUMBER_WORDS) + r")\s+(skills|plugins)\b", re.I)
GENERATED_SPAN_RE = re.compile(r"<!--\s*(catalog|count-badge|" + "|".join(H.COUNT_SPANS) + r"):start\s*-->.*?<!--\s*\1:end\s*-->", re.S)


def hand_written_count_problems(root: Path) -> list[str]:
    """Hand-written "N skills" or "N plugins" phrases that disagree with catalog.json."""
    catalog = H.load_json(root / "catalog.json") or {}
    counts = catalog.get("counts", {})
    sources: list[tuple[str, str]] = []
    readme = root / "README.md"
    if readme.is_file():
        sources.append(("README.md", GENERATED_SPAN_RE.sub("", readme.read_text(encoding="utf-8"))))
    for page in sorted((root / "site" / "content").glob("*.md")):
        sources.append((page.relative_to(root).as_posix(), page.read_text(encoding="utf-8")))
    changelog = root / "CHANGELOG.md"
    if changelog.is_file():
        text = changelog.read_text(encoding="utf-8")
        m = re.search(r"^## \[Unreleased\].*?(?=^## \[|\Z)", text, re.S | re.M)
        if m:
            sources.append(("CHANGELOG.md (Unreleased)", m.group(0)))
    problems = []
    for name, text in sources:
        for line_no, line in enumerate(text.split("\n"), start=1):
            for m in COUNT_PHRASE_RE.finditer(line):
                raw = m.group(1).lower()
                n = NUMBER_WORDS.get(raw) or int(raw)
                kind = m.group(2).lower()
                if n != counts.get(kind):
                    problems.append(f"{name}:{line_no}: says {m.group(0)!r} but catalog.json has {counts.get(kind)} {kind}; "
                                    "use a generated count span or a {{" + kind + "}} template variable")
    return problems


def check_quality(root: Path, strict: bool) -> tuple[list[tuple[str, list[str], list[str]]], dict]:
    """Soft quality rules as notes, or as problems when strict. Plus cross-plugin pointer counts."""
    findings = H.quality_findings(root)
    out = []
    for key, label in H.QUALITY_RULES:
        paths = findings[key]
        line = f"{len(paths)} file(s)" + (f"; first five: {', '.join(paths[:5])}" if paths else "")
        name = f"quality: {label}"
        if strict:
            out.append((name, [f"{p}: {label}" for p in paths], []))
        else:
            out.append((name, [], [line + f" (full list in {H.QUALITY_REPORT})"] if paths else [line]))
    cross = findings["cross"]
    summary = ", ".join(f"{p} {len(v)}" for p, v in sorted(cross.items())) or "none"
    out.append(("cross-plugin pointers", [],
                [f"{sum(len(v) for v in cross.values())} across plugins ({summary}); full list in {H.QUALITY_REPORT}"]))
    return out, findings


def house_rules(root: Path, files: list[str]) -> list[tuple[str, list[str], list[str]]]:
    em, models, secrets = [], [], []
    vendored_em = vendored_models = 0
    vendored_secrets: list[str] = []
    compiled = [(label, re.compile(rx)) for label, rx in SECRET_PATTERNS]
    for rel in files:
        text = read_text(root / rel)
        if text is None:
            continue
        vendored = rel.startswith(VENDORED)
        n_em = text.count(EM_DASH)
        if n_em:
            if vendored:
                vendored_em += n_em
            else:
                em.append(f"{rel}: {n_em} em-dash(es)")
        for word in MODEL_NAMES:
            n = text.count(word)
            if n:
                if vendored:
                    vendored_models += n
                else:
                    models.append(f"{rel}: model name {word!r} ({n})")
        for label, rx in compiled:
            for m in rx.finditer(text):
                if m.group(0) in ALLOWED_SECRET_LITERALS:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                msg = f"{rel}:{line}: {label}"
                (vendored_secrets if vendored else secrets).append(msg)
    return [
        ("no em-dashes in repo-authored files", em, [f"vendored or generated content has {vendored_em} (exempt)"]),
        ("no model names in repo-authored files", models,
         [f"vendored or generated content has {vendored_models} mention(s) (exempt; for example incident names)"]),
        ("no secret-shaped strings", secrets,
         [f"vendored: {v} (upstream test placeholder; review in the source repo)" for v in sorted(set(vendored_secrets))]),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--allow-duplicate", action="append", default=[], metavar="NAME",
                    help="tolerate this duplicate skill name (local use only, never in CI)")
    ap.add_argument("--strict-quality", action="store_true",
                    help="report the soft quality rules (long or incomplete descriptions, missing Limits) as errors")
    ap.add_argument("--root", type=Path, default=H.ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    report = Report()
    report.add("plugin structure", check_structure(root))
    fm, dups, notes = check_frontmatter(root, set(args.allow_duplicate))
    report.add("SKILL.md front matter", fm)
    report.add("skill names unique across plugins", dups, notes)
    report.add("marketplace lists exactly the plugin directories", check_marketplace(root))
    report.add("SOURCES.json matches plugins/", check_sources(root))
    cat, readme = check_generated(root)
    report.add("catalog.json matches the tree", cat)
    report.add("README catalog block matches catalog.json", readme)
    report.add("quality report matches plugins/", check_quality_report(root))
    report.add("hand-written skill and plugin counts match catalog.json", hand_written_count_problems(root))
    for name, problems, extra in check_quality(root, args.strict_quality)[0]:
        report.add(name, problems, extra)
    for name, problems, extra in house_rules(root, repo_files(root)):
        report.add(name, problems, extra)
    return report.print()


if __name__ == "__main__":
    sys.exit(main())
