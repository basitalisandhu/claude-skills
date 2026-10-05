"""Shared helpers for sync.py, validate.py and site/build.py. Standard library only.

Everything here is offline and deterministic: it reads the plugins/ tree and the
generated JSON files and returns the same bytes for the same inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGINS_DIR = "plugins"

OWNER = "basitalisandhu"
OWNER_NAME = "Muhammad Basit Ali"
OWNER_URL = f"https://github.com/{OWNER}"
REPO_NAME = "claude-skills"
REPO_URL = f"https://github.com/{OWNER}/{REPO_NAME}"
SITE_URL = f"https://{OWNER}.github.io/{REPO_NAME}/"
SITE_PATH = f"/{REPO_NAME}/"
MARKETPLACE_NAME = "claude-skills"
HUB_VERSION = "0.1.0"
HUB_DESCRIPTION = (
    "Every Claude Code skill maintained by Muhammad Basit Ali, in one marketplace: "
    "security, AWS, Microsoft 365, compliance evidence, GitHub, repository engineering, "
    "everyday development and Mac maintenance. Synced daily from the source repositories."
)

# The source repositories, in sync order. Each one publishes its plugins at plugins/<plugin>/.
SOURCE_REPOS = [
    "agent-security-skills",
    "aws-security-skills",
    "claude-dev-skills",
    "compliance-evidence-skills",
    "github-manager-skills",
    "m365-governance-skills",
    "mac-maintenance-skills",
    "repo-engineering-skills",
    "ways-of-working-skills",
]

# Files and directories never copied from a source plugin.
EXCLUDE_DIRS = {"node_modules", "dist", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}
EXCLUDE_FILES = {".DS_Store"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")

ALLOWED_FRONTMATTER = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LIMITS_HEADING_RE = re.compile(r"^(limits|what it does not do|what this skill does not do|out of scope|non-goals)$", re.I)

CATALOG_START = "<!-- catalog:start -->"
CATALOG_END = "<!-- catalog:end -->"
BADGE_START = "<!-- count-badge:start -->"
BADGE_END = "<!-- count-badge:end -->"
# Hand-written counts in the README are generated spans: <!-- NAME:start -->text<!-- NAME:end -->.
COUNT_SPANS = ("counts", "counts-scripts", "counts-limits")
QUALITY_REPORT = "reports/quality.md"
MAX_DESCRIPTION_SOFT = 600


# ---------------------------------------------------------------- JSON and files

def dumps(obj: object) -> str:
    """Deterministic JSON text with a trailing newline."""
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def load_json(path: Path, default: object = None) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def excluded(rel_parts: tuple[str, ...]) -> bool:
    if any(p in EXCLUDE_DIRS for p in rel_parts[:-1]):
        return True
    name = rel_parts[-1]
    return name in EXCLUDE_FILES or name.endswith(EXCLUDE_SUFFIXES) or name in EXCLUDE_DIRS


def tree_files(base: Path) -> list[Path]:
    """Every file under base that sync copies, sorted, as paths relative to base."""
    out = []
    for path in base.rglob("*"):
        rel = path.relative_to(base)
        if path.is_file() and not path.is_symlink() and not excluded(rel.parts):
            out.append(rel)
    return sorted(out, key=lambda p: p.as_posix())


def tree_hash(base: Path) -> str:
    """SHA-256 over the sorted (path, content) pairs of a plugin directory."""
    h = hashlib.sha256()
    for rel in tree_files(base):
        h.update(rel.as_posix().encode("utf-8") + b"\0")
        h.update(hashlib.sha256((base / rel).read_bytes()).hexdigest().encode("ascii") + b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------- SKILL.md parsing

def parse_frontmatter(text: str) -> tuple[dict, str, list[str]]:
    """Parse the YAML front matter subset used by SKILL.md files.

    Supports `key: value` scalars, quoted scalars, folded or literal blocks (`>`, `|`)
    and one level of nested mapping (metadata). Returns (fields, body, errors).
    """
    errors: list[str] = []
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return {}, text, ["no front matter (file must start with ---)"]
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text, ["front matter is not closed with ---"]
    block = text[4:end]
    body = text[end + 4:].lstrip("\n")
    fields: dict = {}
    lines = block.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line[0] in " \t":
            errors.append(f"unexpected indented line in front matter: {line.strip()[:40]}")
            i += 1
            continue
        if ":" not in line:
            errors.append(f"front matter line is not key: value: {line[:40]}")
            i += 1
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        i += 1
        if value in (">", ">-", "|", "|-", ">+", "|+"):
            parts = []
            while i < len(lines) and (not lines[i].strip() or lines[i][0] in " \t"):
                parts.append(lines[i].strip())
                i += 1
            joiner = " " if value.startswith(">") else "\n"
            fields[key] = joiner.join(p for p in parts if p).strip()
        elif value == "":
            sub: dict = {}
            items: list = []
            while i < len(lines) and (not lines[i].strip() or lines[i][0] in " \t"):
                s = lines[i].strip()
                i += 1
                if not s:
                    continue
                if s.startswith("- "):
                    items.append(_scalar(s[2:]))
                elif ":" in s:
                    k, v = s.split(":", 1)
                    sub[k.strip()] = _scalar(v.strip())
            fields[key] = items if items and not sub else sub
        else:
            fields[key] = _scalar(value)
    return fields, body, errors


def _scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        inner = value[1:-1]
        return inner.replace("''", "'") if value[0] == "'" else inner.replace('\\"', '"')
    return value


def sections(body: str) -> list[tuple[str, str]]:
    """Split a Markdown body into (level-2 heading, section text) pairs, ignoring fenced code."""
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    in_fence = False
    for line in body.split("\n"):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        if not in_fence and line.startswith("## "):
            current = (line[3:].strip(), [])
            out.append(current)
            continue
        if current is not None:
            current[1].append(line)
    return [(h, "\n".join(t).strip()) for h, t in out]


def limits_section(body: str) -> tuple[str, str] | None:
    """The section that says what a skill does not do, if it has one."""
    for heading, text in sections(body):
        if LIMITS_HEADING_RE.match(heading):
            return heading, text
    return None


def first_heading(body: str) -> str:
    for line in body.split("\n"):
        if line.startswith("# "):
            return line[2:].strip()
    return ""


# ---------------------------------------------------------------- discovery and catalog

def plugin_dirs(root: Path = ROOT) -> list[Path]:
    base = root / PLUGINS_DIR
    if not base.is_dir():
        return []
    return sorted((p for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")), key=lambda p: p.name)


def skill_dirs(plugin: Path) -> list[Path]:
    base = plugin / "skills"
    if not base.is_dir():
        return []
    return sorted((p for p in base.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()), key=lambda p: p.name)


def install_names(pairs: list[tuple[str, str]], prefix_all: bool = False) -> dict[tuple[str, str], str]:
    """Map (plugin, skill) to its install directory name.

    Pairs are taken in sorted order. The first skill with a given name keeps the plain name;
    a later one with the same name becomes <plugin>-<skill>. prefix_all names every skill
    <plugin>-<skill>. Same rule as install.py.
    """
    out: dict[tuple[str, str], str] = {}
    taken: set[str] = set()
    for plugin, skill in sorted(pairs):
        name = f"{plugin}-{skill}" if prefix_all or skill in taken else skill
        taken.add(skill)
        taken.add(name)
        out[(plugin, skill)] = name
    return out


def count_files(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for rel in tree_files(path))


def build_catalog(root: Path = ROOT) -> dict:
    """catalog.json content, computed from plugins/ and SOURCES.json."""
    sources = load_json(root / "SOURCES.json", {}) or {}
    src_plugins = sources.get("plugins", {})
    plugins_out = []
    skills_out = []
    pairs = []
    for pdir in plugin_dirs(root):
        for sdir in skill_dirs(pdir):
            pairs.append((pdir.name, sdir.name))
    names = install_names(pairs)
    total_scripts = 0
    for pdir in plugin_dirs(root):
        manifest = load_json(pdir / ".claude-plugin" / "plugin.json", {}) or {}
        src = src_plugins.get(pdir.name, {})
        repo = src.get("repo", "")
        repo_url = f"{OWNER_URL}/{repo}" if repo else ""
        src_path = src.get("path", f"plugins/{pdir.name}")
        ships = {
            "hooks": (pdir / "hooks").is_dir(),
            "commands": (pdir / "commands").is_dir(),
            "agents": (pdir / "agents").is_dir(),
            "mcp": (pdir / ".mcp.json").is_file(),
        }
        skill_names = []
        for sdir in skill_dirs(pdir):
            fields, body, _ = parse_frontmatter((sdir / "SKILL.md").read_text(encoding="utf-8"))
            scripts = count_files(sdir / "scripts")
            total_scripts += scripts
            skill_names.append(sdir.name)
            skills_out.append({
                "name": str(fields.get("name", sdir.name)),
                "install_name": names[(pdir.name, sdir.name)],
                "plugin": pdir.name,
                "description": str(fields.get("description", "")),
                "license": str(fields.get("license", manifest.get("license", ""))),
                "source_repo": repo_url,
                "path": f"plugins/{pdir.name}/skills/{sdir.name}/SKILL.md",
                "source_path": f"{src_path}/skills/{sdir.name}/SKILL.md",
                "scripts": scripts,
                "has_limits_section": limits_section(body) is not None,
                "plugin_ships": ships,
            })
        plugins_out.append({
            "name": pdir.name,
            "display_name": manifest.get("displayName", pdir.name),
            "version": manifest.get("version", ""),
            "description": manifest.get("description", ""),
            "license": manifest.get("license", ""),
            "source_repo": repo_url,
            "source_path": src_path,
            "skills": skill_names,
            "ships": ships,
        })
    return {
        "name": REPO_NAME,
        "note": "Generated by scripts/sync.py from plugins/ and SOURCES.json. Do not edit by hand.",
        "counts": {"plugins": len(plugins_out), "skills": len(skills_out), "script_files": total_scripts},
        "plugins": plugins_out,
        "skills": skills_out,
    }


# ---------------------------------------------------------------- README blocks

SHIP_LABELS = {"hooks": "hooks", "commands": "commands", "agents": "agents", "mcp": "an MCP server"}


def ships_text(ships: dict) -> str:
    """'hooks, commands, agents and an MCP server' for the plugin-level parts a plugin ships."""
    parts = [SHIP_LABELS[k] for k in SHIP_LABELS if ships.get(k)]
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1] if parts else ""


def site_skill_url(plugin: str, skill: str) -> str:
    return f"{SITE_URL}plugins/{plugin}/{skill}/"


def site_plugin_url(plugin: str) -> str:
    return f"{SITE_URL}plugins/{plugin}/"


def md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def one_line(description: str) -> str:
    """First sentence of a description, for tables."""
    m = re.match(r"(.+?(?<!\.[a-z])[.!?])(\s|$)", description)
    return (m.group(1) if m else description).strip()


def render_catalog_block(catalog: dict) -> str:
    c = catalog["counts"]
    out = [
        CATALOG_START,
        "",
        f"**{c['skills']} skills in {c['plugins']} plugins.** "
        f"{c['script_files']} bundled script files. Generated from `catalog.json` by `scripts/sync.py`.",
        "",
    ]
    by_plugin: dict[str, list[dict]] = {}
    for s in catalog["skills"]:
        by_plugin.setdefault(s["plugin"], []).append(s)
    for p in catalog["plugins"]:
        repo = p["source_repo"]
        repo_name = repo.rsplit("/", 1)[-1] if repo else "unknown"
        extras = ships_text(p["ships"])
        out.append(f"### {p['name']}")
        out.append("")
        line = (f"Version {p['version']}. Source: [{repo_name}]({repo}). "
                f"Install: `/plugin install {p['name']}@{MARKETPLACE_NAME}`.")
        if extras:
            line += f" Also ships plugin-level {extras} (marketplace route only)."
        out.append(line)
        out.append("")
        out.append("| Skill | What it does | Scripts | Links |")
        out.append("| --- | --- | --- | --- |")
        for s in by_plugin.get(p["name"], []):
            src = f"{repo}/blob/main/{s['source_path']}" if repo else ""
            name = s["name"] if s["install_name"] == s["name"] else f"{s['name']} (installs as `{s['install_name']}`)"
            out.append(
                f"| {md_cell(name)} | {md_cell(one_line(s['description']))} | "
                f"{'yes' if s['scripts'] else 'no'} | "
                f"[page]({site_skill_url(s['plugin'], s['name'])}) · [source]({src}) |"
            )
        out.append("")
    out.append(CATALOG_END)
    return "\n".join(out)


def render_badge_block(catalog: dict) -> str:
    n = catalog["counts"]["skills"]
    p = catalog["counts"]["plugins"]
    return (f"{BADGE_START}[![{n} skills in {p} plugins](https://img.shields.io/badge/skills-{n}%20in%20{p}%20plugins-2E6BFF)]"
            f"(#catalog){BADGE_END}")


def replace_block(text: str, start: str, end: str, new_block: str) -> str:
    a = text.find(start)
    b = text.find(end)
    if a == -1 or b == -1 or b < a:
        raise ValueError(f"markers {start} ... {end} not found in README.md")
    return text[:a] + new_block + text[b + len(end):]


def render_count_span(name: str, catalog: dict) -> str:
    """Text between <!-- NAME:start --> and <!-- NAME:end -->, computed from catalog.json."""
    n = catalog["counts"]["skills"]
    p = catalog["counts"]["plugins"]
    skills = catalog["skills"]
    if name == "counts":
        repos = len({pl["source_repo"] for pl in catalog["plugins"]})
        return f"**{n} skills in {p} plugins, from {repos} source repositories.**"
    if name == "counts-scripts":
        return f"{sum(1 for s in skills if s['scripts'])} of the {n} skills bundle scripts."
    if name == "counts-limits":
        have = sum(1 for s in skills if s["has_limits_section"])
        return (f'{have} of the {n} SKILL.md files have a "Limits" section that says what the skill does not do. '
                f'The site shows it as "What it does not do". The other {n - have} do not have that section yet.')
    raise KeyError(name)


def render_readme(readme: str, catalog: dict) -> str:
    readme = replace_block(readme, CATALOG_START, CATALOG_END, render_catalog_block(catalog))
    readme = replace_block(readme, BADGE_START, BADGE_END, render_badge_block(catalog))
    for name in COUNT_SPANS:
        start, end = f"<!-- {name}:start -->", f"<!-- {name}:end -->"
        readme = replace_block(readme, start, end, start + render_count_span(name, catalog) + end)
    return readme


def render_template(text: str, catalog: dict) -> str:
    """Fill {{skills}}, {{plugins}} and {{repos}} in hand-written pages from catalog.json."""
    c = catalog["counts"]
    repos = len({pl["source_repo"] for pl in catalog["plugins"]})
    return (text.replace("{{skills}}", str(c["skills"])).replace("{{plugins}}", str(c["plugins"]))
            .replace("{{repos}}", str(repos)))


# ---------------------------------------------------------------- quality notes

def quality_findings(root: Path = ROOT) -> dict:
    """Soft quality findings over plugins/: lists of SKILL.md paths per rule and cross-plugin pointers."""
    out: dict = {"long_description": [], "no_use": [], "no_not_for": [], "no_limits": [], "cross": {}}
    skills: list[tuple[str, str, str, str]] = []  # plugin, name, rel path, text
    for pdir in plugin_dirs(root):
        for sdir in skill_dirs(pdir):
            rel = f"plugins/{pdir.name}/skills/{sdir.name}/SKILL.md"
            skills.append((pdir.name, sdir.name, rel, (sdir / "SKILL.md").read_text(encoding="utf-8")))
    owners: dict[str, set[str]] = {}
    for plugin, name, _, _ in skills:
        owners.setdefault(name, set()).add(plugin)
    for plugin, name, rel, text in skills:
        fields, body, _ = parse_frontmatter(text)
        desc = fields.get("description")
        desc = desc if isinstance(desc, str) else ""
        if len(desc) > MAX_DESCRIPTION_SOFT:
            out["long_description"].append(rel)
        if "Use " not in desc:
            out["no_use"].append(rel)
        if "Not for" not in desc:
            out["no_not_for"].append(rel)
        if limits_section(body) is None:
            out["no_limits"].append(rel)
        for other, plugins in sorted(owners.items()):
            if other == name or plugin in plugins:
                continue
            if re.search(r"(?<![\w-])" + re.escape(other) + r"(?![\w-])", text):
                out["cross"].setdefault(plugin, []).append(f"{plugin}/{name} -> {sorted(plugins)[0]}/{other}")
    for key in ("long_description", "no_use", "no_not_for", "no_limits"):
        out[key].sort()
    for lst in out["cross"].values():
        lst.sort()
    return out


QUALITY_RULES = [
    ("long_description", f"description longer than {MAX_DESCRIPTION_SOFT} characters"),
    ("no_use", 'description has no "Use " sentence'),
    ("no_not_for", 'description has no "Not for" boundary'),
    ("no_limits", "SKILL.md has no Limits section"),
]


def render_quality_report(findings: dict) -> str:
    lines = ["# Quality notes", "",
             "Generated by `scripts/sync.py` from `plugins/`; do not edit by hand. These are notes, not errors, "
             "until the source packs are fixed; `python3 scripts/validate.py --strict-quality` turns them into errors.", ""]
    for key, label in QUALITY_RULES:
        paths = findings[key]
        lines += [f"## {label}: {len(paths)}", ""]
        lines += [f"- `{p}`" for p in paths] or ["None."]
        lines.append("")
    cross = findings["cross"]
    total = sum(len(v) for v in cross.values())
    lines += [f"## Skills that point at a skill in another plugin: {total}", "",
              "A single-plugin install leaves these names dangling. Install the sibling plugin, or use "
              "`install.py --only` with several plugins.", ""]
    for plugin in sorted(cross):
        lines += [f"### {plugin} ({len(cross[plugin])})", ""] + [f"- `{x}`" for x in cross[plugin]] + [""]
    if not cross:
        lines += ["None.", ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def quality_summary(findings: dict) -> list[str]:
    lines = []
    for key, label in QUALITY_RULES:
        paths = findings[key]
        lines.append(f"{label}: {len(paths)}" + (f"; first five: {', '.join(paths[:5])}" if paths else ""))
    return lines
