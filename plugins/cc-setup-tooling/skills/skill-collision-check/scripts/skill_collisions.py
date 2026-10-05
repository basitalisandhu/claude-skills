#!/usr/bin/env python3
"""skill_collisions.py: find skills that share a name, shadow each other, or overlap heavily in description.

Input folders (each optional; give at least one):
  --managed DIR        an organisation-managed skills folder (DIR/<skill>/SKILL.md)
  --home DIR           a home folder: DIR/.claude/skills, DIR/.claude/commands, and the plugins root
                       DIR/.claude/plugins unless --plugins-root is given
  --project DIR        a project: DIR/.claude/skills and DIR/.claude/commands
  --plugins-root DIR   installed plugins: installed_plugins.json names each plugin's installPath; without it every
                       cache/<marketplace>/<plugin>/<version>/ folder is read. A plugin's skills are skills/<name>/
                       plus any folder its .claude-plugin/plugin.json lists under "skills"
  --extra LABEL=DIR    any other folder of skills, such as a copy install (repeatable)
  --builtin-names FILE names the host already uses, one per line (for example saved from /help)

Precedence used (from the Claude Code skills docs): when skills share a name across levels, managed wins over
personal, and personal over project; plugin skills are namespaced as plugin:skill, so they do not shadow other levels;
when a skill and a command in .claude/commands share a name, the skill wins.

Findings:
  shadowed            the same name at two or more of managed, personal and project; the winner is named
  command-vs-skill    a command file with the same name as a skill; the skill wins
  plugin-duplicate    the same skill name in two plugins, or in a plugin and a standalone folder; both load, under
                      different names, and the model sees two similar entries
  duplicate-in-folder two skill folders in one location whose front matter gives the same name
  builtin-name        a skill name that is in --builtin-names
  description-overlap two skills whose descriptions have a word cosine similarity at or above --overlap (default
                      0.5; lowercased words without stop words, simple suffixes stripped)

Exit codes: 0 no findings, 1 at least one finding, 2 bad input (no folder given, a folder or file missing).
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _skillmd  # noqa: E402

RANK = {"managed": 0, "personal": 1, "project": 2}
STOP = set(
    "a an and are as at be by for from has in into is it its of on or that the this to with when use not your you "
    "which who what can do does also any all such than then them they their only via per each one two".split()
)


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def stem(w: str) -> str:
    for suf in ("ing", "ies", "es", "ed", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf) and not w.endswith("ss"):
            return w[: -len(suf)] + ("y" if suf == "ies" else "")
    return w


def bag(text: str) -> Counter:
    return Counter(stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 2)


def cosine(a: Counter, b: Counter) -> float:
    dot = sum(a[k] * b[k] for k in a.keys() & b.keys())
    na, nb = math.sqrt(sum(v * v for v in a.values())), math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def skill_entries(folder: Path, level: str, source: str) -> list[dict]:
    out = []
    if not folder.is_dir():
        return out
    for d in sorted(p for p in folder.iterdir() if p.is_dir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        fm = _skillmd.parse(_skillmd.read_text(f))
        out.append(
            {
                "name": fm.text("name") or d.name,
                "folder": d.name,
                "level": level,
                "source": source,
                "path": f.as_posix(),
                "description": fm.text("description"),
            }
        )
    return out


def command_entries(folder: Path, level: str) -> list[dict]:
    if not folder.is_dir():
        return []
    return [{"name": p.stem, "level": level, "path": p.as_posix()} for p in sorted(folder.glob("*.md")) if p.is_file()]


def plugin_dirs(root: Path) -> list[tuple[str, Path]]:
    index = root / "installed_plugins.json"
    out: list[tuple[str, Path]] = []
    if index.is_file():
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise InputError(f"{index}: invalid JSON: {exc}") from exc
        plugins = data.get("plugins", data) if isinstance(data, dict) else {}
        for key, installs in sorted(plugins.items()):
            for inst in installs if isinstance(installs, list) else [installs]:
                if isinstance(inst, dict) and inst.get("installPath"):
                    out.append((key.split("@")[0], Path(inst["installPath"])))
        return sorted(set(out))
    cache = root / "cache"
    if cache.is_dir():
        for version_dir in sorted(cache.glob("*/*/*")):
            if version_dir.is_dir():
                out.append((version_dir.parent.name, version_dir))
    return out


def plugin_skill_folders(plugin_root: Path) -> list[Path]:
    folders = [plugin_root / "skills"]
    manifest = plugin_root / ".claude-plugin" / "plugin.json"
    if manifest.is_file():
        try:
            extra = json.loads(manifest.read_text(encoding="utf-8")).get("skills")
        except (json.JSONDecodeError, AttributeError):
            extra = None
        for e in [extra] if isinstance(extra, str) else extra if isinstance(extra, list) else []:
            if isinstance(e, str):
                folders.append(plugin_root / e)
    return folders


def analyse(args: argparse.Namespace) -> dict:
    if not (args.managed or args.home or args.project or args.plugins_root or args.extra):
        raise InputError("give at least one of --managed, --home, --project, --plugins-root, --extra")
    for label, value in (("--managed", args.managed), ("--home", args.home), ("--project", args.project)):
        if value and not Path(value).is_dir():
            raise InputError(f"{label} {value}: not a folder")
    skills: list[dict] = []
    commands: list[dict] = []
    if args.managed:
        skills += skill_entries(Path(args.managed), "managed", "managed")
    if args.home:
        h = Path(args.home)
        skills += skill_entries(h / ".claude" / "skills", "personal", "personal")
        commands += command_entries(h / ".claude" / "commands", "personal")
    if args.project:
        p = Path(args.project)
        skills += skill_entries(p / ".claude" / "skills", "project", "project")
        commands += command_entries(p / ".claude" / "commands", "project")
    plugins_root = Path(args.plugins_root) if args.plugins_root else None
    if plugins_root is None and args.home:
        plugins_root = Path(args.home) / ".claude" / "plugins"
    if plugins_root is not None:
        if args.plugins_root and not plugins_root.is_dir():
            raise InputError(f"--plugins-root {plugins_root}: not a folder")
        for plugin, root in plugin_dirs(plugins_root) if plugins_root.is_dir() else []:
            for folder in plugin_skill_folders(root):
                skills += skill_entries(folder, "plugin", plugin)
    for spec in args.extra:
        label, _, folder = spec.partition("=") if "=" in spec else ("extra", "", spec)
        if not Path(folder).is_dir():
            raise InputError(f"--extra {folder}: not a folder")
        skills += skill_entries(Path(folder), "extra", label)
    builtins: set[str] = set()
    if args.builtin_names:
        path = Path(args.builtin_names)
        if not path.is_file():
            raise InputError(f"{path}: not found")
        builtins = {ln.strip().lstrip("/") for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}

    findings: list[dict] = []
    by_name: dict[str, list[dict]] = {}
    for s in skills:
        by_name.setdefault(s["name"], []).append(s)
    for name, group in sorted(by_name.items()):
        ranked = sorted((s for s in group if s["level"] in RANK), key=lambda s: RANK[s["level"]])
        if len({s["level"] for s in ranked}) > 1:
            findings.append(
                {
                    "rule": "shadowed",
                    "name": name,
                    "winner": f"{ranked[0]['level']} ({ranked[0]['path']})",
                    "paths": [s["path"] for s in ranked],
                    "detail": f"{ranked[0]['level']} wins; " + ", ".join(s["level"] for s in ranked[1:]) + " ignored",
                }
            )
        per_place: dict[tuple[str, str], list[dict]] = {}
        for s in group:
            per_place.setdefault((s["level"], s["source"]), []).append(s)
        for (_, source), same in sorted(per_place.items()):
            if len(same) > 1:
                findings.append(
                    {
                        "rule": "duplicate-in-folder",
                        "name": name,
                        "winner": "unclear",
                        "paths": [s["path"] for s in same],
                        "detail": f"{len(same)} folders in {source} give the name {name!r}",
                    }
                )
        plugin_sources = sorted({s["source"] for s in group if s["level"] == "plugin"})
        others = [s for s in group if s["level"] != "plugin"]
        if len(plugin_sources) > 1 or (plugin_sources and others):
            labels = [f"{p}:{name}" for p in plugin_sources] + [f"{s['level']} {name}" for s in others]
            findings.append(
                {
                    "rule": "plugin-duplicate",
                    "name": name,
                    "winner": "both load",
                    "paths": [s["path"] for s in group],
                    "detail": "listed as " + ", ".join(labels),
                }
            )
        if name in builtins:
            findings.append(
                {
                    "rule": "builtin-name",
                    "name": name,
                    "winner": "check /help",
                    "paths": [s["path"] for s in group],
                    "detail": "the host already uses this name",
                }
            )
    standalone = {s["name"]: s for s in sorted(skills, key=lambda s: RANK.get(s["level"], 9)) if s["level"] != "plugin"}
    for c in commands:
        if c["name"] in standalone:
            findings.append(
                {
                    "rule": "command-vs-skill",
                    "name": c["name"],
                    "winner": f"skill ({standalone[c['name']]['path']})",
                    "paths": [c["path"], standalone[c["name"]]["path"]],
                    "detail": f"{c['level']} command {c['path']} is hidden by the skill",
                }
            )
    bags = [(s, bag(s["description"])) for s in skills if s["description"]]
    for i in range(len(bags)):
        for j in range(i + 1, len(bags)):
            a, b = bags[i][0], bags[j][0]
            if a["name"] == b["name"]:
                continue
            sim = cosine(bags[i][1], bags[j][1])
            if sim >= args.overlap:
                findings.append(
                    {
                        "rule": "description-overlap",
                        "name": f"{a['name']} / {b['name']}",
                        "winner": "n/a",
                        "paths": [a["path"], b["path"]],
                        "detail": f"description similarity {sim:.2f}; add a boundary sentence to both",
                    }
                )
    findings.sort(key=lambda f: (f["rule"], f["name"]))
    return {
        "skills": len(skills),
        "commands": len(commands),
        "locations": sorted({f"{s['level']}:{s['source']}" for s in skills}),
        "overlap_threshold": args.overlap,
        "findings": findings,
    }


def render(rep: dict) -> str:
    out = ["# Skill collisions", ""]
    out.append(
        f"{rep['skills']} skill(s) and {rep['commands']} command(s) read from: "
        f"{', '.join(rep['locations']) or 'nothing'}. {len(rep['findings'])} finding(s)."
    )
    out += ["", "| Rule | Name | Wins | Detail |", "|---|---|---|---|"]
    for f in rep["findings"]:
        out.append(f"| {f['rule']} | {f['name']} | {f['winner']} | {f['detail']} |")
    if not rep["findings"]:
        out.append("| none | | | |")
    out += ["", "## Paths", ""]
    for f in rep["findings"]:
        out.append(f"- {f['rule']} {f['name']}: " + ", ".join(f"`{p}`" for p in f["paths"]))
    out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skill_collisions.py",
        description="Find skills that share a name, shadow each other or overlap in description across managed, "
        "personal, project, plugin and other folders, and say which one wins.",
        epilog="Exit codes: 0 no findings, 1 at least one finding, 2 bad input.",
    )
    p.add_argument("--managed", default=None, help="organisation-managed skills folder")
    p.add_argument("--home", default=None, help="home folder holding .claude/ (personal skills, commands, plugins)")
    p.add_argument("--project", default=None, help="project folder holding .claude/")
    p.add_argument("--plugins-root", default=None, help="plugins folder (default: <home>/.claude/plugins)")
    p.add_argument("--extra", action="append", default=[], help="LABEL=DIR, another folder of skills (repeatable)")
    p.add_argument("--builtin-names", default=None, help="file of names the host already uses, one per line")
    p.add_argument("--overlap", type=float, default=0.5, help="description similarity to report (default 0.5)")
    p.add_argument("--json", action="store_true", help="print the computed data as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rep = analyse(args)
    except InputError as exc:
        print(f"skill_collisions.py: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n" if args.json else render(rep)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
