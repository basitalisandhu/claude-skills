#!/usr/bin/env python3
"""Copy the skills in this repository into a Claude Code skills directory.

Standard library only. Python 3.10 or newer on macOS, Linux or Windows.

    python3 install.py --list                       # show plugins, skills and install names
    python3 install.py --user                       # every skill into ~/.claude/skills/
    python3 install.py --project                    # every skill into ./.claude/skills/ of the current directory
    python3 install.py --user --only aws-security   # one plugin (repeat --only for more)
    python3 install.py --user --skill devops/cron-doctor   # one skill (repeat for more)
    python3 install.py --user --dry-run             # show what would happen, write nothing
    python3 install.py --user --force               # also overwrite skill folders this script did not write
    python3 install.py --user --prefix              # install every skill as <plugin>-<skill>
    python3 install.py --user --uninstall           # remove exactly the files this script wrote

Name collisions: when two plugins have a skill with the same name, the first (in plugin
name order) installs under the plain name and the second as <plugin>-<skill>.

The target directory gets a .claude-skills-manifest.json listing every file this script
wrote. Updates and --uninstall only ever remove files listed there.

Plugin-level hooks, commands, agents and MCP servers are not copied: install the plugin
from the marketplace for those (/plugin install <plugin>@claude-skills).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

MANIFEST = ".claude-skills-manifest.json"
TOOL = "claude-skills install.py"
SKIP_DIRS = {"__pycache__", "node_modules", ".pytest_cache"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def discover(repo: Path) -> list[tuple[str, str, Path]]:
    """(plugin, skill, skill dir) for every plugins/<plugin>/skills/<skill>/SKILL.md, sorted."""
    out = []
    base = repo / "plugins"
    if not base.is_dir():
        return out
    for pdir in sorted(base.iterdir(), key=lambda p: p.name):
        skills = pdir / "skills"
        if not skills.is_dir():
            continue
        for sdir in sorted(skills.iterdir(), key=lambda p: p.name):
            if (sdir / "SKILL.md").is_file():
                out.append((pdir.name, sdir.name, sdir))
    return out


def plan_names(pairs: list[tuple[str, str]], prefix_all: bool) -> dict[tuple[str, str], str]:
    """First skill with a name keeps it; a later duplicate becomes <plugin>-<skill>."""
    names: dict[tuple[str, str], str] = {}
    taken: set[str] = set()
    for plugin, skill in sorted(pairs):
        name = f"{plugin}-{skill}" if prefix_all or skill in taken else skill
        taken.add(skill)
        taken.add(name)
        names[(plugin, skill)] = name
    return names


def skill_files(sdir: Path) -> list[Path]:
    files = []
    for path in sdir.rglob("*"):
        rel = path.relative_to(sdir)
        if any(part in SKIP_DIRS for part in rel.parts) or path.name.endswith(SKIP_SUFFIXES) or path.name == ".DS_Store":
            continue
        if path.is_file() and not path.is_symlink():
            files.append(rel)
    return sorted(files, key=lambda p: p.as_posix())


def load_manifest(target: Path) -> dict:
    path = target / MANIFEST
    if not path.is_file():
        return {"tool": TOOL, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"error: {path} is not valid JSON ({exc}); fix or remove it by hand") from exc
    data.setdefault("entries", {})
    return data


def save_manifest(target: Path, data: dict) -> None:
    path = target / MANIFEST
    if not data["entries"]:
        if path.exists():
            path.unlink()
        return
    data["tool"] = TOOL
    data["entries"] = {k: data["entries"][k] for k in sorted(data["entries"])}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def remove_files(base: Path, rels: list[str], dry_run: bool) -> int:
    """Remove the listed files under base, then any directories left empty. Returns files removed."""
    removed = 0
    for rel in rels:
        path = base / Path(rel)
        if path.is_file():
            if not dry_run:
                path.unlink()
            removed += 1
    if not dry_run:
        dirs = sorted({(base / Path(rel)).parent for rel in rels} | {base}, key=lambda p: len(p.parts), reverse=True)
        for d in dirs:
            while d != base.parent and d.is_dir() and not any(d.iterdir()):
                d.rmdir()
                d = d.parent
    return removed


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_target(args: argparse.Namespace) -> Path:
    if args.target:
        return Path(args.target).expanduser().resolve()
    if args.user:
        return (Path.home() / ".claude" / "skills").resolve()
    return (Path.cwd() / ".claude" / "skills").resolve()


def select(found, only: list[str], skills: list[str]):
    plugins = sorted({p for p, _, _ in found})
    for name in only:
        if name not in plugins:
            raise SystemExit(f"error: unknown plugin {name!r}. Plugins: {', '.join(plugins)}")
    wanted = []
    for item in skills:
        matches = [(p, s) for p, s, _ in found if item in (s, f"{p}/{s}")]
        if not matches:
            raise SystemExit(f"error: unknown skill {item!r}. Use plugin/skill, for example devops/cron-doctor")
        if len(matches) > 1:
            raise SystemExit(f"error: {item!r} is in more than one plugin; use one of "
                             + ", ".join(f"{p}/{s}" for p, s in matches))
        wanted.append(matches[0])
    out = []
    for p, s, d in found:
        if (not only and not skills) or p in only or (p, s) in wanted:
            out.append((p, s, d))
    return out


def cmd_list(found, names) -> int:
    current = None
    for plugin, skill, _ in found:
        if plugin != current:
            current = plugin
            print(f"{plugin}")
        name = names[(plugin, skill)]
        note = f"  (installs as {name})" if name != skill else ""
        print(f"  {skill}{note}")
    print(f"{len(found)} skills in {len({p for p, _, _ in found})} plugins")
    return 0


def cmd_install(found, names, target: Path, args) -> int:
    manifest = load_manifest(target)
    entries = manifest["entries"]
    verb = "would " if args.dry_run else ""
    installed = skipped = 0
    for plugin, skill, sdir in found:
        name = names[(plugin, skill)]
        owner = entries.get(name)
        if owner and (owner.get("plugin"), owner.get("skill")) != (plugin, skill) and not args.prefix:
            alt = f"{plugin}-{skill}"
            print(f"note: {name} is already installed from {owner.get('plugin')}; {verb}install {plugin}/{skill} as {alt}")
            name = alt
            owner = entries.get(name)
        elif name != skill and not args.prefix:
            print(f"note: another plugin also has a skill named {skill}; {verb}install {plugin}/{skill} as {name}")
        dest = target / name
        if dest.exists() and owner is None and not args.force:
            print(f"skip: {dest} exists and was not written by this script (use --force to overwrite)")
            skipped += 1
            continue
        files = skill_files(sdir)
        new_rels = [f.as_posix() for f in files]
        stale = sorted(set(owner.get("files", [])) - set(new_rels)) if owner else []
        if not args.dry_run:
            if stale:
                remove_files(dest, stale, dry_run=False)
            for rel in files:
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(sdir / rel, out)
                if os.name != "nt" and os.access(sdir / rel, os.X_OK):
                    out.chmod(out.stat().st_mode | 0o111)
            entries[name] = {"plugin": plugin, "skill": skill, "files": new_rels}
        print(f"{verb}install {plugin}/{skill} -> {dest} ({len(files)} files)")
        installed += 1
    if not args.dry_run:
        target.mkdir(parents=True, exist_ok=True)
        save_manifest(target, manifest)
    print(f"{installed} skills {'would be ' if args.dry_run else ''}installed into {target}"
          + (f", {skipped} skipped" if skipped else ""))
    return 1 if skipped and not installed else 0


def cmd_uninstall(found, target: Path, args) -> int:
    manifest = load_manifest(target)
    entries = manifest["entries"]
    limit = None
    if args.only or args.skill:
        limit = {(p, s) for p, s, _ in found}
    verb = "would remove" if args.dry_run else "removed"
    count = 0
    for name in sorted(entries):
        entry = entries[name]
        if limit is not None and (entry.get("plugin"), entry.get("skill")) not in limit:
            continue
        n = remove_files(target / name, entry.get("files", []), args.dry_run)
        print(f"{verb} {name} ({n} files)")
        count += 1
        if not args.dry_run:
            del entries[name]
    if not args.dry_run:
        save_manifest(target, manifest)
    print(f"{count} skills {verb} from {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Copy the skills in this repository into a Claude Code skills directory.",
        epilog="Files this script did not write are never deleted.")
    where = ap.add_mutually_exclusive_group()
    where.add_argument("--user", action="store_true", help="install into ~/.claude/skills/")
    where.add_argument("--project", action="store_true", help="install into ./.claude/skills/ of the current directory")
    where.add_argument("--target", help="install into this directory instead")
    ap.add_argument("--list", action="store_true", help="list plugins and skills, then exit")
    ap.add_argument("--json", action="store_true", help="with --list, output plugins, skills and install names as JSON")
    ap.add_argument("--only", action="append", default=[], metavar="PLUGIN", help="only this plugin (repeatable)")
    ap.add_argument("--skill", action="append", default=[], metavar="PLUGIN/SKILL", help="only this skill (repeatable)")
    ap.add_argument("--prefix", action="store_true", help="install every skill as <plugin>-<skill>")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen and write nothing")
    ap.add_argument("--force", action="store_true", help="overwrite skill folders this script did not write")
    ap.add_argument("--uninstall", action="store_true", help="remove the files this script wrote")
    ap.add_argument("--from", dest="repo", default=str(Path(__file__).resolve().parent),
                    help="repository root to install from (default: the folder holding install.py)")
    args = ap.parse_args(argv)
    if args.json and not args.list:
        ap.error("--json requires --list")

    if sys.version_info < (3, 10):
        print("error: Python 3.10 or newer is required", file=sys.stderr)
        return 2
    repo = Path(args.repo).resolve()
    everything = discover(repo)
    if not everything:
        print(f"error: no skills found under {repo / 'plugins'}", file=sys.stderr)
        return 2
    found = select(everything, args.only, args.skill)
    # Names are planned over the whole repository so a skill always gets the same name,
    # whether it is installed alone or with everything else.
    names = plan_names([(p, s) for p, s, _ in everything], args.prefix)
    if args.list:
        if args.json:
            plugins = {}
            for plugin, skill, _ in found:
                plugins.setdefault(plugin, []).append({"name": skill, "install_name": names[(plugin, skill)]})
            print(json.dumps({"plugins": [
                {"name": plugin, "skills": skills} for plugin, skills in plugins.items()
            ]}, indent=2))
            return 0
        return cmd_list(found, names)
    if not (args.user or args.project or args.target):
        ap.error("choose where to install: --user, --project or --target DIR (or use --list)")
    target = resolve_target(args)
    if args.uninstall:
        return cmd_uninstall(found, target, args)
    return cmd_install(found, names, target, args)


if __name__ == "__main__":
    sys.exit(main())
