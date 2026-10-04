#!/usr/bin/env python3
"""Sync plugins/ from the source repositories and regenerate every derived file.

Standard library only. Needs network access and git (it runs `git clone --depth 1`
over https for each source repository), unless --source-dir points at local clones.

    python3 scripts/sync.py                     # sync and write
    python3 scripts/sync.py --check             # exit 1 if anything would change
    python3 scripts/sync.py --summary sync.md   # also write a Markdown summary of what changed
    python3 scripts/sync.py --source-dir ../src # use existing clones named after each repo
    python3 scripts/sync.py --offline           # regenerate derived files from plugins/ as they are

Derived files: SOURCES.json, catalog.json, .claude-plugin/marketplace.json, the README
catalog block and docs/ (the site). A plugin's commit and synced_at only change when its
content or its marketplace entry changed, so a run with no upstream change is a no-op.
"""

from __future__ import annotations

import argparse
import datetime as dt
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hublib as H  # noqa: E402

MARKETPLACE_KEYS = ["name", "source", "description", "version", "author", "homepage", "repository",
                    "license", "keywords", "category", "tags"]


def run(cmd: list[str], cwd: Path | None = None) -> str:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
    return res.stdout.strip()


def fetch(repo: str, workdir: Path, source_dir: Path | None) -> tuple[Path, str]:
    """Return (checkout path, commit sha) for a source repository."""
    if source_dir is not None:
        path = source_dir / repo
        if not path.is_dir():
            raise RuntimeError(f"{path} does not exist")
    else:
        path = workdir / repo
        run(["git", "clone", "--depth", "1", "--quiet", f"https://github.com/{H.OWNER}/{repo}.git", str(path)])
    sha = run(["git", "rev-parse", "HEAD"], cwd=path)
    return path, sha


def copy_plugin(src: Path, dest: Path) -> None:
    for rel in H.tree_files(src):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, target)


def marketplace_entry(entry: dict, plugin: str) -> dict:
    out = {k: entry[k] for k in MARKETPLACE_KEYS if k in entry}
    out["source"] = f"./{H.PLUGINS_DIR}/{plugin}"
    ordered = {k: out[k] for k in MARKETPLACE_KEYS if k in out}
    for k in sorted(entry):  # carry any other key the source uses, after the known ones
        if k not in ordered:
            ordered[k] = entry[k]
    return ordered


def build_marketplace(entries: dict[str, dict]) -> dict:
    return {
        "$schema": "https://anthropic.com/claude-code/marketplace.schema.json",
        "name": H.MARKETPLACE_NAME,
        "description": H.HUB_DESCRIPTION,
        "owner": {"name": H.OWNER_NAME, "url": H.OWNER_URL},
        "metadata": {"description": H.HUB_DESCRIPTION, "version": H.HUB_VERSION},
        "plugins": [entries[name] for name in sorted(entries)],
    }


def stage_from_sources(root: Path, stage: Path, source_dir: Path | None, now: str) -> list[dict]:
    """Fill stage/ with plugins/, SOURCES.json and marketplace.json. Returns change records."""
    old_sources = (H.load_json(root / "SOURCES.json", {}) or {}).get("plugins", {})
    old_market = {p["name"]: p for p in (H.load_json(root / ".claude-plugin" / "marketplace.json", {}) or {}).get("plugins", [])}
    sources: dict[str, dict] = {}
    entries: dict[str, dict] = {}
    changes: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="claude-skills-sync-") as tmp:
        for repo in H.SOURCE_REPOS:
            path, sha = fetch(repo, Path(tmp), source_dir)
            market = H.load_json(path / ".claude-plugin" / "marketplace.json")
            if not market:
                raise RuntimeError(f"{repo}: no .claude-plugin/marketplace.json")
            for entry in market["plugins"]:
                plugin = entry["name"]
                if plugin in sources:
                    raise RuntimeError(f"plugin {plugin} is published by two source repositories")
                rel = str(entry.get("source", f"./plugins/{plugin}")).removeprefix("./").rstrip("/")
                src_dir = path / rel
                manifest = H.load_json(src_dir / ".claude-plugin" / "plugin.json")
                if manifest is None:
                    raise RuntimeError(f"{repo}/{rel}: no .claude-plugin/plugin.json")
                copy_plugin(src_dir, stage / H.PLUGINS_DIR / plugin)
                content = H.tree_hash(stage / H.PLUGINS_DIR / plugin)
                entries[plugin] = marketplace_entry(entry, plugin)
                old = old_sources.get(plugin)
                changed = (old is None or old.get("content_sha256") != content or old.get("repo") != repo
                           or old_market.get(plugin) != entries[plugin])
                record = {
                    "repo": repo,
                    "url": f"https://github.com/{H.OWNER}/{repo}",
                    "path": rel,
                    "commit": sha if changed else old["commit"],
                    "synced_at": now if changed else old["synced_at"],
                    "upstream_version": manifest.get("version", ""),
                    "content_sha256": content,
                }
                sources[plugin] = record
                if changed:
                    changes.append({"plugin": plugin, "repo": repo, "old": old.get("commit") if old else None,
                                    "new": sha, "version": record["upstream_version"],
                                    "old_version": old.get("upstream_version") if old else None})
    for plugin in sorted(set(old_sources) - set(sources)):
        changes.append({"plugin": plugin, "repo": old_sources[plugin].get("repo"), "removed": True})
    (stage / "SOURCES.json").write_text(H.dumps({
        "note": "Generated by scripts/sync.py. One record per vendored plugin.",
        "plugins": {k: sources[k] for k in sorted(sources)},
    }), encoding="utf-8")
    (stage / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (stage / ".claude-plugin" / "marketplace.json").write_text(H.dumps(build_marketplace(entries)), encoding="utf-8")
    return changes


def stage_offline(root: Path, stage: Path) -> None:
    """Copy plugins/, SOURCES.json and marketplace.json as they are (no network)."""
    for pdir in H.plugin_dirs(root):
        copy_plugin(pdir, stage / H.PLUGINS_DIR / pdir.name)
    for rel in ("SOURCES.json", ".claude-plugin/marketplace.json"):
        (stage / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, stage / rel)


def stage_derived(root: Path, stage: Path) -> None:
    """catalog.json, README.md and docs/ from the staged plugins/ and SOURCES.json."""
    catalog = H.build_catalog(stage)
    (stage / "catalog.json").write_text(H.dumps(catalog), encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    (stage / "README.md").write_text(H.render_readme(readme, catalog), encoding="utf-8")
    sys.path.insert(0, str(root / "site"))
    import build as site_build  # noqa: E402  (site/build.py)
    site_build.build(stage, stage / "docs")


def all_files(base: Path) -> set[str]:
    if not base.exists():
        return set()
    return {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}


def diff(root: Path, stage: Path) -> list[str]:
    """Paths that differ between the working tree and the staged result."""
    out = []
    for rel in ("SOURCES.json", "catalog.json", "README.md", ".claude-plugin/marketplace.json"):
        a, b = root / rel, stage / rel
        if not a.exists() or not filecmp.cmp(a, b, shallow=False):
            out.append(rel)
    for top in (H.PLUGINS_DIR, "docs"):
        have, want = all_files(root / top), all_files(stage / top)
        for rel in sorted(have ^ want):
            out.append(f"{top}/{rel}")
        for rel in sorted(have & want):
            if not filecmp.cmp(root / top / rel, stage / top / rel, shallow=False):
                out.append(f"{top}/{rel}")
    return out


def apply(root: Path, stage: Path) -> None:
    for top in (H.PLUGINS_DIR, "docs"):
        if (root / top).exists():
            shutil.rmtree(root / top)
        shutil.copytree(stage / top, root / top)
    for rel in ("SOURCES.json", "catalog.json", "README.md", ".claude-plugin/marketplace.json"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(stage / rel, root / rel)


def summary(changes: list[dict]) -> str:
    if not changes:
        return "No plugin changed upstream.\n"
    lines = ["Plugins whose source changed since the last sync:", ""]
    for c in changes:
        url = f"https://github.com/{H.OWNER}/{c['repo']}"
        if c.get("removed"):
            lines.append(f"- `{c['plugin']}`: removed from {c['repo']}")
        elif c["old"] and c["old"] != c["new"]:
            ver = f", version {c['old_version']} to {c['version']}" if c["old_version"] != c["version"] else ""
            lines.append(f"- `{c['plugin']}` from [{c['repo']}]({url}): "
                         f"[{c['old'][:7]}...{c['new'][:7]}]({url}/compare/{c['old']}...{c['new']}){ver}")
        elif c["old"]:
            lines.append(f"- `{c['plugin']}` from [{c['repo']}]({url}): marketplace entry or content changed at {c['new'][:7]}")
        else:
            lines.append(f"- `{c['plugin']}` from [{c['repo']}]({url}): added at {c['new'][:7]}, version {c['version']}")
    lines += ["", "Regenerated: SOURCES.json, catalog.json, .claude-plugin/marketplace.json, the README catalog block and docs/.",
              "Review the plugin diffs before merging. Skills are edited in their source repositories, not here.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if anything would change; write nothing")
    ap.add_argument("--offline", action="store_true", help="do not fetch; regenerate derived files from plugins/")
    ap.add_argument("--source-dir", type=Path, help="directory holding local clones named after each source repo")
    ap.add_argument("--summary", type=Path, help="write a Markdown summary of changed plugins to this file")
    ap.add_argument("--root", type=Path, default=H.ROOT, help=argparse.SUPPRESS)
    ap.add_argument("--now", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    now = args.now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    changes: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="claude-skills-stage-") as tmp:
        stage = Path(tmp)
        try:
            if args.offline:
                stage_offline(root, stage)
            else:
                changes = stage_from_sources(root, stage, args.source_dir, now)
        except RuntimeError as exc:
            print(f"sync: {exc}", file=sys.stderr)
            return 2
        stage_derived(root, stage)
        changed = diff(root, stage)
        if args.summary:
            args.summary.write_text(summary(changes), encoding="utf-8")
        if args.check:
            if changed:
                print(f"sync --check: {len(changed)} path(s) would change, for example:")
                for rel in changed[:20]:
                    print(f"  {rel}")
                return 1
            print("sync --check: up to date")
            return 0
        if changed:
            apply(root, stage)
        print(f"sync: {len(changed)} path(s) changed; {len(changes)} plugin(s) with a new source commit")
        for c in changes:
            print(f"  {c['plugin']}: {c.get('old') or 'new'} -> {c.get('new', 'removed')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
