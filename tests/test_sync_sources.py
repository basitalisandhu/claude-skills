"""scripts/sync.py --source-dir against two fake source repositories built with git init (issue #7)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "site"))

import hublib as H  # noqa: E402
import sync  # noqa: E402

pytestmark = [
    pytest.mark.skipif(shutil.which("git") is None, reason="needs git"),
    # Same reason as test_generators.py: the site build is not byte-identical on Windows.
    pytest.mark.skipif(sys.platform == "win32", reason="site build output differs on Windows"),
]

SKILL = """---
name: {name}
description: "Check {name} things. Use when testing the sync. Not for real work."
license: MIT
---

# {name}

Does one small thing.

## Limits

- Test fixture only.
"""


def git(cwd: Path, *args: str) -> str:
    res = subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                          "-c", "commit.gpgsign=false", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def fake_source(base: Path, repo: str, plugin: str, skill: str) -> Path:
    path = base / repo
    sdir = path / "plugins" / plugin / "skills" / skill
    sdir.mkdir(parents=True)
    (sdir / "SKILL.md").write_text(SKILL.format(name=skill), encoding="utf-8")
    (path / "plugins" / plugin / ".claude-plugin").mkdir()
    (path / "plugins" / plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": plugin, "version": "1.0.0", "description": f"{plugin} test plugin"}), encoding="utf-8")
    (path / ".claude-plugin").mkdir()
    (path / ".claude-plugin" / "marketplace.json").write_text(json.dumps({
        "name": repo,
        "plugins": [{"name": plugin, "source": f"./plugins/{plugin}", "description": f"{plugin} test plugin",
                     "version": "1.0.0"}],
    }), encoding="utf-8")
    git(path, "init", "-q")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "initial")
    return path


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "hub"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    sources = tmp_path / "sources"
    a = fake_source(sources, "fake-source-a", "alpha", "alpha-check")
    b = fake_source(sources, "fake-source-b", "beta", "beta-check")
    monkeypatch.setattr(H, "SOURCE_REPOS", ["fake-source-a", "fake-source-b"])
    return root, sources, a, b


def test_sync_from_fake_sources_then_no_op(setup, capsys):
    root, sources, a, b = setup
    args = ["--root", str(root), "--source-dir", str(sources), "--now", "2026-10-20T00:00:00Z"]
    assert sync.main(args) == 0

    for plugin, skill in (("alpha", "alpha-check"), ("beta", "beta-check")):
        assert (root / "plugins" / plugin / "skills" / skill / "SKILL.md").is_file()
        assert (root / "docs" / "plugins" / plugin / "index.html").is_file()
    assert sorted(p.name for p in (root / "plugins").iterdir()) == ["alpha", "beta"]

    records = json.loads((root / "SOURCES.json").read_text(encoding="utf-8"))["plugins"]
    assert set(records) == {"alpha", "beta"}
    assert records["alpha"]["repo"] == "fake-source-a"
    assert records["alpha"]["commit"] == git(a, "rev-parse", "HEAD")
    assert records["beta"]["commit"] == git(b, "rev-parse", "HEAD")
    assert records["alpha"]["synced_at"] == "2026-10-20T00:00:00Z"
    market = json.loads((root / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert [p["source"] for p in market["plugins"]] == ["./plugins/alpha", "./plugins/beta"]
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    assert sorted(p["name"] for p in catalog["plugins"]) == ["alpha", "beta"]

    # Second run, nothing changed upstream: nothing is written, even with a later clock.
    before = snapshot(root)
    capsys.readouterr()
    assert sync.main(["--root", str(root), "--source-dir", str(sources), "--now", "2026-10-21T00:00:00Z"]) == 0
    assert "sync: 0 path(s) changed; 0 plugin(s)" in capsys.readouterr().out
    assert sync.main(["--check", "--root", str(root), "--source-dir", str(sources)]) == 0
    assert snapshot(root) == before


def test_upstream_commit_only_touches_that_plugin(setup):
    root, sources, a, b = setup
    sync.main(["--root", str(root), "--source-dir", str(sources), "--now", "2026-10-20T00:00:00Z"])
    skill = a / "plugins" / "alpha" / "skills" / "alpha-check" / "SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8") + "\nOne more line.\n", encoding="utf-8")
    git(a, "commit", "-qam", "edit")
    # An empty commit in b moves HEAD but not the content, so beta keeps its old record.
    git(b, "commit", "-q", "--allow-empty", "-m", "empty")
    summary = root.parent / "summary.md"
    assert sync.main(["--root", str(root), "--source-dir", str(sources), "--now", "2026-10-22T00:00:00Z",
                      "--summary", str(summary)]) == 0
    records = json.loads((root / "SOURCES.json").read_text(encoding="utf-8"))["plugins"]
    assert records["alpha"]["commit"] == git(a, "rev-parse", "HEAD")
    assert records["alpha"]["synced_at"] == "2026-10-22T00:00:00Z"
    assert records["beta"]["commit"] == git(b, "rev-parse", "HEAD~1")
    assert records["beta"]["synced_at"] == "2026-10-20T00:00:00Z"
    text = summary.read_text(encoding="utf-8")
    assert "`alpha`" in text and "`beta`" not in text


def test_same_plugin_from_two_sources_is_refused(setup, capsys):
    root, sources, a, b = setup
    market = b / ".claude-plugin" / "marketplace.json"
    data = json.loads(market.read_text(encoding="utf-8"))
    data["plugins"][0]["name"] = "alpha"
    market.write_text(json.dumps(data), encoding="utf-8")
    before = snapshot(root)
    assert sync.main(["--root", str(root), "--source-dir", str(sources)]) == 2
    assert "published by two source repositories" in capsys.readouterr().err
    assert snapshot(root) == before


def test_missing_source_clone_is_refused(setup, capsys):
    root, sources, a, b = setup
    shutil.rmtree(b)
    assert sync.main(["--root", str(root), "--source-dir", str(sources)]) == 2
    assert "does not exist" in capsys.readouterr().err
