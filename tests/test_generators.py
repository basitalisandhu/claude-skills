"""Offline tests for scripts/hublib.py, scripts/validate.py, scripts/sync.py --offline and site/build.py."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "site"))

import build as site_build  # noqa: E402
import hublib as H  # noqa: E402
import sync  # noqa: E402
import validate  # noqa: E402


def write_skill(root: Path, plugin: str, name: str, front: str) -> None:
    d = root / "plugins" / plugin / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(front + "\n# Title\n\n## Limits\n\n- Does not do X.\n", encoding="utf-8")
    manifest = root / "plugins" / plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"name": plugin, "version": "1.0.0"}), encoding="utf-8")


def test_parse_frontmatter_nested_and_folded():
    text = "---\nname: x\ndescription: >\n  first line\n  second line\nmetadata:\n  author: Someone\n---\nbody\n"
    fields, body, errors = H.parse_frontmatter(text)
    assert errors == []
    assert fields["description"] == "first line second line"
    assert fields["metadata"] == {"author": "Someone"}
    assert body == "body\n"


def test_frontmatter_rules(tmp_path):
    write_skill(tmp_path, "alpha", "good", "---\nname: good\ndescription: Fine.\nlicense: MIT\n---")
    write_skill(tmp_path, "alpha", "bad-name", "---\nname: Bad_Name\ndescription: Fine.\n---")
    write_skill(tmp_path, "alpha", "long", "---\nname: long\ndescription: " + "x" * 1025 + "\n---")
    write_skill(tmp_path, "alpha", "extra", "---\nname: extra\ndescription: Fine.\nversion: 1\n---")
    write_skill(tmp_path, "alpha", "empty", "---\nname: empty\ndescription:\n---")
    problems, dups, _ = validate.check_frontmatter(tmp_path, set())
    text = "\n".join(problems)
    assert "lowercase letters" in text and "does not equal its directory" in text
    assert "limit 1024" in text
    assert "unknown front matter keys ['version']" in text
    assert "empty description" in text
    assert "good/SKILL.md" not in text
    assert dups == []


def test_duplicate_names_fail_unless_allowed(tmp_path):
    write_skill(tmp_path, "alpha", "same", "---\nname: same\ndescription: A.\n---")
    write_skill(tmp_path, "beta", "same", "---\nname: same\ndescription: B.\n---")
    _, dups, _ = validate.check_frontmatter(tmp_path, set())
    assert len(dups) == 1 and "'same'" in dups[0]
    _, dups, notes = validate.check_frontmatter(tmp_path, {"same"})
    assert dups == [] and "allowed duplicate" in notes[0]


def test_install_names_match_install_py():
    pairs = [("code-quality", "x"), ("repo-engineering", "x"), ("docs", "y")]
    names = H.install_names(pairs)
    assert names[("code-quality", "x")] == "x"
    assert names[("repo-engineering", "x")] == "repo-engineering-x"
    assert H.install_names(pairs, prefix_all=True)[("docs", "y")] == "docs-y"


def test_secret_patterns_assembled_at_run_time():
    key = "AK" + "IA" + "Q" * 16
    hits = [label for label, rx in validate.SECRET_PATTERNS if __import__("re").search(rx, key)]
    assert hits == ["aws access key id"]
    assert ("AK" + "IA" + "IOSFODNN7EXAMPLE") in validate.ALLOWED_SECRET_LITERALS


def test_first_clause_and_one_line():
    assert site_build.first_clause("Audit things for risk: more words here.") == "Audit things for risk"
    assert H.one_line("A report with pass, fail or n.a. for each. Next.") == "A report with pass, fail or n.a. for each."


def test_repository_validates_and_site_is_current(capsys):
    assert validate.main([]) == 0
    assert site_build.main(["--check"]) == 0


@pytest.fixture
def repo_copy(tmp_path):
    dest = tmp_path / "repo"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dest


def test_offline_sync_is_a_no_op_and_deterministic(repo_copy):
    before = {p: p.read_bytes() for p in repo_copy.rglob("*") if p.is_file()}
    assert sync.main(["--offline", "--check", "--root", str(repo_copy)]) == 0
    assert sync.main(["--offline", "--root", str(repo_copy)]) == 0
    after = {p: p.read_bytes() for p in repo_copy.rglob("*") if p.is_file()}
    assert before == after


def test_validate_catches_a_hand_edit(repo_copy):
    skill = next((repo_copy / "plugins").glob("*/skills/*/SKILL.md"))
    skill.write_text(skill.read_text(encoding="utf-8") + "\nedited here\n", encoding="utf-8")
    assert validate.check_sources(repo_copy)
    assert validate.check_generated(repo_copy)[0] == []  # catalog is unaffected by body text
