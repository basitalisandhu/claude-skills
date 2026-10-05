"""Tests for the soft quality rules, --strict-quality and the hand-written count rule."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hublib as H  # noqa: E402
import validate  # noqa: E402


def tiny_repo(tmp_path: Path, description: str, limits: bool) -> Path:
    d = tmp_path / "plugins" / "p" / "skills" / "s"
    d.mkdir(parents=True)
    body = "# S\n\n## Limits\n\n- Nothing.\n" if limits else "# S\n"
    (d / "SKILL.md").write_text(f"---\nname: s\ndescription: {description}\n---\n\n{body}", encoding="utf-8")
    return tmp_path


def test_findings_flag_each_rule(tmp_path):
    root = tiny_repo(tmp_path, "x" * 700, limits=False)
    f = H.quality_findings(root)
    rel = "plugins/p/skills/s/SKILL.md"
    assert f["long_description"] == f["no_use"] == f["no_not_for"] == f["no_limits"] == [rel]


def test_clean_skill_has_no_findings(tmp_path):
    root = tiny_repo(tmp_path, "Does a thing. Use when asked. Not for other things.", limits=True)
    f = H.quality_findings(root)
    assert not any(f[k] for k in ("long_description", "no_use", "no_not_for", "no_limits"))


def test_notes_by_default_errors_when_strict(tmp_path):
    root = tiny_repo(tmp_path, "x" * 700, limits=False)
    soft, _ = validate.check_quality(root, strict=False)
    assert all(not problems for _, problems, _ in soft)
    assert any(notes for name, _, notes in soft if name.startswith("quality:"))
    hard, _ = validate.check_quality(root, strict=True)
    assert sum(len(problems) for _, problems, _ in hard) == 4


def test_cross_plugin_pointer_is_counted(tmp_path):
    root = tiny_repo(tmp_path, "Use it. Not for q.", limits=True)
    other = root / "plugins" / "q" / "skills" / "t"
    other.mkdir(parents=True)
    (other / "SKILL.md").write_text("---\nname: t\ndescription: Use it. Not for q.\n---\n\nSee s and `s`.\n", encoding="utf-8")
    cross = H.quality_findings(root)["cross"]
    assert cross == {"q": ["q/t -> p/s"]}


def test_strict_quality_flag_on_the_real_repository(capsys):
    findings = H.quality_findings(ROOT)
    any_findings = any(findings[k] for k, _ in H.QUALITY_RULES)
    assert validate.main([]) == 0
    assert (validate.main(["--strict-quality"]) == 1) == any_findings
    out = capsys.readouterr().out
    assert "quality: SKILL.md has no Limits section" in out


@pytest.fixture
def repo_copy(tmp_path):
    dest = tmp_path / "repo"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dest


def test_stale_hand_written_count_is_a_problem(repo_copy):
    assert validate.hand_written_count_problems(repo_copy) == []
    skills = json.loads((repo_copy / "catalog.json").read_text(encoding="utf-8"))["counts"]["skills"]
    (repo_copy / "site" / "content" / "extra.md").write_text(f"We ship {skills - 9} skills in total.\n", encoding="utf-8")
    problems = validate.hand_written_count_problems(repo_copy)
    assert len(problems) == 1 and "extra.md:1" in problems[0]
    (repo_copy / "CHANGELOG.md").write_text("## [Unreleased]\n\n- 3 plugins.\n\n## [0.1.0]\n\n- 1 plugins old.\n", encoding="utf-8")
    assert any("CHANGELOG.md (Unreleased)" in p for p in validate.hand_written_count_problems(repo_copy))
    assert not any("old" in p for p in validate.hand_written_count_problems(repo_copy))


def test_counts_spans_render_from_the_catalog():
    catalog = H.load_json(ROOT / "catalog.json")
    text = H.render_count_span("counts", catalog)
    assert f"{catalog['counts']['skills']} skills in {catalog['counts']['plugins']} plugins" in text
    assert H.render_template("{{skills}}/{{plugins}}", catalog) == f"{catalog['counts']['skills']}/{catalog['counts']['plugins']}"
