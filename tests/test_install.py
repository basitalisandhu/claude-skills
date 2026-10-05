"""Offline tests for install.py. HOME and the working directory are temporary folders."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("claude_skills_install", ROOT / "install.py")
install = importlib.util.module_from_spec(spec)
sys.modules["claude_skills_install"] = install
spec.loader.exec_module(install)


def skill(repo: Path, plugin: str, name: str, extra: dict[str, str] | None = None) -> None:
    d = repo / "plugins" / plugin / "skills" / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: Test skill {name}.\n---\n\n# {name}\n", encoding="utf-8")
    for rel, text in (extra or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text, encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    skill(repo, "alpha", "shared", {"scripts/run.py": "print('alpha')\n"})
    skill(repo, "alpha", "one")
    skill(repo, "beta", "shared")
    skill(repo, "beta", "two", {"references/notes.md": "notes\n"})
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(work)
    return {"repo": repo, "home": home, "work": work, "user": home / ".claude" / "skills"}


def run(env, *args: str) -> int:
    return install.main(["--from", str(env["repo"]), *args])


def manifest(target: Path) -> dict:
    return json.loads((target / install.MANIFEST).read_text(encoding="utf-8"))


def test_collision_first_plain_second_prefixed(env, capsys):
    assert run(env, "--user") == 0
    out = capsys.readouterr().out
    target = env["user"]
    assert (target / "shared" / "scripts" / "run.py").read_text() == "print('alpha')\n"
    assert (target / "beta-shared" / "SKILL.md").is_file()
    assert (target / "one" / "SKILL.md").is_file()
    assert (target / "two" / "references" / "notes.md").is_file()
    assert "install beta/shared as beta-shared" in out
    entries = manifest(target)["entries"]
    assert entries["shared"]["plugin"] == "alpha"
    assert entries["beta-shared"] == {"plugin": "beta", "skill": "shared", "files": ["SKILL.md"]}


def test_prefix_names_every_skill(env):
    assert run(env, "--user", "--prefix") == 0
    names = sorted(p.name for p in env["user"].iterdir() if p.is_dir())
    assert names == ["alpha-one", "alpha-shared", "beta-shared", "beta-two"]


def test_dry_run_writes_nothing(env, capsys):
    assert run(env, "--user", "--dry-run") == 0
    assert not env["user"].exists()
    assert "would install alpha/one" in capsys.readouterr().out


def test_project_uses_current_directory(env):
    assert run(env, "--project", "--only", "beta") == 0
    target = env["work"] / ".claude" / "skills"
    assert sorted(p.name for p in target.iterdir() if p.is_dir()) == ["beta-shared", "two"]
    assert not env["user"].exists()
    assert not (env["repo"] / ".claude").exists()


def test_only_repeatable_and_unknown_plugin(env):
    assert run(env, "--user", "--only", "alpha", "--only", "beta") == 0
    assert len(manifest(env["user"])["entries"]) == 4
    with pytest.raises(SystemExit):
        run(env, "--user", "--only", "gamma")


def test_skill_selects_one(env):
    assert run(env, "--user", "--skill", "beta/two") == 0
    assert list(manifest(env["user"])["entries"]) == ["two"]
    with pytest.raises(SystemExit):
        run(env, "--user", "--skill", "shared")  # ambiguous


def test_existing_folder_not_overwritten_without_force(env, capsys):
    mine = env["user"] / "one"
    mine.mkdir(parents=True)
    (mine / "SKILL.md").write_text("my own skill\n")
    assert run(env, "--user", "--only", "alpha") == 0
    assert (mine / "SKILL.md").read_text() == "my own skill\n"
    assert "was not written by this script" in capsys.readouterr().out
    assert "one" not in manifest(env["user"])["entries"]
    assert run(env, "--user", "--only", "alpha", "--force") == 0
    assert (mine / "SKILL.md").read_text().startswith("---")


def test_uninstall_removes_only_what_it_wrote(env):
    assert run(env, "--user") == 0
    target = env["user"]
    (target / "two" / "my-notes.md").write_text("keep me\n")
    other = target / "unrelated"
    other.mkdir()
    (other / "SKILL.md").write_text("not ours\n")
    assert run(env, "--user", "--uninstall") == 0
    assert (target / "two" / "my-notes.md").read_text() == "keep me\n"
    assert not (target / "two" / "references").exists()
    assert not (target / "shared").exists()
    assert (other / "SKILL.md").read_text() == "not ours\n"
    assert not (target / install.MANIFEST).exists()


def test_uninstall_only_one_plugin(env):
    assert run(env, "--user") == 0
    assert run(env, "--user", "--uninstall", "--only", "beta") == 0
    assert sorted(manifest(env["user"])["entries"]) == ["one", "shared"]
    assert not (env["user"] / "beta-shared").exists()


def test_reinstall_removes_files_dropped_upstream(env):
    assert run(env, "--user") == 0
    (env["repo"] / "plugins" / "alpha" / "skills" / "shared" / "scripts" / "run.py").unlink()
    assert run(env, "--user") == 0
    assert not (env["user"] / "shared" / "scripts").exists()
    assert manifest(env["user"])["entries"]["shared"]["files"] == ["SKILL.md"]


def test_second_plugin_installed_later_does_not_take_plain_name(env, capsys):
    # beta alone: its shared skill is the second in name order, so it is prefixed even when installed alone
    assert run(env, "--user", "--only", "beta") == 0
    assert (env["user"] / "beta-shared").is_dir()
    assert run(env, "--user", "--only", "alpha") == 0
    assert (env["user"] / "shared" / "scripts" / "run.py").is_file()


def test_list_needs_no_target(env, capsys):
    assert run(env, "--list") == 0
    out = capsys.readouterr().out
    assert "shared  (installs as beta-shared)" in out
    assert "4 skills in 2 plugins" in out


def test_list_default_text_is_unchanged(env, capsys):
    assert run(env, "--list") == 0
    assert capsys.readouterr().out == (
        "alpha\n  one\n  shared\nbeta\n  shared  (installs as beta-shared)\n  two\n"
        "4 skills in 2 plugins\n"
    )


def test_list_json_preserves_collision_names_and_filtering(env, capsys):
    assert run(env, "--list", "--json", "--only", "beta") == 0
    assert json.loads(capsys.readouterr().out) == {
        "plugins": [{
            "name": "beta",
            "skills": [
                {"name": "shared", "install_name": "beta-shared"},
                {"name": "two", "install_name": "two"},
            ],
        }],
    }
    assert not env["user"].exists()
    assert run(env, "--list", "--json", "--prefix", "--skill", "alpha/one") == 0
    assert json.loads(capsys.readouterr().out)["plugins"][0]["skills"] == [
        {"name": "one", "install_name": "alpha-one"},
    ]


def test_json_without_list_is_rejected_without_installing(env):
    with pytest.raises(SystemExit) as error:
        run(env, "--user", "--json")
    assert error.value.code == 2
    assert not env["user"].exists()


def test_requires_a_target(env):
    with pytest.raises(SystemExit):
        run(env)


def test_real_repository_list_matches_catalog(capsys):
    catalog = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    assert install.main(["--list"]) == 0
    out = capsys.readouterr().out
    c = catalog["counts"]
    assert f"{c['skills']} skills in {c['plugins']} plugins" in out
    for s in catalog["skills"]:
        assert s["install_name"] == install.plan_names(
            [(x["plugin"], x["name"]) for x in catalog["skills"]], False)[(s["plugin"], s["name"])]
