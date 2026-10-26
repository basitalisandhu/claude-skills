# changelog-keeper

Maintain CHANGELOG.md in the Keep a Changelog format with a bundled script that validates the structure, adds entries under Unreleased in the right category, cuts a release (version, date, compare links) and prints a version's section.

Use it when asked to "update the changelog", when a change needs a changelog line, when preparing a release, or when the changelog has drifted from the format.
Not for generating entries from git history (use release-notes for that, then add the entries here).

Claude follows [SKILL.md](SKILL.md); it is part of the `docs` plugin (`/plugin install docs@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/docs/skills/changelog-keeper/scripts/changelog.py --file tests/fixtures/changelog-keeper/CHANGELOG.md check
```

Inside Claude Code the skill runs `changelog.py` from `${CLAUDE_PLUGIN_ROOT}/skills/changelog-keeper/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/changelog-keeper/` (synthetic data):

<!-- sample: plugins/docs/skills/changelog-keeper/scripts/changelog.py --file tests/fixtures/changelog-keeper/CHANGELOG.md check -->
```text
changelog check 0.1.0: tests/fixtures/changelog-keeper/CHANGELOG.md: 3 sections, 0 problems
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
