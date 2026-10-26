# release-notes

Generate release notes from a git commit range with a bundled script that groups commits by Conventional Commits type (breaking, features, fixes, performance, docs, build), links commits and issues, and lists contributors; then edit them into notes a user can read.

Use it when asked to "write the release notes", when cutting a release, writing a GitHub release body, or updating CHANGELOG.md from history.
Not for deciding the version number (use semver-advisor) and not for commit message writing.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/release-notes/scripts/release_notes.py --input tests/fixtures/release-notes/git.log --version 1.3.0 --date 2026-10-26
```

Inside Claude Code the skill runs `release_notes.py` from `${CLAUDE_PLUGIN_ROOT}/skills/release-notes/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/release-notes/` (synthetic data):

<!-- sample: plugins/devops/skills/release-notes/scripts/release_notes.py --input tests/fixtures/release-notes/git.log --version 1.3.0 --date 2026-10-26 -->
```text
## 1.3.0 (2026-10-26)

### Breaking changes

- Drop legacy client: v1 client removed (cccc333)

### Features

- **api:** Add pagination (#12) (aaaa111)

### Bug fixes

- Handle empty body (#34) (#34) (bbbb222)

### Refactoring

- Drop legacy client (cccc333)

### Documentation

- Update README (eeee555)

### Build and dependencies

- Bump dependency foo to 2.0 (dddd444)

### Other changes

- Something unusual happened (PROJ-77) (ffff666)
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
