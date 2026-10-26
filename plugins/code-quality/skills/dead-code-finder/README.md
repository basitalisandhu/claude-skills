# dead-code-finder

Shrink a codebase safely: a bundled script lists probably-unused functions, classes, unused methods and exports in a Python or JavaScript/TypeScript tree, each candidate is confirmed by searching for dynamic use, and the skill proposes a safe order to remove them.

Use it when asked to find dead or unused code, "what can be deleted safely", or to prepare a cleanup before a refactor.
Not for unused imports or variables inside a function (a linter does that) and not for unused dependencies in package manifests.

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/code-quality/skills/dead-code-finder/scripts/dead_code_finder.py tests/fixtures/dead-code-finder
```

Inside Claude Code the skill runs `dead_code_finder.py` from `${CLAUDE_PLUGIN_ROOT}/skills/dead-code-finder/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/dead-code-finder/` (synthetic data):

<!-- sample: plugins/code-quality/skills/dead-code-finder/scripts/dead_code_finder.py tests/fixtures/dead-code-finder -->
```text
dead-code-finder 0.1.0: 4 files, 7 candidates, 3 probably unused
  pkg/util.py:5  function unused_helper
  pkg/util.py:9  class Orphan
  web/format.js:2  export legacyFormat
Name-based heuristic. Dynamic access (getattr, registries, reflection, templates) is not visible; confirm before deleting.
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
