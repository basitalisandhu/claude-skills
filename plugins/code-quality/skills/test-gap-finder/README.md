# test-gap-finder

Find the source modules that have no tests and prioritise which to cover first by risk: a bundled script maps modules to their tests by naming convention and imports and shows what is missing.

Use it when asked "what is untested?", where to add tests first, or to check that a change comes with tests.
Not for line coverage; it works at module level without running anything (use coverage.py, c8 or go test -cover for that).

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/code-quality/skills/test-gap-finder/scripts/test_gap_finder.py tests/fixtures/test-gap-finder
```

Inside Claude Code the skill runs `test_gap_finder.py` from `${CLAUDE_PLUGIN_ROOT}/skills/test-gap-finder/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/test-gap-finder/` (synthetic data):

<!-- sample: plugins/code-quality/skills/test-gap-finder/scripts/test_gap_finder.py tests/fixtures/test-gap-finder -->
```text
test-gap-finder 0.1.0: 2/3 modules have a test by name or import (66.7%), 2 test files
  no test: pkg/beta.py
Name and import based. A module listed as covered may still have weak tests; one listed as uncovered may be exercised indirectly.
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
