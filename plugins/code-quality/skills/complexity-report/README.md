# complexity-report

Rank the functions in a Python or JavaScript/TypeScript tree by cyclomatic complexity, length and nesting depth with a bundled script, then say which are most tangled and how to simplify them.

Use it when asked "which code is most complex?", for the worst offenders by branching and nesting, where to start a cleanup, to measure complexity before and after a refactor, or to add a complexity ceiling in CI.
Not for unused or never used exports (dead-code-finder), a refactoring sequence (refactor-plan) or runtime performance (perf-profile-reader).

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/code-quality/skills/complexity-report/scripts/complexity_report.py tests/fixtures/complexity-report
```

Inside Claude Code the skill runs `complexity_report.py` from `${CLAUDE_PLUGIN_ROOT}/skills/complexity-report/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/complexity-report/` (synthetic data):

<!-- sample: plugins/code-quality/skills/complexity-report/scripts/complexity_report.py tests/fixtures/complexity-report -->
```text
complexity-report 0.1.0: 2 files, 6 functions, mean 4.0, max 10, 0 over threshold
  CC G  len depth  function
  10 B   13     3   orders.py:4 branchy
   6 B    5     2   cart.js:2 two
   4 A    4     1   cart.js:8 method
   2 A    2     0   orders.py:19 K.m
   1 A    2     0   orders.py:1 simple
   1 A    1     0   cart.js:1 one
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
