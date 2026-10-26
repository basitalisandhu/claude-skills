# type-coverage

Measure how much of a Python or TypeScript codebase is type-annotated with a bundled script (parameter and return annotations per function, explicit any counts), count functions missing annotations, find the least-typed files, and plan a gradual typing rollout with a CI threshold.

Use it when asked "how well typed is this code?", where to add types first, or to enforce typing on new code.
Not for finding type errors; it measures annotations only (run mypy, pyright or tsc for that).

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/code-quality/skills/type-coverage/scripts/type_coverage.py tests/fixtures/type-coverage
```

Inside Claude Code the skill runs `type_coverage.py` from `${CLAUDE_PLUGIN_ROOT}/skills/type-coverage/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/type-coverage/` (synthetic data):

<!-- sample: plugins/code-quality/skills/type-coverage/scripts/type_coverage.py tests/fixtures/type-coverage -->
```text
type-coverage 0.1.0: 62.5% of 16 slots annotated across 2 files (7 functions, 2 explicit any)
   60.0%     6/10   app.py
           line 5 untyped: a, b, return
           line 13 m: y
   66.7%     4/6    client.ts
           line 1 f: b
           line 4 method: p
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
