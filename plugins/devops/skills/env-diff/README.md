# env-diff

Compare the keys of .env.example against real .env files with a bundled script, listing missing, extra, empty and duplicate keys without ever printing a value.

Use it when asked "which env vars am I missing?", what to set in .env after cloning a repo, when a service fails on a missing variable, before deploying to a new environment, or to fail CI when .env.example drifts.
Not for comparing values, and not a secret manager.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/env-diff/scripts/env_diff.py tests/fixtures/env-diff/template.env.example tests/fixtures/env-diff/staging.env.sample
```

Inside Claude Code the skill runs `env_diff.py` from `${CLAUDE_PLUGIN_ROOT}/skills/env-diff/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/env-diff/` (synthetic data):

<!-- sample: plugins/devops/skills/env-diff/scripts/env_diff.py tests/fixtures/env-diff/template.env.example tests/fixtures/env-diff/staging.env.sample -->
```text
env-diff 0.1.0: template tests/fixtures/env-diff/template.env.example declares 4 keys
  tests/fixtures/env-diff/staging.env.sample: 2 set, 1 empty, 1 missing, 1 extra
    missing: DEBUG
    empty: API_KEY
    extra: EXTRA
    duplicate keys: PORT (line 5)
not ok: missing or undeclared keys
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
