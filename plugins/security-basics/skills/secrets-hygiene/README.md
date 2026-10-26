# secrets-hygiene

Find leaked credentials (cloud and SaaS keys, private keys, tokens, connection strings, high-entropy assignments) in a repository, directory or staged files with a bundled script that redacts them, check .env files are ignored, keep a baseline of accepted findings, and guide rotation and cleanup.

Use it when asked "did I commit a secret?", before open-sourcing, to add a pre-commit hook, or after a leak.
Not for managing secrets or replacing the platform's secret scanning; it complements it offline.

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/security-basics/skills/secrets-hygiene/scripts/secrets_scan.py tests/fixtures/secrets-hygiene
```

Inside Claude Code the skill runs `secrets_scan.py` from `${CLAUDE_PLUGIN_ROOT}/skills/secrets-hygiene/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/secrets-hygiene/` (synthetic data):

<!-- sample: plugins/security-basics/skills/secrets-hygiene/scripts/secrets_scan.py tests/fixtures/secrets-hygiene -->
```text
secrets-hygiene 0.1.0: 2 files, 1 findings high=1
  [high    ] env-file-not-ignored       app/.env:0  no .env rule in .gitignore  fp=b5c6d084777b05d6
Rotate anything real, then remove it from history (git filter-repo) and add the path to .gitignore.
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
