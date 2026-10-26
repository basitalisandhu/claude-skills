# dependency-audit-reader

Read the JSON output of npm audit, yarn audit, pip-audit or cargo audit with a bundled script that ranks vulnerable packages by severity, separates fixable from unfixable and direct from transitive, and names the packages to upgrade first; then plan the upgrades, overrides and accepted risks with expiry dates.

Use it when an audit fails CI, when asked "what do we do about these vulnerabilities?", or to triage dependency alerts.
Not for finding new vulnerabilities (it reads the tool's output offline) or for licence compliance.

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/security-basics/skills/dependency-audit-reader/scripts/audit_reader.py tests/fixtures/dependency-audit-reader/pip-audit.json
```

Inside Claude Code the skill runs `audit_reader.py` from `${CLAUDE_PLUGIN_ROOT}/skills/dependency-audit-reader/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/dependency-audit-reader/` (synthetic data):

<!-- sample: plugins/security-basics/skills/dependency-audit-reader/scripts/audit_reader.py tests/fixtures/dependency-audit-reader/pip-audit.json -->
```text
dependency-audit-reader 0.1.0: pip-audit: 1 vulnerable packages info=1; 1 fixable, 0 without a fix
severity  package                      installed        direct fix                      advisories
info      requests                     2.25.0           ?      2.31.0                   PYSEC-2023-74, CVE-2023-32681  Leaks Proxy-Authorization
upgrade first: requests
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
