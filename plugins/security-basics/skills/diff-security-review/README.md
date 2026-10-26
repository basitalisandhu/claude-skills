# diff-security-review

Review a change for what it adds to the attack surface before it merges: a bundled script scans only the added lines of a saved git or gh diff for new network calls, shell and process execution, unsafe deserialisation, SQL built from strings, credential-shaped literals, disabled TLS checks and new permissions in workflows and manifests, with file and line.

Use it when asked "is this PR safe security-wise?" or for a security pass on one diff.
Not for a general review (review-checklist) or a whole-repository secrets scan (secrets-hygiene).

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/security-basics/skills/diff-security-review/scripts/diff_security_scan.py tests/fixtures/diff-security-review/change.diff
```

Inside Claude Code the skill runs `diff_security_scan.py` from `${CLAUDE_PLUGIN_ROOT}/skills/diff-security-review/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/diff-security-review/` (synthetic data):

<!-- sample: plugins/security-basics/skills/diff-security-review/scripts/diff_security_scan.py tests/fixtures/diff-security-review/change.diff -->
```text
diff-security-review 0.1.0: 1 files, 3 added lines scanned, 3 findings
  [high] sql-from-string app/views.py:2: query = "SELECT * FROM users WHERE id = " + request.args["id"]
  [high] shell-exec app/views.py:3: subprocess.call(cmd, shell=True)
  [high] code-eval app/views.py:5: return eval(request.data)
by rule: code-eval 1, shell-exec 1, sql-from-string 1
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
