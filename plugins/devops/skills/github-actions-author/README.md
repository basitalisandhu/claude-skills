# github-actions-author

Write or review GitHub Actions workflows in .github/workflows with least-privilege permissions, SHA-pinned actions, timeouts, concurrency and caching, checked by a bundled linter for missing or too permissive permissions, pull_request_target checkout of forks, expression injection in run steps, unpinned actions and literal secrets.

Use it when asked to "write a CI workflow", a release workflow that publishes on a tag, to review a workflow file such as deploy.yml, or to fix a workflow security finding.
Not for other CI systems or branch protection.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/github-actions-author/scripts/gha_lint.py tests/fixtures/github-actions-author/workflow.yml
```

Inside Claude Code the skill runs `gha_lint.py` from `${CLAUDE_PLUGIN_ROOT}/skills/github-actions-author/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/github-actions-author/` (synthetic data):

<!-- sample: --lines=30 plugins/devops/skills/github-actions-author/scripts/gha_lint.py tests/fixtures/github-actions-author/workflow.yml -->
```text
github-actions lint 0.1.0: 1 workflow(s), 11 findings critical=1, high=6, medium=2, low=2
  [critical] GHA-003 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[0]: pull_request_target checks out the pull request head
      ref: ${{ github.event.pull_request.head.sha }}
      fix: Never run fork code with the write token: use the pull_request trigger, or check out the base and only read PR metadata.
  [high    ] GHA-009 tests/fixtures/github-actions-author/workflow.yml jobs.build.runs-on: Self-hosted runner reachable from pull requests
      self-hosted
      fix: Run pull-request jobs on GitHub-hosted runners, or restrict the workflow to trusted branches; a fork can execute code on the runner.
  [high    ] GHA-005 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[0]: Action pinned to a moving branch
      actions/checkout@main
      fix: Pin to a commit SHA with the version in a comment.
  [high    ] GHA-005 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[1]: Action without a version
      some/action
      fix: Pin to a commit SHA: uses: owner/repo@<40-char sha> # vX.Y.Z
  [high    ] GHA-004 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[3]: Untrusted event data expanded inside run
      ${{ github.event.comment.body }}
      fix: Pass it through an environment variable (env: TITLE: ${{ ... }}) and use "$TITLE" in the script.
  [high    ] GHA-007 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[4]: Remote script piped into a shell
      curl -s https://x.example/install.sh | sh
      fix: Download, verify a checksum, then run; or use a pinned action.
  [high    ] GHA-001 tests/fixtures/github-actions-author/workflow.yml permissions: No permissions block at the top level or on every job
      jobs without permissions: build
      fix: Add `permissions: contents: read` at the top level and grant more only on the jobs that need it.
  [medium  ] GHA-011 tests/fixtures/github-actions-author/workflow.yml jobs.build: continue-on-error: true on a job
      fix: Remove it unless the job is informational; failures here will not fail the workflow.
  [medium  ] GHA-005 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[2]: Action pinned to a tag, not a commit SHA
      other/action@v2
      fix: Tags can be moved; pin to the SHA and let dependabot update it.
  [low     ] GHA-006 tests/fixtures/github-actions-author/workflow.yml jobs.build: No timeout-minutes
      fix: Add timeout-minutes so a hung job cannot run for six hours.
  [low     ] GHA-012 tests/fixtures/github-actions-author/workflow.yml jobs.build.steps[0]: actions/checkout keeps the token in .git/config
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
