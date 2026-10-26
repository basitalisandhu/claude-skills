# flaky-test-hunter

Find tests that pass and fail without code changes by comparing JUnit XML reports from several runs with a bundled script, then classify each flaky test by cause (ordering, timing, shared state, resources, environment) and prescribe the fix.

Use it when CI fails intermittently, when someone asks "is this test flaky?", or to quarantine and track flaky tests.
Not for tests that fail every time (that is a bug, use bug-repro-minimiser).

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/debugging/skills/flaky-test-hunter/scripts/flaky_test_hunter.py tests/fixtures/flaky-test-hunter
```

Inside Claude Code the skill runs `flaky_test_hunter.py` from `${CLAUDE_PLUGIN_ROOT}/skills/flaky-test-hunter/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/flaky-test-hunter/` (synthetic data):

<!-- sample: plugins/debugging/skills/flaky-test-hunter/scripts/flaky_test_hunter.py tests/fixtures/flaky-test-hunter -->
```text
flaky-test-hunter 0.1.0: 3 runs, 3 distinct tests, 1 flaky, 1 always failing
  run tests/fixtures/flaky-test-hunter/run1.xml: 3 tests, 2 failed, 0 skipped
  run tests/fixtures/flaky-test-hunter/run2.xml: 3 tests, 1 failed, 0 skipped
  run tests/fixtures/flaky-test-hunter/run3.xml: 3 tests, 2 failed, 0 skipped
flaky (passed and failed across runs):
  pkg.TestX::b  pass=1 fail=2 rate=0.667 reruns=0 time=0.5-0.5s
      timeout
always failing (not flaky, broken):
  pkg.TestX::c  fail=3  assert
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
