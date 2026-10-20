# Debugging

Six skills for finding the cause of a failure: minimise a bug reproduction, cluster log lines, find flaky tests across JUnit reports, explain a stack trace, read a CPU profile, and work a memory leak checklist.

Find this when you search for: race condition, core dump or segfault, CI fails randomly.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install debugging@claude-dev-skills
```

Skills then appear as `/debugging:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `bug-repro-minimiser` | "sometimes", "on my machine", before a fix | smallest deterministic reproduction and a regression test |
| `log-triage` | a log dump, CI log, "logs full of errors" | `log_triage.py` templates with counts, the three things to investigate |
| `flaky-test-hunter` | CI fails intermittently, "is this flaky?" | `flaky_test_hunter.py` flaky list with cause and fix |
| `stack-trace-explainer` | a pasted trace, "what does this mean?" | root cause in the chain, project frame, hypothesis, next check |
| `perf-profile-reader` | a py-spy, pprof or cProfile capture | `perf_profile_reader.py` top frames, busy versus waiting, candidates |
| `memory-leak-checklist` | memory grows until restart, OOM kills | confirm, measure, retaining path, suspect, fix, verify |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.

## Sample output

`flaky-test-hunter` on three JUnit XML reports from the same pytest suite, where the checkout test timed out in two runs and the migration test failed in all three:

```text
$ python3 "${CLAUDE_PLUGIN_ROOT}/skills/flaky-test-hunter/scripts/flaky_test_hunter.py" ci-runs/
flaky-test-hunter 0.1.0: 3 runs, 3 distinct tests, 1 flaky, 1 always failing
  run ci-runs/run-1.xml: 3 tests, 2 failed, 0 skipped
  run ci-runs/run-2.xml: 3 tests, 1 failed, 0 skipped
  run ci-runs/run-3.xml: 3 tests, 2 failed, 0 skipped
flaky (passed and failed across runs):
  tests.test_api::test_checkout  pass=1 fail=2 rate=0.667 reruns=0 time=2.1-5.02s
      TimeoutError: payment stub did not answer in 5s
always failing (not flaky, broken):
  tests.test_db::test_migrate  fail=3  AssertionError: expected 12 tables, found 11
exit 0
```
