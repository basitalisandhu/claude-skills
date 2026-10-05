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
