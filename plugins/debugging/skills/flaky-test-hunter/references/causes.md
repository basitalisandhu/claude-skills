# Flaky test causes, how to confirm them, and the fix

| Cause | Symptoms in the failure | Confirm by | Fix |
|---|---|---|---|
| Order dependence | Passes alone; fails in the suite; fails after a specific test | Run alone 20x (passes); run after the suspect (fails); random order (`pytest -p randomly`, `jest --randomize`) | Isolate state per test: fixtures that create and destroy their own data, reset module state in teardown, no mutation of shared fixtures |
| Timing and sleeps | "expected X got Y" on async results; timeouts; passes on a fast machine | Run under load (two suites in parallel, `stress-ng --cpu 4`); shorten the sleep to make it fail reliably | Replace sleeps with waits on a condition (`waitFor`, polling with a deadline); inject a clock (`freezegun`, fake timers); make async code awaitable in tests |
| Shared mutable state | Fails after a test that writes the same global, cache, singleton, env var, database row | Grep the suite for the shared name; run the two tests in both orders | Reset in fixtures; monkeypatch with automatic undo; unique ids per test; transactions rolled back per test |
| Resource conflicts | "address already in use", "file exists", permission errors | Run two instances at once | Ephemeral ports (bind to 0), `tmp_path`-style unique directories, no fixed file names |
| Environment | Fails only in CI or only locally; dates, locales, paths, missing tools | Diff the environment (`env`, versions, `TZ`, `LANG`); run with the CI image locally | Pin `TZ=UTC` and `LANG=C.UTF-8` in the test runner; assert on parsed values, not formatted strings; skip with a clear reason when a tool is absent |
| Nondeterministic data | Different ordering of results, set iteration, random values, float rounding | Run 20x and diff the failing outputs | Seed random generators in a fixture; sort before comparing; compare floats with tolerance; use ordered structures |
| Network and external services | DNS, 5xx, rate limits, slow responses | Run offline (`--disable-socket`); check for real URLs in tests | Record and replay (VCR, nock, MSW); local stubs; mark true integration tests separately and run them outside the blocking suite |
| Test pollution through time | Depends on today's date, month boundaries, leap years, DST | Run with `TZ` changed and the clock frozen to a boundary | Inject the clock; test boundaries explicitly |
| Concurrency in the code under test | Intermittent wrong results or deadlocks under parallel tests; the failure message points at production code | Run the failing scenario in a loop with more threads or workers; thread sanitizer or race detector (`go test -race`, `tsan`) | This is a real bug: fix the race (locks, atomics, immutable messages), then keep the test as a regression test |
| Resource exhaustion | Out of memory, too many open files, slowness late in the suite | Watch memory and file handles across the run; run the failing test early versus late | Close resources in teardown; cap fixture scope; split the suite |
| Retry masking | A test only passes on the second attempt | Remove the retry marker and run 20x | Find the cause above; retries are a quarantine mechanism, not a fix |

## Quarantine policy that works

- A quarantined test keeps running in a non-blocking job, so the data stays fresh.
- Each entry has an owner, a cause classification (or "unknown, experiments pending"), and a date.
- Past the date: fix, delete, or re-justify in writing. A quarantine list that only grows is a deleted test suite in slow motion.
