# perf-profile-reader

Read a captured CPU profile (py-spy collapsed stacks or dump, Go pprof text output, Python cProfile output) with a bundled script, find the few functions and calls that hold the time, say whether it is real work or waiting, and what to optimise or fix first.

Use it when someone has a profile and asks "where does the time go?", which functions to optimise, or before optimising anything.
Not for taking the profile (instructions are included), memory growth (memory-leak-checklist) or static complexity (complexity-report).

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/debugging/skills/perf-profile-reader/scripts/perf_profile_reader.py tests/fixtures/perf-profile-reader/collapsed.txt
```

Inside Claude Code the skill runs `perf_profile_reader.py` from `${CLAUDE_PLUGIN_ROOT}/skills/perf-profile-reader/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/perf-profile-reader/` (synthetic data):

<!-- sample: plugins/debugging/skills/perf-profile-reader/scripts/perf_profile_reader.py tests/fixtures/perf-profile-reader/collapsed.txt -->
```text
perf-profile-reader 0.1.0: format=collapsed, total=100 samples, 4 distinct frames, max depth 4
top by self (where time is spent):
   50.0%          50  socket.recv
   30.0%          30  parse_json
   15.0%          15  render
    5.0%           5  idle
top by cumulative (what calls the expensive code):
  100.0%         100  main
   95.0%          95  handle_request
   50.0%          50  query_db
   50.0%          50  socket.recv
   30.0%          30  parse_json
   15.0%          15  render
    5.0%           5  idle
hottest full stacks:
   50.0%  main;handle_request;query_db;socket.recv
   30.0%  main;handle_request;parse_json
   15.0%  main;handle_request;render
    5.0%  main;idle
checks:
  - one frame holds 50.0% of self time: socket.recv
  - waiting, locking or GC frames in the top ten by self time: socket.recv (the program may be blocked rather than busy)
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
