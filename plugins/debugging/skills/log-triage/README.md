# log-triage

Reduce a large log file or production log dump to its distinct message templates with counts, levels, first and last occurrence and attached stack traces using a bundled clustering script, then rank what to look at first.

Use it when handed a log dump or a failing CI log with "the logs are full of errors" or "cluster the messages and tell me what to look at".
Not for log shipping or alerting setup, a single stack trace (use stack-trace-explainer), or binary or structured-only formats without a text line per event.

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/debugging/skills/log-triage/scripts/log_triage.py tests/fixtures/log-triage/app.log
```

Inside Claude Code the skill runs `log_triage.py` from `${CLAUDE_PLUGIN_ROOT}/skills/log-triage/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/log-triage/` (synthetic data):

<!-- sample: plugins/debugging/skills/log-triage/scripts/log_triage.py tests/fixtures/log-triage/app.log -->
```text
log-triage 0.1.0: 9 lines, 4 distinct templates
by level: error=2, warn=1, info=2, debug=1
 count level    lines         template
     2 error    3-7           <ts> ERROR db connection refused host=<ip> attempt=<n>
                                +3 continuation lines (stack trace), e.g. Traceback (most recent call last):
     1 warn     8             <ts> WARN cache miss key=<str>
     2 info     1-2           <ts> INFO request id=<uuid> path=<path> took <n>
     1 debug    9             <ts> DEBUG tick
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
