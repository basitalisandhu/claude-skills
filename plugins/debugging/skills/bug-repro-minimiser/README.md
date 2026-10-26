# bug-repro-minimiser

Turn a vague bug report or a long failing script into the smallest reliable reproduction: reduce it to a single command or test that fails every time and still shows the bug, with the environment, input and expected versus actual result pinned down.

Use it when a bug report says "sometimes", "on my machine" or "it just crashes", before any fix is attempted, or when a fix needs a regression test.
Not for performance regressions (perf-profile-reader) and not a debugger tutorial.

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/report-template.md`](references/report-template.md), and states what it could not check.

## Example requests

- "A user says it just crashes sometimes on upload. Help me get a reliable repro"
- "The ticket says it works on my machine but fails in CI. Pin down the smallest failing case"
- "I fixed the race but need a regression test first, how do I get a command that fails every time?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
