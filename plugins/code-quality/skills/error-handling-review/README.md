# error-handling-review

Review how a service or library handles failures: places that swallow an exception, call out without a timeout or retry, errors without context, raw database or internal errors returned to users, inconsistent error types across layers; then propose one consistent error policy and strategy (which error types, what wraps what, what gets retried) with examples.

Use it when asked to review error handling or error paths, or when something "failed silently".
Not for a general review of a PR (review-checklist), logging setup alone, or incident write-ups (postmortem-writer).

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/checklist.md`](references/checklist.md), [`references/examples.md`](references/examples.md), and states what it could not check.

## Example requests

- "Users say the export job failed silently again, can you look at how errors are handled in jobs/export.py?"
- "Go through our payment service and find every place we swallow an exception or call out without a timeout"
- "We return raw database errors to the browser, review the error paths and suggest one consistent policy"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
