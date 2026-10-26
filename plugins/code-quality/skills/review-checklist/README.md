# review-checklist

Review a pull request, diff, patch or branch against a fixed checklist (correctness, tests, error handling, security, performance, readability, compatibility) and give findings with file and line references and a verdict: approve or request changes.

Use it when asked to "review this code", review a PR or a colleague's diff, "look over my changes" before merging, or go through a patch properly.
Not for a security-only pass (diff-security-review), a deep error-handling pass (error-handling-review), formatter nitpicks or architecture reviews.

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/checklist.md`](references/checklist.md), [`references/comment-style.md`](references/comment-style.md), and states what it could not check.

## Example requests

- "Can you look over my changes before I merge? Branch is feature/retry-queue"
- "Review PR 482 for correctness, tests and anything risky, with line references"
- "Here is the diff from my colleague. Give me findings and a verdict: approve or request changes"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
