# onboarding-doc

Write a developer onboarding doc that takes a new developer from a clean laptop to their first merged change: setup verified step by step, how the code is organised, how to run, test, deploy and ship the project, the configuration it needs, who owns what, and first tasks.

Use it when asked to "write an onboarding guide", to document a project for newcomers, when a repo has no onboarding, or before the team grows.
Not for user-facing documentation (readme-author), a refactoring plan, or HR onboarding.

Claude follows [SKILL.md](SKILL.md); it is part of the `docs` plugin (`/plugin install docs@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/template.md`](references/template.md), and states what it could not check.

## Example requests

- "Write an onboarding guide for the backend team, our last joiner took three days to get running"
- "A new developer starts Monday. I need a doc from a clean laptop to their first merged change"
- "We have no onboarding for this repo, can you write one covering setup, tests, deploys and who owns what?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
