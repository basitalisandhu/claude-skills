# naming-audit

Audit function, variable, method and module names in a file or diff: are the names any good, consistent with how the project names things, or misleading names that lie about behaviour (a getter that creates), then propose renames with a migration path for public ones.

Use it when asked "are these names clear?", whether names are misleading, to review naming in a PR, or to agree naming conventions for a new codebase (modules, functions, constants).
Not for formatting or choosing a product name.

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/conventions.md`](references/conventions.md), and states what it could not check.

## Example requests

- "Are these function names in utils.py any good? Some of them feel misleading"
- "Check the variable and method names in this diff against how the rest of the project names things"
- "getUser actually creates a user when none exists. Which other names in this module lie like that?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
