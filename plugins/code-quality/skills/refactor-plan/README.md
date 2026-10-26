# refactor-plan

Plan a safe refactor of a module, package or large file as small, behaviour-preserving commits, with the tests that guard each step and a rollback point: split a 3000-line file into smaller units, untangle packages that import each other in a circle, or clean up code when behaviour must not change.

Use it when asked to "plan this refactor", for the steps to split or restructure a module, or to untangle dependencies.
Not for ranking complexity (complexity-report), finding unused code (dead-code-finder), renames alone (naming-audit) or features and bug fixes.

Claude follows [SKILL.md](SKILL.md); it is part of the `code-quality` plugin (`/plugin install code-quality@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/moves.md`](references/moves.md), [`references/plan-template.md`](references/plan-template.md), and states what it could not check.

## Example requests

- "orders.py is 3000 lines. How do I split it up without breaking anything?"
- "Plan a safe refactor of the notification module into smaller units, small commits only"
- "These packages import each other in a circle. Give me an order of moves to untangle them"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
