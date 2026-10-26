# adr-writer

Write an Architecture Decision Record for a technical choice, with context, the options considered and their trade-offs, the decision and its consequences, in a fixed format with a status lifecycle (proposed, accepted, superseded), numbered and stored in the repository.

Use it when asked to "write an ADR", when a team is choosing between technologies, patterns or designs, when someone asks why something was done this way, or to record a decision already made.
Not for product requirements or meeting minutes.

Claude follows [SKILL.md](SKILL.md); it is part of the `docs` plugin (`/plugin install docs@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/template.md`](references/template.md), and states what it could not check.

## Example requests

- "Write an ADR for choosing Kafka over RabbitMQ"
- "We are deciding between two designs, record the options and trade-offs"
- "Someone asked why we used a monorepo, document the decision"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
