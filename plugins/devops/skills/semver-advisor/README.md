# semver-advisor

Decide the next version number (major, minor, patch or a pre-release) for a library, service, REST API, CLI or schema from the actual changes, with a table of what counts as a breaking change for each, and explain the bump with evidence.

Use it when asked "is this a breaking change?", "what version should I release?", whether removing or adding a field or parameter needs a major bump, or how to version an API.
Not for release notes (release-notes) or a changelog entry (changelog-keeper).

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/decision-table.md`](references/decision-table.md), and states what it could not check.

## Example requests

- "We removed a required query parameter. Does that make it a major bump?"
- "What version should I release? I added one function and fixed two bugs"
- "How should we version our REST API when we add a field to a response?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
