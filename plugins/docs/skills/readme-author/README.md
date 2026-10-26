# readme-author

Write or rewrite a README that answers what the project is, who it is for, how to install and use it in under five minutes, and where everything else lives, using a fixed section order and a quality checklist (first screen, copy-pasteable commands verified to work, no stale claims).

Use it when asked to "write a README", when a repository has none or it is out of date, or when a project is about to be published.
Not for API reference generation (use api-docs-from-code) and not for marketing copy.

Claude follows [SKILL.md](SKILL.md); it is part of the `docs` plugin (`/plugin install docs@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/template.md`](references/template.md), and states what it could not check.

## Example requests

- "This repo has no README, can you write one?"
- "Rewrite our README, it is out of date and nobody knows how to install it"
- "We are about to publish this project, make the README ready"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
