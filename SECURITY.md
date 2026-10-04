# Security policy

This repository collects skills from 8 source repositories and adds four things of its own: `install.py`, `scripts/sync.py`, `scripts/validate.py` and the site builder in `site/`.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository: the "Security" tab, then "Report a vulnerability".

Include what you found, how to reproduce it and the impact you expect. You will get an acknowledgement within 5 working days.

## Where to report

A problem in a skill, its scripts, or a plugin's hooks, agents or MCP server belongs to the skill's source repository. Report it there with that repository's private vulnerability reporting.

| Plugin | Source repository |
| --- | --- |
| agent-security | [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills/security) |
| aws-security | [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills/security) |
| code-quality, data, debugging, devops, docs, security-basics | [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills/security) |
| compliance-evidence | [compliance-evidence-skills](https://github.com/basitalisandhu/compliance-evidence-skills/security) |
| github-manager | [github-manager-skills](https://github.com/basitalisandhu/github-manager-skills/security) |
| m365-governance | [m365-governance-skills](https://github.com/basitalisandhu/m365-governance-skills/security) |
| mac-maintenance | [mac-maintenance-skills](https://github.com/basitalisandhu/mac-maintenance-skills/security) |
| repo-engineering | [repo-engineering-skills](https://github.com/basitalisandhu/repo-engineering-skills/security) |

`SOURCES.json` has the same mapping with the exact commit each plugin was synced from.

Report here when the problem is in this repository's own code. Examples:

- `install.py` writes outside the target folder, or deletes a file it did not write.
- `scripts/sync.py` copies something other than the source plugin folder, or a sync pull request hides a change.
- A workflow in `.github/workflows/` has more permissions than it needs, or runs untrusted input.
- The site in `docs/` runs script or loads a remote asset.

## What this repository does and does not do

- `install.py`, `scripts/validate.py` and `site/build.py` make no network calls.
- `scripts/sync.py` runs `git clone --depth 1` over https for the 8 public source repositories, and nothing else.
- Nothing here sends telemetry.
- The site is static HTML and CSS, with no JavaScript and no third-party assets.
