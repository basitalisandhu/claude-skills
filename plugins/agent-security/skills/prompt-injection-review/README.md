# Prompt injection review

Guides a review that traces untrusted input (web pages, e-mails, tickets, tool results) to consequential tool calls and judges each path against provenance and approval rules. The bundled `tool_inventory.py` seeds the review: it lists the tools an agent exposes with a consequential or regular tier, the designator parameters (recipients, URLs, ids, paths) a provenance rule must cover, and the readers of untrusted content.

Use it when asked whether an agent can be prompt injected, or to decide where approvals belong. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the inventory of the crewAI fixture agent (the first 14 lines; the heading path is shortened). Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/prompt-injection-review/scripts/tool_inventory.py plugins/agent-security/skills/tool-approval-gate-audit/scripts/fixtures/crewai --format markdown
```

```markdown
# Tool inventory for `<path>`

Files scanned: 1. Tools: 4 (3 consequential, 1 regular). Untrusted readers: 0. Suspicious tool descriptions: 0.

## Tools

| Tool | Tier | Designator params | Location |
|---|---|---|---|
| `cleanup_cache` | consequential | path | `crew.py:20` |
| `send_newsletter` | consequential | - | `crew.py:10` |
| `update_crm` | consequential | record_id | `crew.py:36` |
| `lookup_customer` | regular | email | `crew.py:30` |

## Untrusted readers
...
```
<!-- sample:end -->

Exit codes for `tool_inventory.py`: 0 inventory written, 2 the root is missing or `--out` is not writable.

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
