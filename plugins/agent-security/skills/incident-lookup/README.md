# Incident lookup

Searches 80 coded AI-agent security incidents from 2023 to 2026, mapped to OWASP Agentic and LLM Top 10 and MITRE ATLAS, and ranks precedents for a design by input channel, authority, vector and impact channel. It reads a daily-refreshed copy of the published dataset and falls back to the bundled snapshot offline.

Use it to answer "has this happened before?", to justify a control with evidence, or to cite precedents in a threat model. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: precedents for an agent that reads e-mail and can send messages, from the bundled snapshot (the first 16 lines). Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/incident-lookup/scripts/incidents.py --offline --format markdown precedents --channel-in email --authority send-message --limit 3
```

```markdown
Precedents for the design: 8 matching incident(s), showing 3

| id | date | name | score | why | outcome | owasp_agentic |
|---|---|---|---|---|---|---|
| 005 | 2023-05 | [ChatGPT plugin cross-plugin request forgery](https://embracethered.com/blog/posts/2023/chatgpt-cross-plugin-request-forgery-and-prompt-injection./) | 3 | authority send-message | data-exfiltration | ASI01, ASI02 |
| 026 | 2025-02 | [ChatGPT Operator prompt-injection data theft](https://embracethered.com/blog/posts/2025/chatgpt-operator-prompt-injection-exploits/) | 3 | authority send-message | data-exfiltration | ASI01, ASI02 |
| 029 | 2025-04 | [MCP tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | 3 | authority send-message | data-exfiltration | ASI04, ASI02 |

Outcomes among matches:
  data-exfiltration          7  88%
  none-demo                  1  12%

OWASP Agentic Top 10 among matches:
  ASI01                      6  75%
  ASI02                      6  75%
  ASI04                      2  25%
...
```
<!-- sample:end -->

Exit codes: 0 results printed, 2 a usage error or a `--data` or `--design` file that cannot be read or has the wrong shape.

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
