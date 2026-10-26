# Agent threat model

Drafts the input file for the [agent-threat-model](https://github.com/basitalisandhu/agent-threat-model) analyser (`atm`) from the code: principals, agents, tools, channels and data stores, with each entry naming the files it was detected in. You review the draft, fill in what static scanning cannot see, run `atm` for STRIDE and OWASP findings and attach incident precedents.

Use it for a design review, or when someone asks what could go wrong with an agent. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the draft for the crewAI fixture agent used by the approval gate tests (the first 31 lines). Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/agent-threat-model/scripts/scan_agent_stack.py plugins/agent-security/skills/tool-approval-gate-audit/scripts/fixtures/crewai
```

```yaml
# Draft written by scan_agent_stack.py (agent-security plugin). Review every entry; descriptions name the files
# each one was detected in. Fill system.description and system.owner, fix tool auth/approval/scope, set data store
# sensitivity, and list the catalogue controls that are really in place (atm catalogue controls).
# Format: https://github.com/basitalisandhu/agent-threat-model/blob/main/docs/input-format.md

system:
  name: crewai
  description: ""
  owner: ""

principals:
  - id: operator
    kind: human
    trust: high
    channels: [operator-cli]
    description: Runs and configures the agent.
  - id: external-party
    kind: human
    trust: low
    channels: [email-in]
    description: Anyone who can write to the untrusted channels.

agents:
  - id: main-agent
    model_provider: hosted LLM
    autonomy: act-with-approval
    memory: none
    inputs: [operator-cli, email-in]
    tools: [send-message, file-delete]
    model_pinned: false
    description: "Frameworks: crewai. Approval signals: crew.py."
...
```
<!-- sample:end -->

Exit codes for `scan_agent_stack.py`: 0 draft written, 2 the root is not a directory or `--out` cannot be written. A malformed MCP config file is reported on stderr and skipped.

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
