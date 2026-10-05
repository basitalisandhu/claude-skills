# agent-identity-governance

Agent identity governance skills that compute from exports you already can take, each with a tested standard-library Python script. Install with `/plugin marketplace add basitalisandhu/agent-identity-governance-skills` and then `/plugin install agent-identity-governance@agent-identity-governance-skills`. Skills appear as `/agent-identity-governance:<skill>`, and Claude also invokes them on its own when a request matches a skill's description.

| Skill | Script | Use it to |
|---|---|---|
| `nhi-inventory` | `skills/nhi-inventory/scripts/nhi_inventory.py` | merge Entra, AWS IAM, GitHub and register exports into one inventory of non-human identities with owner, last use and credential age, and flag ownerless, dormant and never-used identities |
| `entra-agent-id-review` | `skills/entra-agent-id-review/scripts/entra_agent_review.py` | review Entra agent identities and agent-like apps for high-risk permissions, credential expiry, redirect URIs, owners and Conditional Access coverage |
| `agent-recertification` | `skills/agent-recertification/scripts/agent_recertification.py` | prepare the quarterly recertification: one sheet per owner and a tracking CSV, flagging never attested, stale attestations, owners who left and removals not done |
| `credential-expiry-radar` | `skills/credential-expiry-radar/scripts/credential_expiry_radar.py` | bucket secrets, certificates, access keys and tokens as expired, 7, 30 or 90 days, and list actions per owner |
| `connector-register` | `skills/connector-register/scripts/connector_register.py` | check an MCP server, connector and plugin register for missing fields and overdue reviews, and against saved tool listings and permission manifests |
| `agent-action-timeline` | `skills/agent-action-timeline/scripts/agent_action_timeline.py` | build one ordered timeline of an agent's actions from Entra, CloudTrail, GitHub and application logs, flagging bursts, first-seen actions and actions outside an allow list |
| `agent-kill-switch-runbook` | `skills/agent-kill-switch-runbook/scripts/kill_switch_runbook.py` | write the ordered switch-off runbook for one identity with read-only verification commands, and check every credential and assignment has a step |
| `leaked-credential-response` | `skills/leaked-credential-response/scripts/leaked_credential_response.py` | work out a leaked credential's reach, use after the leak and rotation order, and write a hashed evidence folder |

Requirements: Python 3.10 or newer on `PATH` as `python3`. The scripts read local files only: no network access, no third-party packages. Key ids are shown by their last four characters and secret values are never read.
