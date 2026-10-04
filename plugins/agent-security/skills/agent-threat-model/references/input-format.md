# agent-threat-model input format

Condensed from `docs/input-format.md` and `schema/system.schema.json` of https://github.com/basitalisandhu/agent-threat-model (`atm schema` prints the schema). One YAML file with seven top-level keys. Unknown keys are errors, ids match `^[a-z0-9][a-z0-9._-]*$` (at most 64 characters) and are unique across all element types, and every reference must resolve. `atm validate` checks all of this plus the control ids.

```yaml
system:        {name, description, owner}
principals:    [...]   # optional
agents:        [...]   # at least one
channels:      [...]
tools:         [...]
data_stores:   [...]
controls:      [...]   # catalogue ids already in place
```

## system

| Field | Type | Notes |
|---|---|---|
| `name` | string, required | Shown in report titles |
| `description` | string | One paragraph on what the system does |
| `owner` | string | Team or person accountable |

## principals

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `human` or `service`, required | |
| `trust` | `low`, `medium`, `high`, required | How much the operator trusts instructions from this principal; anonymous users and external partners are `low` |
| `channels` | list of channel ids | Channels this principal speaks through |
| `description` | string | |

## agents

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `model_provider` | string | Free text (`hosted LLM`, `self-hosted model`); not interpreted |
| `autonomy` | `suggest`, `act-with-approval`, `act`, required | `suggest` never calls side-effecting tools alone; `act-with-approval` asks a human; `act` runs on its own |
| `memory` | `none`, `session`, `persistent` | Default `none` |
| `inputs` | list of channel ids | What the agent reads |
| `tools` | list of tool ids | What the agent may call; unreferenced tools are ignored by the rules |
| `delegates_to` | list of agent ids | |
| `model_pinned` | bool | `true` when the model version is pinned and change-controlled |
| `description` | string | |

## channels

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `chat`, `email`, `web`, `document`, `rag`, `api`, `file`, `cli`, required | |
| `trusted` | bool, required | `false` when an attacker could influence the content (public chat, inbound e-mail, web pages, shared documents, tickets) |
| `origin` | `user`, `third-party`, `internal`, required | |
| `description` | string | |

## tools

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `read`, `write`, `exec`, `network`, `payment`, `messaging`, required | |
| `target` | string | What the tool touches; a data store id here links the tool to that store |
| `scope` | string | Free text; empty, `*`, `all`, `admin`, `full`, `root`, `owner`, `any`, `unrestricted` count as broad |
| `auth` | `none`, `static-key`, `short-lived`, `brokered`, required | |
| `approval` | `none`, `threshold`, `always` | Default `none` |
| `sandboxed` | bool | Default `false`; matters for `exec` |
| `provider` | `first-party`, `third-party` | Default `first-party`; third-party tools bring their own descriptions |
| `pinned` | bool | `true` when the tool version or description hash is pinned |
| `data_stores` | list of data store ids | Stores reachable in addition to `target` |
| `description` | string | |

## data_stores

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `sensitivity` | `public`, `internal`, `confidential`, `regulated`, required | A `regulated` store in scope raises a threat's impact by one |
| `description` | string | |

## controls

Catalogue control ids already in place. Unknown ids fail validation. A listed control lowers the residual score of every threat it mitigates and switches some threats off entirely (for example `missing-audit-trail` when `audit-log` is present).

| Effort | Control ids |
|---|---|
| low | `argument-validation`, `budget-caps`, `egress-allowlist`, `incident-response-playbook`, `kill-switch`, `model-version-pinning`, `output-encoding`, `prompt-injection-filtering`, `rate-limiting`, `secrets-out-of-context`, `tool-integrity-pinning` |
| medium | `adversarial-testing`, `agent-identity`, `approval-fatigue-controls`, `approval-gates`, `audit-log`, `backups-and-rollback`, `brokered-credentials`, `dlp-outbound`, `input-provenance-tagging`, `least-privilege-tool-scopes`, `memory-write-validation`, `per-user-authorisation`, `rag-source-vetting`, `runtime-policy-enforcement`, `sandboxed-execution`, `session-isolation` |
| high | `behavioural-monitoring`, `untrusted-content-isolation` |

A credential broker in front of the agent's credentials can satisfy `brokered-credentials`, `secrets-out-of-context`, `approval-gates`, `audit-log`, `kill-switch`, `least-privilege-tool-scopes` and `rate-limiting` (see `examples/governed-agent.yaml` upstream).

## Scoring

Inherent severity = likelihood x impact (1 to 5 each, from the catalogue; impact +1 with a `regulated` store in scope). Coverage = weighted share of listed mitigations in place (preventive 1.0, detective 0.6, corrective 0.5). Residual = inherent x (1 - 0.8 x coverage). Bands: critical 20 to 25, high 12 to 19.9, medium 6 to 11.9, low below 6. The residual risk score is 100 x residual total / inherent total of the uncontrolled system; rating critical 75+, high 50+, medium 25+, otherwise low.

## How scan_agent_stack.py maps what it finds

| Detection | Emitted as |
|---|---|
| chat, e-mail, web, document, ticket, repository-issue, calendar libraries | channel of kind `chat`, `email`, `web`, `document`, `api`, `api`, `api`; `trusted: false`; origin `user` for chat, `third-party` otherwise |
| instruction files (CLAUDE.md, .cursorrules, AGENTS.md) | channel `rules-files`, kind `file`, `trusted: false`, origin `internal` |
| vector store | data store `vector-store` plus channel `rag-index` of kind `rag` |
| subprocess, child_process, os.system | tool `shell-exec`, kind `exec`, `sandboxed` from sandbox signals |
| SMTP, Slack, Twilio, nodemailer | tool `send-message`, kind `messaging` |
| database drivers and ORMs | tool `database-access`, kind `write`, `target` the detected store |
| git push, PR creation | tool `repo-write`, kind `write`, store `source-code` |
| cloud SDKs | tool `cloud-api`, kind `write` |
| payment SDKs | tool `payments`, kind `payment` |
| file deletion | tool `file-delete`, kind `write` |
| file reads and search | tool `read-files`, kind `read` |
| requests, fetch, browsers | tool `fetch-url`, kind `network` |
| each MCP server in `.mcp.json` or desktop config | tool `mcp-<name>`, kind guessed from the name, `provider: third-party`, `pinned` from the version spec, `auth` from its env |
| `*_API_KEY`, `*_TOKEN` env vars | `auth: static-key` on tools (or `brokered` when a credential broker is detected) |
| approval, sandbox, limit, kill-switch, audit, credential broker signals | `autonomy`, `sandboxed`, and the controls `sandboxed-execution`, `rate-limiting`, `kill-switch`, `audit-log`, `approval-gates`, `brokered-credentials`, `least-privilege-tool-scopes` |

Everything else (`description`, `owner`, `scope`, `approval`, sensitivities, principals' trust) is a placeholder for the reviewer.
