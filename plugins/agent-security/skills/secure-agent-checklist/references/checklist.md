# The checklist

Verdicts: `pass` (verified with evidence), `fail` (verified absent, or could not be verified), `n.a.` (does not apply; say why). Rating in brackets is the severity of a `fail`.

## 1. Identity

| # | Item | Verify by | Evidence to cite |
|---|---|---|---|
| 1.1 [high] | Each agent (and each deployment of it) has its own credential; none is shared with humans or other services | List every credential the agent holds and where else it is used | env files, secret manager entries, the broker's agent list |
| 1.2 [high] | Credentials are short-lived or brokered, not long-lived API keys in the agent's environment | Check whether tokens expire in minutes (a credential broker's token endpoint, STS, OAuth) or never | token issuance code, broker policies |
| 1.3 [medium] | The agent's identity is visible downstream (user-agent, principal, audit `sub`) | Make one call and find it in the upstream's log | log excerpt |
| 1.4 [medium] | Rotation is one command and was exercised once | Rotate in staging | runbook line, `rotate-key` output |

## 2. Least privilege

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 2.1 [critical] | No wildcard permission: no `Bash(*)`, `crm:*`, `*`, admin tokens, root filesystem mounts | `agent-config-audit` PERM-*, MCP-007; the broker's policy linter, if it has one | finding ids |
| 2.2 [high] | Reads and writes are separate scopes or connectors; writes are the exception | Count scopes per method | policy table |
| 2.3 [high] | Each tool exposes the minimum arguments; destructive tools are absent unless required | `prompt-injection-review` inventory: consequential tools list | inventory table |
| 2.4 [medium] | Network egress is allowlisted (domains, no raw IPs, HTTPS only) | Egress config, `warn-insecure-fetch` hook enabled, WebFetch domain rules | config excerpt |
| 2.5 [medium] | The agent cannot modify its own instructions, hooks or permissions | Deny rules on `.claude/`, `.git/hooks`, instruction files; broker policy gating writes to `<project>/.claude/*` | deny list |

## 3. Approvals

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 3.1 [critical] | Every consequential action (send, pay, delete, deploy, push, exec outside sandbox) needs a human or a deterministic policy before it runs | Map consequential tools to the gate that fronts them | tool to gate table |
| 3.2 [high] | The approver sees who, what, why (purpose) and the exact arguments | Trigger one approval in staging | screenshot or request JSON |
| 3.3 [high] | Designators in consequential calls (recipients, URLs, amounts, ids) are sourced from the user's request or typed tool results, never only from third-party text | Provenance rule in the PEP or executor; eval evidence | `prompt-injection-review` findings, eval ASR |
| 3.4 [medium] | Approvals are single-use where the action is one-off; tokens do not outlive the task | single-use broker tokens, TTLs under 10 min for writes | policy table |
| 3.5 [medium] | The agent cannot approve its own requests (separate roles) | Operator roles | operator list |

## 4. Sandboxing

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 4.1 [critical] | Model-generated code and shell commands run in a sandbox with no production credentials | Where `exec`, `subprocess`, `child_process` run; `semgrep-agentic` llm-output-to-exec-eval, llm-output-to-subprocess, agent-tool-param-to-shell | rule hits, sandbox config |
| 4.2 [high] | Filesystem scope is the project, not the home directory or root | Mounts, filesystem MCP roots, `additionalDirectories` | config |
| 4.3 [high] | Sandbox egress is denied by default | Network policy of the sandbox | policy |
| 4.4 [medium] | Resource limits: time, memory, iterations, tokens, cost | `max_turns`, timeouts, budget ledger | code or config |

## 5. Audit

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 5.1 [high] | Every tool call is logged with agent id, tool, arguments summary, decision and purpose | Read one day of logs | log excerpt |
| 5.2 [high] | Logs never contain secrets or full file contents | Grep logs for key formats | grep output |
| 5.3 [medium] | The log is tamper-evident or shipped off the host (hash chain, signed checkpoints, forwarder) | the log's own verify command, SIEM forwarder | verify output |
| 5.4 [medium] | Someone reads the log: alert on denials, kills, approvals outside hours | Alert rule | rule |

## 6. Kill switch

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 6.1 [critical] | One action stops the agent and revokes its live tokens, and it was tested | the broker's kill endpoint, feature flag, revocation list | runbook, test date |
| 6.2 [high] | The person on call knows the action and has the right to take it | Runbook, role | runbook link |
| 6.3 [medium] | Compromise of the agent key is recoverable: kill, rotate, redeploy, upstream rotation for leased secrets | Runbook | runbook |

## 7. Supply chain

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 7.1 [high] | MCP servers, skills, plugins and packages are pinned to versions or digests | `agent-config-audit` MCP-003; lockfiles | finding ids |
| 7.2 [high] | Tool descriptions and instruction files from third parties were read in full before enabling | `prompt-injection-review` description check; `agent-config-audit` INJ-* | finding ids |
| 7.3 [medium] | Models and datasets are loaded from verified sources (safetensors, signatures) | `semgrep-agentic` pickle-load-model-file, torch-load-without-weights-only, transformers-trust-remote-code | rule hits |
| 7.4 [medium] | CI runs the config audit and Semgrep pack on every change | workflow file | path |

## 8. Evals

| # | Item | Verify by | Evidence |
|---|---|---|---|
| 8.1 [high] | A security eval exists with benign tasks and injection tasks against this agent's tools | `agent-eval-harness` suite | suite file |
| 8.2 [high] | Attack success rate under the chosen policy is measured and acceptable, and benign utility is reported alongside | eval results | ASR, utility numbers |
| 8.3 [medium] | The eval runs in CI or before every prompt or tool change | workflow | path |
| 8.4 [low] | Incident precedents for this design were reviewed and mapped to controls | `incident-lookup precedents` | output |
