# MCP server review

A guided review of an MCP server you wrote or plan to install. Claude reads the server code and answers the questions in [references/checklist.md](references/checklist.md) area by area, then reports a verdict per area with severity and `file:line` evidence. There is no bundled script: the checks need reading code, not pattern matching, so the skill gives no output without a server to read.

Use it before publishing a server, or before enabling a third-party one. Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow and the `## Limits` section.

## What it checks

The checklist has nine areas, each with the severity a failure carries:

1. Transport and binding (critical): stdio unless remote access is needed, loopback binding, `Origin` checks, session ids, TLS.
2. Authentication and authorisation (critical): verified credentials, audience and expiry checks, per-tool scopes, no token passthrough.
3. Tool input validation (high): strict schemas, confined paths, no shell strings, SSRF guards.
4. Tool, resource and prompt descriptions (high): hidden instructions and description changes after install.
5. Secrets (high).
6. Rate limits and resource use (medium).
7. Logging and audit (medium).
8. Error handling (medium).
9. Supply chain and packaging (medium).

For the agent configuration that starts a server (`.mcp.json`), use `agent-config-audit`; its sample output is in [../agent-config-audit/README.md](../agent-config-audit/README.md).
