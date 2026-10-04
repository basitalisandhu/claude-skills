# agent-incidents MCP server

A read-only MCP server over the [ai-agent-incidents](https://github.com/basitalisandhu/ai-agent-incidents) dataset bundled with the `agent-security` plugin (records follow its `schema/incident.schema.json`). Stdio transport only: it never opens a port and never makes a network request. It reads one JSON file at start-up (`AGENT_INCIDENTS_DATA`, or the plugin's bundled `data/incidents.json`).

Tools:

| Tool | What it does |
|---|---|
| `search_incidents` | Filter by the coded fields, `vendor`, `product`, `framework`, `owasp_agentic`, `owasp_llm`, `mitre_atlas`, `tag`, `status`, `since`, `until`, `cve_only`, `adversarial`, `query`, `limit`; returns mappings, affected and the primary source |
| `get_incident` | One record in full, by id (`"030"` or `"30"`) |
| `stats` | Counts by any coded field, `year`, `status`, `vendor`, `product`, `framework`, `owasp_agentic`, `owasp_llm`, `mitre_atlas` or `tag`, with optional filters |

Build and test (offline after `npm install`):

```bash
npm install
npm run build
npm test
```

The plugin declares the server in `plugins/agent-security/.mcp.json`. After installing the plugin, run `npm install && npm run build` in this directory once; the server then appears in `/mcp` as `plugin:agent-security:agent-incidents` and its tools as `mcp__plugin_agent-security_agent-incidents__<tool>`.

Outside the plugin, install the published package `@basitalisandhu/agent-incidents-mcp` from GitHub Packages (`npx -y @basitalisandhu/agent-incidents-mcp@0.1.1`, with the `@basitalisandhu` scope pointed at `https://npm.pkg.github.com`) or run the image `ghcr.io/basitalisandhu/agent-incidents-mcp:0.1.1` with `docker run --rm -i`. Both carry a copy of the dataset snapshot (`data/incidents.json`, added by `prepack` and by the Dockerfile at the repository root) and use it when it is present. See the repository README for the token setup and the verify commands.

To use a fresher dataset than the bundled snapshot, fetch `https://raw.githubusercontent.com/basitalisandhu/ai-agent-incidents/main/site/incidents.json` yourself and point `AGENT_INCIDENTS_DATA` at the file.
