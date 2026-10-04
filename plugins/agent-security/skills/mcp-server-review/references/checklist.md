# MCP server review checklist

Severity in brackets is for a `fail`. "Verify" says what to look at in code; "Fix" is the standard remedy.

## 1. Transport and binding [critical]

| Question | Verify | Fix |
|---|---|---|
| Is stdio the transport unless remote access is a requirement? | `StdioServerTransport` / `mcp.run()` vs an HTTP listener | Prefer stdio; the host spawns the process and no socket exists |
| If HTTP: does it bind 127.0.0.1 by default? | `listen(port, host)`, `uvicorn.run(host=...)`, `FastMCP(host=...)` | Bind loopback; put a reverse proxy with TLS in front for remote use |
| Does it validate the `Origin` header and reject unexpected origins (DNS rebinding)? | Middleware on the HTTP transport; SDK `enableDnsRebindingProtection`, `allowedHosts`, `allowedOrigins` | Enable the SDK protection or add an explicit check |
| Are session ids unguessable and bound to the authenticated client? | `sessionIdGenerator`, session store | Use the SDK generator; never accept client-chosen ids |
| Is TLS terminated somewhere for any non-loopback traffic? | Deployment config | TLS at the proxy; refuse plain HTTP |

## 2. Authentication and authorisation [critical]

| Question | Verify | Fix |
|---|---|---|
| Does every remote request carry a credential the server verifies (OAuth 2.1 bearer, API key)? | Auth middleware; `requireBearerAuth`; token verification against the issuer | Add auth before any tool handler runs |
| Are tokens validated for audience (this server), expiry and signature, not just presence? | Verifier code | Check `aud`, `exp`, signature; reject tokens issued for other servers (no token passthrough) |
| Is authorisation per tool, not per server (read tools vs write tools)? | Scope checks in handlers | Map scopes to tools; deny by default |
| Does the server never forward the client's token upstream? | Outbound calls | Use the server's own credential for upstreams; or a credential broker lease |

## 3. Tool input validation [high]

| Question | Verify | Fix |
|---|---|---|
| Every tool has a strict input schema (types, bounds, enums, max lengths)? | `inputSchema` / `zod` / pydantic models | Add bounds; reject unknown fields |
| Paths are canonicalised and confined to an allowed root? | `path.resolve` + prefix check; `os.path.realpath`; no `..`, no symlink escape | Resolve then check `startsWith(root + sep)` |
| Shell commands are never built from arguments? | `exec`, `spawn(shell)`, `subprocess(shell=True)`, `os.system` | `execFile`/`spawn` with argv; allowlist programs |
| SQL and query languages are parameterised? | String concatenation into queries | Parameters or a query builder |
| URLs from arguments are allowlisted by host, resolved to public addresses, with redirects disabled (SSRF)? | `fetch(url)`, `requests.get(url)` on an argument | Host allowlist; block private and link-local ranges including 169.254.169.254; `redirect: "manual"` |
| Output size is bounded (files, HTTP bodies, query results)? | Read limits | Cap bytes and rows; truncate with a marker |

## 4. Tool, resource and prompt descriptions [high]

| Question | Verify | Fix |
|---|---|---|
| Descriptions state what the tool does and nothing else (no instructions to the model, no "always", "ignore", "before calling")? | Read every description string | Rewrite as plain statements |
| No hidden content: HTML comments, zero-width or bidi characters, very long descriptions, base64? | `agent-config-audit` INJ-005, INJ-006, INJ-007 on the source; `tool_inventory.py` flags | Remove |
| Descriptions are static (not fetched at runtime, not changed after first `tools/list`)? | Where descriptions come from | Hard-code; version the server |
| Resource contents returned to the model are labelled as data, not instructions? | Resource handlers | Wrap third-party content; strip instruction-like text where feasible |
| Tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) are accurate? | `annotations` on each tool | Set them honestly; hosts gate on them |

## 5. Secrets [high]

| Question | Verify | Fix |
|---|---|---|
| Credentials come from the environment or a broker, never from source or config literals? | `grep` for key formats; `agent-config-audit` SEC-001 | Env or a credential broker lease; rotate anything found |
| Secrets never appear in tool results, error messages or logs? | Error handlers, `console.error`, logging calls that print config or env | Redact; log identifiers not values |
| The server does not expose a tool that reads arbitrary env vars or files outside its root? | Tool list | Remove or confine |
| Credentials are scoped to the server's job (read-only token for a read-only server)? | Upstream token scopes | Narrow; split servers by write capability |

## 6. Rate limits and resource use [medium]

| Question | Verify | Fix |
|---|---|---|
| Per-client and per-tool rate limits exist for remote servers? | Middleware | Add limits; return a `Retry-After` |
| Concurrency, timeouts and memory are bounded (no unbounded buffering)? | Handlers, upstream timeouts | Timeouts on every outbound call; stream or cap |
| Expensive or destructive tools are rate-limited more tightly than reads? | Limits by tool | Tier the limits |

## 7. Logging and audit [medium]

| Question | Verify | Fix |
|---|---|---|
| Every tool call is logged with client identity, tool, argument summary and outcome? | Logging in the call path | Add structured logs |
| Logs are secret-free (arguments can contain tokens, bodies can contain keys)? | Redaction in the logger | Redact known formats; truncate |
| Stdout is reserved for the protocol on stdio servers (logs go to stderr)? | `console.log` in a stdio server | Use `console.error` or a logger bound to stderr |

## 8. Error handling [medium]

| Question | Verify | Fix |
|---|---|---|
| Tool errors return `isError: true` with a safe message, not stack traces or internal paths? | Error branches | Map to short messages |
| Unexpected exceptions cannot crash the server into an inconsistent state (half-written files, open transactions)? | Try/finally around state changes | Transactional writes |

## 9. Supply chain and packaging [medium]

| Question | Verify | Fix |
|---|---|---|
| Dependencies are minimal and pinned with a lockfile? | `package.json`, lockfile, `pyproject` | Lock; audit |
| No `postinstall` scripts, no runtime downloads of code? | `package.json` scripts; `deno run https://` | Remove |
| The published artefact matches the source (build in CI, provenance or signature)? | Release workflow | Build in CI; sign |
| The server documents exactly what it can touch (files, hosts, credentials) so an installer can decide? | README | Write the "what this server can touch" section |

## Quick wins for a stdio-only local server

Most local servers only need: strict input schemas, confined paths, no shell string building, no secrets in logs, honest tool descriptions and annotations, pinned dependencies. The transport and auth sections become `n.a.` when the server never opens a socket; say so explicitly in the report.
