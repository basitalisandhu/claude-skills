# Check reference for audit_agent_config.py

Severity in brackets is the default; the scanner lowers it when the context is narrower (for example a risky program with a specific argument pattern).

## Permissions (Claude Code settings.json, Codex config.toml)

| ID | Trigger | Why it matters |
|---|---|---|
| PERM-001 [critical] | `Bash`, `Bash(*)` in `permissions.allow` | Any shell command runs without a prompt |
| PERM-002 [high, medium, low] | A risky program pre-approved: `rm`, `sudo`, `curl`, `wget`, `nc`, `bash`, `eval`, `dd`, `python -c`, … with a wildcard; package managers, cloud CLIs, `git`, `docker` with a wildcard | One injected instruction becomes an executed command |
| PERM-003 [critical, high, medium] | `defaultMode: bypassPermissions`; `dontAsk`/`auto`; `permissionMode` in agent frontmatter; Codex `approval_policy = never` | Removes the human from the loop |
| PERM-004 [medium] | `Write`, `Edit` allowed for every path | The agent can rewrite its own hooks and settings |
| PERM-005 [medium] | `WebFetch`, `WebSearch` allowed for every domain | Exfiltration channel under injection |
| PERM-006 [medium] | A whole MCP server allowed (`mcp__name`, `mcp__name__*`) | Write and delete tools run without a prompt |
| PERM-007 [medium] | `enableAllProjectMcpServers: true` | A cloned repo's `.mcp.json` starts processes automatically |
| PERM-008 [medium] | `disableAllHooks: true` | Guard hooks do not run |
| PERM-009 [high] | An allow rule carries `--dangerously-skip-permissions` or similar | Bypass flag baked into a pre-approval |
| PERM-010 [medium] | `additionalDirectories` includes `/`, `~` or the home directory | Whole-disk read and write scope |
| PERM-011 [low] | Broad allow rules and no deny rules | No backstop for the obvious disasters |

## Hooks (settings hooks, plugin hooks/hooks.json, plugin.json hooks)

| ID | Trigger | Why it matters |
|---|---|---|
| HOOK-001 [medium] | Command or first exec-form argument points at a script that does not exist | The control is absent; failure mode depends on the host |
| HOOK-002 [high, medium] | Hook command uses `curl`, `wget`, `ssh`, `nc`, an `http` hook to a non-loopback URL, or a hook script that can reach the network | Hook input contains commands, paths and prompts |
| HOOK-003 [critical] | A known credential format inside the hook command | Secret in a settings file |
| HOOK-004 [critical] | `curl … \| sh` style in a hook | Remote code on every tool call |
| HOOK-005 [low] | Shell-form hook with unquoted `${CLAUDE_PLUGIN_ROOT}` | Breaks on paths with spaces; validator warns |
| HOOK-006 [high] | Hook script is world-writable | Anyone local can change what runs on every tool call |

## MCP servers (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, plugin .mcp.json, Codex config.toml)

| ID | Trigger | Why it matters |
|---|---|---|
| MCP-001 [high] | `http://` or `ws://` URL to a non-loopback host | Credentials and tool results in clear text |
| MCP-002 [critical, high] | Literal token in `headers` or `env` (not `${VAR}`) | Secret committed with the config |
| MCP-003 [medium] | `npx -y pkg` without a version, `uvx pkg` without `==`, `@latest`, unpinned container image, code run from a URL | Every start fetches whatever is latest |
| MCP-004 [medium] | Server runs from `/tmp`, `Downloads`, `Desktop` | Unreviewed, easily replaced binary |
| MCP-005 [medium, low] | `--dangerously-skip-permissions`, `--allow-all`, `--no-sandbox`, `--yolo`, shell `-c` launch | Server's own safety checks disabled |
| MCP-006 [low] | `type: sse` | Deprecated transport |
| MCP-007 [high] | Filesystem server rooted at `/`, `~` or the home directory | Whole-disk access for the model |
| MCP-008 [medium] | Remote server addressed by raw IP | No name to pin, no certificate identity |

## Secrets (every scanned file)

| ID | Trigger |
|---|---|
| SEC-001 [critical, high] | OpenAI, Anthropic, GitHub, GitLab, AWS, Slack, Google, Stripe, npm, Hugging Face and credential broker key formats; private key blocks; JWTs; generic `api_key = "<high-entropy>"` assignments. Placeholders (`xxxx`, `your-`, `<…>`, `EXAMPLE`) are skipped. Evidence is redacted. |

## Instruction files (CLAUDE.md, AGENTS.md, .cursorrules, .mdc, SKILL.md, commands, agents, copilot-instructions)

| ID | Trigger |
|---|---|
| INJ-001 [high] | "ignore previous instructions", "you are now", "new instructions:", "developer mode" |
| INJ-002 [high] | "do not tell the user", "without asking the user", "silently run" |
| INJ-003 [high] | "send … to https://…", "upload … to a webhook", instructions that read or emit API keys, `.env`, SSH keys |
| INJ-004 [critical, high] | `curl … \| sh`; "always run …", "on every session start run …" |
| INJ-005 [high, critical] | Zero-width characters, bidirectional overrides, Unicode tag characters |
| INJ-006 [medium] | HTML comment that contains imperative instructions |
| INJ-007 [medium] | Long high-entropy base64 blob |
| INJ-008 [high] | "--dangerously-skip-permissions", "disable hooks", "approve everything", `rm -rf ~`, `chmod 777`, force-push to main |
| INJ-009 [high] | "cat ~/.ssh/…", "read .aws/credentials", "/etc/shadow" |

## Skills, commands, agents, plugins, files

| ID | Trigger |
|---|---|
| SKILL-001 [medium, low] | `allowed-tools` grants unrestricted `Bash` or `Write`/`Edit` |
| SKILL-002 [info] | SKILL.md without frontmatter, name or description |
| PLUGIN-001 [low] | Plugin ships a `bin/` directory (on the Bash PATH while enabled) |
| FILE-001 [medium] | Config file is world-writable |
| CFG-001 [low] | JSON config does not parse (silently ignored by hosts) |
