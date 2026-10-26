# Semgrep agentic

Scans Python, JavaScript and TypeScript agent code with Semgrep rules written for agents: model output reaching shells, SQL, file paths or HTML, user input in system prompts, MCP servers without authentication and leaked provider keys. It also bundles config rules for `.claude/settings.json` and `.mcp.json`, and an offline copy of the rules for when the upstream set cannot be fetched. Claude then triages the hits.

Use it for the code step of an agent security audit, or to add agent rules to CI. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow, the rule sources and the `## Limits` section; this page is the short version.

## Run it

Semgrep 1.179 or later must be installed (`pip install semgrep`). Sample: the bundled config rules on the bad configuration fixture, run with Semgrep 1.179.0 from `plugins/agent-security/skills/semgrep-agentic/rules` (the first findings of five):

```bash
semgrep --metrics=off --config agentic-config.yaml tests/config-bad/.claude/settings.json tests/config-bad/.mcp.json --text
```

```text


┌─────────────────┐
│ 5 Code Findings │
└─────────────────┘

    tests/config-bad/.claude/settings.json
   ❯❯❱ agentic.config.bypass-permissions-default
          ❰❰ Blocking ❱❱
          defaultMode bypassPermissions removes every permission prompt, including for destructive commands.
          Use default or acceptEdits and allowlist what you need.

            3┆ "defaultMode": "bypassPermissions",

   ❯❯❱ agentic.config.bash-wildcard-allowed
          ❰❰ Blocking ❱❱
          permissions.allow pre-approves every shell command. One prompt injection then runs anything without
          a prompt. List specific commands instead (Bash(npm test), Bash(git status *)) and add deny rules.
    tests/config-bad/.mcp.json
    ❯❱ agentic.config.mcp-plain-http
...
```

Test the rules themselves with `semgrep --metrics=off --test --config agentic-python.yaml tests/agentic-python.py` (and the JavaScript pair); CI runs both on every pull request.
