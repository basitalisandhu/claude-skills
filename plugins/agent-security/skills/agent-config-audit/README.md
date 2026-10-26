# Agent configuration audit

Scans the agent configuration in a project (`.claude/settings*.json`, `.mcp.json`, `CLAUDE.md`, `.cursor` rules, hooks, skills and plugins) for risky permissions, leaked secrets, unpinned MCP servers and hidden instructions. The bundled scanner is read-only, uses the standard library only and masks every secret it reports.

Run it before you trust a cloned repository, before committing agent settings, or in CI with `--fail-on high`. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the bundled bad configuration used by the Semgrep rule tests (the first 26 lines; the Root line is shortened). Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/agent-config-audit/scripts/audit_agent_config.py --root plugins/agent-security/skills/semgrep-agentic/rules/tests/config-bad --format markdown
```

```markdown
# Agent configuration audit

Root: `<path>`
Generated: <timestamp>
Files scanned: 2

| Severity | Count |
|---|---|
| critical | 2 |
| high | 2 |
| medium | 1 |
| low | 1 |
| info | 0 |

Total findings: 6

| ID | Severity | Title | File | Line | Evidence |
|---|---|---|---|---|---|
| PERM-003 | critical | defaultMode is bypassPermissions | `.claude/settings.json` | 3 | `"defaultMode": "bypassPermissions"` |
| PERM-001 | critical | Any shell command is pre-approved | `.claude/settings.json` | 5 | `Bash(*)` |
| MCP-001 | high | MCP server plain uses plain HTTP | `.mcp.json` | 3 | `http://mcp.example.com/mcp` |
| MCP-002 | high | Literal credential in headers.Authorization of MCP server plain | `.mcp.json` | 3 | `headers.Authorization: Bearer abcd****` |
| MCP-003 | medium | MCP server unpinned runs an unpinned npm package | `.mcp.json` | 10 | `npx -y @scope/some-server` |
| PERM-011 | low | Broad allow rules with no deny rules | `.claude/settings.json` |  | `permissions.deny is empty` |

## Recommendations
...
```
<!-- sample:end -->

Exit codes: 0 report written, 1 with `--fail-on SEVERITY` when a finding at or above that severity exists. A malformed settings value (a number where a list belongs) is ignored rather than crashing the scan.

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
