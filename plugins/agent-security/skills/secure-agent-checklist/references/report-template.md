# Agent security review: <agent name>

Date: <YYYY-MM-DD>  
Reviewer: <name or "agent-security plugin, confirmed by <person>">  
Scope: <what runs where, with which credentials, affecting whom>

**Verdict:** <ship | fix first | do not ship>. <one sentence>

**Top fixes**

1. <highest-impact fix, with the item number>
2. <…>
3. <…>

## Results

| Area | Item | Verdict | Evidence | Fix |
|---|---|---|---|---|
| Identity | 1.1 Own credential per agent | pass | broker agent `mailbot`; no shared keys in `.env.example` | |
| Identity | 1.2 Short-lived or brokered | pass | `/v1/token` TTL 120 s | |
| Least privilege | 2.1 No wildcards | fail (critical) | `.claude/settings.json:4` `Bash(*)` (PERM-001) | Replace with specific rules; add deny list |
| … | | | | |

Totals: <n> pass, <n> fail (<n> critical, <n> high), <n> n.a.

## Evidence sources

- `agent-config-audit` report: <path or inline summary>
- `semgrep-agentic` results: <path>
- `prompt-injection-review` inventory: <path>
- `agent-eval-harness` results: <ASR, utility>
- Incident precedents: <ids>

## Notes for the next review

<assumptions made, items to re-check after fixes, owner and date>
