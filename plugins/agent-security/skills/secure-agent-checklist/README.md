# Secure agent checklist

A pre-ship security checklist for an LLM agent. Claude works through the items in [references/checklist.md](references/checklist.md) (identity, least privilege, approvals, sandboxing, audit, kill switch, supply chain and evals), marks each pass, fail or n.a. with evidence, and writes a go or no-go report in the shape of [references/report-template.md](references/report-template.md). There is no bundled script: the evidence comes from the other skills' reports and from reading the deployment.

Use it before deploying, releasing, open-sourcing or demoing an agent. Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow and the `## Limits` section.

## Where the evidence comes from

| Checklist area | Skill that produces the evidence | Its sample |
|---|---|---|
| Least privilege, supply chain | `agent-config-audit` | [README](../agent-config-audit/README.md) |
| Approvals | `tool-approval-gate-audit`, `prompt-injection-review` | [README](../tool-approval-gate-audit/README.md), [README](../prompt-injection-review/README.md) |
| Evals | `agent-eval-harness` | [README](../agent-eval-harness/README.md) |
| Audit, incident precedents | `agent-session-log-review`, `incident-lookup` | [README](../agent-session-log-review/README.md), [README](../incident-lookup/README.md) |

The report opens with the verdict and the top three fixes, then one row per item, for example (from the template):

```markdown
| Area | Item | Verdict | Evidence | Fix |
|---|---|---|---|---|
| Least privilege | 2.1 No wildcards | fail (critical) | `.claude/settings.json:4` `Bash(*)` (PERM-001) | Replace with specific rules; add deny list |
```
