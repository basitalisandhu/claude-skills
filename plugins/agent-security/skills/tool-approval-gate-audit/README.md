# Tool approval gate audit

Parses Python agent code with the standard library `ast` module (it never imports or runs it), lists every tool the model can call in the OpenAI Agents SDK, LangChain and LangGraph, crewAI and FastMCP, records the side effects found in each tool body and the approval gate in front of it, and reports tools whose gate is missing, can fail open or has its answer ignored.

Use it before shipping an agent, or to check `needs_approval` and `interrupt` gates against a reviewed policy with `--policy`. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the crewAI fixture agent. Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/tool-approval-gate-audit/scripts/approval_gates.py plugins/agent-security/skills/tool-approval-gate-audit/scripts/fixtures/crewai
```

```markdown
# Tool approval gate audit: `plugins/agent-security/skills/tool-approval-gate-audit/scripts/fixtures/crewai`

Files scanned: 1. Tools: 4 (3 consequential). Findings: 1 high, 1 info.

## Tools

| Tool | Framework | Location | Side effects | Gate |
|---|---|---|---|---|
| `send_newsletter` | crewai | `crew.py:9` | mail: `smtplib.SMTP('mail.example.com')` L14; mail: `smtp.send_message(build_message(subject, body))` L15 | `Task(human_input=True)` (conditional) L45 |
| `cleanup_cache` | crewai | `crew.py:19` | file-delete: `os.remove(path)` L25 | `input(f'Delete {path}? ')` (answer ignored) L24 |
| `lookup_customer` | crewai | `crew.py:30` | read-only | none |
| `update_crm` | crewai | `crew.py:36` | sql-write: `db.execute('UPDATE customers SET status = ? WHERE id = ?', (status, record_id))` L40 | `request_approval(f'update {record_id} to {status}')` L38 |

## Findings

| # | Severity | Id | Tool | Location | Finding | Fix |
|---|---|---|---|---|---|---|
| 1 | high | GATE-RESULT-IGNORED | `cleanup_cache` | `crew.py:19` | input(f'Delete {path}? ') at line 24 discards the answer, so a refusal does not stop the tool | Use the answer: stop the tool (return or raise) unless the approval call says yes. |
| 2 | info | GATE-CONDITIONAL | `send_newsletter` | `crew.py:9` | Task(human_input=True) is a task-level review: check it happens before the tool acts, not after the task's output; read it | Read the condition: it must be deterministic code, fail closed on errors, and cover every consequential argument. |

Findings are leads from static rules. Read each gate in the code before signing off.
```
<!-- sample:end -->

Exit codes: 0 no finding at or above `--fail-on` (default high), 1 findings at or above it, 2 bad input or usage (missing root, unreadable or malformed policy, or with `--strict` a file that does not parse).

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
