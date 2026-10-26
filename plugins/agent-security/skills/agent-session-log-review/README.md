# Agent session log review

Reads one agent session (a Claude Code transcript, a chat messages export or generic JSON event lines), normalises it into prompts, tool calls, tool results and messages, and flags events with fixed structural rules: values that reached a consequential call only through untrusted content, denied actions retried another way, destructive commands, writes outside the root, network calls to unknown hosts and secrets in the session.

Use it after a suspicious run, or before trusting what an agent says it did. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the bundled synthetic session `references/example-session.jsonl` (summary and flag table). Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/agent-session-log-review/scripts/review_session_log.py plugins/agent-security/skills/agent-session-log-review/references/example-session.jsonl
```

```markdown
## Agent session log review: example-session.jsonl

**Summary:** 14 events (6 tool calls), 5 flags: 1 critical, 3 high, 1 medium.

### Flags

| # | Event | Time | Severity | Flag | Tool | Finding | Evidence |
|---|---|---|---|---|---|---|---|
| 1 | 2 | 2026-10-05T09:00:03Z | medium | EGRESS-NETWORK | WebFetch | Network call to a host not on the allow list | github.com |
| 2 | 6 | 2026-10-05T09:00:14Z | high | TOOL-DENIED-RETRY | Read | Denied action retried with a different tool | Bash was denied; Read then targeted .env |
| 3 | 7 | 2026-10-05T09:00:14Z | high | EGRESS-SECRET | Read | Secret-shaped string in the session | in a tool result: AWS_ACCESS_KEY_ID=[masked secret] DEBUG=1 |
| 4 | 8 | 2026-10-05T09:00:18Z | critical | INJ-PROVENANCE | Bash | Tool call uses a value that came only from untrusted content | collector.example.net (from event 3) |
| 5 | 8 | 2026-10-05T09:00:18Z | high | EGRESS-NETWORK | Bash | Network call to a host not on the allow list carrying data | collector.example.net |
...
```
<!-- sample:end -->

Exit codes: 0 no flag at or above `--fail-on` (default high), 1 flags to review, 2 bad input (unreadable or non-UTF-8 file, unknown shape).

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
