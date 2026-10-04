---
description: Query the AI agent incident dataset (vector, outcome, vendor, framework, OWASP or ATLAS id, channel, authority, date) or rank precedents for a design
argument-hint: <filters or a design description>
allowed-tools: Bash(python3 *)
---

Answer `$ARGUMENTS` from the AI agent incident dataset using the `incident-lookup` skill.

Decide the query shape from the request:

- A design or feature ("an agent that reads tickets and can refund"): map it to `channel_in`, `authority` and `vector` values and run `precedents`.
- A topic, vendor, product, framework, OWASP or ATLAS id, vector or date range: run `list` with the matching filters.
- A specific event or id: run `show`.
- "How common" or "how many": run `stats`.

```bash
S="${CLAUDE_PLUGIN_ROOT}/skills/incident-lookup/scripts/incidents.py"
python3 "$S" fields                                    # vocabulary, vendors, frameworks, mapping ids
python3 "$S" list --vector indirect-injection --since 2025-01 --format markdown
python3 "$S" list --owasp-agentic ASI01 --framework MCP
python3 "$S" precedents --channel-in "support ticket" --authority database --limit 8
python3 "$S" show 037
python3 "$S" stats --by owasp_agentic
```

Add `--offline` if the user does not want any network access; the script otherwise refreshes its cache once a day and falls back to the bundled snapshot on any failure.

Reply with the skill's output format: a short answer first, then the table with dates, names, outcomes, OWASP Agentic ids and primary source URLs, then the controls that would have helped. Cite only what the records say, and mention a record's `status` when it is not `confirmed`.
