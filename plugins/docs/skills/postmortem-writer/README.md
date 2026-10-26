# postmortem-writer

Write a blameless incident postmortem from the timeline, logs, chat transcript and metrics: impact with numbers, a minute-by-minute timeline, contributing causes found with a structured analysis rather than a single root cause, what went well and what did not, and action items with owners, deadlines and a check that they would have prevented or shortened the incident.

Use it when asked to "write up what went wrong" after an outage, a data incident, a security event or a serious near-miss.
Not for bug reports (use bug-repro-minimiser) and not for performance reviews of people.

Claude follows [SKILL.md](SKILL.md); it is part of the `docs` plugin (`/plugin install docs@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/analysis.md`](references/analysis.md), [`references/template.md`](references/template.md), and states what it could not check.

## Example requests

- "Write up what went wrong in yesterday's outage, I have the timeline and Slack export"
- "Draft a blameless postmortem for the data loss incident with impact numbers and action items"
- "We nearly leaked customer data last week. Turn these notes into an incident review"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
