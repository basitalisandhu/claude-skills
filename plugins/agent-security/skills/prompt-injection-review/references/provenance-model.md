# The provenance and approval model

A policy enforcement point (PEP) mediates every proposed tool call with two rules and no model in the enforcement path. In AgentDojo it replaces the tool executor; the same rules fit any agent whose tool calls pass through one place.

## Tiering

Every tool is **regular** (read-only: it changes nothing outside the agent) or **consequential** (it sends, pays, deletes, modifies, executes, shares, schedules). Only consequential calls are checked. Examples from the AgentDojo suites:

| Suite | Consequential tools |
|---|---|
| slack | send_direct_message, send_channel_message, add_user_to_channel, invite_user_to_slack, remove_user_from_slack, post_webpage, get_webpage (fetches a model-chosen URL) |
| banking | send_money, schedule_transaction, update_scheduled_transaction, update_password, update_user_info |
| travel | create_calendar_event, cancel_calendar_event, reserve_hotel, reserve_car_rental, reserve_restaurant, send_email |
| workspace | send_email, delete_email, create_calendar_event, cancel_calendar_event, reschedule_calendar_event, add_calendar_event_participants, append_to_file, create_file, delete_file, share_file |

## Key arguments

Each consequential tool names its **key arguments**: the ones that decide who is affected and how much.

| Tool | Key arguments |
|---|---|
| send_email | recipients, cc, bcc, attachments |
| send_money | recipient, amount |
| send_direct_message | recipient |
| post_webpage, get_webpage | url |
| share_file | file_id, email, permission |
| create_calendar_event | participants, start_time |
| delete_file | file_id |

Two classes inside key arguments:

- **Designators** (fail closed): recipient, recipients, cc, bcc, user_email, email, url, user, participants. Anything that names a party or a destination.
- **Identifiers**: event_id, email_id, file_id, id. Must be identifiers the system returned, or named in the request.

## Pools

As the conversation runs, the PEP keeps three pools of canonical values:

- **request**: the principal's message.
- **typed**: values from typed fields of tool results (ids, addresses in structured fields, numbers). Trusted because the tool, not the text, produced them.
- **free text**: every free-text field of a tool result (body, subject, description, content, reviews, title, text, notes) and every result of a tool whose output is wholly third-party text (get_webpage, read_file, review tools). Untrusted.

Canonicalisation: case, whitespace, URL scheme and `www.`, trailing slash, IBAN spacing, number formatting; comparisons use token boundaries so `bob@x.com` does not match inside `bob@x.com.evil`.

## Rule 1: provenance

For a consequential call, every key argument is checked:

1. A designator value must be present in the request pool or the typed pool. If it is present only in the free-text pool, the call is refused: `designator '<v>' in '<arg>' originates only from untrusted content`.
2. An identifier value must be in the typed pool or the request.
3. Designator-like tokens inside free-text arguments (an e-mail address or URL embedded in a message body) are also checked; a tainted token that is not sourced from the request or typed data fails.

Refusals are logged with the argument and reason. Nothing is sanitised or rewritten; the call simply does not run.

## Rule 2: approval

An oracle principal (in the benchmark, the ground-truth task; in production, the human or a deterministic matcher over the request) approves a consequential action **once** when its key arguments match an action the request entails. A call can be escalated after a provenance failure only when every failing argument matches, exactly, a binding value the request itself contains; a tainted designator inside free text is never approvable.

## Why both

Provenance alone stops the classic exfiltration (an injected address becomes a recipient). Approval alone is worn down by repetition and by arguments the approver cannot verify. Use both. For a review the point is that the rules are cheap, deterministic and testable; measure them on your own suite with `agent-eval-harness`.

## Applying it in a review

For each consequential tool in the system under review, fill:

| Tool | Key arguments | Designators | Identifiers | Free-text args | Where provenance is checked | Where approval is asked |
|---|---|---|---|---|---|---|

A row with designators and no provenance check is a finding. A row with designators, a provenance check and no approval is acceptable for low-impact actions and a finding for payments, deletions and anything irreversible.

## Mapping to incident vectors

| Flow | Incident vector | Typical precedent |
|---|---|---|
| Untrusted text sets a designator | indirect-injection | GitHub MCP toxic agent flow (2025-05), EchoLeak (2025-06), ShadowLeak (2025-09) |
| Model output executed | generated-code | LangChain LLMMathChain (2023-04), Vanna.AI (2024-05) |
| Memory or retrieval carries injected text forward | retrieval-memory | SpAIware (2024-09), CoSnitch (2026-08) |
| Tool description carries instructions | supply-chain, indirect-injection | MCP tool poisoning (2025-04), postmark-mcp (2025-09) |
| Rules file carries instructions | indirect-injection via rules file | Rules File Backdoor (2025-03), Gemini CLI context file (2025-07) |
