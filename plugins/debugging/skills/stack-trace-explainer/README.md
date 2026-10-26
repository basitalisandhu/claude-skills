# stack-trace-explainer

Explain a stack trace, traceback, panic or crash from Python, JavaScript and Node, Java and the JVM, Go, Rust, .NET, Ruby or PHP: which frame holds the real fault versus where it surfaced (including a Caused by chain), what the error type means, and what to check next.

Use it when someone pastes a traceback or an error such as a TypeError and asks "what does this error mean?", to explain a trace, why a program panicked, or where to look first.
Not for profiles (perf-profile-reader) or logs with no trace (log-triage).

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/formats.md`](references/formats.md), and states what it could not check.

## Example requests

- "What does this mean? TypeError: Cannot read properties of undefined (reading 'map') at renderList"
- "Pasting a Java trace with a long Caused by chain, which frame is the real problem?"
- "Rust panicked with index out of bounds, where do I look first?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
