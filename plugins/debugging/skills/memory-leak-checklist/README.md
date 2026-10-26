# memory-leak-checklist

Diagnose a service whose memory keeps growing or only goes up, with a fixed checklist: confirm it is a real leak and not a cache warming up or fragmentation, measure with heap tools (tracemalloc, objgraph, Node heap snapshots, Go pprof heap, JVM histograms), follow the retaining paths to what holds the objects, and fix the usual causes (unbounded caches, listeners, closures, registries, pools).

Use it when asked "why does memory keep growing?", or when RSS climbs until an OOM kill or restart.
Not for CPU profiles (perf-profile-reader).

Claude follows [SKILL.md](SKILL.md); it is part of the `debugging` plugin (`/plugin install debugging@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/suspects.md`](references/suspects.md), [`references/tools.md`](references/tools.md), and states what it could not check.

## Example requests

- "Our Node service grows by 50MB an hour until the container gets OOM killed. Where do I start?"
- "Is this a real leak or just a cache warming up? RSS keeps climbing in the worker"
- "Python daemon memory only goes up, how do I find what is holding the objects?"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
