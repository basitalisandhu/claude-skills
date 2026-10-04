# ADR-NNNN: <decision in one line, active voice>

**Status:** proposed | accepted (<date>, <who>) | deprecated (<date>) | superseded by ADR-NNNN
**Deciders:** <names or team>
**Related:** <ADRs, issues, pull requests, design docs>

## Context

<One paragraph. The problem, the forces (requirements, constraints, numbers: load, data size, team, deadline, existing systems), and why the decision is being made now.>

## Options considered

| Option | Description | Fit to requirements | Operational cost | Team familiarity | Lock-in and maturity | Main risk |
|---|---|---|---|---|---|---|
| 1. <name> | | | | | | |
| 2. <name> | | | | | | |
| 3. Do nothing | | | | | | |

<Optional: a paragraph per option when the table cannot carry the nuance. Link spikes and benchmarks instead of inlining them.>

## Decision

We will <option> because <the two or three forces that decided it>.

<What is explicitly out of scope of this decision.>

## Consequences

- **Easier:** <what this enables>
- **Harder:** <what this costs, honestly>
- **To do:** <follow-up work: migrations, training, tooling, a follow-up ADR>
- **Revisit when:** <the measurable condition that would reopen this decision, and where to watch it>

## Notes

<Dates of discussions, links to the thread, anything a future reader needs to reconstruct the moment.>

---

## Conventions for the directory

- Files: `docs/adr/NNNN-short-slug.md`, zero-padded four digits, never renumbered.
- `0001-record-architecture-decisions.md` records the decision to use ADRs.
- An accepted ADR is immutable except for its status line and links; changes of mind are new ADRs that supersede it.
- An index (`docs/adr/README.md`) lists number, title and status; keep it in the same pull request as the ADR.
