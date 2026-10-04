# Refactor plan: <target path or feature>

**Requested by / why:** <the feature or defect this unblocks>
**Scope:** <paths in>; <paths explicitly out>
**Behaviour contract:** <what must not change: public API, outputs, side effects, performance envelope>

## Before

| Measure | Value | Command |
|---|---|---|
| Functions over CC 10 | | `complexity-report <path>` |
| Probably-dead symbols | | `dead-code-finder <path>` |
| Modules without a test | | `test-gap-finder <path>` |
| Lines in the largest file | | `wc -l` |
| Known circular imports | | import graph or tool output |

## Safety net

- Existing tests: `<command>`, <n> passing.
- Characterisation tests to add: <file>, covering <inputs>.
- Manual check (only if automation is impossible): <what to run, expected output>.

## Steps

Each step is one commit. Every step leaves the code compiling and the tests green.

| Step | Move | What changes | Files | Tests to run | Expected size | Revert |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |

## Not in scope (behaviour changes to do afterwards)

- <item, with issue link>

## After

| Measure | Before | After |
|---|---|---|
| | | |

**Follow-ups:** <what the refactor revealed but did not fix>
