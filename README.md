# Claude Code skills: every skill I maintain, in one repository

[![ci](https://github.com/basitalisandhu/claude-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/basitalisandhu/claude-skills/actions/workflows/ci.yml)
[![pages](https://github.com/basitalisandhu/claude-skills/actions/workflows/pages.yml/badge.svg)](https://basitalisandhu.github.io/claude-skills/)
[![licence](https://img.shields.io/github/license/basitalisandhu/claude-skills)](LICENSE)
<!-- count-badge:start -->[![87 skills in 13 plugins](https://img.shields.io/badge/skills-87%20in%2013%20plugins-2E6BFF)](#catalog)<!-- count-badge:end -->

**87 skills in 13 plugins, from 8 source repositories, as of 2026-10-04.**

This repository collects every Claude Code skill I maintain. Clone it once and you have all of them. It is also one Claude Code plugin marketplace, so you can install any plugin from it by name. The numbers above are a snapshot; the [catalog](#catalog) below is regenerated on every sync and is the live count.

Browse the skills on the site: <https://basitalisandhu.github.io/claude-skills/>

## What it is

- A copy of the plugin folders from 8 source repositories, under `plugins/<plugin>/`.
- A marketplace file, `.claude-plugin/marketplace.json`, named `claude-skills`.
- `install.py`, which copies skills into a Claude Code skills folder without the plugin system.
- `catalog.json` and `SOURCES.json`, which say what is here and which commit it came from.

It is for people who use Claude Code and want security, cloud, compliance, GitHub, repository and everyday development skills from one place. Each skill is a `SKILL.md` file. Most also bundle a small Python script.

Why one repository: one clone, one marketplace to add, one place to search. The skills are still written and tested in their own repositories. This one only syncs them.

## Install

### 1. As a plugin marketplace (recommended)

In Claude Code:

```text
/plugin marketplace add basitalisandhu/claude-skills
/plugin install aws-security@claude-skills
```

Replace `aws-security` with any plugin name from the [catalog](#catalog). This route also loads plugin-level hooks, commands, agents and MCP servers, and keeps `${CLAUDE_PLUGIN_ROOT}` script paths in the skills working.

### 2. Clone and copy the skills

```bash
git clone https://github.com/basitalisandhu/claude-skills
cd claude-skills
python3 install.py --user
```

`--user` copies every skill into `~/.claude/skills/`. Other options:

| Command | What it does |
| --- | --- |
| `python3 install.py --project` | Copies into `./.claude/skills/` of the directory you run it from |
| `python3 install.py --list` | Lists plugins and skills, with the name each installs as |
| `python3 install.py --user --only <plugin>` | One plugin; repeat `--only` for more |
| `python3 install.py --user --skill <plugin>/<skill>` | One skill; repeat for more |
| `python3 install.py --user --dry-run` | Shows what would happen and writes nothing |
| `python3 install.py --user --force` | Also overwrites skill folders the script did not write |
| `python3 install.py --user --prefix` | Installs every skill as `<plugin>-<skill>` |
| `python3 install.py --user --uninstall` | Removes exactly the files the script wrote |

It needs Python 3.10 or newer and nothing else. It works on macOS, Linux and Windows.

The script writes `.claude-skills-manifest.json` in the target folder. That file lists every file it wrote. Updates and `--uninstall` only remove files on that list. If a skill folder already exists and the script did not write it, the script skips it unless you pass `--force`.

If two plugins ever ship a skill with the same name, the first in plugin name order installs under the plain name and the second as `<plugin>-<skill>`. The script says so when it happens. Today every skill name is unique, and `scripts/validate.py` fails the build if that changes.

The copy route installs skills only. Plugin-level hooks, commands, agents and MCP servers need the marketplace route. Some skills call their script as `${CLAUDE_PLUGIN_ROOT}/skills/<skill>/scripts/...`; after a copy install the script is in the skill's own `scripts/` folder instead.

### 3. Other agents

Other agents that read the Agent Skills format can install from this repository with `npx skills add basitalisandhu/claude-skills`.

## When to use this

Use this repository when you want many of these skills, or want to browse them all in one place.

Go to a single source repository instead when you want only that pack, want to file an issue, or want to read its tests. The source of each plugin is linked in the catalog and in [SOURCES.json](SOURCES.json).

## Catalog

<!-- catalog:start -->

**87 skills in 13 plugins.** 118 bundled script files. Generated from `catalog.json` by `scripts/sync.py`.

### agent-security

Version 0.1.1. Source: [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills). Install: `/plugin install agent-security@claude-skills`. Also ships plugin-level hooks, commands, agents and an MCP server (marketplace route only).

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| agent-config-audit | Audit AI-agent configuration for risky permissions, leaked secrets, unpinned MCP servers and prompt-injection in instruction files. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/agent-config-audit/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/agent-config-audit/SKILL.md) |
| agent-eval-harness | Set up AgentDojo-style security evaluations for an agent: benign user tasks, injection tasks planted in tool results, utility and attack-success-rate metrics, and a policy hook (provenance, approval) in the tool executor. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/agent-eval-harness/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/agent-eval-harness/SKILL.md) |
| agent-threat-model | Write a system description of an LLM-agent codebase in the agent-threat-model YAML format (principals, agents, channels, tools, data stores, controls), validate it with atm validate, run atm analyse for a STRIDE and OWASP threat model with residual risk scoring, then interpret and summarise the result with incident precedents. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/agent-threat-model/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/agent-threat-model/SKILL.md) |
| incident-lookup | Look up real AI agent security incidents, vulnerability disclosures and threat reports (80 coded events, 2023 to 2026, mapped to OWASP Agentic Top 10, OWASP LLM Top 10 and MITRE ATLAS) and summarise precedents for a design. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/incident-lookup/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/incident-lookup/SKILL.md) |
| mcp-server-review | Checklist-driven security review of an MCP server implementation (TypeScript or Python) covering authentication, transport binding and origin checks, input validation, tool description poisoning, resource and path handling, SSRF, rate limits and secret-free logging, with a Semgrep pass. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/mcp-server-review/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/mcp-server-review/SKILL.md) |
| prompt-injection-review | Trace untrusted inputs (web pages, emails, documents, tickets, repo issues, tool results, retrieved memory) to consequential tool calls in an agent codebase and judge each flow with deterministic provenance and approval rules. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/prompt-injection-review/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/prompt-injection-review/SKILL.md) |
| secure-agent-checklist | Pre-ship security checklist for an LLM agent covering identity, least privilege, approvals, sandboxing, audit, kill switch, supply chain and evals, producing a markdown report with pass, fail or n.a. per item and the evidence behind each verdict. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/secure-agent-checklist/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/secure-agent-checklist/SKILL.md) |
| semgrep-agentic | Run the agentic-semgrep-rules pack (36 rules for Python, JavaScript and TypeScript agent code: model output reaching exec, shells, SQL, URLs, file paths and HTML; user input in system prompts; tool parameters reaching shells and paths; MCP servers without auth or bound to every interface; leaked provider keys; unsafe model and config loading) against a repository, fall back to the bundled offline rules, and triage the results. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/agent-security/semgrep-agentic/) · [source](https://github.com/basitalisandhu/agent-security-skills/blob/main/plugins/agent-security/skills/semgrep-agentic/SKILL.md) |

### aws-security

Version 0.2.0. Source: [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills). Install: `/plugin install aws-security@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| agent-safe-aws-access | Set up least-privilege, auditable AWS access for an AI coding agent, or review an existing agent role. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/agent-safe-aws-access/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/agent-safe-aws-access/SKILL.md) |
| aws-account-audit | Read-only security audit of one AWS account. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/aws-account-audit/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/aws-account-audit/SKILL.md) |
| aws-incident-response-runbook | Produce a step-by-step AWS incident response runbook in Markdown for one of six scenarios (leaked access key, compromised EC2 instance, public S3 bucket exposure, suspicious IAM activity, ransomware against S3 or EBS, crypto-mining), filled in with the account, region and resource identifiers. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/aws-incident-response-runbook/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/aws-incident-response-runbook/SKILL.md) |
| aws-spend-guardrails | Generate AWS spend guardrails and check exported cost data against them. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/aws-spend-guardrails/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/aws-spend-guardrails/SKILL.md) |
| iam-least-privilege-review | Review AWS IAM policy documents offline for over-broad permissions and privilege-escalation paths. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/iam-least-privilege-review/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/iam-least-privilege-review/SKILL.md) |
| landing-zone-blast-radius | Design an AWS Organizations landing zone with one account per workload and environment, and show the blast radius of each account. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/landing-zone-blast-radius/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/landing-zone-blast-radius/SKILL.md) |
| sandbox-account-guardrail-pack | Generate a complete guardrail pack for an AWS sandbox OU where engineers and AI agents experiment. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/sandbox-account-guardrail-pack/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/sandbox-account-guardrail-pack/SKILL.md) |
| scp-guardrails | Generate and lint AWS Organizations service control policies (SCPs). | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/scp-guardrails/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/scp-guardrails/SKILL.md) |
| security-hub-triage | Triage exported AWS Security Hub (ASFF) and GuardDuty findings offline into an owner-assigned next-actions list. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/aws-security/security-hub-triage/) · [source](https://github.com/basitalisandhu/aws-security-skills/blob/main/plugins/aws-security/skills/security-hub-triage/SKILL.md) |

### code-quality

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install code-quality@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| complexity-report | Rank the functions in a Python or JavaScript/TypeScript tree by cyclomatic complexity, length and nesting depth with a bundled script, then explain which ones to simplify and how. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/complexity-report/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/complexity-report/SKILL.md) |
| dead-code-finder | Find probably-unused functions, classes, methods and exports in a Python or JavaScript/TypeScript tree with a bundled script, confirm each candidate by searching for dynamic use, and propose a safe deletion order. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/dead-code-finder/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/dead-code-finder/SKILL.md) |
| error-handling-review | Review how a codebase or change handles failures: swallowed exceptions, missing timeouts and retries, errors without context, leaking internals to users, and inconsistent error types across layers; then propose a consistent policy with code examples. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/error-handling-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/error-handling-review/SKILL.md) |
| naming-audit | Audit the names in a module or diff (variables, functions, classes, files, database columns, API fields) for clarity, consistency with the project's conventions, and lies (names that no longer match behaviour), then propose renames with a migration path for public ones. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/naming-audit/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/naming-audit/SKILL.md) |
| refactor-plan | Produce a step-by-step refactoring plan for a module, package or feature, with a behaviour-preserving sequence of small commits, the tests that guard each step, and a rollback point. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/refactor-plan/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/refactor-plan/SKILL.md) |
| review-checklist | Review a pull request, diff or branch against a fixed checklist (correctness, tests, error handling, security, performance, readability, compatibility) and produce findings with file and line references and a verdict. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/review-checklist/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/review-checklist/SKILL.md) |
| test-gap-finder | Map source modules to their test files by naming convention and imports with a bundled script, list the modules that have no test, and prioritise which to cover first by risk. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/test-gap-finder/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/test-gap-finder/SKILL.md) |
| type-coverage | Measure how much of a Python or TypeScript codebase is type-annotated with a bundled script (parameters and return values per function, explicit any counts), find the least-typed files, and plan a gradual typing rollout with a CI threshold. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/code-quality/type-coverage/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/code-quality/skills/type-coverage/SKILL.md) |

### compliance-evidence

Version 0.1.1. Source: [compliance-evidence-skills](https://github.com/basitalisandhu/compliance-evidence-skills). Install: `/plugin install compliance-evidence@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| auditor-narrative-drafter | Draft short control narratives for an ISO 27001 or SOC 2 assessment strictly from a control map, with an inline citation [evidence: file#field] on every sentence that reports evidence, and lint any narrative (drafted or hand-edited) before it reaches the assessor. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/compliance-evidence/auditor-narrative-drafter/) · [source](https://github.com/basitalisandhu/compliance-evidence-skills/blob/main/plugins/compliance-evidence/skills/auditor-narrative-drafter/SKILL.md) |
| aws-identity-and-logging-evidence | Turn saved aws CLI output from one AWS account into evidence rows for logging, access control and backup controls (ISO/IEC 27001:2022 A.8.15, A.8.16, A.8.5, A.8.2, A.5.17, A.8.9, A.5.15, A.8.13 and SOC 2 CC7.2, CC6.1, CC7.1, CC6.6, A1.2 by identifier). | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/compliance-evidence/aws-identity-and-logging-evidence/) · [source](https://github.com/basitalisandhu/compliance-evidence-skills/blob/main/plugins/compliance-evidence/skills/aws-identity-and-logging-evidence/SKILL.md) |
| control-map-from-exports | Map the exports inside an evidence pack to ISO/IEC 27001:2022 Annex A or SOC 2 control identifiers with a mapping file, and report per control one of three states (supported, contradicted, not assessable) with citations to the exact file, field and value, plus the gaps. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/compliance-evidence/control-map-from-exports/) · [source](https://github.com/basitalisandhu/compliance-evidence-skills/blob/main/plugins/compliance-evidence/skills/control-map-from-exports/SKILL.md) |
| evidence-pack-builder | Turn a folder of exports already on disk (GitHub, AWS, Microsoft 365 JSON, CSV or text) into an integrity-checked evidence pack for an ISO 27001 or SOC 2 assessment. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/compliance-evidence/evidence-pack-builder/) · [source](https://github.com/basitalisandhu/compliance-evidence-skills/blob/main/plugins/compliance-evidence/skills/evidence-pack-builder/SKILL.md) |
| github-change-control-evidence | Turn saved gh api and gh pr list exports of one GitHub repository into evidence rows for change management and vulnerability management controls (ISO/IEC 27001:2022 A.8.32, A.8.8, A.8.12 and SOC 2 CC8.1, CC7.1, CC6.1 by identifier). | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/compliance-evidence/github-change-control-evidence/) · [source](https://github.com/basitalisandhu/compliance-evidence-skills/blob/main/plugins/compliance-evidence/skills/github-change-control-evidence/SKILL.md) |

### data

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install data@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| api-contract-review | Lint an OpenAPI 3.x document (YAML or JSON) with a bundled script for missing operationIds, undeclared path parameters, responses without schemas or error cases, servers over http, missing security schemes, unused or dangling components and naming inconsistencies; then review the contract for consistency, versioning and client friendliness. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/api-contract-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/api-contract-review/SKILL.md) |
| csv-profiler | Profile a CSV or TSV file with a bundled script (column types, nulls, distinct counts, ranges and statistics, candidate keys, ragged and duplicate rows, mixed types, whitespace) and turn the profile into import decisions: column types for a table or schema, cleaning steps and validation rules. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/csv-profiler/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/csv-profiler/SKILL.md) |
| json-schema-author | Write a JSON Schema (draft 2020-12) for an API payload, configuration file or event by inferring a draft from sample documents with a bundled script (types, required fields, nullability, formats, enums, bounds) and then hand-finishing it: tightening constraints, adding descriptions and examples, and deciding additionalProperties and versioning. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/json-schema-author/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/json-schema-author/SKILL.md) |
| regex-builder | Build, explain and test regular expressions against labelled cases with a bundled script that reports which cases match, the captured groups, and warnings for patterns that can backtrack catastrophically, with timing on adversarial inputs. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/regex-builder/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/regex-builder/SKILL.md) |
| schema-migration-plan | Plan a database schema change as a sequence of backwards-compatible, reversible migration steps (expand, migrate data, contract) that work with the running application version, with lock and downtime analysis per step, a batched backfill for large tables, and a rollback plan. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/schema-migration-plan/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/schema-migration-plan/SKILL.md) |
| sql-query-review | Review SQL queries, ORM-generated SQL and query plans for correctness and performance: injection, implicit casts, NULL logic, non-sargable predicates, missing indexes, N+1 patterns, unbounded result sets, lock contention and transaction scope, using a fixed checklist and EXPLAIN reading notes for PostgreSQL, MySQL and SQLite. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/data/sql-query-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/data/skills/sql-query-review/SKILL.md) |

### debugging

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install debugging@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| bug-repro-minimiser | Turn a vague bug report into the smallest reliable reproduction: a single command or test that fails every time, with the environment, input and expected versus actual result pinned down. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/bug-repro-minimiser/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/bug-repro-minimiser/SKILL.md) |
| flaky-test-hunter | Find tests that pass and fail without code changes by comparing JUnit XML reports from several runs with a bundled script, then classify each flaky test by cause (ordering, timing, shared state, resources, environment) and prescribe the fix. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/flaky-test-hunter/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/flaky-test-hunter/SKILL.md) |
| log-triage | Reduce a large log file to its distinct message templates with counts, levels, first and last occurrence and attached stack traces using a bundled clustering script, then rank what to investigate. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/log-triage/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/log-triage/SKILL.md) |
| memory-leak-checklist | Diagnose a process whose memory grows over time with a fixed checklist: confirm it is a leak and not a cache or fragmentation, measure with the runtime's heap tools (tracemalloc, objgraph, Node heap snapshots, Go pprof heap, JVM histograms), find the retaining path, and fix the usual suspects (unbounded caches, listeners, closures, global registries, connection pools, large buffers). | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/memory-leak-checklist/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/memory-leak-checklist/SKILL.md) |
| perf-profile-reader | Summarise a captured CPU profile (py-spy collapsed stacks or dump, Go pprof text, Python cProfile output) into the few functions that hold the time, separate busy from waiting, and name the optimisation to try first, using a bundled script. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/perf-profile-reader/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/perf-profile-reader/SKILL.md) |
| stack-trace-explainer | Read a stack trace or crash report from any mainstream runtime (Python, JavaScript and Node, Java and JVM, Go, Rust, .NET, Ruby, PHP), identify the frame where the fault lives versus where it surfaced, explain the error type, and propose the next diagnostic step. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/debugging/stack-trace-explainer/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/debugging/skills/stack-trace-explainer/SKILL.md) |

### devops

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install devops@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| cron-doctor | Diagnose a crontab with a bundled script that validates every schedule, explains it in words, computes the next runs, and flags jobs with no output redirection, unescaped percent signs, PATH assumptions, day-of-month plus day-of-week confusion, DST-sensitive hours, overlapping frequent jobs and duplicates; then fix the entries and add locking and logging. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/cron-doctor/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/cron-doctor/SKILL.md) |
| dockerfile-hardening | Lint a Dockerfile with a bundled script for images that run as root, unpinned or latest base images, secrets in ENV or ARG, remote scripts piped to a shell, unclean apt layers, world-writable permissions and missing HEALTHCHECK, then rewrite it as a smaller, pinned, non-root multi-stage build. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/dockerfile-hardening/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/dockerfile-hardening/SKILL.md) |
| env-diff | Compare the keys of a .env.example (or any template) against real .env files with a bundled script, listing missing, extra, empty and duplicated keys and template values that look like real credentials, without ever printing a value. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/env-diff/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/env-diff/SKILL.md) |
| github-actions-author | Write or review GitHub Actions workflows with least-privilege permissions, SHA-pinned actions, timeouts, concurrency and caching, and validate them with a bundled linter that catches missing permissions, pull_request_target checkout of fork code, expression injection in run steps, unpinned actions and literal secrets. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/github-actions-author/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/github-actions-author/SKILL.md) |
| k8s-manifest-review | Review Kubernetes manifests (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods, Services, Secrets) with a bundled script for missing resource limits and probes, privileged or root containers, mutable image tags, host namespaces and hostPath mounts, inline secrets and missing seccomp, then produce the corrected YAML. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/k8s-manifest-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/k8s-manifest-review/SKILL.md) |
| release-notes | Generate release notes from a git commit range with a bundled script that groups commits by Conventional Commits type (breaking, features, fixes, performance, docs, build), links commits and issues, and lists contributors; then edit them into notes a user can read. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/release-notes/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/release-notes/SKILL.md) |
| semver-advisor | Decide the next version number (major, minor or patch, or a pre-release) for a library, service, API, CLI or schema from the actual changes, using a decision table for what counts as breaking in each kind of artefact, and explain the decision with evidence. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/semver-advisor/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/semver-advisor/SKILL.md) |
| terraform-review | Review Terraform or OpenTofu code against a fixed checklist: state and backend safety, provider and module version pinning, variables with types and validation, secrets handling, public exposure (open security groups, public buckets, 0.0.0.0/0), encryption and logging defaults, lifecycle and destroy protection, and plan hygiene. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/devops/terraform-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/devops/skills/terraform-review/SKILL.md) |

### docs

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install docs@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| adr-writer | Write an Architecture Decision Record for a technical choice, with context, the options considered and their trade-offs, the decision and its consequences, in a fixed format with a status lifecycle (proposed, accepted, superseded), numbered and stored in the repository. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/adr-writer/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/adr-writer/SKILL.md) |
| api-docs-from-code | Generate an API reference from source with a bundled script that extracts Python docstrings (Google, NumPy and reST styles) and JavaScript/TypeScript JSDoc blocks into Markdown or JSON, lists undocumented public symbols, and measures documentation coverage; then fill the gaps and wire the extraction into the docs build. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/api-docs-from-code/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/api-docs-from-code/SKILL.md) |
| changelog-keeper | Maintain CHANGELOG.md in the Keep a Changelog format with a bundled script that validates the structure, adds entries under Unreleased in the right category, cuts a release (version, date, compare links) and prints a version's section. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/changelog-keeper/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/changelog-keeper/SKILL.md) |
| onboarding-doc | Write a developer onboarding document for a repository or service that gets a new team member from a clean machine to a merged change: environment setup verified step by step, how the code is organised, how to run and test it, the configuration it needs, the deployment path, who owns what, and the first tasks. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/onboarding-doc/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/onboarding-doc/SKILL.md) |
| postmortem-writer | Write a blameless incident postmortem from the timeline, logs, chat transcript and metrics: impact with numbers, a minute-by-minute timeline, contributing causes found with a structured analysis rather than a single root cause, what went well and what did not, and action items with owners, deadlines and a check that they would have prevented or shortened the incident. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/postmortem-writer/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/postmortem-writer/SKILL.md) |
| readme-author | Write or rewrite a README that answers what the project is, who it is for, how to install and use it in under five minutes, and where everything else lives, using a fixed section order and a quality checklist (first screen, copy-pasteable commands verified to work, no stale claims). | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/docs/readme-author/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/docs/skills/readme-author/SKILL.md) |

### github-manager

Version 0.1.1. Source: [github-manager-skills](https://github.com/basitalisandhu/github-manager-skills). Install: `/plugin install github-manager@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| incident-postmortem-timeline | Build a blameless postmortem timeline and document skeleton from a saved incident issue export (gh issue view with comments, the issue timeline, and the PRs it references), with a bundled script that orders every label change, assignment, comment, cross-reference, PR merge and close by time, derives detected, acknowledged, mitigated and resolved from those records, reports where two signals for one phase disagree, lists people as roles, and writes contributing factors as questions for the review, citing each row to its comment id, event id or PR. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/github-manager/incident-postmortem-timeline/) · [source](https://github.com/basitalisandhu/github-manager-skills/blob/main/plugins/github-manager/skills/incident-postmortem-timeline/SKILL.md) |
| iteration-report | Write a team-level iteration or sprint report from saved gh pr list, gh issue list and milestone exports, with a bundled script that lists what shipped (merged PRs with the issues they close), what carried over, what was newly opened, what was closed as not planned and which PRs merged outside the window, and computes cycle time (median and p90, from first commit or from PR creation, stated) and review turnaround (median), every number followed by the PR or issue rows it came from. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/github-manager/iteration-report/) · [source](https://github.com/basitalisandhu/github-manager-skills/blob/main/plugins/github-manager/skills/iteration-report/SKILL.md) |
| pr-queue-digest | Build a stuck-PR and review-queue digest from a saved gh pr list export, with a bundled script that flags PRs waiting on review longer than a threshold, PRs blocked on one overloaded reviewer, changes requested with no new commits, new commits with no re-request, failing checks, merge conflicts, approved but unmerged PRs, PRs with no reviewer and stale drafts, then prints a review-queue table per reviewer (counts only) and one next action per PR (nudge, re-request, rebase, fix checks, merge, close as stale), each citing the PR. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/github-manager/pr-queue-digest/) · [source](https://github.com/basitalisandhu/github-manager-skills/blob/main/plugins/github-manager/skills/pr-queue-digest/SKILL.md) |

### m365-governance

Version 0.2.1. Source: [m365-governance-skills](https://github.com/basitalisandhu/m365-governance-skills). Install: `/plugin install m365-governance@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| access-review-pack | Build a quarterly Microsoft 365 access review package from read-only Graph exports. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/access-review-pack/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/access-review-pack/SKILL.md) |
| conditional-access-gap-analysis | Find gaps, overlaps and exclusion problems in Microsoft Entra Conditional Access from read-only Graph exports. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/conditional-access-gap-analysis/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/conditional-access-gap-analysis/SKILL.md) |
| entra-posture-review | Review a Microsoft Entra ID tenant's identity posture from read-only Graph exports. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/entra-posture-review/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/entra-posture-review/SKILL.md) |
| graph-permission-preflight | Preflight the Microsoft Graph permissions an app registration, enterprise application or third-party connector requests or already holds, before it touches a Microsoft 365 tenant. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/graph-permission-preflight/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/graph-permission-preflight/SKILL.md) |
| guest-and-external-sharing-review | Review guest accounts and external sharing in Microsoft 365 from read-only exports. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/guest-and-external-sharing-review/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/guest-and-external-sharing-review/SKILL.md) |
| intune-baseline-check | Check a Microsoft Intune estate against a device baseline from read-only Graph exports. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/intune-baseline-check/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/intune-baseline-check/SKILL.md) |
| license-and-service-plan-audit | Audit Microsoft 365 licence assignments from read-only Graph exports and draft a reclaim list. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/license-and-service-plan-audit/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/license-and-service-plan-audit/SKILL.md) |
| privileged-access-review | Review privileged Microsoft Entra ID role holders from read-only Graph exports and score each admin account. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/privileged-access-review/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/privileged-access-review/SKILL.md) |
| teams-and-groups-sprawl | Report Microsoft Teams and Microsoft 365 group sprawl from read-only Graph exports and draft a cleanup list. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/m365-governance/teams-and-groups-sprawl/) · [source](https://github.com/basitalisandhu/m365-governance-skills/blob/main/plugins/m365-governance/skills/teams-and-groups-sprawl/SKILL.md) |

### mac-maintenance

Version 0.1.1. Source: [mac-maintenance-skills](https://github.com/basitalisandhu/mac-maintenance-skills). Install: `/plugin install mac-maintenance@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| mac-app-leftovers | Find what uninstalled applications left behind on a Mac with a bundled script: Application Support and container folders, caches, preferences, saved state, WebKit and HTTP storage, logs, login items whose app is gone, and launch agents or daemons whose program no longer exists. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/mac-maintenance/mac-app-leftovers/) · [source](https://github.com/basitalisandhu/mac-maintenance-skills/blob/main/plugins/mac-maintenance/skills/mac-app-leftovers/SKILL.md) |
| mac-cleanup | Clean up and speed up a Mac in three tiers with two bundled scripts. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/mac-maintenance/mac-cleanup/) · [source](https://github.com/basitalisandhu/mac-maintenance-skills/blob/main/plugins/mac-maintenance/skills/mac-cleanup/SKILL.md) |
| mac-duplicate-finder | Find byte-for-byte duplicate files in a Mac's user folders with a bundled script (size grouping, then partial and full hashing), report the largest groups and which folders mirror each other, and single out "suffix copies" (IMG_1 (1).MOV next to an identical IMG_1.MOV) that can be moved to a dated Trash folder after a second hash check, with the original untouched. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/mac-maintenance/mac-duplicate-finder/) · [source](https://github.com/basitalisandhu/mac-maintenance-skills/blob/main/plugins/mac-maintenance/skills/mac-duplicate-finder/SKILL.md) |

### repo-engineering

Version 0.3.0. Source: [repo-engineering-skills](https://github.com/basitalisandhu/repo-engineering-skills). Install: `/plugin install repo-engineering@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| adr-miner | Recover architecture decisions that were made but never written down, by mining git history (commit messages with decision phrases such as switch to, replace, adopt, drop, migrate, deprecate, in favour of), configuration changes (a dependency swapped in a manifest, a Dockerfile base image changed, CI files added or removed) and TODO or NOTE comments that carry a rationale, then drafting MADR stubs with status proposed that cite the commit SHA for every line; a second script lints an existing docs/adr folder for numbering gaps, duplicate numbers, missing or unknown status and broken superseded links. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/adr-miner/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/adr-miner/SKILL.md) |
| agent-context-writer | Write or refresh AGENTS.md and CLAUDE.md so they hold only what an agent cannot learn by reading the code (commands that are in no manifest, conventions, forbidden actions, environment setup, where to look first), and lint the result with a bundled script that flags lines restating package.json scripts, pyproject scripts, Makefile or justfile targets, dependency lists, pinned runtime versions or directory trees, paths that do not exist, generic advice, and length over a budget. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/agent-context-writer/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/agent-context-writer/SKILL.md) |
| cited-codebase-audit | Audit a whole repository against a fixed checklist (structure, entry points, dependency hygiene, dead code candidates, test coverage of entry points, secrets and config handling, CI health) where every finding must cite a path:line with a quoted snippet, and a bundled validator rejects any finding whose citation does not resolve. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/cited-codebase-audit/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/cited-codebase-audit/SKILL.md) |
| docs-truth-check | Verify that a repository's README, docs/, AGENTS.md and CLAUDE.md still match the code, using a deterministic script that checks file paths, relative links, CLI flags and their documented defaults, environment variables, function and class names, config keys, npm and make targets, and version strings against the working tree. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/docs-truth-check/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/docs-truth-check/SKILL.md) |
| readme-who-what-why | Check whether a README answers six questions in its first screen (what it is in one sentence, who it is for, why it exists or what it replaces, how to install in one block, how to run one example, where to ask) with a bundled script that scores presence and position of each, flags hype words, and prints the gaps as a to-do list; then fix the gaps with verified text. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/readme-who-what-why/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/readme-who-what-why/SKILL.md) |
| release-notes-verifier | Check a release's notes against what actually changed, with a bundled script that reads the commits between two tags (and, only when asked, pull request titles through a read-only gh call) and compares them with the CHANGELOG section or a release notes file, flagging notes that match no commit, commits with no note (chores excluded by a configurable pattern), manifest versions that disagree with the tag, and missing compare or reference links. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/release-notes-verifier/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/release-notes-verifier/SKILL.md) |
| repo-hygiene-bundle | Run one offline hygiene pass over a repository with a bundled script and report each finding with a severity, as a table, JSON or SARIF, with an exit code for CI. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/repo-hygiene-bundle/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/repo-hygiene-bundle/SKILL.md) |
| repo-onboarding-guide | Write an onboarding guide for a repository (how to run it, how to test it, where things live, which services it needs, who owns what) only from facts a bundled script extracted with a path:line citation each, then lint the guide so every sentence that names a command, path, variable, service or owner matches a fact, and run docs-truth-check on the result. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/repo-onboarding-guide/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/repo-onboarding-guide/SKILL.md) |
| restructure-planner | Plan a repository restructure (split a package or a monorepo, merge packages, fix module boundaries) from the real import graph instead of a guess, using a bundled script that reads Python imports with ast and JS or TS imports and requires with regex, then reports the most coupled files, import cycles, files importing from many packages and god modules, and proposes a move plan as a table (file, from, to, reason, blast radius as the number of importers) with the exact git mv commands, which it prints and never runs. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/restructure-planner/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/restructure-planner/SKILL.md) |
| untested-entry-points | Find public functions, classes and CLI entry points that no test mentions, using a bundled script that parses Python with ast and JS or TS exports with regex, maps each unit to the test files that reference it by name, ranks the untested ones (entry points first, then by size and fan-in), and writes characterisation test stubs in the project's framework (pytest, unittest, jest, vitest, node:test). | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/repo-engineering/untested-entry-points/) · [source](https://github.com/basitalisandhu/repo-engineering-skills/blob/main/plugins/repo-engineering/skills/untested-entry-points/SKILL.md) |

### security-basics

Version 0.1.1. Source: [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills). Install: `/plugin install security-basics@claude-skills`.

| Skill | What it does | Scripts | Links |
| --- | --- | --- | --- |
| auth-flow-review | Review an application's authentication and session design against a checklist covering password handling, login and logout, session cookies and tokens, OAuth and OIDC flows (authorization code with PKCE, state, redirect URI validation), multi-factor, password reset, account enumeration, rate limiting, remember-me and device trust, and logging; then produce findings with severity and the corrected flow. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/auth-flow-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/auth-flow-review/SKILL.md) |
| cors-review | Review a web application's Cross-Origin Resource Sharing configuration (allowed origins, credentials, methods, headers, preflight caching, exposed headers) against a checklist of the mistakes that create cross-site data leaks or break legitimate clients, and produce the correct configuration for the framework or gateway in use. | no | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/cors-review/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/cors-review/SKILL.md) |
| dependency-audit-reader | Read the JSON output of npm audit, yarn audit, pip-audit or cargo audit with a bundled script that ranks vulnerable packages by severity, separates fixable from unfixable and direct from transitive, and names the packages to upgrade first; then plan the upgrades, the overrides and the accepted risks with expiry dates. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/dependency-audit-reader/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/dependency-audit-reader/SKILL.md) |
| http-security-headers | Check the security headers of a captured HTTP response (saved from curl or the browser) with a bundled script that grades HSTS, Content-Security-Policy, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy, cookie flags, CORS with credentials, information disclosure and caching, then produce the header set for the web server or framework. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/http-security-headers/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/http-security-headers/SKILL.md) |
| jwt-inspector | Decode a JSON Web Token without verifying it with a bundled script that prints the header and claims with times explained, and flags unsafe settings (alg none, empty signature, missing or long expiry, jku or x5u headers, suspicious kid, symmetric algorithms, sensitive claims in the payload), then review how the application issues and verifies tokens. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/jwt-inspector/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/jwt-inspector/SKILL.md) |
| secrets-hygiene | Scan a repository, a directory or the files staged for commit for leaked credentials (cloud and SaaS API keys, private keys, tokens, connection strings with passwords, high-entropy assignments) with a bundled script that redacts what it finds, check that .env files are ignored, maintain a baseline of accepted findings, and walk the rotation and history cleanup when something real is found. | yes | [page](https://basitalisandhu.github.io/claude-skills/plugins/security-basics/secrets-hygiene/) · [source](https://github.com/basitalisandhu/claude-dev-skills/blob/main/plugins/security-basics/skills/secrets-hygiene/SKILL.md) |

<!-- catalog:end -->

## How it stays in sync

- `scripts/sync.py` clones each source repository with `git clone --depth 1` and replaces `plugins/<plugin>/` wholesale.
- It then regenerates `SOURCES.json`, `catalog.json`, the marketplace file, the catalog block in this README and the site in `docs/`.
- A [daily workflow](.github/workflows/sync.yml) runs the sync and opens or updates a pull request on branch `sync/plugins`. The pull request lists each plugin whose source commit changed.
- `SOURCES.json` records, for each plugin, the source repository, path, commit, sync time, upstream version and a SHA-256 of the plugin folder. `scripts/validate.py` fails if a vendored folder no longer matches that hash, so a hand edit here is caught.
- A run with no upstream change writes nothing. A plugin's commit and sync time only change when its content or marketplace entry changed.
- Tagged releases ship a tarball with `SHA256SUMS` and a build provenance attestation.

## Design rules the skills follow

These are true of the files in `plugins/` today:

- Every skill is a `SKILL.md` with `name`, `description`, `license`, `compatibility` and `metadata` front matter, checked by `scripts/validate.py`.
- 67 of the 87 skills bundle scripts. Every bundled Python script imports only the standard library or another bundled script.
- The scripts work on local files and exports. One script can reach the network: `incident-lookup` can refresh its incident dataset, and falls back to the bundled copy. Some skills tell you to export data first with a vendor CLI (`gh`, `aws`, Microsoft Graph); the scripts themselves make no calls.
- No skill sends telemetry.
- Each source repository runs its own tests in CI before a change reaches its main branch.
- 50 of the 87 SKILL.md files have a "Limits" section that says what the skill does not do. The site shows it as "What it does not do". The other 37 do not have that section yet.

## FAQ

**Why not one plugin with every skill?**
Plugins are the unit you install and enable. Thirteen plugins let you load AWS skills without Mac maintenance skills. One marketplace keeps them easy to find.

**Why copies rather than git submodules?**
A submodule needs `git clone --recursive`; a plain clone would leave `plugins/` empty, for the marketplace and for `install.py`. Copies work with any clone, and `SOURCES.json` keeps the provenance: source repository, commit and content hash for each plugin.

**How do I report a bug in a skill?**
Open an issue in the skill's source repository. Each skill page on the site and each row in the catalog links to it. See [SECURITY.md](SECURITY.md) for security problems.

**Does it work with other agents that read SKILL.md?**
The skills use the open Agent Skills format: a folder with a `SKILL.md` that has `name` and `description` front matter. This repository checks them with Claude Code's plugin validator only. Other agents that read the format can install them with `npx skills add basitalisandhu/claude-skills`.

**Is anything sent anywhere?**
`install.py`, `scripts/validate.py` and `site/build.py` make no network calls. `scripts/sync.py` clones the 8 public source repositories from GitHub, and nothing else. The skills' own network use is described under [Design rules](#design-rules-the-skills-follow).

## Related repositories

Source repositories:

- [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills)
- [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills)
- [claude-dev-skills](https://github.com/basitalisandhu/claude-dev-skills)
- [compliance-evidence-skills](https://github.com/basitalisandhu/compliance-evidence-skills)
- [github-manager-skills](https://github.com/basitalisandhu/github-manager-skills)
- [m365-governance-skills](https://github.com/basitalisandhu/m365-governance-skills)
- [mac-maintenance-skills](https://github.com/basitalisandhu/mac-maintenance-skills)
- [repo-engineering-skills](https://github.com/basitalisandhu/repo-engineering-skills)

Tools for Claude Code configuration:

- [skill-scan-gate](https://github.com/basitalisandhu/skill-scan-gate): CI gate that scans skills and plugins
- [cc-plugin-lock](https://github.com/basitalisandhu/cc-plugin-lock): lock file for Claude Code plugins
- [claude-perm-sim](https://github.com/basitalisandhu/claude-perm-sim): permission rule simulator
- [cc-hooks](https://github.com/basitalisandhu/cc-hooks): typed Python SDK and test runner for hooks
- [claude-mcp-allow](https://github.com/basitalisandhu/claude-mcp-allow): least-privilege permission rules for MCP tools

Docs hub: <https://basitalisandhu.github.io/>

## Contributing

Skills are edited in their source repositories. See [CONTRIBUTING.md](CONTRIBUTING.md) for how this repository syncs, validates and builds.

## License

MIT. See [LICENSE](LICENSE). The vendored plugins are MIT, by the same author.
