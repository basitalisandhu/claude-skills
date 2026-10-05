# cc-setup-tooling

Skills that keep a Claude Code setup safe and tidy, each with a tested standard-library Python script. Install with `/plugin marketplace add basitalisandhu/claude-code-tooling-skills` and then `/plugin install cc-setup-tooling@claude-code-tooling-skills`. Skills appear as `/cc-setup-tooling:<skill>`, and Claude also invokes them on its own when a request matches a skill's description.

| Skill | Script | Use it to |
|---|---|---|
| `skill-supply-chain-review` | `skills/skill-supply-chain-review/scripts/skill_inventory.py` | review a third-party skill or plugin before installing it: skill-scan-gate, cc-plugin-lock scan and lock, and an offline inventory of scripts, imports, URLs, shell patterns, hooks, MCP servers and permissions, ending in a one-page verdict |
| `skill-description-linter` | `skills/skill-description-linter/scripts/description_lint.py` | lint SKILL.md front matter (double-quoted description under 600 characters, verb first, quoted trigger phrase, Use when, Not for, name equals folder, strict YAML, Limits section) and fix the quoting |
| `skill-trigger-eval` | `skills/skill-trigger-eval/scripts/trigger_eval.py` | score descriptions against a labelled prompt set with transparent lexical rules, report precision and recall, and compare two versions |
| `context-budget-audit` | `skills/context-budget-audit/scripts/context_budget.py` | estimate what a project loads on every turn (memory files and imports, rules, skill listings, MCP tool schemas), rank it and flag duplicates and stale sections |
| `permissions-builder` | `skills/permissions-builder/scripts/perm_merge.py` | merge allow, ask and deny rules from claude-mcp-allow and the team's own lists, order deny first, diff against the current settings, then test with claude-perm-sim |
| `hook-author` | `skills/hook-author/scripts/hook_scaffold.py` | scaffold a cc-hooks hook from a short spec with fixtures, a pytest file and the settings block, then prove it with `cc-hooks test` |
| `skill-collision-check` | `skills/skill-collision-check/scripts/skill_collisions.py` | find skills that share a name, shadow each other or overlap in description across managed, personal, project, plugin and copied folders, and say which wins |
| `skill-portability-check` | `skills/skill-portability-check/scripts/portability_check.py` | find what breaks on other hosts and operating systems (YAML colons, home paths, plugin-root fallbacks, GNU or BSD shell, missing encoding, POSIX-only calls, backslash paths, CRLF, symlinks) |

Requirements: Python 3.10 or newer on `PATH` as `python3`. The scripts read local files only: no network access, no third-party packages. The separate tools the skills drive (skill-scan-gate, cc-plugin-lock, cc-hooks, claude-perm-sim, claude-mcp-allow) are installed and run by the user; each skill says what to do when one is missing.
