# Changelog

All notable changes to this repository are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

Changes to individual skills are recorded in their source repositories. Plugin versions and source commits are in `SOURCES.json`.

## [Unreleased]

## [0.6.1] - 2026-10-26

### Fixed

- Sync pull requests showed only CodeQL and were marked unstable (#45): check runs from the `ci` run that `sync.yml` starts are not listed on a pull request, and the `pull_request` run GitHub creates for `github-actions[bot]` waited for approval. `ci.yml` now posts its result as `ci / <job>` commit statuses on dispatched runs off `main`, `sync.yml` marks them pending first, and `sync.yml` deletes only that bot run waiting for approval. Approval for first-time contributors is unchanged.

### Changed

- The marketplace metadata version is 0.6.1.

## [0.6.0] - 2026-10-26

### Changed

- Synced in #45 after the second deep pass on eight source packs: m365-governance 0.6.0, agent-identity-governance 0.4.0, agent-security 0.6.0, aws-security 0.6.1, github-manager 0.4.0, the claude-dev plugins 0.4.1, ways-of-working 0.5.0 and mac-maintenance 0.2.0. Across these packs, skill descriptions were reworded where the trigger check found misses, input parsers were fuzzed and now exit 2 with a message instead of a traceback (including a YAML reader that looped for ever on some malformed input), several quadratic loops were made linear, and every skill has a README with a sample produced by its script. New behaviour includes `agent-action-timeline --azure-activity`, the GuardDuty detector status check, `log-triage --since/--until`, milestone scope changes in `iteration-report`, stateful-resource notes in change records and `safe_clean.py --list-actions`.
- The sync pull request #45 got its `ci` checks from the run that `sync.yml` starts, with no close and reopen (#24).
- The marketplace metadata version is 0.6.0.

## [0.5.1] - 2026-10-26

### Fixed

- `install.py` and the catalog could give two skills the same install directory, so one overwrote the other: a skill renamed to `<plugin>-<skill>` could land on a name another skill already used (for example `a/b-s`, `a/s` and `b/s`). A taken name now gets a number (`<plugin>-<skill>-2`). Today's catalog has no such clash, so no install name changes.
- SKILL.md front matter with nothing between the two `---` lines was reported as not closed, and the closing line must now be exactly `---`, so a value line that starts with `---` no longer ends the block early.
- Daily sync pull requests now get the `ci` checks without anyone closing and reopening them: `sync.yml` starts `ci.yml` on the sync branch (#24). The start is a separate job that holds only `actions: write`, so the job that runs the synced code never gets that permission.

### Added

- Property-based tests with Hypothesis for install naming, the front matter parser and the site's Markdown converter (raw HTML is always escaped, no `javascript:` links), in `tests/test_properties.py`.
- Tests that sync from two fake source repositories built with `git init` and check that a second run writes nothing, that an upstream commit only touches its own plugin, and that a plugin published twice is refused (#7).

### Changed

- The marketplace metadata version is 0.5.1.

## [0.5.0] - 2026-10-26

### Added

- New skills synced from their source repositories in #39: `session-usage-ledger`, `shell-slip-audit` and `compaction-loss-check` (cc-setup-tooling 0.5.0), `mcp-registry-publish-preflight` (repo-engineering 0.6.0) and `iso27001-soa-check` (compliance-evidence 0.7.0). Each has a standard-library script, synthetic fixtures and tests in its source repository. The catalog now lists 140 skills in 16 plugins.

### Changed

- The marketplace metadata version is 0.5.0.

## [0.4.0] - 2026-10-20

### Added

- New skills synced from their source repositories in #35: `unattended-run-preflight` and `subagent-tool-scope-review` (cc-setup-tooling 0.4.0), `preventive-control-mapper` (aws-security 0.5.0), `evidence-collection-plan` (compliance-evidence 0.6.0) and `agent-audit-log-integrity` (agent-identity-governance 0.3.0). Each has a standard-library script, synthetic fixtures and tests in its source repository. The catalog now lists 135 skills in 16 plugins.

### Changed

- Daily sync pull requests (#33, #35) updated the plugins; versions and source commits are in `SOURCES.json`.
- The synced example fixtures' documentation AWS key ids are baselined for the secrets scanner (#34).
- The marketplace metadata version is 0.4.0.

## [0.3.0] - 2026-10-16

### Added

- New skills synced from their source repositories: `tool-approval-gate-audit` (agent-security 0.4.0), `sandbox-config-review` (cc-setup-tooling 0.2.0), `vendor-attestation-digest` and `maester-control-map` (compliance-evidence 0.4.0) and `next-actions-sweep` (ways-of-working 0.3.0). Each has a standard-library script, synthetic fixtures and tests in its source repository.
- `ROADMAP.md`, a Contributors section and links to GitHub Discussions (#27, #30).

### Changed

- Daily sync pull requests (#25, #31) updated the plugins; versions and source commits are in `SOURCES.json`.
- The marketplace metadata version is 0.3.0.

## [0.2.0] - 2026-10-13

### Added

- Three plugins synced from new source repositories: `agent-identity-governance` (agent-identity-governance-skills), `cc-setup-tooling` (claude-code-tooling-skills) and `ways-of-working` (ways-of-working-skills).
- `install.py --list --json` for scripted plugin and skill listing.
- Site: an install guide, FAQ structured data and IndexNow notification on deploy.
- `scripts/validate.py` fails when a hand-written "N skills" or "N plugins" phrase in `README.md`, `site/content/*.md` or this section disagrees with `catalog.json`.
- Soft quality notes in `scripts/validate.py` (description over 600 characters, no "Use " or "Not for", no Limits section) and a count of cross-plugin skill pointers per plugin. `--strict-quality` turns the first four rules into errors.
- `reports/quality.md`, the full lists behind those notes, regenerated by `scripts/sync.py` and quoted in the sync pull request.
- A "Skills refer to each other across plugins" note in the README FAQ and the install guide.
- A `windows-latest` leg in CI that runs `tests/` only, and a `.gitattributes` that keeps LF line endings so content hashes match on Windows checkouts. Two tests that rebuild the site are skipped on Windows, marked in `tests/test_generators.py`.

### Changed

- Daily sync pull requests updated the existing plugins; each plugin's version and source commit are in `SOURCES.json` and the release notes.
- The marketplace metadata version is 0.2.0.
- The README intro, the design-rule counts and the install guide take their numbers from `catalog.json` at sync or build time (`<!-- counts:start -->` spans and `{{skills}}` and `{{plugins}}` template variables), so they read the current skill and plugin counts (from catalog.json) today and stay current.

## [0.1.0] - 2026-10-04

### Added

- 13 plugins with 87 skills, synced from 8 source repositories into `plugins/`.
- `.claude-plugin/marketplace.json`, a single marketplace named `claude-skills`.
- `install.py` to copy skills into `~/.claude/skills/` or `./.claude/skills/`, with a manifest so updates and `--uninstall` touch only files it wrote.
- `scripts/sync.py`, `scripts/validate.py`, `catalog.json` and `SOURCES.json`.
- A static site in `docs/` with a page per plugin and per skill, `sitemap.xml`, `llms.txt`, `llms-full.txt` and an Atom feed.
- Workflows for CI, a daily sync pull request, GitHub Pages and releases with build provenance.

[Unreleased]: https://github.com/basitalisandhu/claude-skills/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/basitalisandhu/claude-skills/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/basitalisandhu/claude-skills/releases/tag/v0.1.0
