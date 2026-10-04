# Changelog

All notable changes to this repository are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

Changes to individual skills are recorded in their source repositories. Plugin versions and source commits are in `SOURCES.json`.

## [Unreleased]

## [0.1.0] - 2026-10-04

### Added

- 13 plugins with 87 skills, synced from 8 source repositories into `plugins/`.
- `.claude-plugin/marketplace.json`, a single marketplace named `claude-skills`.
- `install.py` to copy skills into `~/.claude/skills/` or `./.claude/skills/`, with a manifest so updates and `--uninstall` touch only files it wrote.
- `scripts/sync.py`, `scripts/validate.py`, `catalog.json` and `SOURCES.json`.
- A static site in `docs/` with a page per plugin and per skill, `sitemap.xml`, `llms.txt`, `llms-full.txt` and an Atom feed.
- Workflows for CI, a daily sync pull request, GitHub Pages and releases with build provenance.

[Unreleased]: https://github.com/basitalisandhu/claude-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/claude-skills/releases/tag/v0.1.0
