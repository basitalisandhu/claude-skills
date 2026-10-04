# Contributing

Thank you for helping. Read this first: skills are not edited here.

## Where changes go

- **A skill, its scripts, a plugin README, hooks, agents or the MCP server:** open an issue or pull request in the source repository. The source of every plugin is in [SOURCES.json](SOURCES.json) and in the catalog in [README.md](README.md). The next sync brings the change here.
- **This repository's own files:** `install.py`, `scripts/`, `site/`, `tests/`, the workflows and the docs at the top level. Pull requests for those are welcome here.

Never edit `plugins/`, `catalog.json`, `SOURCES.json`, `.claude-plugin/marketplace.json`, the README catalog block or `docs/` by hand. They are generated, and `scripts/validate.py` fails when they drift.

## Run it locally

You need Python 3.10 or newer and git. pytest is only needed for the tests.

```bash
python3 scripts/sync.py              # fetch the 8 sources and regenerate everything (needs network)
python3 scripts/sync.py --check      # exit 1 if a sync would change anything (needs network)
python3 scripts/sync.py --offline    # regenerate catalog, README block and site from plugins/ as they are
python3 scripts/validate.py          # structure, front matter, generated files, house rules
python3 site/build.py                # build the site into docs/
python3 site/build.py --check        # fail if docs/ is stale or a link is broken
python3 -m pytest -q                 # tests for install.py and the generators, offline
```

With the Claude Code CLI installed:

```bash
claude plugin validate --strict .
for p in plugins/*/; do claude plugin validate --strict "$p"; done
```

## House rules

- Standard library only for every script here.
- Short sentences in docs. Every claim in the README must be true of the files in the repository.
- No em-dashes and no AI model names in files written for this repository. `scripts/validate.py` checks both.
- Never commit a string that looks like a credential. Tests assemble any key-shaped value at run time.

## Propose a new pack

A new pack starts as its own repository with the same layout as the sources: `.claude-plugin/marketplace.json` at the root and each plugin at `plugins/<plugin>/` with `.claude-plugin/plugin.json` and `skills/<skill>/SKILL.md`. It needs an MIT licence, tests in CI, and skill names that no other plugin here uses.

Then open an issue here titled "New pack: <repository>". To add it, append the repository to `SOURCE_REPOS` in `scripts/hublib.py` and run a sync.
