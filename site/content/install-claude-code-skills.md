---
title: How to install Claude Code skills (three ways)
description: Install Claude Code skills from this repository as a plugin marketplace, by cloning and running install.py, or with npx skills add. Includes troubleshooting and uninstall steps.
---
# How to install Claude Code skills (three ways)

This guide shows three ways to install the skills in this repository: through the Claude Code plugin marketplace, by cloning the repository and running `install.py`, and with the `npx skills` command for other agents. It ends with troubleshooting and a list of what the installer does not do.

## What a skill is

A skill is a folder with a file named `SKILL.md`. The file starts with YAML front matter that has a `name` and a `description`, followed by instructions in Markdown. The folder can also hold scripts and reference files. Claude Code reads the description to decide when a skill is relevant and loads the rest only when it is used. The same layout is the Agent Skills format, which other agents also read.

Claude Code finds skills in three places:

- **Personal skills** live in `~/.claude/skills/<name>/SKILL.md` and are available in every project.
- **Project skills** live in `.claude/skills/<name>/SKILL.md` inside a repository and are available in that project.
- **Plugin skills** ship inside a plugin and load when you install and enable the plugin.

The folder name must be the same as the `name` in the front matter.

## Route 1: the plugin marketplace

This is the route I recommend. In Claude Code, add this repository as a marketplace:

```text
/plugin marketplace add basitalisandhu/claude-skills
```

Then install a plugin from it. The marketplace is named `claude-skills`, so the plugin name is followed by `@claude-skills`:

```text
/plugin install aws-security@claude-skills
```

Replace `aws-security` with any plugin from the [plugin list](../../index.html#plugins). Run `/plugin` to open the plugin manager and see what is installed. To refresh the catalog and pick up new versions, run:

```text
/plugin marketplace update claude-skills
```

This route also loads plugin-level hooks, commands, agents and MCP servers when a plugin ships them, and it keeps `${CLAUDE_PLUGIN_ROOT}` script paths working.

## Route 2: clone and run install.py

Clone the repository and run the installer. It needs Python 3.10 or newer and nothing else.

```bash
git clone https://github.com/basitalisandhu/claude-skills
cd claude-skills
python3 install.py --user
```

`--user` copies every skill into `~/.claude/skills/`. These flags change what it does:

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

To update, run `git pull` in the clone and run the same command again. The copy route installs skills only. Hooks, commands, agents and MCP servers need route 1.

## Route 3: npx skills add

Other agents that read the Agent Skills format can install from this repository with the `skills` command line tool:

```bash
npx skills add basitalisandhu/claude-skills
```

On 2026-10-04 the tool found all 87 skills in this repository. I have not tested it with every agent it supports, so check the result in the agent you use.

## Troubleshooting

### A skill does not show up

Check these in order:

- The `name` in `SKILL.md` must be the same as the name of its folder.
- The front matter must be strict YAML. A description that contains a colon must be wrapped in double quotes, or some parsers reject the file.
- Run `python3 install.py --list` in the clone. It prints the name each skill installs as, so you can see whether it is in the catalog at all.
- Start a new Claude Code session. Skills are read when a session starts.

### Two skills have the same name

If two plugins ever ship a skill with the same name, the first in plugin name order installs under the plain name and the second as `<plugin>-<skill>`, and the script says so. To avoid any clash, pass `--prefix` and every skill installs as `<plugin>-<skill>`. Today every skill name here is unique, and `scripts/validate.py` fails the build if that changes.

If a skill folder already exists and `install.py` did not write it, the script skips it. Pass `--force` to overwrite it.

### Uninstall

For the marketplace route, run `/plugin uninstall <plugin>@claude-skills` and, to drop the catalog, `/plugin marketplace remove claude-skills`. For the copy route, run `python3 install.py --user --uninstall` (or `--project --uninstall`). The script writes `.claude-skills-manifest.json` in the target folder and removes only the files listed there, so skills you wrote yourself stay.

## What this does not do

- It makes no network calls. `install.py` only copies files from your clone.
- It sends no telemetry and collects no data.
- It does not change your Claude Code settings. It does not edit `settings.json`, permissions or hooks.
- It does not install plugin-level hooks, commands, agents or MCP servers. Use route 1 for those.

Report a problem with a skill in the issues of its source repository, which each skill page links. Problems with the installer go to [this repository's issues](https://github.com/basitalisandhu/claude-skills/issues).
