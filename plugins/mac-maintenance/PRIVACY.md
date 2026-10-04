# Privacy policy

This plugin runs on your own Mac and nothing it does leaves your machine.

## What it reads

The scripts read file and folder names, sizes and modification dates in your home folder and in the locations named in each script's docstring, the metadata of installed applications (bundle id, version, Spotlight's last-used date), your login items and launch agent files, the list of running processes, and the output of Docker and Homebrew commands. They read file contents only to hash them when you look for duplicates.

## What it collects, stores or sends

Nothing is collected and nothing is sent anywhere. The scripts make no network connections and contain no telemetry, analytics or crash reporting. They write files only where you tell them to: a survey report with `--out`, duplicate lists with `--out-dir`, a cleanup log with `--log`, and moved items in a dated folder under your own Trash. Those files stay on your Mac and are yours to delete.

## What Claude sees

When you use the skills in Claude Code, the scripts' output (file names, sizes, app names, process names) is shown to Claude in your conversation so it can explain the findings and ask for your decisions. That output is handled under the Claude plan and privacy terms of the account you use; this plugin does not send it anywhere else.

## Children

The plugin is not directed at people under 18.

## Changes and contact

Changes to this policy are recorded in [CHANGELOG.md](CHANGELOG.md). Questions: open an issue on [github.com/basitalisandhu/mac-maintenance-skills](https://github.com/basitalisandhu/mac-maintenance-skills). Security concerns: see [SECURITY.md](SECURITY.md).
