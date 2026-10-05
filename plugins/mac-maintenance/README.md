# mac-maintenance

Mac maintenance skills for Claude Code: a survey that only measures, a safe tier that removes only the caches programs recreate, and a written list for every decision that is yours. For people whose Mac has filled up with build caches, duplicate phone exports, leftovers of uninstalled apps and a few gigabytes pinned in memory, and who do not want a cleaner that guesses.

Install with `/plugin marketplace add basitalisandhu/mac-maintenance-skills` and then `/plugin install mac-maintenance@mac-maintenance-skills`, or add it from Anthropic's directory. Skills appear as `/mac-maintenance:<skill>`, and Claude also invokes them on its own when a request matches a skill's description. Ask "look at my Mac and clean up the garbage" to start.

Use it when "System Data is huge" in Storage settings (the survey shows the caches, Docker and developer folders that usually make it up), or when Docker.raw has grown (the survey reports its size on disk, and the safe tier prunes Docker build cache). Time Machine local snapshots are not measured or removed by these skills; `tmutil listlocalsnapshots /` lists them.

## Skills

| Skill | Script | Use it to |
|---|---|---|
| `mac-cleanup` | `skills/mac-cleanup/scripts/mac_survey.py`, `skills/mac-cleanup/scripts/safe_clean.py` | survey what takes space and memory without changing anything, then remove only the caches and leftovers programs recreate (dry run by default), then write the decision list for everything else |
| `mac-duplicate-finder` | `skills/mac-duplicate-finder/scripts/find_dupes.py` | find byte-identical files in the user folders, see which folders mirror each other, and move verified " (1)" copies to a dated Trash folder |
| `mac-app-leftovers` | `skills/mac-app-leftovers/scripts/app_leftovers.py` | list data, preferences, login items and launch agents left by uninstalled apps, and move the ones the user names to a dated Trash folder |

## How it treats your Mac

- **Nothing of yours is deleted.** The cleaner removes only the cache and leftover locations listed below, and only when you pass `--apply`. Duplicate files and app leftovers are moved into a dated folder under `~/.Trash` with their relative paths kept, so Finder can put them back, and only after you say which ones.
- **Every size is measured**, by `du` or file metadata, and anything a tool could not check is reported as unverified rather than estimated.
- **No network, no telemetry, no sudo.** Nothing leaves the machine. Launch daemons that need administrator rights are listed with the command for you to run yourself.

## What the scripts run

The survey (`mac_survey.py`) is read-only. It runs `du -sk`, `docker system df`, `docker volume ls`, `docker buildx ls`, `brew cleanup -n`, `brew outdated`, `brew list`, `brew uses`, `brew services list`, `mdls` (Spotlight last-used dates of apps), `ps`, `sysctl`, `uptime`, and one `osascript` call to System Events to read login items. It writes a report only where you pass `--out`.

The cleaner (`safe_clean.py`) prints a plan by default. With `--apply` it removes these locations and runs these commands, each only when its condition holds: `~/.npm/_cacache` (unless npm is installing), stale `~/.npm/_npx` entries, `~/Library/Caches/go-build`, `uv cache prune`, `pip3 cache purge`, `brew cleanup --prune=all -s`, `docker builder prune -af`, `docker image prune -f` (dangling images), `docker volume prune -f` (anonymous unused volumes), `docker volume rm` of buildx state volumes whose builder no longer exists, Docker Desktop update downloads under Application Support and the temp folder (after `hdiutil detach` of a mounted installer image), `~/Library/Caches/*-updater` folders, `~/Library/Developer/Xcode/DerivedData` (unless Xcode is running), `xcrun simctl delete unavailable`, files in `~/Library/Logs` older than seven days, `~/Library/Caches/Google/Chrome/*/Cache` (unless Chrome is running), and `osascript` to delete login items whose app no longer exists. It refuses symbolic links and any path outside your home and temp folders.

The duplicate finder (`find_dupes.py`) reads files to hash them and moves files only with `--trash-suffix-copies`. The leftover finder (`app_leftovers.py`) runs `du -sk`, `mdfind` and one `osascript` call, reads `brew list`, and moves entries only with `--trash`.

## Where it works

The scripts need to run on the Mac being cleaned, so use the skills from Claude Code on that machine (the terminal, an IDE extension or the desktop app's Code tab). In claude.ai chat and Cowork the skill text loads but the scripts cannot reach your Mac's file system. Requirements: macOS with Python 3.11 or newer on `PATH` as `python3`. No third-party packages. Optional tools (docker, brew, uv, pip3, xcrun, mdls, osascript) are used when present and reported as unverified when not.

## Licence

MIT. See [LICENSE](LICENSE). Privacy: [PRIVACY.md](PRIVACY.md) (nothing is collected or sent). Source, tests and issues: [github.com/basitalisandhu/mac-maintenance-skills](https://github.com/basitalisandhu/mac-maintenance-skills).
