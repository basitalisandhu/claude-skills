# Decision tiers: how to judge what the survey cannot

The safe tier is small on purpose. Most of the space on a developer's Mac sits in things that are regenerable in principle but have a cost or a risk the script cannot weigh: a checkout with uncommitted work, a model that took an hour to download, a CI cache that makes builds fast. This file is the checklist for turning those into a decision the user can make in a sentence.

## Git worktrees and sibling checkouts

A folder of worktrees from a batch of agent or campaign work is the most common multi-gigabyte leftover. For each worktree:

```bash
git -C <main repo> fetch --quiet origin
git -C <worktree> rev-parse --abbrev-ref HEAD                      # branch
git -C <worktree> status --porcelain | grep -v '^??' | wc -l       # modified tracked files
git -C <worktree> status --porcelain | grep '^??'                  # untracked files
git -C <worktree> branch -r --contains HEAD                        # remote branches that already contain it
```

Classify:

| Finding | Proposal |
|---|---|
| HEAD contained in the integration branch (origin/main or whatever the repository integrates into), no modified files, untracked files are only node_modules, logs or build output | remove with `git worktree remove --force <path>`; the branch stays |
| HEAD not on any remote branch | keep; say so |
| modified tracked files | keep; list the files so the user can decide |
| untracked file that looks like work (a report, a data file) | copy it to the dated cleanup folder first, then treat as the row above |

Check which branch the repository integrates into before judging "merged": a repository whose main branch is `v2` makes "not in origin/main" meaningless. Two full clones of the same remote in different folders are not duplicates to remove on sight; one may be a runner's or a tool's checkout.

## node_modules

Regenerable with the package manager, but a running test or dev server may be using one. Check `ps -axo args` for the folder before proposing it, prefer removing node_modules inside worktrees that are going anyway, and leave the main checkout's alone unless the user asks.

## CI and build caches in the home folder

Folders such as a buildx `--cache-to type=local` directory, Gradle, Maven, Cargo and Go module caches. Find who uses it (`grep -rIl <folder name> <repos> --exclude-dir=node_modules --exclude-dir=.git`), look at the newest file inside, and say what a removal costs: one slower cold build, a re-download. Untouched for weeks is a strong signal; still the user's call when it is large.

## Model and dataset caches

Ollama models (`ollama list`, `ollama ps`), Hugging Face and Whisper caches. A model that is loaded (`ollama ps`) is being used by something; find the client (`lsof -nP -iTCP:<port>`) before suggesting to stop it, and never stop it on your own when an experiment may be running. Unloading a model frees memory at once; deleting it frees disk and costs a download.

## Applications

- Same name family (`App` and `App (Classic)`, `App 2`): compare bundle ids and versions; the survey marks them. Usually the older or the "(Classic)" one goes, but say which is which.
- Several tools for one job (three editors, two terminals, two VPNs): list them with last-used dates and let the user pick.
- Last-used date: Spotlight's `kMDItemLastUsedDate` is missing for many apps that are used daily (password managers, menu bar apps). Present "no record" as exactly that.
- Apps with a poor reputation (bundled adware downloaders, free VPNs of unknown origin): say what they are in one neutral sentence and let the user decide; do not remove them unasked.
- Apple's creative apps (iMovie, GarageBand and the shared sound libraries in /Library/Application Support) are several gigabytes and reinstall from the App Store; a reasonable candidate when never opened.

## Homebrew

- `brew cleanup -n` for the safe estimate; `brew autoremove -n` for dependencies nothing needs.
- A formula installed as both a cask and a formula (PowerShell, some editors) is a duplicate; check which binary is on PATH (`which -a`) before proposing which to drop.
- Several versions of one family (`icu4c@76`, `@77`, `@78`): the survey lists which installed formulae need each; a version with no users is the candidate.
- `brew upgrade` is not a cleanup step. A major bump of node or a database under running work is the user's decision; mention the outdated count and leave it.

## Personal folders

Photo and video dumps from old phones often mirror each other (an `Iphone 7` export, a `data` folder, an `Unset` folder). The duplicate finder's folder-pair table shows which folders mirror which; propose keeping the better-organised side and moving the other's duplicates to the Trash, never deleting. Archives next to the folder they were made from (`X.rar` beside `X/`) are a question for the user, not a conclusion.

## Startup and memory

- Login items: each one is a process at boot; three or four chat and meeting apps at login are a legitimate thing to mention.
- `brew services list`: a database started at login that the user does not use daily is a candidate to stop (`brew services stop <name>`), not to uninstall.
- Launch agents and daemons whose program no longer exists are safe to remove; system-level ones need sudo, so hand over the command.
- Swap in use with gigabytes wired by one process: name the process and what it is doing; a reboot after cleanup clears compressed memory and swap.
