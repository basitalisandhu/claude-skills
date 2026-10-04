#!/usr/bin/env python3
"""Find data, preferences, login items and launch agents left behind by applications that are no longer
installed, and optionally move chosen leftovers into a dated folder in the Trash.

Where it looks (under --home unless noted):
  Library/Application Support, Library/Containers, Library/Group Containers, Library/Caches,
  Library/Preferences (*.plist), Library/Saved Application State, Library/HTTPStorages, Library/WebKit,
  Library/Logs, Library/LaunchAgents, and read-only /Library/LaunchAgents and /Library/LaunchDaemons

How "installed" is decided:
  every .app in the --apps-dir folders (default /Applications, ~/Applications, /System/Applications and their
  Utilities) contributes its bundle id, bundle name and file name; executables on PATH and Homebrew formulae
  count as installed tools. An entry is matched when its name or bundle id equals one of those, shares a token
  of three or more characters with one, contains or is contained in an installed name of five or more
  characters, when Spotlight knows an app with that bundle id (mdfind, unless --no-commands), when its Group
  Containers team id is also used by a matched entry, or when it is on the built-in list of system folders.
  Apple entries (com.apple.*) and UUID-named containers are never reported. Everything else is a candidate
  with its size and last change; cache, log, WebKit and saved-state entries below --min-mb are left out.

Login items whose target path no longer exists, and launch agents or daemons whose program no longer exists, are
listed separately; system-level ones need sudo and the command is printed rather than run.

With --trash ID[,ID...] the named candidates are moved into --trash-dir keeping their relative paths. Entries
macOS refuses to move (sandboxed containers) are reported with the Finder path instead of being forced.

Exit codes: 0 no candidates, 1 candidates found (or items moved), 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path

AREAS: list[tuple[str, str, str]] = [
    # id, relative folder, kind: dir entries or plist files
    ("app-support", "Library/Application Support", "dir"),
    ("containers", "Library/Containers", "dir"),
    ("group-containers", "Library/Group Containers", "dir"),
    ("caches", "Library/Caches", "dir"),
    ("preferences", "Library/Preferences", "plist"),
    ("saved-state", "Library/Saved Application State", "dir"),
    ("http-storages", "Library/HTTPStorages", "dir"),
    ("webkit", "Library/WebKit", "dir"),
    ("logs", "Library/Logs", "dir"),
]
SYSTEM_NAMES = {
    "addressbook", "animoji", "app store", "callhistorydb", "callhistorytransactions", "clouddocs", "controlcenter",
    "crashreporter", "differentialprivacy", "diskimages", "facetime", "familysettings", "fileprovider",
    "knowledge", "mobilesync", "music", "sesstorage", "spotlight", "syncservices", "appplaceholdersyncd",
    "contactsd", "default.store", "default.store-shm", "default.store-wal", "icloud", "dock", "caches",
    "byhost", "loginwindow", ".globalpreferences", "com.googlecode.iterm2", "textmate", "mail", "messages",
    "photos", "safari", "notes", "reminders", "calendar", "diagnosticreports", "corespotlight", "homebrew",
    "pip", "go-build", "node-gyp", "python", "cocoapods", "ms-playwright", "puppeteer", "claude-cli-nodejs",
    "geoservices", "cloudkit", "metadata", "logs", "fonts", "keychains", "accessibility", "colorpickers",
    "services", "scripts", "sounds", "spelling", "autosave information", "shared", "ubiquity", "passkit",
    "gamekit", "askpermissiond", "familycircled", "mbuseragent", "icloudmailagent", "networkserviceproxy",
    "webpush", "minilauncher", "sharedfilelist", "corespeech", "siri", "news", "stocks", "weather", "tips",
    "homeenergyd", "stickersd", "tipsd", "corespotlightd", "sharedfilelistd", "pbs", "mobilemeaccounts",
    "tokenbucketratelimiter", "icdd", "mobileassetdesktop", "wallpaper", "replayd", "shazamd",
}
TEAM_PREFIX_RE = re.compile(r"^[A-Z0-9]{10}\.")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
LESSER_AREAS = {"caches", "saved-state", "http-storages", "webkit", "logs"}
MIN_TOKEN = 3
SUBSTRING_MIN = 5


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= MIN_TOKEN and t not in {"com", "org",
            "net", "app", "mac", "macos", "desktop", "the", "inc", "llc", "electron", "helper", "software"}}


class Installed:
    def __init__(self, app_dirs: list[Path], commands: bool, timeout: int) -> None:
        self.bundle_ids: set[str] = set()
        self.names: set[str] = set()
        self.tokens: set[str] = set()
        self.tools: set[str] = set()
        self.commands = commands
        self.timeout = timeout
        self._mdfind: dict[str, bool] = {}
        # command-line tools: executables on PATH and Homebrew formulae, so their caches are not "leftovers"
        for folder in os.environ.get("PATH", "").split(os.pathsep):
            try:
                self.tools |= {n.lower() for n in os.listdir(folder)} if folder else set()
            except OSError:
                pass
        if commands and shutil.which("brew"):
            try:
                proc = subprocess.run(["brew", "list", "--formula"], capture_output=True, text=True,
                                      timeout=timeout, check=False)
                if proc.returncode == 0:
                    self.tools |= {n.split("@")[0].lower() for n in proc.stdout.split()}
            except (subprocess.TimeoutExpired, OSError):
                pass
        for folder in app_dirs:
            if not folder.is_dir():
                continue
            for app in folder.glob("*.app"):
                self.add(app.stem)
                try:
                    with open(app / "Contents" / "Info.plist", "rb") as fh:
                        plist = plistlib.load(fh)
                except (OSError, plistlib.InvalidFileException, ValueError):
                    continue
                for key in ("CFBundleIdentifier",):
                    if plist.get(key):
                        self.bundle_ids.add(str(plist[key]).lower())
                        self.tokens |= tokens(str(plist[key]))
                for key in ("CFBundleName", "CFBundleDisplayName", "CFBundleExecutable"):
                    if plist.get(key):
                        self.add(str(plist[key]))

    def add(self, name: str) -> None:
        self.names.add(name.lower())
        self.tokens |= tokens(name)

    def spotlight_has(self, bundle_id: str) -> bool | None:
        if not self.commands or shutil.which("mdfind") is None:
            return None
        if bundle_id not in self._mdfind:
            try:
                proc = subprocess.run(["mdfind", f"kMDItemCFBundleIdentifier == '{bundle_id}'"],
                                      capture_output=True, text=True, timeout=self.timeout, check=False)
                self._mdfind[bundle_id] = proc.returncode == 0 and bool(proc.stdout.strip())
            except (subprocess.TimeoutExpired, OSError):
                self._mdfind[bundle_id] = False
        return self._mdfind[bundle_id]

    def match(self, entry_name: str) -> str | None:
        """Why the entry belongs to something installed, or None when nothing claims it."""
        name = TEAM_PREFIX_RE.sub("", entry_name)
        low = name.lower()
        for suffix in (".plist", ".savedstate", ".app"):
            if low.endswith(suffix):
                low = low[: -len(suffix)]
        if low.startswith("com.apple") or low in SYSTEM_NAMES or UUID_RE.match(low):
            return "system"
        if low in self.bundle_ids or low in self.names:
            return "installed app"
        if low in self.tools:
            return "command-line tool on PATH or in Homebrew"
        entry_tokens = tokens(low)
        shared = entry_tokens & (self.tokens | self.tools)
        if shared:
            return "name shared with installed app or tool: " + ", ".join(sorted(shared)[:3])
        for et in entry_tokens:
            if len(et) < SUBSTRING_MIN:
                continue
            for it in self.tokens | self.tools:
                if len(it) >= SUBSTRING_MIN and (it in et or et in it):
                    return f"name contains installed name: {it}"
        if "." in low and not low.startswith("."):
            found = self.spotlight_has(low)
            if found:
                return "Spotlight knows an app with this bundle id"
        return None


def size_of(path: Path, commands: bool, timeout: int) -> int | None:
    if commands and shutil.which("du"):
        try:
            proc = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True, timeout=timeout,
                                  check=False)
            m = re.match(r"^\s*(\d+)", proc.stdout)
            if m:
                return int(m.group(1)) * 1024
        except (subprocess.TimeoutExpired, OSError):
            pass
    total = 0
    try:
        if path.is_file():
            return path.lstat().st_blocks * 512
        for root, dirs, files in os.walk(path, onerror=lambda e: None):
            for name in files + dirs:
                try:
                    total += os.lstat(os.path.join(root, name)).st_blocks * 512
                except OSError:
                    pass
    except OSError:
        return None
    return total


def scan(home: Path, installed: Installed, commands: bool, timeout: int, keep: set[str],
         min_bytes: int) -> list[dict]:
    """Two passes: match every entry, then let a Group Containers team id that any installed app uses vouch for
    the other entries with the same team id (Office's shared container is named by team id, not by an app)."""
    entries: list[tuple[str, Path]] = []
    for area_id, rel, kind in AREAS:
        folder = home / rel
        if not folder.is_dir():
            continue
        try:
            listing = sorted(folder.iterdir())
        except OSError:
            continue
        for entry in listing:
            if entry.name.startswith(".") and entry.name not in (".GlobalPreferences.plist",):
                continue
            if kind == "plist" and (entry.suffix != ".plist" or not entry.is_file()):
                continue
            if kind == "dir" and not entry.is_dir():
                continue
            if entry.name.lower() in keep or entry.stem.lower() in keep:
                continue
            entries.append((area_id, entry))
    reasons = {str(entry): installed.match(entry.name) for _, entry in entries}
    vouched_teams = {entry.name[:10] for area_id, entry in entries
                     if area_id == "group-containers" and TEAM_PREFIX_RE.match(entry.name)
                     and reasons[str(entry)] not in (None, "system")}
    candidates = []
    for area_id, entry in entries:
        reason = reasons[str(entry)]
        if reason is None and area_id == "group-containers" and entry.name[:10] in vouched_teams:
            reason = "team id shared with an installed app"
        if reason is not None:
            continue
        size = size_of(entry, commands, timeout)
        if area_id in LESSER_AREAS and (size or 0) < min_bytes:
            continue
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d")
        except OSError:
            mtime = None
        kind = "cache or log (regenerable)" if area_id in LESSER_AREAS else "app data"
        candidates.append({"id": f"{area_id}:{entry.name}", "area": area_id, "name": entry.name,
                           "path": str(entry), "bytes": size, "last_changed": mtime, "kind": kind,
                           "note": "no installed app or tool claims this name; confirm before moving it"})
    candidates.sort(key=lambda c: c["bytes"] or 0, reverse=True)
    return candidates


def startup_leftovers(home: Path, commands: bool, timeout: int) -> dict:
    out: dict = {"login_items": [], "launch_agents": [], "launch_daemons": []}
    if commands and shutil.which("osascript"):
        try:
            proc = subprocess.run(["osascript", "-e",
                                   'tell application "System Events" to get {name, path} of every login item'],
                                  capture_output=True, text=True, timeout=timeout, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                halves = proc.stdout.strip().split(", ")
                n = len(halves) // 2
                for name, path in zip(halves[:n], halves[n:], strict=False):
                    if path and not Path(path).exists():
                        fix = ('osascript -e \'tell application "System Events" to delete login item '
                               f'"{name}"\'')
                        out["login_items"].append({"name": name, "path": path, "fix": fix})
        except (subprocess.TimeoutExpired, OSError):
            pass
    for key, folder, system in (("launch_agents", home / "Library/LaunchAgents", False),
                                ("launch_agents", Path("/Library/LaunchAgents"), True),
                                ("launch_daemons", Path("/Library/LaunchDaemons"), True)):
        if not folder.is_dir():
            continue
        for plist_path in sorted(folder.glob("*.plist")):
            try:
                with open(plist_path, "rb") as fh:
                    plist = plistlib.load(fh)
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            program = plist.get("Program") or (plist.get("ProgramArguments") or [None])[0]
            if program and "/" in str(program) and not Path(str(program)).exists():
                domain = "system" if system else f"gui/{os.getuid()}"
                fix = (f"sudo launchctl bootout {domain} {plist_path} && sudo rm {plist_path}" if system
                       else f"launchctl bootout {domain} {plist_path} && rm {plist_path}")
                out[key].append({"plist": str(plist_path), "program": str(program), "fix": fix})
    return out


def trash(candidates: list[dict], ids: set[str], trash_dir: Path, home: Path) -> tuple[list[dict], list[dict]]:
    moved, failed = [], []
    by_id = {c["id"]: c for c in candidates}
    for item_id in sorted(ids):
        c = by_id.get(item_id)
        if c is None:
            failed.append({"id": item_id, "error": "not a candidate in this run"})
            continue
        src = Path(c["path"])
        try:
            rel = src.relative_to(home)
            dest = trash_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                raise OSError(f"already in the trash folder: {dest}")
            shutil.move(str(src), str(dest))
            moved.append({**c, "moved_to": str(dest)})
        except PermissionError as exc:
            failed.append({**c, "error": f"macOS refused ({exc.strerror}); move it to the Trash in Finder: {src}"})
        except (OSError, ValueError) as exc:
            failed.append({**c, "error": str(exc)})
    return moved, failed


def render(result: dict, top: int) -> str:
    lines = [f"Installed apps known: {result['installed_apps']} (bundle ids), scanned {len(AREAS)} areas under "
             f"{result['home']}/Library", ""]
    if result["candidates"]:
        lines.append(f"Leftover candidates ({len(result['candidates'])}, {human(result['candidate_bytes'])}); "
                     "confirm each before moving it:")
        for c in result["candidates"][:top]:
            lines.append(f"  {human(c['bytes']):>10}  changed {c['last_changed'] or '?':<10}  "
                         f"{c['kind']:<26}  {c['id']}")
        if len(result["candidates"]) > top:
            lines.append(f"  ... {len(result['candidates']) - top} more (use --json or a larger --top)")
    else:
        lines.append("No leftover candidates.")
    st = result["startup"]
    for key, label in (("login_items", "Login items whose app is gone"),
                       ("launch_agents", "Launch agents whose program is gone"),
                       ("launch_daemons", "Launch daemons whose program is gone (need sudo)")):
        if st[key]:
            lines.append("")
            lines.append(f"{label}:")
            for item in st[key]:
                lines.append(f"  {item.get('name') or item.get('plist')}  ->  "
                             f"{item.get('path') or item.get('program')}")
                lines.append(f"      fix: {item['fix']}")
    if result.get("moved") is not None:
        lines.append("")
        lines.append(f"Moved to {result['trash_dir']}: {len(result['moved'])} items, {human(result['moved_bytes'])}")
        lines += [f"  not moved: {f.get('id')}: {f['error']}" for f in result["failed"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--home", default=str(Path.home()), help="home folder (default: your home)")
    ap.add_argument("--apps-dir", action="append", default=None,
                    help="application folder (repeatable; default /Applications, ~/Applications, /System/Applications)")
    ap.add_argument("--keep", action="append", default=[], help="entry name to never report (repeatable)")
    ap.add_argument("--min-mb", type=float, default=1.0,
                    help="smallest cache, log, WebKit or saved-state entry to report in MB (default 1); "
                         "app data areas are always reported")
    ap.add_argument("--trash", help="comma-separated candidate ids (area:name) to move into --trash-dir")
    ap.add_argument("--trash-dir", help="destination for moved items (default ~/.Trash/app-leftovers-<date>)")
    ap.add_argument("--top", type=int, default=25, help="rows in the text output (default 25)")
    ap.add_argument("--no-commands", action="store_true", help="do not run mdfind, osascript or du")
    ap.add_argument("--timeout", type=int, default=60, help="seconds per external command (default 60)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser()
    if not home.is_dir():
        print(f"error: not a directory: {home}", file=sys.stderr)
        return 2
    app_dirs = [Path(p).expanduser() for p in args.apps_dir] if args.apps_dir else [
        Path("/Applications"), Path("/Applications/Utilities"), home / "Applications", Path("/System/Applications"),
        Path("/System/Applications/Utilities")]
    commands = not args.no_commands
    started = time.time()
    installed = Installed(app_dirs, commands, args.timeout)
    keep = {k.lower() for k in args.keep}
    candidates = scan(home, installed, commands, args.timeout, keep, int(args.min_mb * 1024 * 1024))
    result = {"home": str(home), "installed_apps": len(installed.bundle_ids), "candidates": candidates,
              "candidate_bytes": sum(c["bytes"] or 0 for c in candidates),
              "startup": startup_leftovers(home, commands, args.timeout), "moved": None, "failed": [],
              "moved_bytes": 0, "trash_dir": None, "seconds": round(time.time() - started, 1)}
    if args.trash:
        ids = {s.strip() for s in args.trash.split(",") if s.strip()}
        trash_dir = (Path(args.trash_dir).expanduser() if args.trash_dir
                     else home / ".Trash" / f"app-leftovers-{date.today()}")
        trash_dir.mkdir(parents=True, exist_ok=True)
        moved, failed = trash(candidates, ids, trash_dir, home)
        result.update({"moved": moved, "failed": failed, "moved_bytes": sum(m["bytes"] or 0 for m in moved),
                       "trash_dir": str(trash_dir)})
    print(json.dumps(result, indent=2) if args.json else render(result, args.top))
    st = result["startup"]
    return 1 if (candidates or st["login_items"] or st["launch_agents"] or st["launch_daemons"]) else 0


if __name__ == "__main__":
    sys.exit(main())
