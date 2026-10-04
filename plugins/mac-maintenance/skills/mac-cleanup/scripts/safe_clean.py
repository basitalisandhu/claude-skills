#!/usr/bin/env python3
"""Plan, and with --apply perform, the safe tier of a Mac cleanup: only caches and leftovers that a program
recreates on its own. Nothing here touches documents, photos, applications, app settings or the Trash.

Actions (each is skipped with a reason when its condition is not met; the default run is a dry run that prints
the plan with sizes):
  npm-cache               ~/.npm/_cacache                      unless npm install or npm ci is running
  npx-stale               ~/.npm/_npx entries older than --npx-days and not used by a running process
  go-build                ~/Library/Caches/go-build
  uv-cache                uv cache prune                       reported as locked when uv processes hold the lock
  pip-cache               pip3 cache purge, else the pip cache folders
  brew-cleanup            brew cleanup --prune=all -s
  docker-build-cache      docker builder prune -af             when the Docker daemon answers
  docker-dangling-images  docker image prune -f
  docker-anon-volumes     docker volume prune -f               anonymous volumes no container uses
  docker-orphan-buildx    docker volume rm of buildx_buildkit_*_state volumes whose builder no longer exists
  docker-stuck-installer  Docker Desktop update downloads in Application Support and the temp folder, after
                          detaching any installer image still mounted from them
  electron-updaters       ~/Library/Caches/*-updater and @*electron-updater download folders
  xcode-derived-data      ~/Library/Developer/Xcode/DerivedData  unless Xcode is running
  simulators-unavailable  xcrun simctl delete unavailable
  old-logs                files in ~/Library/Logs older than --log-days
  chrome-cache            ~/Library/Caches/Google/Chrome/*/Cache  unless Google Chrome is running
  orphan-login-items      login items whose target no longer exists

Every path action refuses symbolic links and anything outside the home folder, and records entries macOS would
not let it remove (sandboxed containers) instead of pretending. Exit codes: dry run 1 when there is something
to clean, 0 when there is nothing; --apply 0 when every applicable action succeeded, 1 when any failed; 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ACTION_IDS = ["npm-cache", "npx-stale", "go-build", "uv-cache", "pip-cache", "brew-cleanup", "docker-build-cache",
              "docker-dangling-images", "docker-anon-volumes", "docker-orphan-buildx", "docker-stuck-installer",
              "electron-updaters", "xcode-derived-data", "simulators-unavailable", "old-logs", "chrome-cache",
              "orphan-login-items"]


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


class Cleaner:
    def __init__(self, home: Path, tmpdir: Path, commands: bool, apply: bool, timeout: int, npx_days: int,
                 log_days: int, log_path: Path | None) -> None:
        self.home = home.resolve()
        self.tmpdir = tmpdir
        self.commands = commands
        self.apply = apply
        self.timeout = timeout
        self.npx_days = npx_days
        self.log_days = log_days
        self.log_path = log_path
        self.actions: list[dict] = []
        self._ps_cache: str | None = None

    # ---------- plumbing ----------
    def log(self, line: str) -> None:
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {line}\n")

    def record(self, action_id: str, title: str, status: str, size: int | None = None, detail: str = "",
               targets: list[str] | None = None) -> dict:
        row = {"id": action_id, "title": title, "status": status, "bytes": size, "detail": detail,
               "targets": targets or []}
        self.actions.append(row)
        self.log(f"{action_id}: {status} {human(size) if size else ''} {detail}".strip())
        return row

    def have(self, cmd: str) -> bool:
        return self.commands and shutil.which(cmd) is not None

    def run(self, argv: list[str], env: dict | None = None) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout, check=False,
                                  env={**os.environ, **(env or {})})
            return proc.returncode, proc.stdout, proc.stderr
        except (subprocess.TimeoutExpired, OSError) as exc:
            return 124, "", str(exc)

    def ps(self) -> str:
        if self._ps_cache is None:
            self._ps_cache = self.run(["ps", "-axo", "args="])[1] if self.have("ps") else ""
        return self._ps_cache

    def running(self, pattern: str) -> bool:
        return re.search(pattern, self.ps(), re.MULTILINE) is not None

    def size_of(self, path: Path) -> int:
        if not path.exists():
            return 0
        if self.have("du"):
            rc, out, _ = self.run(["du", "-sk", str(path)])
            m = re.match(r"^\s*(\d+)", out)
            if rc == 0 and m:
                return int(m.group(1)) * 1024
        total = 0
        if path.is_file():
            return path.lstat().st_blocks * 512
        for root, dirs, files in os.walk(path, onerror=lambda e: None):
            for name in files + dirs:
                try:
                    total += os.lstat(os.path.join(root, name)).st_blocks * 512
                except OSError:
                    pass
        return total

    def safe_path(self, path: Path) -> str | None:
        """Reason the path must not be removed, or None when it is a plain entry inside the home or temp folder."""
        if path.is_symlink():
            return "symbolic link"
        try:
            resolved = path.resolve()
        except OSError as exc:
            return str(exc)
        allowed_roots = (str(self.home) + os.sep, str(self.tmpdir.resolve()) + os.sep)
        if not str(resolved).startswith(allowed_roots):
            return "outside the home and temp folders"
        if resolved in (self.home, self.home / "Library", self.home / "Library" / "Application Support"):
            return "refusing to remove a top-level folder"
        return None

    def remove_paths(self, action_id: str, title: str, paths: list[Path], detail: str = "") -> None:
        paths = [p for p in paths if p.exists() or p.is_symlink()]
        if not paths:
            self.record(action_id, title, "nothing to do", 0, detail)
            return
        blocked = {str(p): r for p in paths if (r := self.safe_path(p))}
        allowed = [p for p in paths if str(p) not in blocked]
        size = sum(self.size_of(p) for p in allowed)
        if blocked:
            detail = ((detail + "; " if detail else "") + "refused: "
                      + "; ".join(f"{p} ({r})" for p, r in blocked.items()))
        if not self.apply:
            self.record(action_id, title, "planned", size, detail, [str(p) for p in allowed])
            return
        failures: list[str] = []
        for p in allowed:
            if p.is_dir():
                shutil.rmtree(p, onerror=lambda f, path, exc: failures.append(f"{path}: {exc[1]}"))
            else:
                try:
                    p.unlink()
                except OSError as exc:
                    failures.append(f"{p}: {exc}")
        status = "done" if not failures else "partly failed"
        self.record(action_id, title, status, size,
                    (detail + f"; {len(failures)} entries not removed, e.g. {failures[0][:160]}")
                    if failures else detail,
                    [str(p) for p in allowed])

    def run_command(self, action_id: str, title: str, argv: list[str], detail: str = "",
                    env: dict | None = None, ok_pattern: str | None = None) -> None:
        if not self.have(argv[0]):
            self.record(action_id, title, "skipped", 0, f"{argv[0]} not available")
            return
        if not self.apply:
            self.record(action_id, title, "planned", None, f"{' '.join(argv)}; {detail}".strip("; "))
            return
        rc, out, err = self.run(argv, env)
        text = (out + err).strip()
        if rc == 0:
            m = re.search(ok_pattern, text) if ok_pattern else None
            self.record(action_id, title, "done", None, m.group(0) if m else text[-160:], [" ".join(argv)])
        elif "lock" in text.lower() and "timeout" in text.lower():
            self.record(action_id, title, "locked", None, "another process holds the cache lock; retry later")
        else:
            self.record(action_id, title, "failed", None, text[-200:])

    # ---------- actions ----------
    def npm_cache(self) -> None:
        if self.running(r"npm (install|ci|i)\b"):
            self.record("npm-cache", "npm download cache", "skipped", 0, "npm install is running")
            return
        self.remove_paths("npm-cache", "npm download cache", [self.home / ".npm" / "_cacache"],
                          "npm re-downloads packages on the next install")

    def npx_stale(self) -> None:
        folder = self.home / ".npm" / "_npx"
        if not folder.is_dir():
            self.record("npx-stale", "stale npx packages", "nothing to do", 0)
            return
        cutoff = time.time() - self.npx_days * 86400
        in_use = set(re.findall(r"_npx/([0-9a-f]+)", self.ps()))
        stale = [p for p in folder.iterdir() if p.is_dir() and p.name not in in_use and p.stat().st_mtime < cutoff]
        self.remove_paths("npx-stale", "stale npx packages", stale,
                          f"older than {self.npx_days} days and not used by a running process")

    def go_build(self) -> None:
        self.remove_paths("go-build", "Go build cache", [self.home / "Library" / "Caches" / "go-build"],
                          "go rebuilds what it needs")

    def uv_cache(self) -> None:
        self.run_command("uv-cache", "uv cache", ["uv", "cache", "prune"], "removes unused cache entries",
                         env={"UV_LOCK_TIMEOUT": "15"}, ok_pattern=r"Removed [^\n]+")

    def pip_cache(self) -> None:
        if self.have("pip3"):
            self.run_command("pip-cache", "pip cache", ["pip3", "cache", "purge"], ok_pattern=r"Files removed: \d+")
        else:
            self.remove_paths("pip-cache", "pip cache",
                              [self.home / "Library" / "Caches" / "pip", self.home / ".cache" / "pip"])

    def brew_cleanup(self) -> None:
        self.run_command("brew-cleanup", "Homebrew cleanup", ["brew", "cleanup", "--prune=all", "-s"],
                         "old versions and downloads", ok_pattern=r"freed approximately [^\n]+")

    def docker_ready(self) -> bool:
        if not self.have("docker"):
            return False
        rc, _, _ = self.run(["docker", "info", "--format", "{{.ServerVersion}}"])
        return rc == 0

    def docker(self) -> None:
        if not self.docker_ready():
            for action_id, title in (("docker-build-cache", "Docker build cache"),
                                     ("docker-dangling-images", "Docker dangling images"),
                                     ("docker-anon-volumes", "Docker unused anonymous volumes"),
                                     ("docker-orphan-buildx", "Docker orphan buildx volumes")):
                self.record(action_id, title, "skipped", 0, "docker not available or daemon not running")
        else:
            self.run_command("docker-build-cache", "Docker build cache", ["docker", "builder", "prune", "-af"],
                             ok_pattern=r"Total reclaimed space: [^\n]+")
            self.run_command("docker-dangling-images", "Docker dangling images", ["docker", "image", "prune", "-f"],
                             ok_pattern=r"Total reclaimed space: [^\n]+")
            self.run_command("docker-anon-volumes", "Docker unused anonymous volumes",
                             ["docker", "volume", "prune", "-f"], ok_pattern=r"Total reclaimed space: [^\n]+")
            _, volumes, _ = self.run(["docker", "volume", "ls", "--format", "{{.Name}}"])
            _, builders, _ = self.run(["docker", "buildx", "ls"])
            names = {line.split()[0].rstrip("*") for line in builders.splitlines()[1:]
                     if line.strip() and not line.startswith(" ")}
            orphans = [v for v in volumes.split()
                       if (m := re.fullmatch(r"buildx_buildkit_(.+?)\d*_state", v))
                       and not any(n.startswith(m.group(1)) for n in names)]
            if not orphans:
                self.record("docker-orphan-buildx", "Docker orphan buildx volumes", "nothing to do", 0)
            elif not self.apply:
                self.record("docker-orphan-buildx", "Docker orphan buildx volumes", "planned", None,
                            "state volumes whose builder is no longer registered", orphans)
            else:
                rc, out, err = self.run(["docker", "volume", "rm", *orphans])
                self.record("docker-orphan-buildx", "Docker orphan buildx volumes", "done" if rc == 0 else "failed",
                            None, (out + err).strip()[-160:], orphans)
        self.docker_stuck_installer()

    def docker_stuck_installer(self) -> None:
        targets = [self.home / "Library" / "Application Support" / "com.docker.install" / "in_progress",
                   self.tmpdir / "com.docker.install", self.tmpdir / "DockerDesktopUpdates"]
        present = [t for t in targets if t.exists()]
        if present and self.apply and self.have("hdiutil"):
            _, info, _ = self.run(["hdiutil", "info"])
            for line in info.splitlines():
                mount = line.strip().split("\t")[-1]
                if any(mount.startswith(str(t)) for t in targets) and mount.startswith("/"):
                    self.run(["hdiutil", "detach", mount, "-force"])
                    self.log(f"docker-stuck-installer: detached {mount}")
        self.remove_paths("docker-stuck-installer", "Docker Desktop stuck update downloads", present,
                          "Docker downloads the update again when needed")

    def electron_updaters(self) -> None:
        caches = self.home / "Library" / "Caches"
        found = [p for p in caches.glob("*") if p.is_dir() and (p.name.endswith("-updater")
                                                                or p.name.endswith("electron-updater"))] \
            if caches.is_dir() else []
        self.remove_paths("electron-updaters", "Electron app update downloads", found,
                          "apps download the next update again")

    def xcode_derived_data(self) -> None:
        if self.running(r"/Xcode\.app/Contents/MacOS/Xcode"):
            self.record("xcode-derived-data", "Xcode DerivedData", "skipped", 0, "Xcode is running")
            return
        self.remove_paths("xcode-derived-data", "Xcode DerivedData",
                          [self.home / "Library" / "Developer" / "Xcode" / "DerivedData"], "Xcode rebuilds")

    def simulators(self) -> None:
        if not (self.home / "Library" / "Developer" / "CoreSimulator").is_dir():
            self.record("simulators-unavailable", "unavailable simulators", "nothing to do", 0)
            return
        self.run_command("simulators-unavailable", "unavailable simulators",
                         ["xcrun", "simctl", "delete", "unavailable"])

    def old_logs(self) -> None:
        folder = self.home / "Library" / "Logs"
        if not folder.is_dir():
            self.record("old-logs", "old log files", "nothing to do", 0)
            return
        cutoff = time.time() - self.log_days * 86400
        files = [p for p in folder.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_mtime < cutoff]
        self.remove_paths("old-logs", f"log files older than {self.log_days} days", files)

    def chrome_cache(self) -> None:
        if self.running(r"/Google Chrome\.app/Contents/MacOS/Google Chrome( |$)"):
            self.record("chrome-cache", "Chrome cache", "skipped", 0, "Google Chrome is running; quit it and rerun")
            return
        base = self.home / "Library" / "Caches" / "Google" / "Chrome"
        found = [p for p in base.glob("*/Cache") if p.is_dir()] + [p for p in base.glob("*/Code Cache") if p.is_dir()] \
            if base.is_dir() else []
        self.remove_paths("chrome-cache", "Chrome cache", found, "Chrome rebuilds it")

    def orphan_login_items(self) -> None:
        if not self.have("osascript"):
            self.record("orphan-login-items", "login items with missing targets", "skipped", 0,
                        "osascript not available")
            return
        rc, out, _ = self.run(["osascript", "-e",
                               'tell application "System Events" to get {name, path} of every login item'])
        if rc != 0 or not out.strip():
            self.record("orphan-login-items", "login items with missing targets", "nothing to do", 0)
            return
        halves = out.strip().split(", ")
        n = len(halves) // 2
        missing = [name for name, path in zip(halves[:n], halves[n:], strict=False) if path and not Path(path).exists()]
        if not missing:
            self.record("orphan-login-items", "login items with missing targets", "nothing to do", 0)
        elif not self.apply:
            self.record("orphan-login-items", "login items with missing targets", "planned", None,
                        "the app behind each item no longer exists", missing)
        else:
            failed = []
            for name in missing:
                rc, _, err = self.run(["osascript", "-e",
                                       f'tell application "System Events" to delete login item "{name}"'])
                if rc != 0:
                    failed.append(f"{name}: {err.strip()[:80]}")
            self.record("orphan-login-items", "login items with missing targets",
                        "done" if not failed else "partly failed", None, "; ".join(failed), missing)

    def plan(self, only: set[str] | None, skip: set[str]) -> None:
        wanted = [a for a in ACTION_IDS if (only is None or a in only) and a not in skip]
        if "npm-cache" in wanted:
            self.npm_cache()
        if "npx-stale" in wanted:
            self.npx_stale()
        if "go-build" in wanted:
            self.go_build()
        if "uv-cache" in wanted:
            self.uv_cache()
        if "pip-cache" in wanted:
            self.pip_cache()
        if "brew-cleanup" in wanted:
            self.brew_cleanup()
        if {"docker-build-cache", "docker-dangling-images", "docker-anon-volumes", "docker-orphan-buildx",
                "docker-stuck-installer"} & set(wanted):
            if {"docker-build-cache", "docker-dangling-images", "docker-anon-volumes",
                    "docker-orphan-buildx"} & set(wanted):
                self.docker()
            else:
                self.docker_stuck_installer()
        if "electron-updaters" in wanted:
            self.electron_updaters()
        if "xcode-derived-data" in wanted:
            self.xcode_derived_data()
        if "simulators-unavailable" in wanted:
            self.simulators()
        if "old-logs" in wanted:
            self.old_logs()
        if "chrome-cache" in wanted:
            self.chrome_cache()
        if "orphan-login-items" in wanted:
            self.orphan_login_items()


def free_bytes(path: Path) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def render(result: dict) -> str:
    lines = [f"{'Mode: apply' if result['applied'] else 'Mode: dry run (nothing changed; add --apply)'}", ""]
    for a in result["actions"]:
        size = human(a["bytes"]) if a["bytes"] else ""
        lines.append(f"  {a['status']:<14} {size:>10}  {a['id']:<24} {a['title']}")
        if a["detail"]:
            lines.append(f"  {'':<14} {'':>10}  {'':<24} {a['detail']}")
    lines.append("")
    lines.append(f"Planned or done: {human(result['bytes_planned_or_done'])} across "
                 f"{result['count_planned_or_done']} actions")
    if result["free_before"] is not None and result["free_after"] is not None:
        lines.append(f"Free space: {human(result['free_before'])} before, {human(result['free_after'])} after")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Actions: " + ", ".join(ACTION_IDS))
    ap.add_argument("--apply", action="store_true", help="perform the actions (default: dry run)")
    ap.add_argument("--only", help="comma-separated action ids to run")
    ap.add_argument("--skip", default="", help="comma-separated action ids to leave out")
    ap.add_argument("--home", default=str(Path.home()), help="home folder (default: your home)")
    ap.add_argument("--tmpdir", default=os.environ.get("TMPDIR", "/tmp"), help="temporary folder (default $TMPDIR)")
    ap.add_argument("--npx-days", type=int, default=14, help="npx entries older than this are stale (default 14)")
    ap.add_argument("--log-days", type=int, default=7, help="log files older than this are removed (default 7)")
    ap.add_argument("--no-commands", action="store_true",
                    help="do not run external programs (brew, docker, uv, pip, osascript); path actions only")
    ap.add_argument("--timeout", type=int, default=600, help="seconds per external command (default 600)")
    ap.add_argument("--log", help="append a line per action to this file")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser()
    if not home.is_dir():
        print(f"error: not a directory: {home}", file=sys.stderr)
        return 2
    only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    unknown = ((only or set()) | skip) - set(ACTION_IDS)
    if unknown:
        print(f"error: unknown action id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    cleaner = Cleaner(home, Path(args.tmpdir), not args.no_commands, args.apply, args.timeout, args.npx_days,
                      args.log_days, Path(args.log) if args.log else None)
    before = free_bytes(home)
    cleaner.log(f"safe_clean {'apply' if args.apply else 'dry-run'} home={home} free_before={human(before)}")
    cleaner.plan(only, skip)
    after = free_bytes(home) if args.apply else None
    counted = [a for a in cleaner.actions if a["status"] in ("planned", "done", "partly failed")]
    result = {"applied": args.apply, "home": str(home), "actions": cleaner.actions,
              "bytes_planned_or_done": sum(a["bytes"] or 0 for a in counted),
              "count_planned_or_done": len(counted), "free_before": before, "free_after": after}
    cleaner.log(f"free_after={human(after)}")
    print(json.dumps(result, indent=2) if args.json else render(result))
    if args.apply:
        return 1 if any(a["status"] in ("failed", "partly failed") for a in cleaner.actions) else 0
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
