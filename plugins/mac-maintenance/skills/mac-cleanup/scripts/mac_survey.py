#!/usr/bin/env python3
"""Read-only survey of a Mac before a cleanup: what takes space, what is regenerable, what starts at login, what
is using memory. Nothing is deleted or changed.

Sections (every item names the path or command it came from; anything that could not be measured is listed under
"unverified" with the reason, never estimated):
  disk        free and total space of the volume holding the home folder
  home        size of each top-level entry of the home folder and of ~/Library
  caches      known regenerable caches and installer leftovers with sizes and how each comes back
  docker      images, containers, volumes and build cache with reclaimable sizes; buildx state volumes whose
              builder no longer exists; actual size of the Docker Desktop disk image
  brew        Homebrew cleanup estimate, outdated formulae, formula families installed in several versions and
              which installed formulae need each, running services
  apps        applications with size, version, bundle id and Spotlight last-used date; likely duplicate bundles
  startup     login items (with missing targets), third-party launch agents and daemons (with missing programs)
  processes   memory in use, swap, uptime and the top memory users
  large       files over --large-mb in the home folder, outside caches, clouds and the Trash
  node        node_modules folders over --node-mb

Exit codes: 0 nothing reclaimable found, 1 reclaimable candidates found, 2 bad input.
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
from pathlib import Path

CACHE_CATALOGUE: list[tuple[str, str, str]] = [
    # relative path, label, how it comes back
    ("Library/Caches", "app caches (per-app breakdown below)", "apps rebuild them"),
    (".npm/_cacache", "npm download cache", "npm re-downloads packages"),
    (".npm/_npx", "npx package cache", "npx reinstalls on next use"),
    ("Library/Caches/go-build", "Go build cache", "go rebuilds"),
    (".cache/uv", "uv cache", "uv re-downloads"),
    (".cache/pip", "pip cache", "pip re-downloads"),
    ("Library/Caches/pip", "pip cache", "pip re-downloads"),
    ("Library/Caches/Homebrew", "Homebrew downloads", "brew re-downloads"),
    ("Library/Caches/ms-playwright", "Playwright browsers", "playwright install"),
    (".cache/puppeteer", "Puppeteer browsers", "puppeteer reinstalls"),
    (".cache/huggingface", "Hugging Face models", "re-downloaded on use"),
    (".ollama/models", "Ollama models", "ollama pull (check ollama list first)"),
    ("Library/Developer/Xcode/DerivedData", "Xcode DerivedData", "Xcode rebuilds"),
    ("Library/Developer/Xcode/iOS DeviceSupport", "iOS device support files", "copied again from the device"),
    ("Library/Developer/CoreSimulator/Caches", "Simulator caches", "rebuilt"),
    ("Library/Logs", "user logs", "apps write new ones"),
    ("Library/Caches/Google/Chrome", "Chrome cache", "Chrome rebuilds it; clear with Chrome closed"),
    ("Library/Application Support/com.docker.install", "Docker Desktop installer downloads", "Docker re-downloads"),
    (".Trash", "Trash", "empty it from Finder when you are sure"),
    ("Downloads", "Downloads", "user files; installers (.dmg, .pkg, .zip) are the usual junk"),
]
LARGE_PRUNE = {"Library", ".Trash", "node_modules", ".git", ".npm", ".cache", ".ollama", ".docker"}
NON_APPLE_PLIST_SKIP = ("com.apple.",)


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


class Survey:
    def __init__(self, home: Path, commands: bool, timeout: int, large_mb: int, node_mb: int, fast: bool,
                 progress: bool) -> None:
        self.home = home
        self.commands = commands
        self.timeout = timeout
        self.large_mb = large_mb
        self.node_mb = node_mb
        self.fast = fast
        self.progress = progress
        self.report: dict = {"home": str(home), "sections": {}, "unverified": [], "candidates": []}

    # ---------- helpers ----------
    def note(self, msg: str) -> None:
        if self.progress:
            print(f"[survey] {msg}", file=sys.stderr, flush=True)

    def unverified(self, section: str, reason: str) -> None:
        self.report["unverified"].append({"section": section, "reason": reason})

    def candidate(self, kind: str, what: str, size: int | None, note: str) -> None:
        self.report["candidates"].append({"kind": kind, "what": what, "bytes": size, "note": note})

    def run(self, argv: list[str], section: str, env: dict | None = None) -> str | None:
        """Run a read-only command; None when disabled, missing or failing (recorded as unverified)."""
        if not self.commands:
            self.unverified(section, f"commands disabled: {' '.join(argv)}")
            return None
        if shutil.which(argv[0]) is None:
            self.unverified(section, f"{argv[0]} not on PATH")
            return None
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout, check=False,
                                  env={**os.environ, **(env or {})})
        except (subprocess.TimeoutExpired, OSError) as exc:
            self.unverified(section, f"{' '.join(argv)}: {exc}")
            return None
        if proc.returncode != 0:
            self.unverified(section, f"{' '.join(argv)}: exit {proc.returncode} {proc.stderr.strip()[:120]}")
            return None
        return proc.stdout

    def size_of(self, path: Path) -> int | None:
        """Bytes on disk (du -sk when available, else a Python walk that does not follow symlinks)."""
        if not path.exists():
            return None
        if self.commands and shutil.which("du"):
            try:
                proc = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True,
                                      timeout=self.timeout, check=False)
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
                        st = os.lstat(os.path.join(root, name))
                    except OSError:
                        continue
                    total += st.st_blocks * 512
        except OSError:
            return None
        return total

    def sizes_of_children(self, path: Path, top: int) -> list[dict]:
        rows = []
        try:
            children = [c for c in path.iterdir()]
        except OSError:
            return rows
        for child in children:
            size = self.size_of(child)
            if size is not None:
                rows.append({"path": str(child), "bytes": size})
        rows.sort(key=lambda r: r["bytes"], reverse=True)
        return rows[:top]

    # ---------- sections ----------
    def disk(self) -> None:
        self.note("disk")
        try:
            usage = shutil.disk_usage(self.home)
            self.report["sections"]["disk"] = {"total": usage.total, "used": usage.used, "free": usage.free,
                                               "source": f"disk_usage({self.home})"}
        except OSError as exc:
            self.unverified("disk", str(exc))

    def home_sizes(self, top: int) -> None:
        self.note("home folder sizes (this is the slow part)")
        self.report["sections"]["home"] = {
            "top_level": self.sizes_of_children(self.home, top),
            "library": self.sizes_of_children(self.home / "Library", top),
            "source": "du -sk" if self.commands and shutil.which("du") else "python walk",
        }

    def caches(self, top: int) -> None:
        self.note("caches")
        rows = []
        for rel, label, comeback in CACHE_CATALOGUE:
            p = self.home / rel
            size = self.size_of(p)
            if size is None:
                continue
            rows.append({"path": str(p), "label": label, "bytes": size, "comes_back": comeback})
            if size > 0 and rel not in (".Trash", "Downloads", "Library/Caches", ".ollama/models",
                                        ".cache/huggingface"):
                self.candidate("cache", str(p), size, f"{label}; {comeback}")
        tmp = Path(os.environ.get("TMPDIR", "/tmp"))
        tsize = self.size_of(tmp)
        if tsize is not None:
            rows.append({"path": str(tmp), "label": "temporary folder", "bytes": tsize,
                         "comes_back": "programs recreate what they need; stuck installer images live here"})
        per_app = self.sizes_of_children(self.home / "Library" / "Caches", top)
        installers = []
        for folder in (self.home / "Downloads", self.home / "Desktop"):
            if folder.is_dir():
                for p in folder.rglob("*"):
                    if p.is_file() and p.suffix.lower() in {".dmg", ".pkg", ".iso"}:
                        installers.append({"path": str(p), "bytes": p.stat().st_size})
        self.report["sections"]["caches"] = {"known": rows, "library_caches_top": per_app,
                                             "installers": installers}

    def docker(self) -> None:
        self.note("docker")
        out = self.run(["docker", "system", "df", "--format",
                        "{{.Type}}\t{{.TotalCount}}\t{{.Active}}\t{{.Size}}\t{{.Reclaimable}}"], "docker")
        section: dict = {}
        if out is not None:
            section["usage"] = [dict(zip(("type", "total", "active", "size", "reclaimable"), line.split("\t"),
                                     strict=False))
                                for line in out.strip().splitlines() if line.strip()]
            for row in section["usage"]:
                if row.get("reclaimable", "").split(" ")[0] not in ("0B", "0", ""):
                    self.candidate("docker", row["type"], None, f"reclaimable {row['reclaimable']}")
            volumes = self.run(["docker", "volume", "ls", "--format", "{{.Name}}"], "docker")
            builders = self.run(["docker", "buildx", "ls"], "docker")
            if volumes is not None and builders is not None:
                names = {line.split()[0] for line in builders.splitlines()[1:] if line.strip()
                         and not line.startswith(" ")}
                names = {n.rstrip("*") for n in names}
                orphans = []
                for vol in volumes.split():
                    m = re.fullmatch(r"buildx_buildkit_(.+?)\d*_state", vol)
                    if m and m.group(1) not in names and not any(n.startswith(m.group(1)) for n in names):
                        orphans.append(vol)
                section["orphan_buildx_volumes"] = orphans
                for vol in orphans:
                    self.candidate("docker", vol, None, "buildx state volume with no registered builder")
        raw = self.home / "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
        if raw.exists():
            section["docker_raw_bytes_on_disk"] = self.size_of(raw)
            section["docker_raw_apparent_bytes"] = raw.stat().st_size
        self.report["sections"]["docker"] = section

    def brew(self) -> None:
        self.note("homebrew")
        section: dict = {}
        out = self.run(["brew", "cleanup", "-n"], "brew")
        if out is not None:
            m = re.search(r"free approximately ([\d.,]+\s*[KMG]B)", out)
            section["cleanup_estimate"] = m.group(1) if m else "0"
            if m:
                self.candidate("brew", "brew cleanup --prune=all", None, f"would free {m.group(1)}")
        out = self.run(["brew", "outdated", "--quiet"], "brew")
        if out is not None:
            section["outdated"] = [line.strip() for line in out.splitlines() if line.strip()]
        out = self.run(["brew", "list", "--formula"], "brew")
        if out is not None:
            families: dict[str, list[str]] = {}
            for name in out.split():
                base = name.split("@")[0]
                families.setdefault(base, []).append(name)
            multi = {k: v for k, v in families.items() if len(v) > 1}
            section["versioned_families"] = {}
            for base, names in multi.items():
                users = {}
                for name in names:
                    dep = self.run(["brew", "uses", "--installed", name], "brew")
                    users[name] = dep.split() if dep is not None else None
                section["versioned_families"][base] = users
                for name, needed_by in users.items():
                    if needed_by == []:
                        self.candidate("brew", name, None,
                                       "installed in several versions; nothing installed needs this one")
        out = self.run(["brew", "services", "list"], "brew")
        if out is not None:
            section["services"] = [line.split()[0] for line in out.splitlines()[1:]
                                   if len(line.split()) > 1 and line.split()[1] == "started"]
        self.report["sections"]["brew"] = section

    def apps(self, app_dirs: list[Path]) -> None:
        self.note("applications")
        rows = []
        for folder in app_dirs:
            if not folder.is_dir():
                continue
            for app in sorted(folder.glob("*.app")):
                info = app / "Contents" / "Info.plist"
                bundle_id = version = None
                try:
                    with open(info, "rb") as fh:
                        plist = plistlib.load(fh)
                    bundle_id = plist.get("CFBundleIdentifier")
                    version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                except (OSError, plistlib.InvalidFileException, ValueError):
                    pass
                last_used = None
                out = self.run(["mdls", "-name", "kMDItemLastUsedDate", "-raw", str(app)], "apps")
                if out is not None and out.strip() not in ("(null)", ""):
                    last_used = out.strip()[:10]
                rows.append({"path": str(app), "name": app.stem, "bytes": self.size_of(app),
                             "bundle_id": bundle_id, "version": version, "last_used": last_used})
        by_stem: dict[str, list[dict]] = {}
        for row in rows:
            stem = re.sub(r"\s*(\(.*\)|\d+|copy)$", "", row["name"]).strip().lower()
            by_stem.setdefault(stem, []).append(row)
        duplicates = [[r["name"] for r in group] for group in by_stem.values() if len(group) > 1]
        for group in duplicates:
            self.candidate("apps", ", ".join(group), None, "same name family; likely duplicate bundles, confirm")
        rows.sort(key=lambda r: r["bytes"] or 0, reverse=True)
        self.report["sections"]["apps"] = {"apps": rows, "likely_duplicates": duplicates,
                                           "note": "last_used is Spotlight's record and is often missing for "
                                                   "apps that are used; confirm before acting on it"}

    def startup(self) -> None:
        self.note("startup items")
        section: dict = {"login_items": [], "launch_agents": [], "launch_daemons": []}
        out = self.run(["osascript", "-e",
                        'tell application "System Events" to get {name, path} of every login item'], "startup")
        if out is not None and out.strip():
            halves = out.strip().split(", ")
            # osascript prints "name1, name2, path1, path2" for a {name, path} pair of lists
            n = len(halves) // 2
            for name, path in zip(halves[:n], halves[n:], strict=False):
                exists = Path(path).exists() if path else False
                section["login_items"].append({"name": name, "path": path, "exists": exists})
                if not exists:
                    self.candidate("startup", f"login item {name}", None, f"target missing: {path}")
        for key, folder in (("launch_agents", self.home / "Library/LaunchAgents"),
                            ("launch_agents", Path("/Library/LaunchAgents")),
                            ("launch_daemons", Path("/Library/LaunchDaemons"))):
            if not folder.is_dir():
                continue
            for plist_path in sorted(folder.glob("*.plist*")):
                program = None
                try:
                    with open(plist_path, "rb") as fh:
                        plist = plistlib.load(fh)
                    program = plist.get("Program") or (plist.get("ProgramArguments") or [None])[0]
                except (OSError, plistlib.InvalidFileException, ValueError):
                    pass
                missing = bool(program) and not Path(str(program)).exists() and "/" in str(program)
                section[key].append({"plist": str(plist_path), "program": program, "program_missing": missing,
                                     "disabled": plist_path.suffix != ".plist"})
                if missing:
                    self.candidate("startup", str(plist_path), None, f"program missing: {program}")
        self.report["sections"]["startup"] = section

    def processes(self, top: int) -> None:
        self.note("processes")
        section: dict = {}
        out = self.run(["sysctl", "-n", "vm.swapusage"], "processes")
        if out is not None:
            section["swap"] = out.strip()
        out = self.run(["uptime"], "processes")
        if out is not None:
            section["uptime"] = out.strip()
        out = self.run(["ps", "-axo", "rss=,pcpu=,comm="], "processes")
        if out is not None:
            procs = []
            for line in out.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) == 3 and parts[0].isdigit():
                    procs.append({"rss_bytes": int(parts[0]) * 1024, "cpu": parts[1], "command": parts[2]})
            procs.sort(key=lambda p: p["rss_bytes"], reverse=True)
            section["top_memory"] = procs[:top]
            section["total_rss_bytes"] = sum(p["rss_bytes"] for p in procs)
        out = self.run(["sysctl", "-n", "hw.memsize"], "processes")
        if out is not None and out.strip().isdigit():
            section["physical_bytes"] = int(out.strip())
        self.report["sections"]["processes"] = section

    def large_and_node(self, top: int) -> None:
        self.note("large files and node_modules (walking the home folder)")
        large, node = [], []
        limit, node_limit = self.large_mb * 1024 * 1024, self.node_mb * 1024 * 1024
        for root, dirs, files in os.walk(self.home, onerror=lambda e: None):
            keep = []
            for d in dirs:
                full = os.path.join(root, d)
                if d == "node_modules":
                    size = self.size_of(Path(full))
                    if size is not None and size >= node_limit:
                        node.append({"path": full, "bytes": size})
                    continue
                if (root == str(self.home) and d in LARGE_PRUNE) or d in {".git", "node_modules"} \
                        or os.path.islink(full) or full.startswith(str(self.home / "Library")):
                    continue
                keep.append(d)
            dirs[:] = keep
            for name in files:
                try:
                    st = os.lstat(os.path.join(root, name))
                except OSError:
                    continue
                if st.st_size >= limit and not os.path.islink(os.path.join(root, name)):
                    large.append({"path": os.path.join(root, name), "bytes": st.st_size})
        large.sort(key=lambda r: r["bytes"], reverse=True)
        node.sort(key=lambda r: r["bytes"], reverse=True)
        self.report["sections"]["large"] = large[:top]
        self.report["sections"]["node"] = node[:top]
        for row in node:
            self.candidate("node_modules", row["path"], row["bytes"],
                           "regenerable with the package manager if the project is idle")


def render(report: dict, top: int) -> str:
    s = report["sections"]
    lines = [f"Mac survey of {report['home']}", ""]
    if "disk" in s:
        d = s["disk"]
        lines += [f"Disk: {human(d['free'])} free of {human(d['total'])}", ""]
    if "home" in s:
        lines.append("Largest entries in the home folder:")
        lines += [f"  {human(r['bytes']):>10}  {r['path']}" for r in s["home"]["top_level"][:top]]
        lines.append("Largest entries in ~/Library:")
        lines += [f"  {human(r['bytes']):>10}  {r['path']}" for r in s["home"]["library"][:top]]
        lines.append("")
    if "caches" in s:
        lines.append("Known caches and leftovers (size, path, how it comes back):")
        for r in sorted(s["caches"]["known"], key=lambda r: r["bytes"], reverse=True):
            lines.append(f"  {human(r['bytes']):>10}  {r['path']}  [{r['comes_back']}]")
        if s["caches"]["installers"]:
            lines.append("Installer files in Downloads and Desktop:")
            lines += [f"  {human(r['bytes']):>10}  {r['path']}" for r in s["caches"]["installers"][:top]]
        lines.append("")
    if s.get("docker"):
        lines.append("Docker:")
        for r in s["docker"].get("usage", []):
            lines.append(f"  {r['type']:<14} total {r['total']:>4}  active {r['active']:>3}  size {r['size']:>9}  "
                         f"reclaimable {r['reclaimable']}")
        if s["docker"].get("orphan_buildx_volumes"):
            lines.append(f"  orphan buildx volumes: {', '.join(s['docker']['orphan_buildx_volumes'])}")
        if "docker_raw_bytes_on_disk" in s["docker"]:
            lines.append(f"  Docker.raw on disk: {human(s['docker']['docker_raw_bytes_on_disk'])}")
        lines.append("")
    if s.get("brew"):
        b = s["brew"]
        lines.append(f"Homebrew: cleanup would free {b.get('cleanup_estimate', '?')}, "
                     f"{len(b.get('outdated', []))} outdated, services started: "
                     f"{', '.join(b.get('services', [])) or 'none'}")
        for base, users in b.get("versioned_families", {}).items():
            lines.append(f"  {base}: " + "; ".join(f"{n} needed by {', '.join(u) if u else 'nothing'}"
                                                   for n, u in users.items()))
        lines.append("")
    if s.get("apps"):
        lines.append("Applications (size, last used per Spotlight, name, version, bundle id):")
        for r in s["apps"]["apps"][:top * 2]:
            lines.append(f"  {human(r['bytes']):>10}  {r['last_used'] or 'no record':<10}  {r['name']:<28} "
                         f"{(r['version'] or '')[:12]:<12} {r['bundle_id'] or ''}")
        if s["apps"]["likely_duplicates"]:
            lines.append("  likely duplicates: " + "; ".join(", ".join(g) for g in s["apps"]["likely_duplicates"]))
        lines.append("")
    if s.get("startup"):
        st = s["startup"]
        lines.append("Login items: " + ", ".join(f"{i['name']}{'' if i['exists'] else ' (missing)'}"
                                                 for i in st["login_items"]) if st["login_items"]
                     else "Login items: none read")
        for key in ("launch_agents", "launch_daemons"):
            for a in st[key]:
                flag = " MISSING PROGRAM" if a["program_missing"] else (" (disabled)" if a["disabled"] else "")
                lines.append(f"  {key.replace('_', ' ')}: {a['plist']}{flag}")
        lines.append("")
    if s.get("processes"):
        p = s["processes"]
        lines.append(f"Memory: {human(p.get('total_rss_bytes'))} resident of {human(p.get('physical_bytes'))}; "
                     f"swap {p.get('swap', '?')}; {p.get('uptime', '')}")
        for r in p.get("top_memory", [])[:top]:
            lines.append(f"  {human(r['rss_bytes']):>10}  {r['cpu']:>5}%  {r['command']}")
        lines.append("")
    if s.get("large"):
        lines.append("Large files:")
        lines += [f"  {human(r['bytes']):>10}  {r['path']}" for r in s["large"][:top]]
        lines.append("")
    if s.get("node"):
        lines.append("node_modules folders:")
        lines += [f"  {human(r['bytes']):>10}  {r['path']}" for r in s["node"][:top]]
        lines.append("")
    lines.append(f"Reclaimable candidates: {len(report['candidates'])}")
    for c in report["candidates"]:
        lines.append(f"  [{c['kind']}] {c['what']}  {human(c['bytes']) if c['bytes'] else ''}  {c['note']}")
    if report["unverified"]:
        lines.append("")
        lines.append("Unverified (not measured, so not claimed):")
        lines += [f"  {u['section']}: {u['reason']}" for u in report["unverified"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--home", default=str(Path.home()), help="home folder to survey (default: your home)")
    ap.add_argument("--apps-dir", action="append", default=None,
                    help="application folder to scan (repeatable; default /Applications and ~/Applications)")
    ap.add_argument("--top", type=int, default=15, help="rows per table (default 15)")
    ap.add_argument("--large-mb", type=int, default=1024, help="large file threshold in MB (default 1024)")
    ap.add_argument("--node-mb", type=int, default=200, help="node_modules threshold in MB (default 200)")
    ap.add_argument("--fast", action="store_true", help="skip the home-folder walk (large files, node_modules)")
    ap.add_argument("--no-commands", action="store_true",
                    help="do not run external commands (docker, brew, mdls, osascript, ps); file sizes only")
    ap.add_argument("--timeout", type=int, default=180, help="seconds per external command (default 180)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--out", help="also write the JSON report to this file")
    ap.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser()
    if not home.is_dir():
        print(f"error: not a directory: {home}", file=sys.stderr)
        return 2
    app_dirs = [Path(p) for p in args.apps_dir] if args.apps_dir else [Path("/Applications"), home / "Applications"]
    survey = Survey(home, not args.no_commands, args.timeout, args.large_mb, args.node_mb, args.fast,
                    not args.quiet)
    started = time.time()
    survey.disk()
    survey.home_sizes(args.top)
    survey.caches(args.top)
    survey.docker()
    survey.brew()
    survey.apps(app_dirs)
    survey.startup()
    survey.processes(args.top)
    if not args.fast:
        survey.large_and_node(args.top)
    survey.report["seconds"] = round(time.time() - started, 1)
    if args.out:
        Path(args.out).write_text(json.dumps(survey.report, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(survey.report, indent=2))
    else:
        print(render(survey.report, args.top))
    return 1 if survey.report["candidates"] else 0


if __name__ == "__main__":
    sys.exit(main())
