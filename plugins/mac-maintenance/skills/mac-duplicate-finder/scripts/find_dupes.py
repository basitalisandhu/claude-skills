#!/usr/bin/env python3
"""Find files that are byte-for-byte duplicates in the user's folders, and optionally move the obvious copies
(" (1)", " (2)" and similar suffixes beside an identical original) into a dated folder in the Trash.

Method:
  1. walk the roots (default Desktop, Documents, Pictures, Downloads, Movies, Music under --home), skipping
     symbolic links and the --exclude-dir names (default node_modules, .git, Library, .Trash)
  2. group files of at least --min-mb by size; only sizes that occur more than once go further
  3. hash the first 64 KiB of each candidate, then the whole file for those that still match (blake2b)
  4. report groups ordered by wasted bytes, the folder pairs that duplicate each other, and "suffix copies":
     files named like "IMG_1.MOV" next to an identical "IMG_1 (1).MOV"
  5. with --trash-suffix-copies, re-check size and hash of each copy against its original, then move the copy
     into --trash-dir keeping its relative path, so it can be put back; the original is never touched

Outputs: a text summary (or --json), and with --out-dir three files: duplicates.txt (every group),
suffix-copies.txt (one path per line), folder-pairs.txt. Nothing is deleted; moves go to the Trash folder only.

Exit codes: 0 no duplicates, 1 duplicates found (or copies moved), 2 bad input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

DEFAULT_ROOTS = ("Desktop", "Documents", "Pictures", "Downloads", "Movies", "Music")
DEFAULT_EXCLUDES = ("node_modules", ".git", "Library", ".Trash")
SUFFIX_RE = re.compile(r"^(?P<stem>.+?) (?:\((?P<n>\d+)\)|copy(?: \d+)?)(?P<ext>\.[A-Za-z0-9]{1,8})?$")
HEAD_BYTES = 65536


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def walk(roots: list[Path], excludes: set[str], min_bytes: int, progress) -> tuple[dict[int, list[Path]], int, int]:
    """Group regular files by size. Files whose data is not on disk (iCloud placeholders, sparse files: fewer
    than half the blocks their size needs) are counted and skipped, because hashing one would download it."""
    by_size: dict[int, list[Path]] = defaultdict(list)
    seen = dataless = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in excludes and not os.path.islink(os.path.join(dirpath, d))]
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                seen += 1
                if st.st_size < min_bytes:
                    continue
                if st.st_blocks * 512 < st.st_size // 2:
                    dataless += 1
                    continue
                by_size[st.st_size].append(Path(full))
            if progress and seen % 20000 == 0 and seen:
                progress(f"{seen} files seen")
    return by_size, seen, dataless


def digest(path: Path, limit: int | None = None) -> str | None:
    h = hashlib.blake2b(digest_size=20)
    try:
        with open(path, "rb") as fh:
            if limit is None:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            else:
                h.update(fh.read(limit))
    except OSError:
        return None
    return h.hexdigest()


def find_groups(by_size: dict[int, list[Path]], progress) -> list[dict]:
    groups = []
    candidates = {size: paths for size, paths in by_size.items() if len(paths) > 1}
    done = 0
    for size, paths in candidates.items():
        heads: dict[str, list[Path]] = defaultdict(list)
        for p in paths:
            h = digest(p, HEAD_BYTES)
            if h:
                heads[h].append(p)
        for head_paths in heads.values():
            if len(head_paths) < 2:
                continue
            fulls: dict[str, list[Path]] = defaultdict(list)
            for p in head_paths:
                h = digest(p)
                if h:
                    fulls[h].append(p)
            for full_hash, same in fulls.items():
                if len(same) > 1:
                    groups.append({"hash": full_hash, "bytes": size, "paths": sorted(str(p) for p in same),
                                   "wasted": size * (len(same) - 1)})
        done += 1
        if progress and done % 200 == 0:
            progress(f"{done} of {len(candidates)} size groups hashed")
    groups.sort(key=lambda g: g["wasted"], reverse=True)
    return groups


def suffix_copies(groups: list[dict]) -> list[dict]:
    """Copies whose name carries a suffix and whose original (same stem and extension) is in the same group."""
    out = []
    for g in groups:
        paths = [Path(p) for p in g["paths"]]
        by_dir_name = {(p.parent, p.name): p for p in paths}
        for p in paths:
            m = SUFFIX_RE.match(p.name)
            if not m:
                continue
            original = by_dir_name.get((p.parent, m.group("stem") + (m.group("ext") or "")))
            if original is not None and original != p:
                out.append({"copy": str(p), "original": str(original), "bytes": g["bytes"]})
    return out


def folder_pairs(groups: list[dict], home: Path, depth: int) -> list[dict]:
    """Wasted bytes aggregated by the set of folders (relative to home, --pair-depth levels) a group spans."""
    totals: dict[tuple[str, ...], dict] = {}
    for g in groups:
        keys = []
        for p in g["paths"]:
            try:
                rel = Path(p).relative_to(home).parts[:-1]
            except ValueError:
                rel = Path(p).parts[1:-1]
            keys.append("/".join(rel[:depth]) or ".")
        key = tuple(sorted(set(keys)))
        entry = totals.setdefault(key, {"folders": list(key), "wasted": 0, "groups": 0})
        entry["wasted"] += g["wasted"]
        entry["groups"] += 1
    return sorted(totals.values(), key=lambda e: e["wasted"], reverse=True)


def trash_copies(copies: list[dict], trash_dir: Path, base: Path, progress) -> tuple[list[dict], list[dict]]:
    moved, failed = [], []
    for item in copies:
        copy, original = Path(item["copy"]), Path(item["original"])
        try:
            if not (copy.is_file() and original.is_file()):
                raise OSError("copy or original no longer exists")
            if copy.stat().st_size != original.stat().st_size or digest(copy) != digest(original):
                raise OSError("copy and original differ now; not moved")
            try:
                rel = copy.relative_to(base)
            except ValueError:
                rel = Path(*copy.parts[1:])
            dest = trash_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                raise OSError(f"already in the trash folder: {dest}")
            shutil.move(str(copy), str(dest))
            moved.append({**item, "moved_to": str(dest)})
        except OSError as exc:
            failed.append({**item, "error": str(exc)})
        if progress and (len(moved) + len(failed)) % 100 == 0:
            progress(f"{len(moved)} moved, {len(failed)} failed")
    return moved, failed


def render(result: dict, top: int) -> str:
    lines = [f"Scanned {result['files_seen']} files in {len(result['roots'])} roots; "
             f"{result['group_count']} duplicate groups; {human(result['wasted_bytes'])} wasted"]
    if result.get("files_dataless"):
        lines.append(f"Skipped {result['files_dataless']} files whose data is not on disk "
                     "(iCloud placeholders or sparse files); hashing them would download them")
    lines.append("")
    if result["groups"]:
        lines.append(f"Largest groups (of {result['group_count']}):")
        for g in result["groups"][:top]:
            lines.append(f"  {human(g['wasted']):>10} wasted  {len(g['paths'])} x {human(g['bytes'])}")
            lines += [f"      {p}" for p in g["paths"]]
        lines.append("")
    if result["folder_pairs"]:
        lines.append("Folders that duplicate each other:")
        for e in result["folder_pairs"][:top]:
            lines.append(f"  {human(e['wasted']):>10}  {e['groups']:>5} groups  {' <-> '.join(e['folders'])}")
        lines.append("")
    lines.append(f"Suffix copies next to an identical original: {len(result['suffix_copies'])} files, "
                 f"{human(result['suffix_copies_bytes'])}")
    if result.get("moved") is not None:
        lines.append(f"Moved to {result['trash_dir']}: {len(result['moved'])} files, "
                     f"{human(result['moved_bytes'])}; failed: {len(result['failed'])}")
        lines += [f"  failed: {f['copy']}: {f['error']}" for f in result["failed"][:top]]
    if result["out_dir"]:
        lines.append(f"Lists written to {result['out_dir']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="*", help="folders to scan (default: the user folders under --home)")
    ap.add_argument("--home", default=str(Path.home()), help="home folder (default: your home)")
    ap.add_argument("--min-mb", type=float, default=2.0, help="smallest file to consider in MB (default 2)")
    ap.add_argument("--exclude-dir", action="append", default=None,
                    help=f"directory name to skip (repeatable; default {', '.join(DEFAULT_EXCLUDES)})")
    ap.add_argument("--pair-depth", type=int, default=3, help="folder levels for the folder-pair table (default 3)")
    ap.add_argument("--top", type=int, default=15, help="rows per table in the text output (default 15)")
    ap.add_argument("--out-dir", help="write duplicates.txt, suffix-copies.txt and folder-pairs.txt here")
    ap.add_argument("--trash-suffix-copies", action="store_true",
                    help="move verified suffix copies into --trash-dir (originals stay)")
    ap.add_argument("--trash-dir", help="destination for moved copies (default ~/.Trash/duplicates-<date>)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser()
    if not home.is_dir():
        print(f"error: not a directory: {home}", file=sys.stderr)
        return 2
    roots = [Path(r).expanduser() for r in args.roots] if args.roots else [home / r for r in DEFAULT_ROOTS]
    roots = [r for r in roots if r.is_dir()]
    if not roots:
        print("error: no existing root folders to scan", file=sys.stderr)
        return 2
    excludes = set(args.exclude_dir) if args.exclude_dir else set(DEFAULT_EXCLUDES)
    progress = None if args.quiet else (lambda m: print(f"[dupes] {m}", file=sys.stderr, flush=True))

    by_size, seen, dataless = walk(roots, excludes, int(args.min_mb * 1024 * 1024), progress)
    groups = find_groups(by_size, progress)
    copies = suffix_copies(groups)
    result = {"home": str(home), "roots": [str(r) for r in roots], "files_seen": seen, "files_dataless": dataless,
              "group_count": len(groups),
              "wasted_bytes": sum(g["wasted"] for g in groups), "groups": groups,
              "folder_pairs": folder_pairs(groups, home, args.pair_depth), "suffix_copies": copies,
              "suffix_copies_bytes": sum(c["bytes"] for c in copies), "out_dir": args.out_dir,
              "moved": None, "failed": [], "moved_bytes": 0, "trash_dir": None}

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "duplicates.txt", "w", encoding="utf-8") as fh:
            for g in groups:
                fh.write(f"[{len(g['paths'])} copies x {human(g['bytes'])}, {human(g['wasted'])} wasted]\n")
                fh.write("".join(f"  {p}\n" for p in g["paths"]) + "\n")
        (out / "suffix-copies.txt").write_text("".join(f"{c['copy']}\n" for c in copies), encoding="utf-8")
        with open(out / "folder-pairs.txt", "w", encoding="utf-8") as fh:
            for e in result["folder_pairs"]:
                fh.write(f"{human(e['wasted']):>10}  {e['groups']:>5} groups  {' <-> '.join(e['folders'])}\n")

    if args.trash_suffix_copies:
        trash_dir = (Path(args.trash_dir).expanduser() if args.trash_dir
                     else home / ".Trash" / f"duplicates-{date.today()}")
        trash_dir.mkdir(parents=True, exist_ok=True)
        moved, failed = trash_copies(copies, trash_dir, home, progress)
        result.update({"moved": moved, "failed": failed, "moved_bytes": sum(m["bytes"] for m in moved),
                       "trash_dir": str(trash_dir)})

    print(json.dumps(result, indent=2) if args.json else render(result, args.top))
    return 1 if groups else 0


if __name__ == "__main__":
    sys.exit(main())
