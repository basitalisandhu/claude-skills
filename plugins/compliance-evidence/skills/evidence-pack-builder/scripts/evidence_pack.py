#!/usr/bin/env python3
"""Build, verify and age-check an integrity-checked evidence pack from a folder of exports already on disk.

Subcommands:
  sidecar <folder>                 write a skeleton evidence-sources.json listing every file in the folder, for the
                                   collector to fill in (refuses to overwrite an existing one)
  build <folder> --out <pack>      copy (default) or reference every export, compute SHA-256 per file, record the
                                   collector, collection time, source system and command from the sidecar, and write
                                   <pack>/manifest.json and <pack>/MANIFEST.md
  verify <pack>                    recompute every hash; report modified, missing and unexpected files
  expire <pack> --days N           flag evidence collected more than N days before --as-of

Sidecar (evidence-sources.json in the export folder, or --sidecar PATH). Top-level values are defaults for every file:
  {
    "collector": "jane.doe@example.com",
    "collected_at": "2026-10-01T09:30:00Z",
    "scope": "AWS account 123456789012 and GitHub repository example-org/payments-api",
    "period": {"start": "2026-07-01", "end": "2026-09-30"},
    "files": {
      "github/branch-protection.json": {"source_system": "github",
                                        "command": "gh api repos/example-org/payments-api/branches/main/protection"}
    }
  }
A file the sidecar does not describe is still packed and hashed, and is listed as a provenance gap. Its source system
is taken from its first folder name (github, aws, m365) and its date from the file modification time, which is
weaker evidence of when it was collected; MANIFEST.md says so.

Integrity: hashes show whether a file changed after packing. They do not prove who exported it or that the export
was complete. build prints the SHA-256 of manifest.json itself; give that value to the assessor separately so that
`verify --manifest-sha256` can also detect a rewritten manifest.

Privacy: --redact replaces user identifiers in manifest.json, MANIFEST.md and the printed report (collector e-mail
addresses, names in the sidecar). File contents are never altered, because that would break the hashes: redact the
exports themselves before packing if the pack will leave your organisation.

Exit codes: 0 ok, 1 verify found modified, missing or unexpected files (or a manifest hash mismatch), or expire found
evidence older than the limit, 2 bad input. Nothing here calls any API or the network.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    DISCLAIMER,
    InputError,
    add_common_args,
    as_of_datetime,
    cell,
    days_between,
    dumps,
    load_json,
    parse_dt,
    redact,
    sha256_file,
)

SCHEMA = "compliance-evidence-pack/1"
TOOL = "evidence_pack.py 0.1.0"
SIDECAR = "evidence-sources.json"
KNOWN_SYSTEMS = {"github", "aws", "m365", "azure", "gcp", "okta", "jira", "hr"}
FILE_KEYS = {"source_system", "command", "collected_at", "collector", "description"}
TOP_KEYS = {"collector", "collected_at", "scope", "period", "files", "notes"}


# ---- helpers ----------------------------------------------------------------------------------------------------

def walk(folder: Path, skip: set[Path]) -> tuple[list[str], list[str]]:
    """Return (relative posix paths of regular files, gap notes for skipped entries)."""
    files: list[str] = []
    gaps: list[str] = []
    for p in sorted(folder.rglob("*")):
        rel = p.relative_to(folder)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if p.resolve() in skip:
            continue
        if p.is_symlink():
            gaps.append(f"{rel.as_posix()}: symbolic link skipped (pack only regular files inside the folder)")
            continue
        if p.is_file():
            files.append(rel.as_posix())
    return files, gaps


def load_sidecar(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        raise InputError(f"{path}: sidecar must be a JSON object")
    unknown = set(data) - TOP_KEYS
    if unknown:
        raise InputError(f"{path}: unknown sidecar keys: {', '.join(sorted(unknown))}")
    files = data.get("files", {})
    if not isinstance(files, dict):
        raise InputError(f"{path}: 'files' must map relative paths to objects")
    for rel, meta in files.items():
        if not isinstance(meta, dict):
            raise InputError(f"{path}: files[{rel!r}] must be an object")
        bad = set(meta) - FILE_KEYS
        if bad:
            raise InputError(f"{path}: files[{rel!r}] has unknown keys: {', '.join(sorted(bad))}")
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:
            raise InputError(f"{path}: files[{rel!r}] must be a relative path inside the export folder")
    return data


def infer_system(rel: str) -> str:
    first = PurePosixPath(rel).parts[0].lower() if len(PurePosixPath(rel).parts) > 1 else ""
    return first if first in KNOWN_SYSTEMS else "unknown"


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def sidecar_names(sidecar: dict) -> set[str]:
    names = set()
    for meta in [sidecar, *sidecar.get("files", {}).values()]:
        c = meta.get("collector") if isinstance(meta, dict) else None
        if isinstance(c, str) and c and "@" not in c:
            names.add(c)
    return names


# ---- sidecar ----------------------------------------------------------------------------------------------------

def cmd_sidecar(args) -> int:
    folder = Path(args.folder)
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    target = Path(args.sidecar) if args.sidecar else folder / SIDECAR
    if target.exists():
        raise InputError(f"{target}: already exists; edit it instead of regenerating")
    files, _ = walk(folder, {target.resolve()})
    skeleton = {
        "collector": "",
        "collected_at": "",
        "scope": "",
        "period": {"start": "", "end": ""},
        "files": {rel: {"source_system": infer_system(rel), "command": ""} for rel in files},
    }
    target.write_text(dumps(skeleton) + "\n", encoding="utf-8")
    print(f"Wrote {target} with {len(files)} file entries. Fill in collector, collected_at, scope, period and the "
          "exact command for each file before building the pack.")
    return 0


# ---- build ------------------------------------------------------------------------------------------------------

def build_manifest(folder: Path, out: Path, sidecar_path: Path | None, mode: str, built_at: datetime) -> dict:
    sidecar = load_sidecar(sidecar_path)
    skip = {(folder / SIDECAR).resolve()}  # the default sidecar is provenance, not evidence, even when --sidecar points elsewhere
    if sidecar_path and sidecar_path.exists():
        skip.add(sidecar_path.resolve())
    files, gaps = walk(folder, skip)
    if not files:
        raise InputError(f"{folder}: no files to pack")
    described = sidecar.get("files", {})
    for rel in sorted(set(described) - set(files)):
        gaps.append(f"{rel}: listed in the sidecar but not found in the export folder")
    entries = []
    for rel in files:
        src = folder / rel
        meta = described.get(rel, {})
        stat = src.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime, UTC)
        collected = meta.get("collected_at") or sidecar.get("collected_at") or ""
        collected_dt = parse_dt(collected)
        if collected and collected_dt is None:
            raise InputError(f"{rel}: collected_at {collected!r} is not an ISO 8601 date")
        command = meta.get("command", "")
        entry = {
            "path": rel,
            "sha256": sha256_file(src),
            "bytes": stat.st_size,
            "source_system": meta.get("source_system") or infer_system(rel),
            "command": command,
            "collector": meta.get("collector") or sidecar.get("collector") or "",
            "collected_at": iso(collected_dt) if collected_dt else "",
            "file_mtime": iso(mtime),
            "date_basis": "sidecar" if collected_dt else "file modification time",
        }
        if meta.get("description"):
            entry["description"] = meta["description"]
        if not command:
            gaps.append(f"{rel}: no export command recorded; the assessor cannot repeat this export")
        if not entry["collector"]:
            gaps.append(f"{rel}: no collector recorded")
        if not collected_dt:
            gaps.append(f"{rel}: no collection time recorded; using the file modification time")
        entries.append(entry)
    manifest = {
        "schema": SCHEMA,
        "tool": TOOL,
        "built_at": iso(built_at),
        "mode": mode,
        "source_root": str(folder.resolve()) if mode == "reference" else None,
        "collector": sidecar.get("collector", ""),
        "scope": sidecar.get("scope", ""),
        "period": sidecar.get("period", {}),
        "notes": sidecar.get("notes", ""),
        "file_count": len(entries),
        "files": entries,
        "gaps": gaps,
        "disclaimer": DISCLAIMER,
    }
    return manifest


def manifest_markdown(m: dict) -> str:
    period = m.get("period") or {}
    lines = [
        "# Evidence pack manifest",
        "",
        f"> {DISCLAIMER}",
        "",
        f"- Built: {m['built_at']} by {TOOL}",
        f"- Mode: {m['mode']}" + (f" (files stay at {cell(m['source_root'])})" if m["mode"] == "reference" else " (files copied under evidence/)"),
        f"- Scope: {cell(m.get('scope') or 'not stated')}",
        f"- Period: {cell(period.get('start') or '?')} to {cell(period.get('end') or '?')}",
        f"- Collector: {cell(m.get('collector') or 'not stated')}",
        f"- Files: {m['file_count']}",
        "",
        "## Files",
        "",
        "| Path | Source system | Command | Collected (basis) | Collector | SHA-256 | Bytes |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in m["files"]:
        when = f["collected_at"] or f["file_mtime"]
        lines.append(f"| {cell(f['path'])} | {cell(f['source_system'])} | {cell(f['command'] or 'not recorded')} | "
                     f"{when} ({f['date_basis']}) | {cell(f['collector'] or 'not recorded')} | `{f['sha256']}` | {f['bytes']} |")
    lines += ["", "## Gaps", ""]
    lines += [f"- {cell(g)}" for g in m["gaps"]] or ["- None recorded."]
    lines += ["", "## How to verify", "",
              "Recompute every hash and compare it with this manifest:", "",
              "```bash", "python3 evidence_pack.py verify <pack> --manifest-sha256 <value given to you separately>", "```", ""]
    return "\n".join(lines)


def cmd_build(args) -> int:
    folder = Path(args.folder)
    out = Path(args.out)
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise InputError(f"{out}: already exists and is not empty; choose a new pack folder")
    if is_inside(out, folder) or is_inside(folder, out):
        raise InputError("--out must be outside the export folder (and the export folder outside --out)")
    sidecar_path = Path(args.sidecar) if args.sidecar else folder / SIDECAR
    if args.sidecar and not sidecar_path.is_file():
        raise InputError(f"{sidecar_path}: sidecar not found")
    built_at = as_of_datetime(args.as_of) if args.as_of else datetime.now(UTC)
    manifest = build_manifest(folder, out, sidecar_path, args.mode, built_at)
    if args.redact:
        names = sidecar_names(load_sidecar(sidecar_path))
        originals = [(f["path"], f["sha256"]) for f in manifest["files"]]
        manifest = redact(manifest, names)
        for f, (path, digest) in zip(manifest["files"], originals, strict=True):
            f["path"], f["sha256"] = path, digest  # paths and hashes must stay exact for verify
        manifest["redacted"] = True
    out.mkdir(parents=True, exist_ok=True)
    if args.mode == "copy":
        for f in manifest["files"]:
            dst = out / "evidence" / f["path"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(folder / f["path"], dst)
            if sha256_file(dst) != f["sha256"]:
                raise InputError(f"{f['path']}: the copy does not match the source hash; the file changed while packing")
    (out / "manifest.json").write_text(dumps(manifest) + "\n", encoding="utf-8")
    (out / "MANIFEST.md").write_text(manifest_markdown(manifest), encoding="utf-8")
    manifest_hash = sha256_file(out / "manifest.json")
    summary = {"pack": str(out), "files": manifest["file_count"], "gaps": manifest["gaps"],
               "manifest_sha256": manifest_hash, "disclaimer": DISCLAIMER}
    if args.json:
        print(dumps(summary))
    else:
        print(f"# Evidence pack built\n\n> {DISCLAIMER}\n")
        print(f"Pack: {out} ({manifest['file_count']} files, mode {args.mode}).")
        print(f"SHA-256 of manifest.json: {manifest_hash}")
        print("Record this value outside the pack (send it to the assessor separately) so a rewritten manifest can be detected.\n")
        print(f"Gaps ({len(manifest['gaps'])}):")
        for g in manifest["gaps"]:
            print(f"- {g}")
    return 0


# ---- verify -----------------------------------------------------------------------------------------------------

def load_manifest(pack: Path) -> dict:
    mpath = pack / "manifest.json"
    if not mpath.is_file():
        raise InputError(f"{pack}: no manifest.json (is this an evidence pack?)")
    m = load_json(mpath)
    if not isinstance(m, dict) or m.get("schema") != SCHEMA or not isinstance(m.get("files"), list):
        raise InputError(f"{mpath}: not a {SCHEMA} manifest")
    return m


def evidence_root(pack: Path, manifest: dict) -> Path:
    if manifest.get("mode") == "reference":
        root = manifest.get("source_root")
        if not root:
            raise InputError("reference-mode manifest has no source_root")
        return Path(root)
    return pack / "evidence"


def verify_pack(pack: Path, manifest_sha256: str | None = None) -> dict:
    m = load_manifest(pack)
    root = evidence_root(pack, m)
    results = []
    listed = set()
    for f in m["files"]:
        rel = f.get("path", "")
        listed.add(rel)
        p = root / rel
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:
            results.append({"path": rel, "status": "invalid path", "expected": f.get("sha256"), "actual": None})
        elif not p.is_file():
            results.append({"path": rel, "status": "missing", "expected": f.get("sha256"), "actual": None})
        else:
            actual = sha256_file(p)
            results.append({"path": rel, "status": "ok" if actual == f.get("sha256") else "modified",
                            "expected": f.get("sha256"), "actual": actual})
    if m.get("mode") != "reference" and root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                if rel not in listed:
                    results.append({"path": rel, "status": "unexpected", "expected": None, "actual": sha256_file(p)})
    manifest_check = None
    if manifest_sha256:
        actual = sha256_file(pack / "manifest.json")
        manifest_check = {"expected": manifest_sha256.lower(), "actual": actual, "ok": actual == manifest_sha256.lower()}
    problems = [r for r in results if r["status"] != "ok"]
    ok = not problems and (manifest_check is None or manifest_check["ok"])
    return {"pack": str(pack), "ok": ok, "checked": len(results), "problems": problems, "results": results,
            "manifest_check": manifest_check, "disclaimer": DISCLAIMER}


def cmd_verify(args) -> int:
    report = verify_pack(Path(args.pack), args.manifest_sha256)
    if args.redact:
        report = redact(report)
    if args.json:
        print(dumps(report))
    else:
        print(f"# Evidence pack verification\n\n> {DISCLAIMER}\n")
        print(f"Pack: {cell(report['pack'])}. Files checked: {report['checked']}.")
        mc = report["manifest_check"]
        if mc:
            print(f"manifest.json hash: {'matches' if mc['ok'] else 'DOES NOT MATCH'} the value given ({mc['actual']}).")
        else:
            print("manifest.json hash: not checked (pass --manifest-sha256 with the value recorded at build time).")
        if report["problems"]:
            print("\n| Path | Status | Expected SHA-256 | Actual SHA-256 |\n|---|---|---|---|")
            for r in report["problems"]:
                print(f"| {cell(r['path'])} | {r['status'].upper()} | {r['expected'] or '-'} | {r['actual'] or '-'} |")
            print("\nResult: FAILED. Treat the files above as unreliable until re-exported and re-packed.")
        else:
            print("\nResult: every file matches its recorded hash.")
    return 0 if report["ok"] else 1


# ---- expire -----------------------------------------------------------------------------------------------------

def parse_max_age(values: list[str] | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values or []:
        name, sep, num = v.partition("=")
        if not sep or not num.isdigit():
            raise InputError(f"--max-age {v!r}: use SOURCE=DAYS, for example github=30")
        out[name.strip().lower()] = int(num)
    return out


def expire_pack(pack: Path, days: int, now: datetime, per_source: dict[str, int] | None = None) -> dict:
    m = load_manifest(pack)
    rows = []
    for f in m["files"]:
        limit = (per_source or {}).get(str(f.get("source_system", "")).lower(), days)
        when = f.get("collected_at") or f.get("file_mtime")
        age = days_between(when, now)
        if age is None:
            status = "undated"
        elif age > limit:
            status = "expired"
        else:
            status = "current"
        rows.append({"path": f["path"], "source_system": f.get("source_system"), "collected": when,
                     "date_basis": f.get("date_basis", "sidecar"), "age_days": age, "limit_days": limit, "status": status})
    flagged = [r for r in rows if r["status"] != "current"]
    return {"pack": str(pack), "as_of": now.strftime("%Y-%m-%d"), "default_limit_days": days, "files": rows,
            "flagged": flagged, "disclaimer": DISCLAIMER}


def cmd_expire(args) -> int:
    if args.days < 0:
        raise InputError("--days must be zero or more")
    report = expire_pack(Path(args.pack), args.days, as_of_datetime(args.as_of), parse_max_age(args.max_age))
    if args.redact:
        report = redact(report)
    if args.json:
        print(dumps(report))
    else:
        print(f"# Evidence age check as of {report['as_of']}\n\n> {DISCLAIMER}\n")
        print("| Path | Source | Collected | Basis | Age (days) | Limit | Status |\n|---|---|---|---|---|---|---|")
        for r in report["files"]:
            print(f"| {cell(r['path'])} | {cell(r['source_system'])} | {r['collected']} | {r['date_basis']} | "
                  f"{r['age_days'] if r['age_days'] is not None else '-'} | {r['limit_days']} | {r['status'].upper()} |")
        weak = [r for r in report["files"] if r["date_basis"] != "sidecar"]
        if weak:
            print(f"\n{len(weak)} file(s) are dated by file modification time only, which copying can change; record collected_at in the sidecar.")
        if report["flagged"]:
            print(f"\n{len(report['flagged'])} file(s) need re-export before the assessment.")
        else:
            print("\nEvery file is within the limit.")
    return 1 if report["flagged"] else 0


# ---- main -------------------------------------------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="evidence_pack.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sidecar", help="write a skeleton evidence-sources.json")
    s.add_argument("folder")
    s.add_argument("--sidecar", help=f"where to write it (default <folder>/{SIDECAR})")
    s.set_defaults(func=cmd_sidecar)
    b = sub.add_parser("build", help="build a pack with manifest.json and MANIFEST.md")
    b.add_argument("folder")
    b.add_argument("--out", required=True, help="new pack folder (must not exist or be empty, outside the export folder)")
    b.add_argument("--sidecar", help=f"provenance file (default <folder>/{SIDECAR})")
    b.add_argument("--mode", choices=["copy", "reference"], default="copy",
                   help="copy files into the pack (default) or record their location and hashes only")
    add_common_args(b, fail_on=False)
    b.set_defaults(func=cmd_build)
    v = sub.add_parser("verify", help="recompute hashes and report tampering or missing files")
    v.add_argument("pack")
    v.add_argument("--manifest-sha256", help="the manifest.json hash recorded at build time")
    add_common_args(v, fail_on=False)
    v.set_defaults(func=cmd_verify)
    e = sub.add_parser("expire", help="flag evidence older than N days")
    e.add_argument("pack")
    e.add_argument("--days", type=int, required=True, help="maximum age in days")
    e.add_argument("--max-age", action="append", metavar="SOURCE=DAYS", help="per source system limit, for example github=30 (repeatable)")
    add_common_args(e, fail_on=False)
    e.set_defaults(func=cmd_expire)
    # Options shown in the top-level help so every script documents --json and --redact in one place.
    ap.epilog = "Common options on build, verify and expire: --json (print JSON), --redact (tokenise user identifiers), --as-of YYYY-MM-DD."
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
