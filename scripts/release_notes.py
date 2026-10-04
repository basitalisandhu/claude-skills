#!/usr/bin/env python3
"""Print release notes in Markdown from catalog.json and SOURCES.json. Standard library only.

    python3 scripts/release_notes.py v0.1.0 > notes.md
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hublib as H  # noqa: E402


def notes(tag: str, root: Path = H.ROOT) -> str:
    catalog = H.load_json(root / "catalog.json")
    sources = (H.load_json(root / "SOURCES.json", {}) or {}).get("plugins", {})
    c = catalog["counts"]
    out = [f"{c['skills']} skills in {c['plugins']} plugins, synced from their source repositories.", "",
           "| Plugin | Version | Skills | Source commit |", "| --- | --- | --- | --- |"]
    for p in catalog["plugins"]:
        rec = sources.get(p["name"], {})
        commit = rec.get("commit", "")
        link = f"[{commit[:7]}]({rec.get('url', '')}/commit/{commit})" if commit else ""
        out.append(f"| {p['name']} | {p['version']} | {len(p['skills'])} | {link} |")
    out += ["", f"Install: `/plugin marketplace add {H.OWNER}/{H.REPO_NAME}`, then "
            f"`/plugin install <plugin>@{H.MARKETPLACE_NAME}`.", "",
            f"The tarball `{H.REPO_NAME}-{tag}.tar.gz` holds plugins/, install.py, catalog.json, SOURCES.json, "
            "LICENSE and README.md. Check it with SHA256SUMS and `gh attestation verify`.", ""]
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: release_notes.py <tag>")
    sys.stdout.write(notes(sys.argv[1]))
