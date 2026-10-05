#!/usr/bin/env python3
"""Tell IndexNow search engines which site URLs exist, in one POST. Standard library only.

    INDEXNOW_KEY=<key> python3 scripts/indexnow.py             # submit every URL in docs/sitemap.xml
    python3 scripts/indexnow.py --dry-run                      # print the payload, send nothing
    python3 scripts/indexnow.py --urls-file urls.txt           # submit the URLs in a file instead

The key is public by design: it is served as a text file at the root of the host, and
KEY_LOCATION points to it. Exit codes: 0 accepted (HTTP 200 or 202), 1 rejected or network
error, 2 usage problem (no key, no URLs).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "https://api.indexnow.org/indexnow"
HOST = "basitalisandhu.github.io"
KEY_LOCATION = "https://basitalisandhu.github.io/92e8b361795a4af2e514c405cf94f171.txt"
MAX_URLS = 10000  # the IndexNow limit for one request


def urls_from_sitemap(xml: str) -> list[str]:
    """The <loc> values of a sitemap, unescaped, in order, without duplicates."""
    seen: dict[str, None] = {}
    for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", xml, flags=re.S):
        seen.setdefault(html.unescape(loc), None)
    return list(seen)


def urls_from_text(text: str) -> list[str]:
    """One URL per line; blank lines and lines starting with # are ignored."""
    seen: dict[str, None] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            seen.setdefault(line, None)
    return list(seen)


def build_payload(urls: list[str], key: str) -> dict:
    """The JSON body for one IndexNow submission. Every URL must be on HOST."""
    bad = [u for u in urls if not re.match(rf"^https://{re.escape(HOST)}/", u)]
    if bad:
        raise ValueError(f"URL not on https://{HOST}/: {bad[0]}")
    if not urls:
        raise ValueError("no URLs to submit")
    if len(urls) > MAX_URLS:
        raise ValueError(f"{len(urls)} URLs is more than the {MAX_URLS} IndexNow allows per request")
    return {"host": HOST, "key": key, "keyLocation": KEY_LOCATION, "urlList": urls}


def post(payload: dict, timeout: int = 30) -> int:
    request = urllib.request.Request(
        ENDPOINT, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "claude-skills-indexnow/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sitemap", type=Path, default=ROOT / "docs" / "sitemap.xml", help="sitemap to read (default docs/sitemap.xml)")
    ap.add_argument("--urls-file", type=Path, help="read URLs from this file (one per line) instead of the sitemap")
    ap.add_argument("--dry-run", action="store_true", help="print the payload and send nothing")
    args = ap.parse_args(argv)

    key = os.environ.get("INDEXNOW_KEY", "").strip()
    if not key and not args.dry_run:
        print("INDEXNOW_KEY is not set; nothing submitted.", file=sys.stderr)
        return 2
    try:
        source = args.urls_file or args.sitemap
        text = source.read_text(encoding="utf-8")
        urls = urls_from_text(text) if args.urls_file else urls_from_sitemap(text)
        payload = build_payload(urls, key or "<INDEXNOW_KEY>")
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.dry_run:
        shown = dict(payload, key="<hidden>")
        print(json.dumps(shown, indent=1))
        print(f"dry run: {len(urls)} URLs, nothing sent")
        return 0
    status = post(payload)
    print(f"IndexNow answered HTTP {status} for {len(urls)} URLs")
    return 0 if status in (200, 202) else 1


if __name__ == "__main__":
    sys.exit(main())
