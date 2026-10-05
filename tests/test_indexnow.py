"""Offline tests for scripts/indexnow.py: URL extraction and payload shape. No network."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import indexnow  # noqa: E402

SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://basitalisandhu.github.io/claude-skills/</loc><lastmod>2026-10-04</lastmod></url>
  <url><loc>https://basitalisandhu.github.io/claude-skills/a?x=1&amp;y=2</loc></url>
  <url><loc>https://basitalisandhu.github.io/claude-skills/</loc></url>
</urlset>
"""


def test_urls_from_sitemap_unescapes_and_dedupes():
    assert indexnow.urls_from_sitemap(SITEMAP) == [
        "https://basitalisandhu.github.io/claude-skills/",
        "https://basitalisandhu.github.io/claude-skills/a?x=1&y=2",
    ]


def test_urls_from_text_skips_comments_and_blanks():
    text = "# note\n\nhttps://basitalisandhu.github.io/a\n  https://basitalisandhu.github.io/b  \nhttps://basitalisandhu.github.io/a\n"
    assert indexnow.urls_from_text(text) == ["https://basitalisandhu.github.io/a", "https://basitalisandhu.github.io/b"]


def test_payload_shape():
    urls = ["https://basitalisandhu.github.io/claude-skills/"]
    payload = indexnow.build_payload(urls, "abc123")
    assert payload == {
        "host": "basitalisandhu.github.io",
        "key": "abc123",
        "keyLocation": "https://basitalisandhu.github.io/92e8b361795a4af2e514c405cf94f171.txt",
        "urlList": urls,
    }
    json.dumps(payload)


def test_payload_rejects_foreign_hosts_and_empty_lists():
    with pytest.raises(ValueError):
        indexnow.build_payload(["https://example.com/x"], "k")
    with pytest.raises(ValueError):
        indexnow.build_payload([], "k")


def test_repository_sitemap_gives_a_valid_payload():
    urls = indexnow.urls_from_sitemap((ROOT / "docs" / "sitemap.xml").read_text(encoding="utf-8"))
    assert indexnow.build_payload(urls, "k")["urlList"] == urls


def test_dry_run_sends_nothing_and_missing_key_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(indexnow, "post", lambda *a, **k: pytest.fail("network used"))
    monkeypatch.delenv("INDEXNOW_KEY", raising=False)
    assert indexnow.main(["--dry-run"]) == 0
    assert "<hidden>" in capsys.readouterr().out
    assert indexnow.main([]) == 2


def test_exit_code_follows_http_status(monkeypatch):
    monkeypatch.setenv("INDEXNOW_KEY", "k")
    for status, code in ((200, 0), (202, 0), (403, 1), (422, 1)):
        monkeypatch.setattr(indexnow, "post", lambda payload, status=status: status)
        assert indexnow.main([]) == code
