"""Property-based tests (Hypothesis) for the parsers and naming rules the hub depends on.

Skipped when Hypothesis is not installed: `python3 -m pip install pytest hypothesis`.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "site"))

import hublib as H  # noqa: E402
import markdown as md  # noqa: E402

spec = importlib.util.spec_from_file_location("claude_skills_install_props", ROOT / "install.py")
install = importlib.util.module_from_spec(spec)
sys.modules["claude_skills_install_props"] = install
spec.loader.exec_module(install)

SETTINGS = settings(max_examples=300, deadline=None)

# Plugin and skill names as the validator allows them: lower case, digits and hyphens.
name = st.from_regex(r"[a-z][a-z0-9]{0,3}(-[a-z0-9]{1,3}){0,2}", fullmatch=True)
pairs = st.lists(st.tuples(name, name), unique=True, max_size=12)


# ---------------------------------------------------------------- install names

@SETTINGS
@given(pairs, st.booleans())
def test_install_names_never_collide(ps, prefix_all):
    """Two skills must never be given the same install directory, or one overwrites the other."""
    for fn in (H.install_names, install.plan_names):
        names = fn(ps, prefix_all)
        assert set(names) == set(ps)
        assert len(set(names.values())) == len(ps), names


@SETTINGS
@given(pairs)
def test_install_names_same_rule_in_hub_and_installer(ps):
    for prefix_all in (False, True):
        assert H.install_names(ps, prefix_all) == install.plan_names(ps, prefix_all)


@SETTINGS
@given(pairs)
def test_unique_skill_names_keep_their_plain_name(ps):
    skills = [s for _, s in ps]
    names = H.install_names(ps)
    for (plugin, skill), got in names.items():
        if skills.count(skill) == 1 and not any(f"{p}-{s}" == skill for p, s in ps):
            assert got == skill


def test_install_names_prefixed_name_already_taken():
    # a/b-s keeps "b-s"; the second "s" (from b) would become "b-s" too.
    ps = [("a", "b-s"), ("a", "s"), ("b", "s")]
    names = H.install_names(ps)
    assert len(set(names.values())) == 3
    assert names[("a", "b-s")] == "b-s"
    assert names[("a", "s")] == "s"


# ---------------------------------------------------------------- SKILL.md front matter

key = st.from_regex(r"[a-z][a-z0-9_-]{0,10}", fullmatch=True)
# Printable single-line values without characters that need YAML quoting rules we do not model.
value = st.text(st.characters(min_codepoint=32, max_codepoint=0x2FF, blacklist_characters='"\\'), max_size=60)


@SETTINGS
@given(st.dictionaries(key, value, max_size=6), st.text(max_size=80))
def test_frontmatter_round_trip(fields, body):
    lines = "".join(f'{k}: "{v}"\n' for k, v in fields.items())
    text = f"---\n{lines}---\n{body}"
    got, got_body, errors = H.parse_frontmatter(text)
    assert errors == []
    assert got == fields
    assert got_body == body.replace("\r\n", "\n").lstrip("\n")


@SETTINGS
@given(st.text(max_size=400))
def test_frontmatter_never_raises(text):
    fields, body, errors = H.parse_frontmatter(text)
    assert isinstance(fields, dict) and isinstance(body, str) and isinstance(errors, list)


@SETTINGS
@given(st.text(max_size=200))
def test_frontmatter_never_raises_with_fences(inner):
    H.parse_frontmatter("---\n" + inner + "\n---\nbody")


def test_frontmatter_empty_block_is_closed():
    fields, body, errors = H.parse_frontmatter("---\n---\nbody\n")
    assert errors == []
    assert fields == {}
    assert body == "body\n"


# ---------------------------------------------------------------- site Markdown

ALLOWED_TAG = re.compile(r"</?(a|code|strong|em|p|ul|ol|li|pre|blockquote|h[1-6]|table|thead|tbody|tr|th|td)( [^<>]*)?>")


def _no_raw_html(out: str) -> None:
    stripped = ALLOWED_TAG.sub("", out)
    assert "<" not in stripped and ">" not in stripped, out


def _hrefs(out: str) -> list[str]:
    return re.findall(r'href="([^"]*)"', out)


md_text = st.lists(st.sampled_from(list("ab <>[]()*_`#-|:/\\\n!\"'&") + ["javascript:", "http://", "<script>"]),
                   max_size=60).map("".join)


@SETTINGS
@given(md_text)
def test_inline_escapes_raw_html(text):
    out = md.inline(text)
    _no_raw_html(out)


@SETTINGS
@given(md_text)
def test_convert_escapes_raw_html_and_never_links_scripts(text):
    out = md.convert(text)
    _no_raw_html(out)
    for href in _hrefs(out):
        assert not href.lower().lstrip().startswith(("javascript:", "data:", "vbscript:")), href


@SETTINGS
@given(st.text(max_size=80))
def test_safe_url_rejects_unknown_schemes(url):
    got = md.safe_url(url)
    if got is not None:
        head = got.split("/", 1)[0]
        assert ":" not in head or got.startswith(md._SAFE_SCHEMES)


@SETTINGS
@given(st.text(max_size=60))
def test_slugify_is_idempotent_and_url_safe(text):
    slug = md.slugify(text)
    assert md.slugify(slug) == slug
    assert not re.search(r"\s", slug)
