#!/usr/bin/env python3
"""Build the static site into docs/ from catalog.json, SOURCES.json and plugins/.

Standard library only, offline and deterministic: the same inputs give the same bytes.
No JavaScript. Pages are served from /claude-skills/ (a GitHub project site), so links
are relative wherever possible and absolute ones carry that prefix.

    python3 site/build.py            # build into docs/
    python3 site/build.py --check    # build into a temp dir, fail if docs/ is stale or a link is broken
"""

from __future__ import annotations

import argparse
import filecmp
import html
import json
import posixpath
import re
import shutil
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

SITE_DIR = Path(__file__).resolve().parent
ROOT = SITE_DIR.parent
sys.path.insert(0, str(SITE_DIR))
sys.path.insert(0, str(ROOT / "scripts"))

import hublib as H  # noqa: E402
import markdown as md  # noqa: E402

SITE_NAME = "Claude Code skills"
CRAWLERS = ["GPTBot", "ClaudeBot", "Claude-Web", "anthropic-ai", "PerplexityBot", "Google-Extended",
            "Googlebot", "Bingbot", "CCBot", "Applebot-Extended"]
STOP_WORDS = {"a", "an", "and", "as", "at", "by", "for", "from", "in", "into", "of", "on", "or", "the", "to", "with"}
MIT_URL = "https://opensource.org/licenses/MIT"
e = html.escape

GUIDE_SLUG = "install-claude-code-skills"
GUIDE_REL = f"guide/{GUIDE_SLUG}/"

# Questions shown on the index page and published as FAQPage structured data.
# Google requires the marked-up answers to be visible on the page, so one list feeds both.
FAQS = [
    ("What is this repository?",
     "It is one repository with every Claude Code skill maintained by {name}, and it is also a single Claude Code "
     "plugin marketplace. Each skill is a SKILL.md file, and most bundle a small Python script."),
    ("How do I install the skills?",
     "In Claude Code, run /plugin marketplace add {owner}/{repo} and then /plugin install <plugin>@{market}. "
     "Or clone the repository and run python3 install.py --user to copy every skill into ~/.claude/skills/. "
     "The install guide on this site covers both routes and a third one for other agents."),
    ("Is anything sent anywhere?",
     "No. install.py, the validator and the site builder make no network calls, and the installer sends no "
     "telemetry. Only the daily sync clones the public source repositories from GitHub. What a skill's own "
     "script does is described on that skill's page."),
    ("Where do I report a bug in a skill?",
     "Open an issue in the skill's source repository. Each skill page and each row of the catalog links to it. "
     "Problems with the installer or the site go to the issues of {repo} on GitHub."),
    ("How does the catalog stay in sync with the source repositories?",
     "Skills are edited in their source repositories. A workflow in this repository copies them in every day, "
     "regenerates the catalog and the site, and records the source commit of each plugin in SOURCES.json."),
    ("Can other agents use these skills?",
     "Agents that read the open Agent Skills format can use them, because every skill is a folder with a "
     "SKILL.md that has name and description front matter. The command npx skills add {owner}/{repo} found every "
     "skill on 2026-10-04. This repository tests them with Claude Code only."),
    ("What licence are the skills under?",
     "MIT. The vendored plugins are MIT too, by the same author."),
]


def faq_items(s: "Site") -> list[tuple[str, str]]:
    fmt = {"name": H.OWNER_NAME, "owner": H.OWNER, "repo": H.REPO_NAME, "market": H.MARKETPLACE_NAME}
    return [(q, a.format(**fmt)) for q, a in FAQS]


def load_content(name: str) -> tuple[dict[str, str], str]:
    """Read site/content/<name>.md (next to this script, like style.css) and return its front matter and Markdown body."""
    text = (SITE_DIR / "content" / f"{name}.md").read_text(encoding="utf-8")
    return md.split_front_matter(text)


# ---------------------------------------------------------------- helpers

def first_clause(text: str) -> str:
    """First clause of a description, for titles."""
    clause = re.split(r"(?<=[a-z0-9)])[.:;](\s|$)", text, maxsplit=1)[0].strip()
    if len(clause) > 70:
        clause = re.split(r",\s| \(| with a bundled script", clause, maxsplit=1)[0].strip()
    if len(clause) > 70:
        words = clause[:70].rsplit(" ", 1)[0].rstrip(",;:(").split()
        while len(words) > 3 and words[-1].lower() in STOP_WORDS:
            words.pop()
        clause = " ".join(words)
    return clause


def date_of(iso: str) -> str:
    return iso[:10] if iso else ""


def blob_url(repo_url: str, path: str) -> str:
    return f"{repo_url}/blob/main/{path}"


def rewriter(repo_url: str, base_path: str):
    """Rewrite relative links in vendored Markdown to the file in its source repository."""
    def rewrite(url: str) -> str:
        if not url or url.startswith(("#", "http://", "https://", "mailto:", "/")):
            return url
        target, _, frag = url.partition("#")
        resolved = posixpath.normpath(posixpath.join(base_path, target))
        if resolved.startswith(".."):
            return repo_url
        kind = "tree" if target.endswith("/") else "blob"
        return f"{repo_url}/{kind}/main/{resolved}" + (f"#{frag}" if frag else "")
    return rewrite


def jsonld(obj: dict) -> str:
    text = json.dumps(obj, indent=1, ensure_ascii=False).replace("</", "<\\/")
    return f'<script type="application/ld+json">\n{text}\n</script>'


def author() -> dict:
    return {"@type": "Person", "name": H.OWNER_NAME, "url": H.OWNER_URL}


def page(*, rel: str, depth: int, title: str, description: str, body: str, extra_head: str = "",
         og_type: str = "website") -> str:
    up = "../" * depth
    canonical = H.SITE_URL + rel
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(description, quote=True)}">
<link rel="canonical" href="{e(canonical, quote=True)}">
<meta property="og:type" content="{og_type}">
<meta property="og:site_name" content="{SITE_NAME}">
<meta property="og:title" content="{e(title, quote=True)}">
<meta property="og:description" content="{e(description, quote=True)}">
<meta property="og:url" content="{e(canonical, quote=True)}">
<meta name="twitter:card" content="summary">
<link rel="stylesheet" href="{up}style.css">
<link rel="alternate" type="application/atom+xml" title="{SITE_NAME} releases" href="{up}feed.xml">
{extra_head}</head>
<body>
<header class="top"><nav><a class="home" href="{up}index.html">{SITE_NAME}</a><a href="{up}index.html#plugins">Plugins</a><a href="{up}llms.txt">llms.txt</a><a href="{H.REPO_URL}">GitHub</a></nav></header>
<main>
{body}
</main>
<footer><p>Skills by <a href="{H.OWNER_URL}">{H.OWNER_NAME}</a>, MIT licence. Each skill is edited in its source repository and synced into <a href="{H.REPO_URL}">{H.REPO_NAME}</a> daily. Other projects: <a href="https://{H.OWNER}.github.io/">{H.OWNER}.github.io</a>.</p></footer>
</body>
</html>
"""


def install_block(plugin: str, skill: str | None = None, install_name: str | None = None) -> str:
    lines = [f"/plugin marketplace add {H.OWNER}/{H.REPO_NAME}", f"/plugin install {plugin}@{H.MARKETPLACE_NAME}"]
    clone = [f"git clone {H.REPO_URL}", f"cd {H.REPO_NAME}"]
    if skill:
        clone.append(f"python3 install.py --user --skill {plugin}/{skill}")
    else:
        clone.append(f"python3 install.py --user --only {plugin}")
    out = ["<h2 id=\"install\">Install</h2>",
           "<p>In Claude Code, add the marketplace and install the plugin:</p>",
           f"<pre><code>{e(chr(10).join(lines))}</code></pre>",
           "<p>Or copy the skill files into <code>~/.claude/skills/</code> from a clone:</p>",
           f"<pre><code>{e(chr(10).join(clone))}</code></pre>"]
    if skill and install_name and install_name != skill:
        out.append(f"<p>Another plugin has a skill with the same name, so the copy route installs this one as "
                   f"<code>{e(install_name)}</code>.</p>")
    return "\n".join(out)


# ---------------------------------------------------------------- build

class Site:
    def __init__(self, root: Path):
        self.root = root
        self.catalog = H.load_json(root / "catalog.json")
        if self.catalog is None:
            raise SystemExit("catalog.json is missing; run python3 scripts/sync.py --offline first")
        self.sources = (H.load_json(root / "SOURCES.json", {}) or {}).get("plugins", {})
        self.plugins = self.catalog["plugins"]
        self.skills = self.catalog["skills"]
        self.by_plugin: dict[str, list[dict]] = {}
        for s in self.skills:
            self.by_plugin.setdefault(s["plugin"], []).append(s)

    def synced(self, plugin: str) -> str:
        return self.sources.get(plugin, {}).get("synced_at", "")

    def latest(self) -> str:
        return max((self.synced(p["name"]) for p in self.plugins), default="")

    def headline(self) -> str:
        c = self.catalog["counts"]
        return f"Claude Code skills: {c['skills']} skills in {c['plugins']} plugins, one repository"


def write(out: Path, rel: str, text: str, written: list[Path]) -> None:
    path = out / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    written.append(path)


def build_index(s: Site) -> str:
    c = s.catalog["counts"]
    faqs = faq_items(s)
    faq_html = "\n".join(f"<h3>{e(q)}</h3>\n<p>{e(a)}</p>" for q, a in faqs)
    rows = []
    for p in s.plugins:
        rows.append(f"<tr><td><a href=\"plugins/{e(p['name'])}/index.html\">{e(p['name'])}</a></td>"
                    f"<td>{len(p['skills'])}</td><td>{e(p['version'])}</td><td>{e(p['description'])}</td></tr>")
    sections = []
    for p in s.plugins:
        items = "".join(
            f"<li><a href=\"plugins/{e(p['name'])}/{e(sk['name'])}/index.html\">{e(sk['name'])}</a>: "
            f"{e(H.one_line(sk['description']))}</li>" for sk in s.by_plugin.get(p["name"], []))
        sections.append(f"<h3 id=\"{e(p['name'])}\"><a href=\"plugins/{e(p['name'])}/index.html\">{e(p['name'])}</a></h3>\n<ul>{items}</ul>")
    body = f"""<h1>{e(s.headline())}</h1>
<p class="lede">One repository with every Claude Code skill maintained by {H.OWNER_NAME}: {c['skills']} skills in {c['plugins']} plugins, synced daily from {len({p['source_repo'] for p in s.plugins})} source repositories. It is also a single Claude Code plugin marketplace. New to skills? Read <a href="guide/{GUIDE_SLUG}/index.html">how to install Claude Code skills (three ways)</a>.</p>
<h2 id="install">Install</h2>
<p>Add the marketplace in Claude Code, then install the plugins you want:</p>
<pre><code>/plugin marketplace add {H.OWNER}/{H.REPO_NAME}
/plugin install aws-security@{H.MARKETPLACE_NAME}</code></pre>
<p>Or clone once and copy every skill into <code>~/.claude/skills/</code>:</p>
<pre><code>git clone {H.REPO_URL}
cd {H.REPO_NAME}
python3 install.py --user</code></pre>
<h2 id="plugins">Plugins</h2>
<table><thead><tr><th>Plugin</th><th>Skills</th><th>Version</th><th>Description</th></tr></thead><tbody>
{chr(10).join(rows)}
</tbody></table>
<h2 id="skills">All skills</h2>
{chr(10).join(sections)}
<h2 id="questions">Questions</h2>
{faq_html}
<p class="meta">Machine-readable: <a href="llms.txt">llms.txt</a>, <a href="llms-full.txt">llms-full.txt</a>, <a href="feed.xml">feed.xml</a>, <a href="{H.REPO_URL}/blob/main/catalog.json">catalog.json</a>.</p>"""
    ld = {
        "@context": "https://schema.org",
        "@type": "ItemList",
        "name": s.headline(),
        "url": H.SITE_URL,
        "numberOfItems": c["skills"],
        "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "item": {
                "@type": "SoftwareSourceCode",
                "name": sk["name"],
                "description": sk["description"],
                "url": H.site_skill_url(sk["plugin"], sk["name"]),
                "codeRepository": sk["source_repo"],
            }} for i, sk in enumerate(s.skills)
        ],
    }
    faq_ld = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [{"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}}
                       for q, a in faqs],
    }
    desc = (f"{c['skills']} Claude Code skills in {c['plugins']} plugins in one repository and one plugin "
            f"marketplace: security, AWS, Microsoft 365, compliance, GitHub, development and Mac maintenance.")
    return page(rel="", depth=0, title=s.headline(), description=desc, body=body,
                extra_head=jsonld(ld) + "\n" + jsonld(faq_ld) + "\n")


def build_guide(s: Site) -> str:
    meta, body_md = load_content(GUIDE_SLUG)
    title = meta["title"]
    body = f"""<p class="crumbs"><a href="../../index.html">Home</a> / Guide</p>
{md.convert(H.render_template(body_md, s.catalog))}"""
    return page(rel=GUIDE_REL, depth=2, title=title, description=meta["description"], body=body,
                og_type="article")


def build_plugin(s: Site, p: dict) -> str:
    name = p["name"]
    repo = p["source_repo"]
    rows = "".join(
        f"<tr><td><a href=\"{e(sk['name'])}/index.html\">{e(sk['name'])}</a></td><td>{e(H.one_line(sk['description']))}</td>"
        f"<td>{'yes' if sk['scripts'] else 'no'}</td></tr>" for sk in s.by_plugin.get(name, []))
    extras = H.ships_text(p["ships"])
    extra = ""
    if extras:
        extra = (f"<p>This plugin also ships plugin-level {e(extras)}. They load when you install the plugin "
                 f"from the marketplace; <code>install.py</code> copies skills only.</p>")
    readme_html = ""
    readme = s.root / H.PLUGINS_DIR / name / "README.md"
    if readme.is_file():
        text = readme.read_text(encoding="utf-8")
        text = re.sub(r"\A# .*\n", "", text)
        readme_html = "<h2 id=\"readme\">Plugin README</h2>\n" + md.convert(
            text, heading_offset=1, rewrite_link=rewriter(repo, p["source_path"]))
    body = f"""<p class="crumbs"><a href="../../index.html">Home</a> / {e(name)}</p>
<h1>{e(p['display_name'])}</h1>
<p class="lede">{e(p['description'])}</p>
<p class="meta">Plugin <code>{e(name)}</code>, version {e(p['version'])}, {len(p['skills'])} skills, {e(p['license'])} licence. Source: <a href="{e(repo)}">{e(repo.rsplit('/', 1)[-1])}</a>. Synced <time datetime="{e(s.synced(name))}">{e(date_of(s.synced(name)))}</time>.</p>
{install_block(name)}
{extra}
<h2 id="skills">Skills</h2>
<table><thead><tr><th>Skill</th><th>What it does</th><th>Scripts</th></tr></thead><tbody>{rows}</tbody></table>
{readme_html}"""
    title = f"{p['display_name']} plugin: {len(p['skills'])} skills | {SITE_NAME}"
    return page(rel=f"plugins/{name}/", depth=2, title=title, description=p["description"], body=body)


def build_skill(s: Site, p: dict, sk: dict) -> str:
    sdir = s.root / H.PLUGINS_DIR / p["name"] / "skills" / sk["name"]
    _, body_md, _ = H.parse_frontmatter((sdir / "SKILL.md").read_text(encoding="utf-8"))
    heading = H.first_heading(body_md) or sk["name"]
    body_md = re.sub(r"\A\s*# .*\n", "", body_md)
    limits = H.limits_section(body_md)
    rw = rewriter(p["source_repo"], posixpath.dirname(sk["source_path"]))
    limits_html = ""
    if limits:
        limits_html = "<h2 id=\"what-it-does-not-do\">What it does not do</h2>\n" + md.convert(
            limits[1], heading_offset=1, heading_ids=False, rewrite_link=rw)
        # drop the section from the body so it is not shown twice
        body_md = re.sub(r"(?ms)^## " + re.escape(limits[0]) + r"\s*\n.*?(?=^## |\Z)", "", body_md, count=1)
    src_url = blob_url(p["source_repo"], sk["source_path"])
    here_url = blob_url(H.REPO_URL, sk["path"])
    ships = H.ships_text(sk["plugin_ships"])
    ships_html = (f"<p>The <code>{e(p['name'])}</code> plugin also ships {e(ships)} at plugin level. "
                  f"Install the plugin from the marketplace to get them.</p>"
                  if ships else "")
    scripts = (f"{sk['scripts']} bundled script file{'s' if sk['scripts'] != 1 else ''}" if sk["scripts"]
               else "no bundled scripts")
    body = f"""<p class="crumbs"><a href="../../../index.html">Home</a> / <a href="../index.html">{e(p['name'])}</a> / {e(sk['name'])}</p>
<h1>{e(heading)}</h1>
<p class="lede">{e(sk['description'])}</p>
<p class="meta">Skill <code>{e(sk['name'])}</code> in plugin <a href="../index.html">{e(p['name'])}</a> {e(p['version'])}, {scripts}, {e(sk['license'])} licence. Source: <a href="{e(src_url)}">{e(sk['source_path'])}</a> in <a href="{e(p['source_repo'])}">{e(p['source_repo'].rsplit('/', 1)[-1])}</a>. Copy in this repository: <a href="{e(here_url)}">{e(sk['path'])}</a>.</p>
{install_block(p['name'], sk['name'], sk['install_name'])}
{ships_html}
{limits_html}
<h2 id="skill-md">SKILL.md</h2>
{md.convert(body_md, heading_offset=1, rewrite_link=rw)}
<p class="meta">Report a problem with this skill in <a href="{e(p['source_repo'])}/issues">{e(p['source_repo'].rsplit('/', 1)[-1])} issues</a>.</p>"""
    url = H.site_skill_url(p["name"], sk["name"])
    langs = ["Markdown"]
    if any(f.suffix == ".py" for f in (sdir / "scripts").glob("**/*")) if (sdir / "scripts").is_dir() else False:
        langs.append("Python")
    if any(f.suffix in (".sh", ".bash") for f in (sdir / "scripts").glob("**/*")) if (sdir / "scripts").is_dir() else False:
        langs.append("Shell")
    ld = {
        "@context": "https://schema.org",
        "@type": "SoftwareSourceCode",
        "name": sk["name"],
        "description": sk["description"],
        "url": url,
        "codeRepository": p["source_repo"],
        "programmingLanguage": langs,
        "license": MIT_URL if sk["license"] == "MIT" else sk["license"],
        "author": author(),
        "isPartOf": {"@type": "SoftwareSourceCode", "name": p["name"], "url": H.site_plugin_url(p["name"])},
        "version": p["version"],
    }
    title = f"{sk['name']}: {first_clause(sk['description'])} | {SITE_NAME}"
    return page(rel=f"plugins/{p['name']}/{sk['name']}/", depth=3, title=title, description=sk["description"],
                body=body, extra_head=jsonld(ld) + "\n", og_type="article")


def build_404() -> str:
    body = f"""<h1>Page not found</h1>
<p>That page does not exist. Start from the <a href="{H.SITE_PATH}index.html">skill index</a>.</p>"""
    text = page(rel="404.html", depth=0, title=f"Page not found | {SITE_NAME}", description="Page not found.", body=body)
    # 404.html is served at any depth, so its links must be absolute.
    return (text.replace('href="style.css"', f'href="{H.SITE_PATH}style.css"')
                .replace('href="index.html', f'href="{H.SITE_PATH}index.html')
                .replace('href="llms.txt"', f'href="{H.SITE_PATH}llms.txt"')
                .replace('href="feed.xml"', f'href="{H.SITE_PATH}feed.xml"'))


def build_sitemap(s: Site) -> str:
    urls = [(H.SITE_URL, date_of(s.latest())), (H.SITE_URL + GUIDE_REL, date_of(s.latest()))]
    for p in s.plugins:
        urls.append((H.site_plugin_url(p["name"]), date_of(s.synced(p["name"]))))
        for sk in s.by_plugin.get(p["name"], []):
            urls.append((H.site_skill_url(p["name"], sk["name"]), date_of(s.synced(p["name"]))))
    items = "\n".join(f"  <url><loc>{e(u)}</loc>" + (f"<lastmod>{d}</lastmod>" if d else "") + "</url>" for u, d in urls)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{items}\n</urlset>\n'


def build_robots() -> str:
    lines = []
    for bot in CRAWLERS:
        lines += [f"User-agent: {bot}", "Allow: /", ""]
    lines += ["User-agent: *", "Allow: /", "", f"Sitemap: {H.SITE_URL}sitemap.xml", ""]
    return "\n".join(lines)


def build_llms(s: Site) -> str:
    c = s.catalog["counts"]
    out = [f"# {SITE_NAME}", "",
           f"> {c['skills']} Claude Code skills in {c['plugins']} plugins by {H.OWNER_NAME}, in one repository "
           f"({H.REPO_URL}) that is also a Claude Code plugin marketplace named `{H.MARKETPLACE_NAME}`.", "",
           f"Install with `/plugin marketplace add {H.OWNER}/{H.REPO_NAME}` then `/plugin install <plugin>@{H.MARKETPLACE_NAME}`, "
           f"or clone the repository and run `python3 install.py --user` to copy every skill into `~/.claude/skills/`. "
           f"A step-by-step guide is at {H.SITE_URL}{GUIDE_REL}. "
           f"Each skill is a SKILL.md file with optional standard-library scripts. Skills are edited in their source "
           f"repositories and synced here daily.", ""]
    for p in s.plugins:
        out += [f"## {p['name']}", "", f"{p['description']} Source: {p['source_repo']}", ""]
        for sk in s.by_plugin.get(p["name"], []):
            out.append(f"- [{sk['name']}]({H.site_skill_url(p['name'], sk['name'])}): {H.one_line(sk['description'])}")
        out.append("")
    out += ["## Guides", "",
            f"- [How to install Claude Code skills (three ways)]({H.SITE_URL}{GUIDE_REL}): marketplace, clone and install.py, "
            f"or npx skills add, with troubleshooting and uninstall steps", "",
            "## Optional", "",
            f"- [llms-full.txt]({H.SITE_URL}llms-full.txt): the full text of every SKILL.md",
            f"- [catalog.json]({H.REPO_URL}/blob/main/catalog.json): machine-readable catalog",
            f"- [SOURCES.json]({H.REPO_URL}/blob/main/SOURCES.json): source repository and commit for each plugin", ""]
    return "\n".join(out)


def build_llms_full(s: Site) -> str:
    c = s.catalog["counts"]
    out = [f"# {SITE_NAME}", "",
           f"> The full SKILL.md text of all {c['skills']} skills in {c['plugins']} plugins from {H.REPO_URL}.", ""]
    for p in s.plugins:
        for sk in s.by_plugin.get(p["name"], []):
            text = (s.root / sk["path"]).read_text(encoding="utf-8").rstrip()
            out += [f"## {p['name']}/{sk['name']}", "",
                    f"Page: {H.site_skill_url(p['name'], sk['name'])}",
                    f"Source: {blob_url(p['source_repo'], sk['source_path'])}", "",
                    text, ""]
    return "\n".join(out)


def build_feed(s: Site) -> str:
    entries = []
    for p in sorted(s.plugins, key=lambda p: (s.synced(p["name"]), p["name"]), reverse=True):
        url = H.site_plugin_url(p["name"])
        commit = s.sources.get(p["name"], {}).get("commit", "")
        entries.append(f"""  <entry>
    <title>{e(p['name'])} {e(p['version'])}</title>
    <id>{e(url)}#v{e(p['version'])}-{e(commit[:12])}</id>
    <link href="{e(url)}"/>
    <updated>{e(s.synced(p['name']))}</updated>
    <summary>{e(p['description'])} Synced from {e(p['source_repo'])} at commit {e(commit[:12])}.</summary>
  </entry>""")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>{SITE_NAME}: plugin versions</title>
  <id>{H.SITE_URL}</id>
  <link href="{H.SITE_URL}"/>
  <link rel="self" href="{H.SITE_URL}feed.xml"/>
  <updated>{e(s.latest())}</updated>
  <author><name>{H.OWNER_NAME}</name><uri>{H.OWNER_URL}</uri></author>
{chr(10).join(entries)}
</feed>
"""


def build(root: Path, out: Path) -> list[Path]:
    """Build the whole site from root into out (replaced wholesale). Returns the written paths."""
    s = Site(root)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    written: list[Path] = []
    write(out, "index.html", build_index(s), written)
    for p in s.plugins:
        write(out, f"plugins/{p['name']}/index.html", build_plugin(s, p), written)
        for sk in s.by_plugin.get(p["name"], []):
            write(out, f"plugins/{p['name']}/{sk['name']}/index.html", build_skill(s, p, sk), written)
    write(out, GUIDE_REL + "index.html", build_guide(s), written)
    write(out, "404.html", build_404(), written)
    write(out, "sitemap.xml", build_sitemap(s), written)
    write(out, "robots.txt", build_robots(), written)
    write(out, "llms.txt", build_llms(s), written)
    write(out, "llms-full.txt", build_llms_full(s), written)
    write(out, "feed.xml", build_feed(s), written)
    write(out, "style.css", (SITE_DIR / "style.css").read_text(encoding="utf-8"), written)
    write(out, ".nojekyll", "", written)
    return written


# ---------------------------------------------------------------- checks

class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.canonical = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href", "")
        for key in ("href", "src"):
            if a.get(key) and not (tag == "link" and a.get("rel") == "canonical"):
                self.links.append(a[key])


def check_links(out: Path) -> list[str]:
    """Every internal href/src in docs/ resolves to a file; every canonical matches its page."""
    problems = []
    pages = sorted(out.rglob("*.html"))
    parsed: dict[Path, _Links] = {}
    for path in pages:
        parser = _Links()
        parser.feed(path.read_text(encoding="utf-8"))
        parsed[path] = parser
    for path, parser in parsed.items():
        rel_page = path.relative_to(out).as_posix()
        if rel_page != "404.html":
            expect = H.SITE_URL + (rel_page[: -len("index.html")] if rel_page.endswith("index.html") else rel_page)
            if parser.canonical != expect:
                problems.append(f"{rel_page}: canonical {parser.canonical!r} should be {expect!r}")
        for link in parser.links:
            if link.startswith(("http://", "https://", "mailto:")):
                continue
            target, _, frag = link.partition("#")
            if not target:
                if frag and frag not in parser.ids:
                    problems.append(f"{rel_page}: anchor #{frag} not found")
                continue
            if target.startswith("/"):
                if not target.startswith(H.SITE_PATH):
                    problems.append(f"{rel_page}: absolute link {link} lacks the {H.SITE_PATH} prefix")
                    continue
                dest = out / target[len(H.SITE_PATH):]
            else:
                dest = path.parent / target
            dest = Path(posixpath.normpath(dest.as_posix()))
            if target.endswith("/") or dest.is_dir():
                dest = dest / "index.html"
            if not dest.is_file():
                problems.append(f"{rel_page}: broken link {link}")
            elif frag and dest.suffix == ".html":
                other = parsed.get(dest)
                if other is not None and frag not in other.ids:
                    problems.append(f"{rel_page}: anchor {link} not found")
    return problems


def check_sitemap(out: Path) -> list[str]:
    problems = []
    text = (out / "sitemap.xml").read_text(encoding="utf-8")
    for loc in re.findall(r"<loc>(.*?)</loc>", text):
        loc = html.unescape(loc)
        rel = loc[len(H.SITE_URL):] if loc.startswith(H.SITE_URL) else None
        if rel is None or not (out / rel / "index.html" if (not rel or rel.endswith("/")) else out / rel).is_file():
            problems.append(f"sitemap.xml: {loc} has no page")
    pages = {p for p in out.rglob("index.html")}
    if len(pages) != len(re.findall(r"<loc>", text)):
        problems.append(f"sitemap.xml lists {len(re.findall(r'<loc>', text))} URLs but there are {len(pages)} index pages")
    return problems


def compare(a: Path, b: Path) -> list[str]:
    files_a = {p.relative_to(a).as_posix() for p in a.rglob("*") if p.is_file()} if a.exists() else set()
    files_b = {p.relative_to(b).as_posix() for p in b.rglob("*") if p.is_file()}
    out = sorted(files_a ^ files_b)
    out += sorted(r for r in files_a & files_b if not filecmp.cmp(a / r, b / r, shallow=False))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if docs/ is stale or has a broken link")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    docs = root / "docs"
    if not args.check:
        written = build(root, docs)
        pages = [p for p in written if p.suffix == ".html"]
        print(f"built {len(written)} files ({len(pages)} HTML pages) into {docs}")
        return 0
    failed = 0
    with tempfile.TemporaryDirectory(prefix="claude-skills-site-") as tmp:
        fresh = Path(tmp) / "docs"
        build(root, fresh)
        stale = compare(docs, fresh)
        for name, problems in (("docs/ matches a fresh build", [f"stale: docs/{r}" for r in stale]),
                               ("internal links and canonicals", check_links(fresh)),
                               ("sitemap", check_sitemap(fresh))):
            print(f"{'ok  ' if not problems else 'FAIL'} {name}" + (f" ({len(problems)})" if problems else ""))
            for p in problems[:50]:
                print(f"     {p}")
            failed += len(problems)
    if failed and stale:
        print("Run python3 site/build.py to rebuild docs/.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
