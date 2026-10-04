# Origin: basitalisandhu/basitalisandhu.github.io sitekit/markdown.py (MIT, same author), adapted: tables, link rewriting.
"""A tiny Markdown subset converter, standard library only.

Supported blocks: ATX headings (# to ######), paragraphs, unordered lists
(- or *), ordered lists (1.), fenced code blocks (``` with an optional
language), block quotes (>) and front matter (--- key: value ---).
Supported inline: `code`, **bold**, *emphasis*, [links](url) and
<https://autolinks>. Images are dropped (the site loads no external assets)
and raw HTML is escaped, never passed through.

Pipe tables are supported (added in this copy). Nested lists and reference
links are out of scope on purpose; an indented line continues the list item.
convert() takes an optional rewrite_link callback for relative links.
"""

from __future__ import annotations

import html
import re

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_ULIST = re.compile(r"^\s{0,3}[-*+]\s+(.*)$")
_OLIST = re.compile(r"^\s{0,3}(?:\d{1,9})[.)]\s+(.*)$")
_OLIST_NUM = re.compile(r"^\s{0,3}(\d{1,9})[.)]\s")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")

_rewrite = None  # set by convert(); maps a link target to another one
_FENCE = re.compile(r"^\s{0,3}(```+|~~~+)\s*([\w+#.-]*)\s*$")
_QUOTE = re.compile(r"^\s{0,3}>\s?(.*)$")

_SAFE_SCHEMES = ("http://", "https://", "mailto:")


def slugify(text: str) -> str:
    """GitHub-style anchor: lower case, drop punctuation, spaces to hyphens."""
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text)


def safe_url(url: str) -> str | None:
    """Return the URL if its scheme is allowed, else None."""
    url = url.strip()
    if url.startswith(("/", "#", "./", "../")) or url.startswith(_SAFE_SCHEMES):
        return url
    if ":" not in url.split("/", 1)[0]:  # plain relative path such as "page/"
        return url
    return None


def inline(text: str) -> str:
    """Convert inline Markdown to HTML. Input is raw Markdown, output is escaped HTML."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] in "\\`*_[]()<>#!-.+":
            out.append(html.escape(text[i + 1]))
            i += 2
            continue
        if ch == "`":
            run = len(text[i:]) - len(text[i:].lstrip("`"))
            fence = "`" * run
            end = text.find(fence, i + run)
            if end != -1:
                code = text[i + run:end].strip()
                out.append(f"<code>{html.escape(code)}</code>")
                i = end + run
                continue
        if ch == "!" and i + 1 < n and text[i + 1] == "[":
            m = _match_link(text, i + 1)
            if m:
                i = m[2]  # drop images entirely
                continue
        if ch == "[":
            m = _match_link(text, i)
            if m:
                label, url, end = m
                href = safe_url(_rewrite(url) if _rewrite else url)
                if href is None:
                    out.append(inline(label))
                else:
                    out.append(f'<a href="{html.escape(href, quote=True)}">{inline(label)}</a>')
                i = end
                continue
        if ch == "<":
            m = re.match(r"<(https?://[^>\s]+)>", text[i:])
            if m:
                url = m.group(1)
                out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(url)}</a>')
                i += m.end()
                continue
        if text.startswith("**", i) or text.startswith("__", i):
            mark = text[i:i + 2]
            end = text.find(mark, i + 2)
            if end > i + 2:
                out.append(f"<strong>{inline(text[i + 2:end])}</strong>")
                i = end + 2
                continue
        if ch in "*_" and i + 1 < n and not text[i + 1].isspace():
            prev = text[i - 1] if i else " "
            if ch == "*" or not prev.isalnum():
                end = text.find(ch, i + 1)
                after = text[end + 1] if end != -1 and end + 1 < n else " "
                if end > i + 1 and not text[end - 1].isspace() and (ch == "*" or not after.isalnum()):
                    out.append(f"<em>{inline(text[i + 1:end])}</em>")
                    i = end + 1
                    continue
        out.append(html.escape(ch))
        i += 1
    return "".join(out)


def _match_link(text: str, start: int) -> tuple[str, str, int] | None:
    """Match [label](url) at text[start] == '['. Returns (label, url, end index)."""
    depth = 0
    j = start
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "[":
            depth += 1
        elif text[j] == "]":
            depth -= 1
            if depth == 0:
                break
        j += 1
    else:
        return None
    if j + 1 >= len(text) or text[j + 1] != "(":
        return None
    k = j + 2
    depth = 1
    while k < len(text):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                break
        k += 1
    else:
        return None
    url = text[j + 2:k].strip()
    if " " in url:  # [x](url "title")
        url = url.split(" ", 1)[0]
    return text[start + 1:j], url.strip("<>"), k + 1


def split_front_matter(source: str) -> tuple[dict[str, str], str]:
    """Split '---\\nkey: value\\n---' front matter from the body."""
    if not source.startswith("---\n"):
        return {}, source
    end = source.find("\n---\n", 4)
    if end == -1:
        return {}, source
    meta: dict[str, str] = {}
    for line in source[4:end].splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip('"').strip("'")
    return meta, source[end + 5:]


def _cells(row: str) -> list[str]:
    row = row.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|") and not row.endswith("\\|"):
        row = row[:-1]
    cells, cur, i = [], [], 0
    while i < len(row):
        if row[i] == "\\" and i + 1 < len(row) and row[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if row[i] == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(row[i])
        i += 1
    cells.append("".join(cur).strip())
    return cells


def convert(source: str, heading_offset: int = 0, heading_ids: bool = True, rewrite_link=None) -> str:
    """Convert a Markdown string to an HTML fragment.

    heading_offset shifts heading levels down (1 turns '#' into <h2>), capped at h6.
    rewrite_link, if given, maps each link target before it is checked and written.
    """
    global _rewrite
    previous, _rewrite = _rewrite, rewrite_link
    try:
        return _convert(source, heading_offset, heading_ids)
    finally:
        _rewrite = previous


def _convert(source: str, heading_offset: int, heading_ids: bool) -> str:
    lines = source.replace("\r\n", "\n").replace("\t", "    ").split("\n")
    out: list[str] = []
    para: list[str] = []
    i = 0

    def flush_para() -> None:
        if para:
            out.append(f"<p>{inline(' '.join(s.strip() for s in para))}</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        fence = _FENCE.match(line)
        if fence:
            flush_para()
            marker, lang = fence.group(1), fence.group(2)
            body: list[str] = []
            i += 1
            indent = len(line) - len(line.lstrip(" "))
            while i < len(lines) and not lines[i].strip().startswith(marker[0] * len(marker)):
                raw = lines[i]
                body.append(raw[min(indent, len(raw) - len(raw.lstrip(" "))):])
                i += 1
            i += 1  # closing fence (or end of input)
            cls = f' class="language-{html.escape(lang, quote=True)}"' if lang else ""
            out.append(f"<pre><code{cls}>{html.escape(chr(10).join(body))}</code></pre>")
            continue
        if not line.strip():
            flush_para()
            i += 1
            continue
        heading = _HEADING.match(line)
        if heading:
            flush_para()
            level = min(6, len(heading.group(1)) + heading_offset)
            text = heading.group(2)
            ident = f' id="{slugify(text)}"' if heading_ids and slugify(text) else ""
            out.append(f"<h{level}{ident}>{inline(text)}</h{level}>")
            i += 1
            continue
        if _QUOTE.match(line):
            flush_para()
            quoted: list[str] = []
            while i < len(lines) and _QUOTE.match(lines[i]):
                quoted.append(_QUOTE.match(lines[i]).group(1))
                i += 1
            out.append(f"<blockquote>{_convert(chr(10).join(quoted), heading_offset, heading_ids)}</blockquote>")
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush_para()
            head = _cells(line)
            i += 2
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(_cells(lines[i]))
                i += 1
            th = "".join(f"<th>{inline(c)}</th>" for c in head)
            body_rows = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows)
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{body_rows}</tbody></table>")
            continue
        for pattern, tag in ((_ULIST, "ul"), (_OLIST, "ol")):
            if pattern.match(line):
                flush_para()
                items: list[list[str]] = []
                first = _OLIST_NUM.match(line) if tag == "ol" else None
                while i < len(lines):
                    if _FENCE.match(lines[i]):
                        break  # a fenced block inside a list item ends the list here
                    m = pattern.match(lines[i])
                    if m:
                        items.append([m.group(1)])
                    elif lines[i].strip() and lines[i].startswith((" ", "\t")) and items:
                        items[-1].append(lines[i].strip())  # continuation line
                    else:
                        break
                    i += 1
                rendered = "".join(f"<li>{inline(' '.join(item))}</li>" for item in items)
                start = f' start="{int(first.group(1))}"' if first and int(first.group(1)) != 1 else ""
                out.append(f"<{tag}{start}>{rendered}</{tag}>")
                break
        else:
            para.append(line)
            i += 1
    flush_para()
    return "\n".join(out)


def first_paragraph_text(source: str) -> str:
    """Plain text of the first paragraph, for descriptions."""
    _, body = split_front_matter(source)
    for block in re.split(r"\n\s*\n", body):
        block = block.strip()
        if block and not block.startswith(("#", "```", "-", "*", ">", "|")):
            text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", block)
            text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
            text = re.sub(r"[`*_]", "", text)
            return " ".join(text.split())
    return ""
