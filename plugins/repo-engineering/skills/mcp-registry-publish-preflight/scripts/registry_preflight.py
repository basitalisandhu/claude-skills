#!/usr/bin/env python3
"""Check an MCP server repository offline before `mcp-publisher publish` to the official MCP Registry.

Reads server.json and the local package files it can find (package.json, pyproject.toml and the README it names,
Cargo.toml, a .csproj PackageReadmeFile, Dockerfile) and reports what the registry's documented rules would reject,
what it would silently drop, and what most often breaks after publishing. Optionally checks a DNS TXT or HTTP
/.well-known/mcp-registry-auth proof record and the namespace against a domain or a GitHub owner.

Every rule names its source: the registry docs (server.schema.json draft, official-registry-requirements.md,
package-types.mdx, authentication.mdx, versioning.mdx) or the registry's validator code, all at commit e47b29e.
The full table is in references/rules.md next to this script's skill.

Severities: error (the registry would reject it), warn (dropped, or likely to break later), info (not checked,
with the reason). Nothing is fetched: no registry, DNS, npm, PyPI, NuGet, crates.io or container registry call.

Usage:
    registry_preflight.py [REPO] [--server-json FILE] [--package-json FILE] [--pyproject FILE] [--cargo-toml FILE]
                          [--readme FILE] [--dockerfile FILE] [--proof-record FILE_OR_TEXT] [--proof-kind dns|http]
                          [--expected-record TEXT] [--domain DOMAIN] [--github-owner LOGIN]
                          [--fail-on error|warn] [--json] [--out FILE]

Exit codes: 0 nothing at or above --fail-on (default error), 1 findings, 2 bad input or usage.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import shlex
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlparse

PROG = "registry_preflight.py"
COMMIT = "e47b29e"

SOURCES = {
    "schema": "server.schema.json (draft)",
    "reqs": "official-registry-requirements.md",
    "pkg": "package-types.mdx",
    "auth": "authentication.mdx",
    "ver": "versioning.mdx",
    "validators": f"internal/validators (registry code at {COMMIT})",
    "auth-code": f"internal/api/handlers/v0/auth (registry code at {COMMIT})",
    "issue-1707": "registry issue #1707",
    "issue-1694": "registry issue #1694",
    "issue-1715": "registry issue #1715",
    "issue-1682": "registry issues #1682 and #1733",
}

# official-registry-requirements.md, "Restricted Registry Base URLs"
BASE_URLS = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "nuget": "https://api.nuget.org/v3/index.json",
    "cargo": "https://crates.io",
}
OCI_HOSTS = ("docker.io", "ghcr.io", "quay.io", "mcr.microsoft.com")
OCI_SUFFIXES = (".pkg.dev", ".azurecr.io")
MCPB_HOSTS = ("github.com", "www.github.com", "gitlab.com", "www.gitlab.com")
REGISTRY_TYPES = ("npm", "pypi", "nuget", "cargo", "oci", "mcpb")
README_TYPES = ("pypi", "nuget", "cargo")
PUBLISHER_KEY = "io.modelcontextprotocol.registry/publisher-provided"
META_LIMIT = 4096
HTTP_PROOF_LIMIT = 4096
OCI_LABEL = "io.modelcontextprotocol.server.name"

# validators.go: the server name and its two parts
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]/[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$")
# validators.go: version range detection, ported as written
_V = r"v?\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?"
RANGE_RES = (
    re.compile(r"^\s*(?:\^|~|>=|<=|>|<|=)\s*" + _V + r"\s*$"),
    re.compile(r"^\s*" + _V + r"\s-\s*" + _V + r"\s*$"),
    re.compile(r"^\s*(?:" + _V + r"\s*)(?:\|\|\s*" + _V + r"\s*)+$"),
)
DOTTED_WILDCARD_RE = re.compile(r"^\s*(?:v?\d+|x|X|\*)(?:\.(?:\d+|x|X|\*)){1,2}(?:-[0-9A-Za-z.-]+)?\s*$")
# draft schema: transport url and fileSha256 patterns
TRANSPORT_URL_RE = re.compile(r"^(https?://[^\s]+|\{[a-zA-Z_][a-zA-Z0-9_]*\}[^\s]*)$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
# utils.go: repository url per source
REPO_URL_RES = {
    "github": re.compile(r"^https?://(www\.)?github\.com/[\w.-]+/[\w.-]+/?$"),
    "gitlab": re.compile(r"^https?://(www\.)?gitlab\.com/[\w.-]+(/[\w.-]+)+/?$"),
}
# common.go: what the registry accepts as a proof record
PROOF_RE = re.compile(r"v=MCPv1;\s*k=([^;]+);\s*p=([A-Za-z0-9+/=]+)")
P_FIELD_RE = re.compile(r"p=(\S*)")

# NIST P-384, for checking that a compressed public key names a point on the curve
P384_P = 2**384 - 2**128 - 2**96 + 2**32 - 1
P384_B = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)


class BadInput(Exception):
    """Input the script cannot read; reported as one line and exit 2."""


class Report:
    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.checked: list[str] = []

    def add(self, severity: str, rule: str, where: str, detail: str, source: str) -> None:
        self.findings.append({"severity": severity, "rule": rule, "where": where, "detail": detail,
                              "source": SOURCES[source]})

    def error(self, rule: str, where: str, detail: str, source: str) -> None:
        self.add("error", rule, where, detail, source)

    def warn(self, rule: str, where: str, detail: str, source: str) -> None:
        self.add("warn", rule, where, detail, source)

    def info(self, rule: str, where: str, detail: str, source: str) -> None:
        self.add("info", rule, where, detail, source)


# ---------------------------------------------------------------- reading files

def read_text(path: Path, what: str) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BadInput(f"cannot read {what} {path}: {exc.strerror or exc}") from exc
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BadInput(f"{what} {path} is not UTF-8") from exc


def read_json(path: Path, what: str) -> object:
    text = read_text(path, what)
    if not text.strip():
        raise BadInput(f"{what} {path} is empty")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise BadInput(f"{what} {path} is not valid JSON (line {exc.lineno}: {exc.msg})") from exc


def read_toml(path: Path, what: str) -> dict:
    text = read_text(path, what)
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise BadInput(f"{what} {path} is not valid TOML ({exc})") from exc


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def display(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------- server.json rules

def looks_like_range(version: str) -> bool:
    trimmed = version.strip()
    if not trimmed:
        return False
    if any(r.match(trimmed) for r in RANGE_RES):
        return True
    if DOTTED_WILDCARD_RE.match(trimmed):
        return any(c in trimmed for c in "xX*")
    return False


def specific(version: object) -> bool:
    """A version string the registry would accept as one exact version."""
    return isinstance(version, str) and bool(version) and version != "latest" and not looks_like_range(version)


def check_version(rep: Report, where: str, version: object, field: str) -> None:
    if not isinstance(version, str):
        rep.error("schema-type", where, f"{field} must be a string", "schema")
        return
    if version == "latest":
        rep.error("version-latest", where, f'{field} "latest" is reserved; give a specific version', "validators")
    elif looks_like_range(version):
        rep.error("version-range", where, f"{field} {version!r} looks like a version range, which is prohibited",
                  "ver")
    if len(version) > 255:
        rep.error("version-length", where, f"{field} is {len(version)} characters (at most 255)", "schema")


def check_https(rep: Report, rule: str, where: str, url: object, what: str, source: str) -> None:
    if not isinstance(url, str) or not url:
        rep.error("schema-type", where, f"{what} must be a non-empty string", "schema")
        return
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        rep.error(rule, where, f"{what} must be an absolute https URL: {url}", source)


def check_top_level(rep: Report, sj: dict) -> str | None:
    for field in ("name", "description", "version"):
        if field not in sj:
            rep.error("required-field", "server.json", f"{field} is required", "schema")
    name = sj.get("name")
    if "name" in sj:
        if not isinstance(name, str):
            rep.error("schema-type", "name", "name must be a string", "schema")
            name = None
        else:
            if not 3 <= len(name) <= 200:
                rep.error("name-length", "name", f"name is {len(name)} characters (3 to 200)", "schema")
            if name.count("/") != 1 or not NAME_RE.match(name):
                rep.error("name-format", "name", f"{name!r} must be namespace/name in reverse-DNS form, with "
                          "letters, digits, '.', '-' (and '_' after the slash), starting and ending with a letter "
                          "or digit", "validators")
    desc = sj.get("description")
    if "description" in sj:
        if not isinstance(desc, str):
            rep.error("schema-type", "description", "description must be a string", "schema")
        elif not 1 <= len(desc) <= 100:
            rep.error("description-length", "description", f"description is {len(desc)} characters (1 to 100)",
                      "schema")
    if "title" in sj:
        title = sj["title"]
        if not isinstance(title, str):
            rep.error("schema-type", "title", "title must be a string", "schema")
        elif not 1 <= len(title) <= 100:
            rep.error("title-length", "title", f"title is {len(title)} characters (1 to 100)", "schema")
    if "version" in sj:
        check_version(rep, "version", sj["version"], "version")
    if "websiteUrl" in sj:
        check_https(rep, "website-url-https", "websiteUrl", sj["websiteUrl"], "websiteUrl", "validators")
    icons = sj.get("icons")
    if icons is not None:
        if not isinstance(icons, list):
            rep.error("schema-type", "icons", "icons must be a list", "schema")
        else:
            for i, icon in enumerate(icons):
                src = icon.get("src") if isinstance(icon, dict) else None
                check_https(rep, "icon-https", f"icons[{i}].src", src, "icon src", "schema")
    for field in ("packages", "remotes"):
        if field in sj and not isinstance(sj[field], list):
            rep.error("schema-type", field, f"{field} must be a list", "schema")
    return name if isinstance(name, str) else None


def check_meta(rep: Report, sj: dict) -> None:
    meta = sj.get("_meta")
    if meta is None:
        return
    if not isinstance(meta, dict):
        rep.error("schema-type", "_meta", "_meta must be an object", "schema")
        return
    for key in meta:
        if key != PUBLISHER_KEY:
            rep.warn("meta-dropped", f"_meta.{key}", f"only {PUBLISHER_KEY} is kept; this key is silently dropped "
                     "on publish", "reqs")
    if PUBLISHER_KEY in meta:
        block = meta[PUBLISHER_KEY]
        if not isinstance(block, dict):
            rep.error("schema-type", f"_meta.{PUBLISHER_KEY}", "must be an object", "schema")
            return
        size = len(json.dumps(block, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        if size > META_LIMIT:
            rep.error("meta-too-large", f"_meta.{PUBLISHER_KEY}", f"{size} bytes as compact JSON (limit "
                      f"{META_LIMIT}); publishing fails", "reqs")


def check_transport(rep: Report, where: str, transport: object, remote: bool) -> None:
    if not isinstance(transport, dict):
        rep.error("transport-missing" if transport is None else "schema-type", where,
                  "transport is required" if transport is None else "transport must be an object", "schema")
        return
    ttype = transport.get("type")
    allowed = ("streamable-http", "sse") if remote else ("stdio", "streamable-http", "sse")
    if ttype not in allowed:
        rep.error("transport-type", f"{where}.type", f"type {ttype!r} is not one of {', '.join(allowed)}",
                  "validators" if remote else "schema")
        return
    if ttype == "stdio":
        return
    url = transport.get("url")
    if not isinstance(url, str) or not url:
        rep.error("transport-url", f"{where}.url", f"url is required for {ttype}", "schema")
        return
    if not TRANSPORT_URL_RE.match(url):
        rep.error("transport-url", f"{where}.url", f"{url!r} must start with http://, https:// or a {{variable}}",
                  "schema")
        return
    if remote:
        templated = re.sub(r"\{[^}]+\}", "placeholder", url)
        parsed = urlparse(templated)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https":
            rep.error("remote-url-https", f"{where}.url", f"remote url must use https: {url}", "validators")
        elif host in ("localhost", "127.0.0.1") or host.endswith(".localhost"):
            rep.error("remote-url-localhost", f"{where}.url", f"remote url must not be localhost: {url}",
                      "validators")


def oci_host(identifier: str) -> str:
    first = identifier.split("/", 1)[0]
    if "/" not in identifier or ("." not in first and ":" not in first and first != "localhost"):
        return "docker.io"  # a bare image name resolves to Docker Hub
    return first.split(":", 1)[0].lower()


def check_package(rep: Report, i: int, pkg: object) -> dict | None:
    where = f"packages[{i}]"
    if not isinstance(pkg, dict):
        rep.error("schema-type", where, "each package must be an object", "schema")
        return None
    for field in ("registryType", "identifier", "transport"):
        if field not in pkg:
            rep.error("required-field", where, f"{field} is required", "schema")
    rtype, ident = pkg.get("registryType"), pkg.get("identifier")
    if "transport" in pkg:
        check_transport(rep, f"{where}.transport", pkg["transport"], remote=False)
    if not isinstance(rtype, str) or not isinstance(ident, str) or not ident:
        if "registryType" in pkg or "identifier" in pkg:
            rep.error("schema-type", where, "registryType and identifier must be non-empty strings", "schema")
        return None
    if rtype not in REGISTRY_TYPES:
        rep.error("registry-type", f"{where}.registryType", f"{rtype!r} is not a supported registry "
                  f"({', '.join(REGISTRY_TYPES)})", "reqs")
        return None
    version = pkg.get("version")
    sha = pkg.get("fileSha256")
    base = pkg.get("registryBaseUrl")
    if version is not None:
        if isinstance(version, str) and version == "":
            rep.error("version-length", f"{where}.version", "version must not be empty", "schema")
        else:
            check_version(rep, f"{where}.version", version, "package version")
    if sha is not None and not (isinstance(sha, str) and SHA256_RE.match(sha)):
        rep.error("sha256-format", f"{where}.fileSha256", "fileSha256 must be 64 lowercase hex characters", "schema")
    if rtype in BASE_URLS:
        if not version:
            rep.error("package-version-missing", f"{where}.version", f"{rtype} packages need a version; the registry "
                      "looks up that exact version", "validators")
        if base is not None and base != BASE_URLS[rtype]:
            rep.error("registry-base-url", f"{where}.registryBaseUrl", f"{base!r} is not allowed for {rtype}; only "
                      f"{BASE_URLS[rtype]}", "reqs")
        if sha is not None:
            rep.error("sha256-not-allowed", f"{where}.fileSha256", f"{rtype} packages must not set fileSha256",
                      "validators")
    elif rtype == "oci":
        host = oci_host(ident)
        if host not in OCI_HOSTS and not host.endswith(OCI_SUFFIXES):
            rep.error("oci-host", f"{where}.identifier", f"registry host {host!r} is not allowed (docker.io, "
                      "ghcr.io, quay.io, *.pkg.dev, *.azurecr.io, mcr.microsoft.com)", "reqs")
        last = ident.rsplit("/", 1)[-1]
        if ":" not in last and "@" not in ident:
            rep.warn("oci-no-tag", f"{where}.identifier", f"{ident!r} has no tag or digest; the documented form is "
                     "registry/namespace/repository:tag", "pkg")
        for field in ("registryBaseUrl", "version", "fileSha256"):
            if field in pkg:
                rep.error("oci-field", f"{where}.{field}", f"OCI packages must not set {field}; put the version in "
                          "the identifier tag", "validators")
    elif rtype == "mcpb":
        parsed = urlparse(ident)
        if parsed.scheme != "https":
            rep.error("mcpb-url", f"{where}.identifier", f"MCPB identifier must be an https URL: {ident}",
                      "validators")
        elif (parsed.hostname or "").lower() not in MCPB_HOSTS:
            rep.error("mcpb-host", f"{where}.identifier", f"MCPB files must be GitHub or GitLab release assets, not "
                      f"{parsed.hostname}", "reqs")
        if "mcp" not in ident.lower():
            rep.error("mcpb-no-mcp", f"{where}.identifier", 'the MCPB URL must contain the string "mcp"', "pkg")
        if sha is None:
            rep.error("mcpb-sha256", f"{where}.fileSha256", "MCPB packages must include fileSha256", "pkg")
    return pkg


# ---------------------------------------------------------------- local package files

def marker_scan(text: str, name: str) -> tuple[str, int | None, str]:
    """Return (state, index, extra) for the mcp-name token in text.

    state: ok, glued (followed by a name character), case (present with other letter case), other (a marker for
    a different name), missing.
    """
    token = "mcp-name: " + name
    start = 0
    glued_at: int | None = None
    while (idx := text.find(token, start)) >= 0:
        rest = text[idx + len(token):]
        if not rest or not re.match(r"[A-Za-z0-9._/-]", rest[0]) or rest.startswith(("-->", "--!>")):
            return "ok", idx, ""
        if glued_at is None:
            glued_at = idx
        start = idx + 1
    if glued_at is not None:
        return "glued", glued_at, text[glued_at + len(token)]
    lower = text.lower()
    idx = lower.find(token.lower())
    if idx >= 0:
        return "case", idx, text[idx + len("mcp-name: "): idx + len(token)]
    m = re.search(r"mcp-name:\s*([A-Za-z0-9._/-]+)", text)
    if m:
        return "other", m.start(), m.group(1)
    return "missing", None, ""


def in_html_comment(text: str, index: int) -> bool:
    opened = text.rfind("<!--", 0, index)
    return opened >= 0 and text.rfind("-->", opened, index) < 0


def readme_from_pyproject(data: dict, base: Path) -> tuple[Path | None, str | None, str]:
    """(file, inline text, field) for the PyPI long description named in pyproject.toml."""
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    if "readme" in project:
        readme, field = project["readme"], "[project].readme"
    else:
        readme, field = poetry.get("readme"), "[tool.poetry].readme"
    if isinstance(readme, list) and readme:
        readme = readme[0]
    if isinstance(readme, str):
        return base / readme, None, field
    if isinstance(readme, dict):
        if isinstance(readme.get("file"), str):
            return base / readme["file"], None, field
        if isinstance(readme.get("text"), str):
            return None, readme["text"], field
    return None, None, ""


def pyproject_version(data: dict) -> str | None:
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    if isinstance(project.get("version"), str):
        return project["version"]
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    return poetry.get("version") if isinstance(poetry.get("version"), str) else None


def check_marker(rep: Report, rtype: str, where: str, text: str, label: str, name: str) -> bool:
    state, idx, extra = marker_scan(text, name)
    at = f"{label}:{line_of(text, idx)}" if idx is not None else label
    if state == "ok":
        if rtype == "cargo" and in_html_comment(text, idx):
            rep.error("cargo-marker-hidden", at, "crates.io strips HTML comments, so the cargo marker must be "
                      "visible text, not inside <!-- -->", "pkg")
            return False
        return True
    if state == "glued":
        rep.error("marker-glued", at, f"'mcp-name: {name}' is followed by {extra!r}; it must be followed by a "
                  "newline, whitespace, an HTML tag or -->", "pkg")
    elif state == "case":
        rep.error("marker-case", at, f"marker names {extra!r} but server.json says {name!r}; the match is exact, "
                  "including letter case", "issue-1707")
    elif state == "other":
        rep.error("marker-other-name", at, f"marker names {extra!r}, not the server name {name!r}", "pkg")
    else:
        rep.error("marker-missing", at, f"no 'mcp-name: {name}' in {label}, which the registry reads for {rtype} "
                  "ownership", "pkg")
    return False


def check_npm(rep: Report, where: str, pkg: dict, name: str, package_json: Path | None, base: Path) -> None:
    if package_json is None:
        rep.info("not-checked", where, "no package.json found; mcpName and version were not checked "
                 "(pass --package-json)", "pkg")
        return
    label = display(package_json, base)
    data = read_json(package_json, "package.json")
    if not isinstance(data, dict):
        raise BadInput(f"package.json {package_json} must be a JSON object")
    rep.checked.append(label)
    mcp_name = data.get("mcpName")
    if mcp_name is None:
        rep.error("npm-mcpname-missing", label, f'package.json has no "mcpName"; it must be {name!r}', "pkg")
    elif mcp_name != name:
        rep.error("npm-mcpname-mismatch", label, f'"mcpName" is {mcp_name!r}, server.json name is {name!r}', "pkg")
    if isinstance(data.get("name"), str) and data["name"] != pkg["identifier"]:
        rep.warn("npm-name-differs", label, f"package.json name {data['name']!r} is not the identifier "
                 f"{pkg['identifier']!r}; this may not be the package being published", "pkg")
    local = data.get("version")
    if isinstance(local, str) and specific(pkg.get("version")) and local != pkg["version"]:
        rep.warn("version-mismatch", f"{where}.version", f"server.json lists {pkg['version']}, package.json has "
                 f"{local}; the registry checks the exact listed version on npm", "ver")


def check_readme_package(rep: Report, where: str, pkg: dict, name: str, args, base: Path) -> None:
    rtype = pkg["registryType"]
    readme: Path | None = Path(args.readme) if args.readme else None
    inline: str | None = None
    origin = "--readme"
    manifest_version: tuple[str, str] | None = None
    if rtype == "pypi":
        pyproject = Path(args.pyproject) if args.pyproject else base / "pyproject.toml"
        if pyproject.is_file():
            data = read_toml(pyproject, "pyproject.toml")
            label = display(pyproject, base)
            rep.checked.append(label)
            ver = pyproject_version(data)
            if ver:
                manifest_version = (label, ver)
            named, inline_text, field = readme_from_pyproject(data, pyproject.parent)
            if named is not None or inline_text is not None:
                origin = f"{label} {field}"
                if args.readme and named is not None and Path(args.readme).resolve() != named.resolve():
                    rep.warn("readme-not-description", where, f"{field} names {display(named, base)}, so PyPI shows "
                             f"that file, not {args.readme}", "pkg")
                readme, inline = named, inline_text
            elif not args.readme:
                rep.warn("pyproject-no-readme", label, "pyproject.toml names no readme, so the PyPI description may "
                         "be empty and hold no mcp-name marker", "pkg")
        elif not args.readme:
            rep.info("not-checked", where, "no pyproject.toml found; the README PyPI shows is assumed to be "
                     "README.md (pass --pyproject or --readme)", "pkg")
    elif rtype == "cargo":
        cargo = Path(args.cargo_toml) if args.cargo_toml else base / "Cargo.toml"
        if cargo.is_file():
            data = read_toml(cargo, "Cargo.toml")
            label = display(cargo, base)
            rep.checked.append(label)
            package = data.get("package") if isinstance(data.get("package"), dict) else {}
            if isinstance(package.get("version"), str):
                manifest_version = (label, package["version"])
            if isinstance(package.get("readme"), str) and not args.readme:
                readme, origin = cargo.parent / package["readme"], f"{label} [package].readme"
    elif rtype == "nuget" and not args.readme:
        for csproj in sorted(base.glob("**/*.csproj"))[:20]:
            text = read_text(csproj, "project file")
            m = re.search(r"<PackageReadmeFile>\s*([^<]+?)\s*</PackageReadmeFile>", text)
            if m:
                readme, origin = csproj.parent / m.group(1), f"{display(csproj, base)} PackageReadmeFile"
                rep.checked.append(display(csproj, base))
                vm = re.search(r"<(?:Package)?Version>\s*([^<]+?)\s*</(?:Package)?Version>", text)
                if vm:
                    manifest_version = (display(csproj, base), vm.group(1))
                break
    if inline is not None:
        check_marker(rep, rtype, where, inline, origin, name)
    else:
        if readme is None:
            readme = base / "README.md"
            origin = "README.md (default)"
        if not readme.is_file():
            rep.error("readme-missing", where, f"the README for this {rtype} package ({display(readme, base)}, from "
                      f"{origin}) does not exist", "pkg")
        else:
            label = display(readme, base)
            rep.checked.append(label)
            ok = check_marker(rep, rtype, where, read_text(readme, "README"), label, name)
            root_readme = base / "README.md"
            if not ok and rtype == "pypi" and readme.resolve() != root_readme.resolve() and root_readme.is_file():
                root_text = read_text(root_readme, "README")
                rep.checked.append(display(root_readme, base))
                state, idx, _ = marker_scan(root_text, name)
                if state == "ok":
                    rep.error("marker-in-wrong-readme", f"README.md:{line_of(root_text, idx)}", f"the marker is in "
                              f"README.md, but {origin} makes {label} the PyPI description", "pkg")
    if manifest_version and specific(pkg.get("version")) and manifest_version[1] != pkg["version"]:
        rep.warn("version-mismatch", f"{where}.version", f"server.json lists {pkg['version']}, "
                 f"{manifest_version[0]} has {manifest_version[1]}; the registry reads the README of the exact "
                 "listed version", "issue-1707")


def dockerfile_labels(text: str) -> list[tuple[str, str, int]]:
    """(key, value, line) for every LABEL in a Dockerfile, continuations joined."""
    out: list[tuple[str, str, int]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        line = lines[i]
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line.rstrip()[:-1] + " " + lines[i]
        i += 1
        m = re.match(r"^\s*LABEL\s+(.*)$", line, re.I)
        if not m:
            continue
        try:
            parts = shlex.split(m.group(1), posix=True)
        except ValueError:
            continue
        if parts and "=" not in parts[0] and len(parts) >= 2:
            out.append((parts[0], " ".join(parts[1:]), start + 1))
            continue
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                out.append((key, value, start + 1))
    return out


def check_oci_label(rep: Report, where: str, name: str, dockerfile: Path | None, base: Path) -> None:
    if dockerfile is None or not dockerfile.is_file():
        rep.info("not-checked", where, f"no Dockerfile found; the image must carry the {OCI_LABEL} label "
                 "(pass --dockerfile)", "pkg")
        return
    label = display(dockerfile, base)
    rep.checked.append(label)
    found = [(v, ln) for k, v, ln in dockerfile_labels(read_text(dockerfile, "Dockerfile")) if k == OCI_LABEL]
    if not found:
        rep.error("oci-label-missing", label, f'no LABEL {OCI_LABEL}="{name}"', "pkg")
        return
    value, ln = found[-1]
    if "$" in value:
        rep.info("not-checked", f"{label}:{ln}", f"the {OCI_LABEL} value {value!r} uses a build variable", "pkg")
    elif value != name:
        rep.error("oci-label-mismatch", f"{label}:{ln}", f"{OCI_LABEL} is {value!r}, server.json name is {name!r}",
                  "pkg")


# ---------------------------------------------------------------- repository and namespace

def check_repository(rep: Report, sj: dict, name: str | None, github_owner: str | None) -> None:
    repo = sj.get("repository")
    if repo is None:
        rep.warn("repository-missing", "repository", "no repository; the most common later problem in published "
                 "entries is a repository link that cannot be reached", "issue-1715")
        repo = {}
    elif not isinstance(repo, dict):
        rep.error("schema-type", "repository", "repository must be an object", "schema")
        repo = {}
    else:
        url, source = repo.get("url"), repo.get("source")
        if not url:
            rep.error("repository-field", "repository.url", "url is required when repository is given", "schema")
        if not source:
            rep.error("repository-field", "repository.source", "source is required when repository is given",
                      "schema")
        if isinstance(url, str) and url and isinstance(source, str) and source:
            pattern = REPO_URL_RES.get(source)
            if pattern is None:
                rep.error("repository-source", "repository.source", f"source {source!r} is not github or gitlab",
                          "validators")
            elif not pattern.match(url):
                rep.error("repository-url", "repository.url", f"{url!r} is not a {source} repository URL",
                          "validators")
            if not url.startswith("https://"):
                rep.warn("repository-not-https", "repository.url", f"{url!r} is not https", "issue-1715")
        sub = repo.get("subfolder")
        if isinstance(sub, str) and sub and (sub.startswith("/") or ".." in sub.split("/")
                                             or not re.match(r"^[a-zA-Z0-9\-_./]+$", sub)):
            rep.error("repository-subfolder", "repository.subfolder", f"{sub!r} must be a clean relative path",
                      "validators")
    if not name or not name.lower().startswith("io.github."):
        return
    owner = name.split("/", 1)[0][len("io.github."):]
    if github_owner:
        if owner.lower() != github_owner.lower():
            rep.error("github-owner", "name", f"namespace io.github.{owner} is not the login {github_owner}; GitHub "
                      f"sign-in grants io.github.{github_owner}/* (or an organisation you own)", "auth")
        elif owner != github_owner:
            rep.warn("github-owner-case", "name", f"namespace io.github.{owner} differs from the login "
                     f"{github_owner} only in letter case; use the login's exact spelling", "auth")
    url = repo.get("url") if isinstance(repo.get("url"), str) else ""
    m = re.match(r"^https?://(?:www\.)?github\.com/([\w.-]+)/", url)
    if m and m.group(1).lower() != owner.lower():
        rep.warn("repository-owner-differs", "repository.url", f"the name's namespace is io.github.{owner} but the "
                 f"repository is under {m.group(1)}; after a GitHub rename the old namespace cannot be edited",
                 "issue-1682")


def check_domain(rep: Report, name: str | None, domain: str | None) -> None:
    if not name:
        return
    namespace = name.split("/", 1)[0]
    if domain is None:
        if not namespace.lower().startswith("io.github."):
            rep.info("not-checked", "name", f"{namespace} needs DNS or HTTP domain proof; pass --domain to check the "
                     "namespace", "auth")
        return
    labels = [p for p in domain.strip().strip(".").lower().split(".") if p]
    if len(labels) < 2:
        raise BadInput(f"--domain {domain!r} is not a domain name")
    reverse = ".".join(reversed(labels))
    if namespace.lower() != reverse and not namespace.lower().startswith(reverse + "."):
        rep.error("namespace-domain", "name", f"proof for {domain} covers {reverse}/* and {reverse}.*/*, not "
                  f"{namespace}", "auth")


# ---------------------------------------------------------------- proof record

def p384_point_ok(key: bytes) -> bool:
    x = int.from_bytes(key[1:], "big")
    if x >= P384_P:
        return False
    rhs = (pow(x, 3, P384_P) - 3 * x + P384_B) % P384_P
    return rhs == 0 or pow(rhs, (P384_P - 1) // 2, P384_P) == 1


def proof_lines(raw: str, kind: str) -> list[tuple[str | None, str]]:
    """(owner name or None, record text) for each line that mentions MCPv1."""
    if kind == "http":
        return [(None, raw.strip())] if raw.strip() else []
    out = []
    for line in raw.splitlines():
        if "MCPv1" not in line:
            continue
        owner = None
        m = re.match(r"^\s*(\S+)\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+(.*)$", line, re.I)
        value = line
        if m:
            owner, value = m.group(1), m.group(2)
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
        out.append((owner, "".join(chunks) if chunks else value.strip()))
    return out


def parse_one(record: str) -> tuple[str | None, str | None, str | None]:
    """(algorithm, key, problem) for one record, read the way the registry reads it."""
    m = PROOF_RE.search(record)
    raw_p = P_FIELD_RE.search(record)
    if not m:
        if raw_p:
            return None, None, f"p={raw_p.group(1)[:24]!r} holds characters outside base64, so the registry finds no " \
                               "key in this record"
        return None, None, "not in the form v=MCPv1; k=ed25519|ecdsap384; p=<base64>"
    algo, key = m.group(1).strip(), m.group(2)
    if raw_p and raw_p.group(1).rstrip(";\"'") != key:
        return algo, key, f"p= stops being base64 after {len(key)} characters ({raw_p.group(1)[:24]!r})"
    return algo, key, None


def check_proof(rep: Report, args) -> None:
    value = args.proof_record
    path = Path(value)
    try:
        is_file = path.is_file()
    except (OSError, ValueError):
        is_file = False
    if is_file:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise BadInput(f"cannot read --proof-record {path}: {exc.strerror or exc}") from exc
        where = path.name
        rep.checked.append(path.as_posix())
    else:
        data = value.encode("utf-8")
        where = "--proof-record"
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BadInput(f"--proof-record {where} is not UTF-8") from exc
    kind = args.proof_kind
    if kind == "http":
        if len(data) > HTTP_PROOF_LIMIT:
            rep.error("proof-too-large", where, f"{len(data)} bytes; the HTTP proof body may be at most "
                      f"{HTTP_PROOF_LIMIT}", "auth")
        if raw.lstrip().startswith("<"):
            rep.error("proof-html", where, "the body looks like an HTML page, not the proof record", "auth")
    records = proof_lines(raw, kind)
    if not records:
        rep.error("proof-missing", where, "no v=MCPv1 record found", "auth")
        return
    if kind == "dns" and len(records) > 1:
        rep.warn("proof-several", where, f"{len(records)} MCPv1 records; remove retired ones so a stale key is not "
                 "tried first", "auth")
    parsed_keys: list[tuple[str, str]] = []
    for n, (owner, record) in enumerate(records, 1):
        at = f"{where} record {n}" if len(records) > 1 else where
        if owner and owner.lower().lstrip().startswith(("_mcp-auth.", "_mcp-registry.")):
            rep.error("proof-selector", at, f"the record is on {owner}; it must be on the apex of the domain",
                      "auth")
        elif owner and args.domain and owner.rstrip(".").lower() != args.domain.strip(".").lower():
            rep.error("proof-wrong-name", at, f"the record is on {owner}, not {args.domain}", "auth")
        algo, key, problem = parse_one(record)
        if problem and key is None:
            hint = ""
            raw_p = P_FIELD_RE.search(record)
            if raw_p and re.fullmatch(r"[0-9a-fA-F]{64}", raw_p.group(1).rstrip(";\"'")):
                hint = "; it looks like hex, and the key must be base64"
            rep.error("proof-format", at, problem + hint, "issue-1694")
            continue
        if problem:
            rep.error("proof-format", at, problem, "auth-code")
        if algo not in ("ed25519", "ecdsap384"):
            rep.error("proof-algorithm", at, f"k={algo} is not ed25519 or ecdsap384", "auth")
            continue
        try:
            keybytes = base64.b64decode(key, validate=True)
        except (binascii.Error, ValueError):
            rep.error("proof-base64", at, "p= does not decode as base64", "auth-code")
            continue
        if algo == "ed25519" and len(keybytes) != 32:
            hint = "; 64 hex characters read as base64 give 48 bytes" if len(keybytes) == 48 else ""
            rep.error("proof-key-size", at, f"an Ed25519 public key is 32 bytes, this one is {len(keybytes)}{hint}",
                      "auth-code")
            continue
        if algo == "ecdsap384":
            if len(keybytes) != 49 or keybytes[0] not in (2, 3):
                rep.error("proof-key-size", at, f"an ECDSA P-384 key must be 49 bytes in compressed form (leading "
                          f"0x02 or 0x03), this one is {len(keybytes)} bytes", "auth-code")
                continue
            if not p384_point_ok(keybytes):
                rep.error("proof-key-point", at, "the key is not a point on the P-384 curve", "auth-code")
                continue
        parsed_keys.append((algo, key))
    if args.expected_record and parsed_keys:
        algo, key, problem = parse_one(args.expected_record)
        if key is None:
            raise BadInput("--expected-record is not a v=MCPv1; k=...; p=... record")
        if (algo, key) not in parsed_keys:
            published = ", ".join(f"{a}:{k[:8]}" for a, k in parsed_keys)
            rep.error("proof-key-mismatch", where, f"expected {algo}:{key[:8]}, published {published}; the "
                      "published record does not hold the key the login command signs with", "auth")


# ---------------------------------------------------------------- driver

def run(args) -> dict:
    base = Path(args.repo)
    if not base.is_dir():
        raise BadInput(f"repository folder not found: {base}")
    sj_path = Path(args.server_json) if args.server_json else base / "server.json"
    rep = Report()
    name = None
    sj_label: str | None = None
    if args.server_json or sj_path.is_file() or not args.proof_record:
        if not sj_path.is_file():
            raise BadInput(f"server.json not found: {sj_path}")
        sj = read_json(sj_path, "server.json")
        if not isinstance(sj, dict):
            raise BadInput(f"server.json {sj_path} must be a JSON object")
        sj_label = display(sj_path, base)
        rep.checked.append(sj_label)
        name = check_top_level(rep, sj)
        check_meta(rep, sj)
        packages = sj.get("packages") if isinstance(sj.get("packages"), list) else []
        remotes = sj.get("remotes") if isinstance(sj.get("remotes"), list) else []
        for i, remote in enumerate(remotes):
            check_transport(rep, f"remotes[{i}]", remote, remote=True)
        package_json = Path(args.package_json) if args.package_json else None
        if package_json is None:
            for candidate in (base / "package.json",):
                if candidate.is_file():
                    package_json = candidate
        dockerfile = Path(args.dockerfile) if args.dockerfile else base / "Dockerfile"
        for i, raw in enumerate(packages):
            pkg = check_package(rep, i, raw)
            if not pkg or not name:
                continue
            rtype = pkg["registryType"]
            if rtype == "npm":
                check_npm(rep, f"packages[{i}]", pkg, name, package_json, base)
            elif rtype in README_TYPES:
                check_readme_package(rep, f"packages[{i}]", pkg, name, args, base)
            elif rtype == "oci":
                check_oci_label(rep, f"packages[{i}]", name, dockerfile, base)
        if len(packages) == 1 and isinstance(packages[0], dict) and isinstance(sj.get("version"), str):
            pv = packages[0].get("version")
            if isinstance(pv, str) and pv and pv != sj["version"] and not sj["version"].startswith(pv + "-"):
                rep.warn("server-package-version", "version", f"server version {sj['version']} differs from the "
                         f"package version {pv}; the guidance is to keep them aligned", "ver")
        check_repository(rep, sj, name, args.github_owner)
        check_domain(rep, name, args.domain)
    elif args.domain:
        labels = [p for p in args.domain.strip().strip(".").split(".") if p]
        if len(labels) < 2:
            raise BadInput(f"--domain {args.domain!r} is not a domain name")
    if args.proof_record:
        check_proof(rep, args)
    order = {"error": 0, "warn": 1, "info": 2}
    rep.findings.sort(key=lambda f: order[f["severity"]])
    counts = {s: sum(1 for f in rep.findings if f["severity"] == s) for s in order}
    return {"server_json": sj_label, "name": name,
            "files_read": rep.checked, "findings": rep.findings, "counts": counts}


def render(result: dict) -> str:
    head = f"registry preflight: {result['server_json'] or 'proof record only'}"
    if result["name"]:
        head += f" ({result['name']})"
    lines = [head, ""]
    rows = [(f["severity"], f["rule"], f["where"], f["detail"]) for f in result["findings"]]
    if rows:
        w0 = max(4, *(len(r[0]) for r in rows))
        w1 = max(4, *(len(r[1]) for r in rows))
        w2 = min(34, max(5, *(len(r[2]) for r in rows)))
        lines.append(f"{'SEV'.ljust(w0)}  {'RULE'.ljust(w1)}  {'WHERE'.ljust(w2)}  DETAIL")
        for sev, rule, where, detail in rows:
            lines.append(f"{sev.ljust(w0)}  {rule.ljust(w1)}  {where.ljust(w2)}  {detail}")
        lines.append("")
    else:
        lines += ["No findings.", ""]
    c = result["counts"]
    lines.append(f"{c['error']} error(s), {c['warn']} warning(s), {c['info']} not checked; "
                 f"files read: {', '.join(result['files_read']) or 'none'}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to a legacy code page
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Check an MCP server repository offline against the official MCP Registry's documented "
                    "publish rules (server.json, package ownership markers, proof records).",
        epilog="Exit codes: 0 nothing at or above --fail-on, 1 findings, 2 bad input. No network calls.",
    )
    parser.add_argument("repo", nargs="?", default=".", help="the server's repository folder (default .)")
    parser.add_argument("--server-json", help="server.json to check (default REPO/server.json)")
    parser.add_argument("--package-json", help="package.json for an npm package (default REPO/package.json)")
    parser.add_argument("--pyproject", help="pyproject.toml for a PyPI package (default REPO/pyproject.toml)")
    parser.add_argument("--cargo-toml", help="Cargo.toml for a cargo package (default REPO/Cargo.toml)")
    parser.add_argument("--readme", help="the README that becomes the PyPI, NuGet or crates.io description")
    parser.add_argument("--dockerfile", help="Dockerfile for an OCI image (default REPO/Dockerfile)")
    parser.add_argument("--proof-record", help="DNS TXT record (dig output or zone line) or HTTP proof body, as "
                        "a file path or the text itself")
    parser.add_argument("--proof-kind", choices=("dns", "http"), default="dns", help="what --proof-record is "
                        "(default dns)")
    parser.add_argument("--expected-record", help="the 'Expected proof record' line mcp-publisher printed, to "
                      "compare with the published one")
    parser.add_argument("--domain", help="the domain the proof is for; the server name must be its reverse-DNS form")
    parser.add_argument("--github-owner", help="the GitHub login you sign in with, for io.github.<owner>/ names")
    parser.add_argument("--fail-on", choices=("error", "warn"), default="error", help="lowest severity that makes "
                        "the exit code 1 (default error)")
    parser.add_argument("--json", action="store_true", help="JSON report")
    parser.add_argument("--out", help="write the report to this file instead of standard output")
    args = parser.parse_args(argv)
    if args.expected_record and not args.proof_record:
        print(f"{PROG}: --expected-record needs --proof-record", file=sys.stderr)
        return 2
    try:
        result = run(args)
    except BadInput as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2
    out = json.dumps(result, indent=2) + "\n" if args.json else render(result)
    if args.out:
        try:
            Path(args.out).write_text(out, encoding="utf-8")
        except OSError as exc:
            print(f"{PROG}: cannot write --out {args.out}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(out)
    levels = ("error",) if args.fail_on == "error" else ("error", "warn")
    return 1 if any(f["severity"] in levels for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
