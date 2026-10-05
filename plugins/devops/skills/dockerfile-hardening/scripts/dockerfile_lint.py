#!/usr/bin/env python3
"""Lint Dockerfiles for the mistakes that make images large, unreproducible or unsafe.

Checks (id, severity):
  DF-001 high      FROM without a tag, or with :latest (unreproducible builds)
  DF-002 high      final stage never sets a non-root USER (container runs as root)
  DF-003 medium    ADD used where COPY would do; high when ADD fetches a URL
  DF-004 critical  secret-looking literal in ENV or ARG (baked into image layers and history)
  DF-005 high      curl or wget piped into a shell
  DF-006 medium    apt-get install without --no-install-recommends, or without cleaning /var/lib/apt/lists
  DF-007 low       pip or npm install without disabling the cache (bigger layers)
  DF-008 medium    chmod 777 or chmod -R 777
  DF-009 low       final stage has no HEALTHCHECK
  DF-010 medium    EXPOSE 22 (an SSH daemon in a container)
  DF-011 low       COPY . or ADD . with no .dockerignore next to the Dockerfile
  DF-012 medium    sudo inside RUN
  DF-013 low       CMD or ENTRYPOINT in shell form (signals are not forwarded to the process)
  DF-014 high      COPY or ADD of credential files (.env, id_rsa, .git, .aws, .npmrc, .netrc)
  DF-015 info      base image not pinned by digest (@sha256:...)
  DF-016 low       MAINTAINER instruction (deprecated; use LABEL)
  DF-017 medium    apt-get upgrade or dist-upgrade (undoes pinning; prefer rebuilding from a newer base)

Usage:
    dockerfile_lint.py DOCKERFILE [DOCKERFILE ...] [--json] [--fail-on SEVERITY]

Exit codes: 0 nothing at or above --fail-on (default: high), 1 findings at or above it, 2 bad input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|passwd|credential|private[_-]?key|auth|access[_-]?key|client[_-]?secret)")
PLACEHOLDER_RE = re.compile(r"(?i)^(\$\{?[A-Z_]+\}?|\"\"|''|changeme|change-me|xxx+|your[-_]|example|placeholder|<[^>]+>|\.\.\.|\*+|dummy|none|null|false|true|0|1)$")
PIPE_SHELL_RE = re.compile(r"(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|node|perl)\b")
CRED_FILE_RE = re.compile(r"(?i)(^|[\s/])(\.env(\.[\w-]+)?|id_rsa|id_ed25519|id_ecdsa|\.git|\.aws|\.npmrc|\.netrc|\.pypirc|\.docker/config\.json|\.ssh)(\s|$|/)")
MUTABLE_TAGS = {"latest", "stable", "master", "main", "edge", "nightly", "current"}


def parse_dockerfile(text: str) -> list[dict]:
    """Return instructions as {line, instruction, args}. Handles comments, continuations and heredocs."""
    out: list[dict] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        buf = raw
        while buf.rstrip().endswith("\\") and i + 1 < n:
            i += 1
            nxt = lines[i]
            if nxt.strip().startswith("#"):
                continue
            buf = buf.rstrip()[:-1] + " " + nxt.strip()
        m = re.match(r"^\s*([A-Za-z]+)\s*(.*)$", buf, re.S)
        i += 1
        if not m:
            continue
        inst, args = m.group(1).upper(), m.group(2).strip()
        heredoc = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", args)
        if heredoc and inst in {"RUN", "COPY", "ADD"}:
            tag = heredoc.group(1)
            body = []
            while i < n and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            i += 1
            args = args + "\n" + "\n".join(body)
        out.append({"line": start, "instruction": inst, "args": args})
    return out


def split_stages(instructions: list[dict]) -> list[list[dict]]:
    stages: list[list[dict]] = []
    for ins in instructions:
        if ins["instruction"] == "FROM" or not stages:
            stages.append([])
        stages[-1].append(ins)
    return stages


def lint(path: Path, text: str) -> list[dict]:
    findings: list[dict] = []

    def add(fid: str, sev: str, line: int, title: str, evidence: str, fix: str) -> None:
        findings.append({"id": fid, "severity": sev, "file": str(path), "line": line, "title": title, "evidence": evidence[:160], "fix": fix})

    instructions = parse_dockerfile(text)
    if not instructions:
        return findings
    stages = split_stages(instructions)
    stage_names = set()
    for st in stages:
        first = st[0]
        if first["instruction"] == "FROM":
            m = re.match(r"^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", first["args"], re.I)
            if m:
                image, alias = m.group(1), m.group(2)
                if alias:
                    stage_names.add(alias.lower())
                if image.lower() != "scratch" and image.lower() not in stage_names:
                    name_part = image.split("@")[0]
                    tag = name_part.rsplit(":", 1)[1] if ":" in name_part.split("/")[-1] else None
                    if "@sha256:" not in image:
                        if tag is None:
                            add("DF-001", "high", first["line"], "FROM without a tag resolves to :latest", first["args"], "Pin a specific tag (python:3.12-slim) or a digest (@sha256:...).")
                        elif tag.lower() in MUTABLE_TAGS:
                            add("DF-001", "high", first["line"], f"FROM uses the mutable tag :{tag}", first["args"], "Pin a specific version tag or a digest so rebuilds are reproducible.")
                        else:
                            add("DF-015", "info", first["line"], "Base image not pinned by digest", first["args"], "Add @sha256:<digest> after the tag for a fully reproducible base; renovate or dependabot can keep it current.")
    final = stages[-1]
    users = [ins for ins in final if ins["instruction"] == "USER"]
    final_is_scratch_or_alias = final[0]["instruction"] == "FROM" and final[0]["args"].split()[0].lower() in stage_names
    if not users:
        # a non-root USER set in a stage that the final stage builds FROM carries over
        inherited = False
        if final_is_scratch_or_alias:
            base_alias = final[0]["args"].split()[0].lower()
            for st in stages:
                m = re.match(r"^\S+\s+AS\s+(\S+)", st[0]["args"], re.I)
                if m and m.group(1).lower() == base_alias and any(i["instruction"] == "USER" and i["args"].split(":")[0] not in {"root", "0"} for i in st):
                    inherited = True
        if not inherited:
            add("DF-002", "high", final[0]["line"], "Final stage never switches to a non-root USER", "no USER instruction after the last FROM", "Create a user (RUN adduser --system app) and add USER app before CMD/ENTRYPOINT.")
    elif users[-1]["args"].split(":")[0] in {"root", "0"}:
        add("DF-002", "high", users[-1]["line"], "Final USER is root", users[-1]["args"], "Switch to a non-root user as the last USER instruction.")
    if not any(ins["instruction"] == "HEALTHCHECK" for ins in final):
        add("DF-009", "low", final[0]["line"], "No HEALTHCHECK in the final stage", "no HEALTHCHECK instruction", "Add HEALTHCHECK CMD ... so orchestrators can detect a hung process (or HEALTHCHECK NONE on purpose).")
    has_dockerignore = (path.parent / ".dockerignore").exists() if path.parent.exists() else True
    for ins in instructions:
        inst, args, line = ins["instruction"], ins["args"], ins["line"]
        if inst == "ADD":
            src = args.split()[0] if args.split() else ""
            if re.match(r"^https?://", src):
                add("DF-003", "high", line, "ADD downloads from a URL without checksum verification", args, "Use RUN curl -fsSL ... && echo '<sha256> file' | sha256sum -c, or COPY a vendored file.")
            elif not re.search(r"\.(tar|tgz|tar\.gz|tar\.xz|tar\.bz2|zip)\b", src):
                add("DF-003", "medium", line, "ADD used where COPY would do", args, "Use COPY; ADD has surprising auto-extraction and URL behaviour.")
        if inst in {"ENV", "ARG"}:
            pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)", args)
            if not pairs and inst == "ENV":
                parts = args.split(None, 1)
                if len(parts) == 2:
                    pairs = [(parts[0], parts[1])]
            for key, val in pairs:
                v = val.strip("\"'")
                if SECRET_KEY_RE.search(key) and v and not PLACEHOLDER_RE.match(v) and len(v) >= 8 and "$" not in v:
                    masked = v[:3] + "*" * max(3, len(v) - 3)
                    add("DF-004", "critical", line, f"{inst} {key} holds a secret-looking literal", f"{inst} {key}={masked}", "Never bake secrets into images; pass them at run time (env, mounted file) or use RUN --mount=type=secret for build-time secrets.")
                elif SECRET_KEY_RE.search(key) and inst == "ARG" and not v:
                    add("DF-004", "medium", line, f"ARG {key} looks like a secret build argument", f"ARG {key}", "Build args stay in the image history (docker history). Use RUN --mount=type=secret,id=... instead.")
        if inst == "RUN":
            if PIPE_SHELL_RE.search(args):
                add("DF-005", "high", line, "Remote script piped into a shell", args, "Download to a file, verify a checksum or signature, then run it.")
            if re.search(r"apt-get\s+(install|-y\s+install|\S*\s+install)", args) or re.search(r"\bapt-get\b.*\binstall\b", args):
                if "--no-install-recommends" not in args:
                    add("DF-006", "medium", line, "apt-get install without --no-install-recommends", args, "Add --no-install-recommends to keep the layer small.")
                if not re.search(r"rm\s+-rf\s+/var/lib/apt/lists", args) and not re.search(r"apt-get\s+clean", args):
                    add("DF-006", "medium", line, "apt lists not removed in the same layer", args, "End the RUN with && rm -rf /var/lib/apt/lists/*.")
            if re.search(r"apt-get\s+(?:-y\s+)?(upgrade|dist-upgrade)\b", args):
                add("DF-017", "medium", line, "apt-get upgrade in the image build", args, "Rebuild from a newer base image instead; upgrading inside the build makes the result depend on the day it ran.")
            if re.search(r"\bpip3?\s+install\b", args) and "--no-cache-dir" not in args and "PIP_NO_CACHE_DIR" not in text:
                add("DF-007", "low", line, "pip install keeps its download cache in the layer", args, "Add --no-cache-dir (or ENV PIP_NO_CACHE_DIR=1).")
            if re.search(r"\bnpm\s+(install|i|ci)\b", args) and "npm cache clean" not in args and "--cache" not in args:
                add("DF-007", "low", line, "npm install without clearing the cache", args, "Prefer npm ci and add && npm cache clean --force in the same RUN.")
            if re.search(r"chmod\s+(-R\s+)?(a\+rwx|777|0777)", args):
                add("DF-008", "medium", line, "World-writable permissions", args, "Grant the narrowest permission the process needs (755 or 644; chown to the runtime user).")
            if re.search(r"(^|[\s;&|])sudo\s", args + " "):
                add("DF-012", "medium", line, "sudo inside RUN", args, "Build steps already run as root; remove sudo (and do not install it in the image).")
        if inst == "EXPOSE" and re.search(r"(^|\s)22(/tcp)?(\s|$)", args):
            add("DF-010", "medium", line, "Port 22 exposed", args, "Do not run sshd in containers; use docker exec or kubectl exec.")
        if inst in {"COPY", "ADD"}:
            srcs = [a for a in args.split() if not a.startswith("--")][:-1] if len(args.split()) > 1 else []
            if any(s in {".", "./"} for s in srcs) and not has_dockerignore:
                add("DF-011", "low", line, f"{inst} . without a .dockerignore", args, "Add a .dockerignore (at least .git, node_modules, .env, *.log) so secrets and junk do not enter the image.")
            if CRED_FILE_RE.search(" " + " ".join(srcs) + " "):
                add("DF-014", "high", line, "Credential or VCS files copied into the image", args, "Exclude them with .dockerignore and copy only what the runtime needs.")
        if inst in {"CMD", "ENTRYPOINT"} and not args.lstrip().startswith("["):
            add("DF-013", "low", line, f"{inst} in shell form", args, f'Use exec form: {inst} ["executable", "arg"] so PID 1 receives SIGTERM and the container stops cleanly.')
        if inst == "MAINTAINER":
            add("DF-016", "low", line, "MAINTAINER is deprecated", args, 'Use LABEL org.opencontainers.image.authors="..." instead.')
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["line"], f["id"]))
    return findings


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="Dockerfile paths")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = ap.parse_args(argv)
    all_findings: list[dict] = []
    for f in args.files:
        p = Path(f)
        if not p.is_file():
            print(f"error: not a file: {f}", file=sys.stderr)
            return 2
        all_findings += lint(p, p.read_text(encoding="utf-8", errors="replace"))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    counts = {s: sum(1 for x in all_findings if x["severity"] == s) for s in SEVERITIES}
    report = {"version": VERSION, "files": args.files, "findings": all_findings, "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"dockerfile-hardening {VERSION}: {len(all_findings)} findings in {len(args.files)} file(s) " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]))
        for x in all_findings:
            print(f"  [{x['severity']:<8}] {x['id']} {x['file']}:{x['line']} {x['title']}\n      {x['evidence']}\n      fix: {x['fix']}")
    worst = min((order[x["severity"]] for x in all_findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
