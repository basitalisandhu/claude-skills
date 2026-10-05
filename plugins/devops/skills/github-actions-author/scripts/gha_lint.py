#!/usr/bin/env python3
"""Validate GitHub Actions workflow files: structure, token permissions and the common security mistakes.

Checks (id, severity):
  GHA-000 error     structural: not a mapping, missing `on` or `jobs`, job without runs-on/uses, step with both uses and run
  GHA-001 high      no `permissions` block at the top level and not on every job (token gets the repository default)
  GHA-002 high      `permissions: write-all`; info for each explicit write scope so you can confirm it is needed
  GHA-003 critical  `pull_request_target` trigger that checks out the pull request head (code from the fork runs with write token)
  GHA-004 high      untrusted event data expanded directly inside `run:` (script injection); medium for workflow_dispatch inputs
  GHA-005 medium    action pinned to a tag or branch instead of a commit SHA (high for @main/@master)
  GHA-006 low       job without timeout-minutes
  GHA-007 high      curl or wget piped into a shell in a run step
  GHA-008 high      literal secret-looking value in env or with
  GHA-009 high      self-hosted runner used by a workflow that pull requests can trigger
  GHA-010 info      no `concurrency` group on push or pull_request workflows (overlapping runs)
  GHA-011 medium    `continue-on-error: true` on a job (failures will not fail the workflow)
  GHA-012 low       `actions/checkout` without `persist-credentials: false` in a workflow that runs untrusted code

Usage:
    gha_lint.py PATH [PATH ...] [--json] [--fail-on SEVERITY]      (PATH: workflow file or .github/workflows directory)

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 bad input or unparseable YAML.
Standard library only (bundled minimal YAML reader). Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _miniyaml import YAMLError, load  # noqa: E402

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment)\.(?:title|body)"
    r"|github\.event\.pull_request\.head\.(?:ref|label|repo\.(?:name|description|homepage|full_name))"
    r"|github\.head_ref"
    r"|github\.event\.(?:head_commit|commits\[\d*\]|commits\.\*)\.(?:message|author\.(?:name|email))"
    r"|github\.event\.workflow_run\.(?:head_branch|head_commit\.message|head_repository\.description)"
    r"|github\.event\.pages\.\*\.page_name"
    r"|github\.event\.issue\.user\.login)\s*\}\}")
INPUTS_RE = re.compile(r"\$\{\{\s*(?:github\.event\.)?inputs\.[\w-]+\s*\}\}")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")
PIPE_SHELL_RE = re.compile(r"(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b")
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|credential|private[_-]?key|access[_-]?key)")
TRIGGER_FROM_PR = {"pull_request", "pull_request_target", "issue_comment", "pull_request_review", "pull_request_review_comment"}
WRITE_SCOPES = {"contents", "packages", "id-token", "pull-requests", "issues", "deployments", "actions", "security-events", "statuses", "checks", "pages", "discussions", "repository-projects"}


def collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += sorted(x for x in p.iterdir() if x.suffix in {".yml", ".yaml"} and x.is_file())
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(raw)
    return files


def triggers_of(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return set(on)
    return set()


def has_explicit_permissions(obj) -> bool:
    return isinstance(obj, dict) and "permissions" in obj


def lint(path: Path, doc) -> list[dict]:
    findings: list[dict] = []

    def add(fid, sev, where, title, evidence, fix):
        findings.append({"id": fid, "severity": sev, "file": str(path), "where": where, "title": title, "evidence": str(evidence)[:160], "fix": fix})

    if not isinstance(doc, dict):
        add("GHA-000", "critical", "", "Workflow is not a mapping", type(doc).__name__, "A workflow file is a YAML mapping with name, on and jobs.")
        return findings
    trig = triggers_of(doc)
    if not trig:
        add("GHA-000", "critical", "on", "Missing `on` trigger", "", "Add an `on:` block.")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        add("GHA-000", "critical", "jobs", "Missing or empty `jobs`", "", "Add at least one job.")
        return findings
    top_perms = doc.get("permissions")
    if top_perms == "write-all":
        add("GHA-002", "high", "permissions", "Top-level permissions: write-all", top_perms, "List only the scopes the workflow needs, for example `contents: read`.")
    elif isinstance(top_perms, dict):
        writes = [k for k, v in top_perms.items() if v == "write" and k in WRITE_SCOPES]
        if writes:
            add("GHA-002", "info", "permissions", "Top-level write scopes granted", ", ".join(writes), "Confirm each write scope is used; move job-specific writes to that job's permissions.")
    missing_perm_jobs = [name for name, job in jobs.items() if isinstance(job, dict) and not has_explicit_permissions(job)]
    if top_perms is None and missing_perm_jobs:
        add("GHA-001", "high", "permissions", "No permissions block at the top level or on every job", "jobs without permissions: " + ", ".join(missing_perm_jobs), "Add `permissions: contents: read` at the top level and grant more only on the jobs that need it.")
    if "pull_request_target" in trig:
        for name, job in jobs.items():
            for i, step in enumerate(job.get("steps") or [] if isinstance(job, dict) else []):
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                ref = str((step.get("with") or {}).get("ref", "")) if isinstance(step.get("with"), dict) else ""
                if uses.startswith("actions/checkout") and re.search(r"github\.event\.pull_request\.head|github\.head_ref", ref):
                    add("GHA-003", "critical", f"jobs.{name}.steps[{i}]", "pull_request_target checks out the pull request head", f"ref: {ref}", "Never run fork code with the write token: use the pull_request trigger, or check out the base and only read PR metadata.")
    pr_triggered = bool(trig & TRIGGER_FROM_PR)
    concurrency = "concurrency" in doc
    for name, job in jobs.items():
        if not isinstance(job, dict):
            add("GHA-000", "critical", f"jobs.{name}", "Job is not a mapping", job, "Each job is a mapping with runs-on (or uses) and steps.")
            continue
        if "runs-on" not in job and "uses" not in job:
            add("GHA-000", "critical", f"jobs.{name}", "Job has neither runs-on nor uses", "", "Add runs-on: ubuntu-latest (or uses: for a reusable workflow).")
        runs_on = job.get("runs-on")
        runs_on_text = " ".join(str(x) for x in (runs_on if isinstance(runs_on, list) else [runs_on])) if runs_on is not None else ""
        if "self-hosted" in runs_on_text and pr_triggered and "pull_request_target" not in trig or ("self-hosted" in runs_on_text and "pull_request_target" in trig):
            add("GHA-009", "high", f"jobs.{name}.runs-on", "Self-hosted runner reachable from pull requests", runs_on_text, "Run pull-request jobs on GitHub-hosted runners, or restrict the workflow to trusted branches; a fork can execute code on the runner.")
        if job.get("permissions") == "write-all":
            add("GHA-002", "high", f"jobs.{name}.permissions", "Job permissions: write-all", "", "List only the scopes this job needs.")
        if "timeout-minutes" not in job and "uses" not in job:
            add("GHA-006", "low", f"jobs.{name}", "No timeout-minutes", "", "Add timeout-minutes so a hung job cannot run for six hours.")
        if job.get("continue-on-error") is True:
            add("GHA-011", "medium", f"jobs.{name}", "continue-on-error: true on a job", "", "Remove it unless the job is informational; failures here will not fail the workflow.")
        if not concurrency and trig & {"push", "pull_request"}:
            concurrency = True  # report once
            add("GHA-010", "info", "concurrency", "No concurrency group", "", "Add `concurrency: {group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true}` to stop stale runs.")
        for i, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                add("GHA-000", "critical", f"jobs.{name}.steps[{i}]", "Step is not a mapping", step, "Each step is a mapping with uses or run.")
                continue
            where = f"jobs.{name}.steps[{i}]"
            if "uses" in step and "run" in step:
                add("GHA-000", "critical", where, "Step has both uses and run", "", "Split into two steps.")
            uses = step.get("uses")
            if isinstance(uses, str) and not uses.startswith(("./", "docker://")):
                ref = uses.split("@", 1)[1] if "@" in uses else ""
                if not ref:
                    add("GHA-005", "high", where, "Action without a version", uses, "Pin to a commit SHA: uses: owner/repo@<40-char sha> # vX.Y.Z")
                elif ref in {"main", "master", "develop", "latest"}:
                    add("GHA-005", "high", where, "Action pinned to a moving branch", uses, "Pin to a commit SHA with the version in a comment.")
                elif not SHA_RE.search(uses):
                    add("GHA-005", "medium", where, "Action pinned to a tag, not a commit SHA", uses, "Tags can be moved; pin to the SHA and let dependabot update it.")
                if uses.startswith("actions/checkout") and pr_triggered:
                    with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                    if with_.get("persist-credentials") is not False:
                        add("GHA-012", "low", where, "actions/checkout keeps the token in .git/config", uses, "Set `with: persist-credentials: false` unless a later step pushes.")
            run = step.get("run")
            if isinstance(run, str):
                for m in UNTRUSTED_CONTEXT_RE.finditer(run):
                    add("GHA-004", "high", where, "Untrusted event data expanded inside run", m.group(0), "Pass it through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script.")
                for m in INPUTS_RE.finditer(run):
                    add("GHA-004", "medium", where, "workflow input expanded inside run", m.group(0), "Pass inputs through env: and quote them in the script.")
                if PIPE_SHELL_RE.search(run):
                    add("GHA-007", "high", where, "Remote script piped into a shell", run.strip().splitlines()[0], "Download, verify a checksum, then run; or use a pinned action.")
            for block_name in ("env", "with"):
                block = step.get(block_name)
                if isinstance(block, dict):
                    for k, v in block.items():
                        if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and v and "${{" not in v and len(v) >= 8 and not re.match(r"(?i)^(false|true|none|\$\w+)$", v):
                            add("GHA-008", "high", f"{where}.{block_name}.{k}", "Literal secret-looking value", f"{k}={v[:3]}***", "Store it in repository secrets and reference ${{ secrets.NAME }}.")
        env = job.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and v and "${{" not in v and len(v) >= 8:
                    add("GHA-008", "high", f"jobs.{name}.env.{k}", "Literal secret-looking value", f"{k}={v[:3]}***", "Store it in repository secrets and reference ${{ secrets.NAME }}.")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["where"], f["id"]))
    return findings


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = ap.parse_args(argv)
    try:
        files = collect(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("error: no workflow files found", file=sys.stderr)
        return 2
    findings: list[dict] = []
    parse_errors: list[str] = []
    for f in files:
        try:
            doc = load(f.read_text(encoding="utf-8", errors="replace"))
        except YAMLError as exc:
            parse_errors.append(f"{f}: {exc}")
            continue
        findings += lint(f, doc)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITIES}
    report = {"version": VERSION, "files": [str(f) for f in files], "findings": findings, "parse_errors": parse_errors, "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"github-actions lint {VERSION}: {len(files)} workflow(s), {len(findings)} findings " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]))
        for x in findings:
            print(f"  [{x['severity']:<8}] {x['id']} {x['file']} {x['where']}: {x['title']}" + (f"\n      {x['evidence']}" if x["evidence"] else "") + f"\n      fix: {x['fix']}")
        for e in parse_errors:
            print(f"  parse error: {e}")
    if parse_errors:
        return 2
    worst = min((order[x["severity"]] for x in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
