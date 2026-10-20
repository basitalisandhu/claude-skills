#!/usr/bin/env python3
"""Summarise the JSON output of npm audit, yarn audit, pip-audit or cargo audit into one ranked list.

Formats (auto-detected): npm audit v7+ (`vulnerabilities` map), npm audit v6 (`advisories` map), yarn audit
(NDJSON of auditAdvisory records), pip-audit (`-f json`, both the flat list and the `dependencies` object),
cargo audit (`--json`). For every vulnerable package: severity, whether it is a direct dependency, the fixed
version or whether a fix exists, the advisory ids and titles, and the dependents pulling it in. The summary
counts by severity, splits fixable from unfixable, and lists the packages to upgrade first (highest severity,
then most advisories).

Usage:
    audit_reader.py FILE [--json] [--format npm|yarn|pip-audit|cargo] [--fail-on SEVERITY] [--ignore ID ...]

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 unreadable or unrecognised input.
Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "moderate", "low", "info"]
GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}", re.IGNORECASE)
SEV_ALIAS = {"medium": "moderate", "important": "high", "unknown": "info", "none": "info", "informational": "info", "warning": "moderate", "error": "high"}


def norm_sev(s) -> str:
    s = str(s or "info").lower()
    s = SEV_ALIAS.get(s, s)
    return s if s in SEVERITIES else "info"


def load(text: str):
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        records = []
        for line in stripped.splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records


def detect(doc) -> str | None:
    if isinstance(doc, list):
        if doc and isinstance(doc[0], dict) and "type" in doc[0] and doc[0].get("type") in {"auditAdvisory", "auditSummary", "auditAction"}:
            return "yarn"
        if all(isinstance(d, dict) and "name" in d and "vulns" in d for d in doc) or doc == []:
            return "pip-audit"
        return None
    if isinstance(doc, dict):
        if "vulnerabilities" in doc and isinstance(doc["vulnerabilities"], dict) and "list" in doc["vulnerabilities"]:
            return "cargo"
        if "vulnerabilities" in doc and isinstance(doc["vulnerabilities"], dict):
            return "npm"
        if "advisories" in doc:
            return "npm6"
        if "dependencies" in doc and isinstance(doc["dependencies"], list):
            return "pip-audit"
        if doc.get("type") == "auditAdvisory":
            return "yarn"
    return None


def parse_npm7(doc: dict) -> list[dict]:
    out = []
    for name, v in (doc.get("vulnerabilities") or {}).items():
        ids, titles, urls, groups = [], [], [], []
        for via in v.get("via") or []:
            if isinstance(via, dict):
                group = [str(via.get("source") or via.get("url") or via.get("name"))]
                ghsa = GHSA_RE.search(str(via.get("url") or ""))
                if ghsa:  # npm v7 keys advisories by a numeric source; the GHSA id people put in ignore lists is in the url
                    group.append(ghsa.group(0))
                group = [i for i in group if i and i != "None"]
                ids.extend(i for i in group if i not in ids)
                groups.append(group)
                titles.append(via.get("title", ""))
                if via.get("url"):
                    urls.append(via["url"])
        fix = v.get("fixAvailable")
        if isinstance(fix, dict):
            fix_text = f"{fix.get('name')}@{fix.get('version')}" + (" (major)" if fix.get("isSemVerMajor") else "")
        else:
            fix_text = "yes" if fix else "no"
        out.append({"package": name, "version": v.get("range", ""), "severity": norm_sev(v.get("severity")), "direct": bool(v.get("isDirect")),
                    "fix": fix_text, "fixable": bool(fix), "ids": ids, "titles": [t for t in titles if t], "urls": urls,
                    "dependents": [str(e) for e in (v.get("effects") or [])], "_groups": [g for g in groups if g],
                    "via": [str(x) for x in (v.get("via") or []) if isinstance(x, str)]})
    return out


def parse_npm6(doc: dict) -> list[dict]:
    out = []
    for aid, adv in (doc.get("advisories") or {}).items():
        findings = adv.get("findings") or []
        versions = sorted({f.get("version", "") for f in findings})
        direct = any(len(p.split(">")) == 1 for f in findings for p in f.get("paths") or [])
        patched = adv.get("patched_versions") or "<0.0.0"
        ids6 = [str(aid)] + ([adv["github_advisory_id"]] if adv.get("github_advisory_id") else []) + ([adv["cves"][0]] if adv.get("cves") else [])
        out.append({"package": adv.get("module_name", "?"), "version": ", ".join(v for v in versions if v), "severity": norm_sev(adv.get("severity")), "direct": direct,
                    "fix": patched if patched != "<0.0.0" else "no", "fixable": patched != "<0.0.0", "ids": ids6,
                    "titles": [adv.get("title", "")], "urls": [adv["url"]] if adv.get("url") else [], "dependents": [], "_groups": [ids6]})
    return out


def parse_yarn(records: list) -> list[dict]:
    out = []
    for rec in records:
        if not isinstance(rec, dict) or rec.get("type") != "auditAdvisory":
            continue
        adv = (rec.get("data") or {}).get("advisory") or {}
        res = (rec.get("data") or {}).get("resolution") or {}
        patched = adv.get("patched_versions") or "<0.0.0"
        out.append({"package": adv.get("module_name", "?"), "version": ", ".join(sorted({f.get("version", "") for f in adv.get("findings") or []})),
                    "severity": norm_sev(adv.get("severity")), "direct": len(str(res.get("path", "")).split(">")) == 1,
                    "fix": patched if patched != "<0.0.0" else "no", "fixable": patched != "<0.0.0", "ids": [str(adv.get("id"))], "titles": [adv.get("title", "")],
                    "urls": [adv["url"]] if adv.get("url") else [], "dependents": []})
    return out


def parse_pip_audit(doc) -> list[dict]:
    deps = doc.get("dependencies") if isinstance(doc, dict) else doc
    out = []
    for d in deps or []:
        vulns = d.get("vulns") or []
        if not vulns:
            continue
        fixes = sorted({fv for v in vulns for fv in (v.get("fix_versions") or [])})
        out.append({"package": d.get("name", "?"), "version": d.get("version", ""), "severity": norm_sev(max((v.get("severity") or "info" for v in vulns), key=lambda s: -SEVERITIES.index(norm_sev(s)))) if any(v.get("severity") for v in vulns) else "info",
                    "direct": None, "fix": ", ".join(fixes) if fixes else "no", "fixable": bool(fixes),
                    "ids": [v.get("id", "") for v in vulns] + [a for v in vulns for a in (v.get("aliases") or [])],
                    "titles": [(v.get("description") or "")[:120] for v in vulns], "urls": [], "dependents": [],
                    "_groups": [[v.get("id", "")] + list(v.get("aliases") or []) for v in vulns]})
    return out


def parse_cargo(doc: dict) -> list[dict]:
    out = []
    for v in ((doc.get("vulnerabilities") or {}).get("list") or []):
        adv = v.get("advisory") or {}
        pkg = v.get("package") or {}
        patched = (v.get("versions") or {}).get("patched") or []
        out.append({"package": pkg.get("name", "?"), "version": pkg.get("version", ""), "severity": norm_sev(adv.get("cvss_severity") or ("high" if adv.get("cvss") else "info")),
                    "direct": None, "fix": ", ".join(patched) if patched else "no", "fixable": bool(patched), "ids": [adv.get("id", "")] + list(adv.get("aliases") or []),
                    "titles": [adv.get("title", "")], "urls": [adv["url"]] if adv.get("url") else [], "dependents": []})
    for w_list in ((doc.get("warnings") or {}).values() if isinstance(doc.get("warnings"), dict) else []):
        for w in w_list or []:
            pkg = w.get("package") or {}
            adv = w.get("advisory") or {}
            out.append({"package": pkg.get("name", "?"), "version": pkg.get("version", ""), "severity": "low", "direct": None, "fix": "no", "fixable": False,
                        "ids": [adv.get("id", w.get("kind", "warning"))], "titles": [adv.get("title", w.get("kind", ""))], "urls": [], "dependents": []})
    return out


PARSERS = {"npm": parse_npm7, "npm6": parse_npm6, "yarn": parse_yarn, "pip-audit": parse_pip_audit, "cargo": parse_cargo}


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="audit JSON file ('-' for stdin)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--format", choices=["npm", "npm6", "yarn", "pip-audit", "cargo"])
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory id to ignore (repeatable)")
    args = ap.parse_args(argv)
    name = "standard input" if args.file == "-" else args.file
    if args.file != "-" and not Path(args.file).is_file():
        print(f"error: audit file not found: {args.file}", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"error: {name} is not UTF-8 text; pass the JSON output of the audit tool", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read {name}: {exc}", file=sys.stderr)
        return 2
    if not text.strip():
        print(f"error: {name} is empty; capture the report with --json (npm, yarn, cargo) or -f json (pip-audit)", file=sys.stderr)
        return 2
    try:
        doc = load(text)
    except json.JSONDecodeError as exc:
        print(f"error: {name} is not audit JSON: {exc}", file=sys.stderr)
        return 2
    fmt = args.format or detect(doc)
    if fmt is None:
        print("error: unrecognised audit format; pass --format", file=sys.stderr)
        return 2
    try:
        items = PARSERS[fmt](doc)
    except (AttributeError, TypeError) as exc:  # --format forced onto a document of another shape
        print(f"error: {name} does not have the shape of a {fmt} report ({exc}); drop --format to auto-detect", file=sys.stderr)
        return 2
    ignored = {i.lower() for i in args.ignore}
    total = len(items)
    # An advisory is one group of ids (a source number and its GHSA, or an id and its aliases); naming any id in the group
    # ignores that advisory, and a package drops out only when every advisory on it is ignored.
    def kept(item: dict) -> bool:
        groups = item.get("_groups") or [[x] for x in item["ids"]]
        return not groups or any(not ({x.lower() for x in g} & ignored) for g in groups)

    items = [i for i in items if kept(i)]
    for i in items:
        i.pop("_groups", None)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    items.sort(key=lambda i: (order[i["severity"]], -len(i["ids"]), i["package"]))
    counts = {s: sum(1 for i in items if i["severity"] == s) for s in SEVERITIES}
    fixable = [i for i in items if i["fixable"]]
    report = {"version": VERSION, "format": fmt, "vulnerable_packages": len(items), "counts": counts, "fixable": len(fixable), "unfixable": len(items) - len(fixable),
              "direct": sum(1 for i in items if i["direct"]), "upgrade_first": [i["package"] for i in items[:5]], "items": items, "fail_on": args.fail_on,
              "ignored_packages": total - len(items)}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        by_sev = ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s])
        print(f"dependency-audit-reader {VERSION}: {fmt}: {len(items)} vulnerable packages" + (f" {by_sev}" if by_sev else "") + f"; {len(fixable)} fixable, {len(items) - len(fixable)} without a fix"
              + (f"; {total - len(items)} ignored" if total - len(items) else ""))
        print(f"{'severity':<9} {'package':<28} {'installed':<16} {'direct':<6} {'fix':<24} advisories")
        for i in items:
            direct = {True: "yes", False: "no", None: "?"}[i["direct"]]
            print(f"{i['severity']:<9} {i['package'][:28]:<28} {str(i['version'])[:16]:<16} {direct:<6} {i['fix'][:24]:<24} {', '.join(i['ids'][:3]) or ('via ' + ', '.join(i.get('via') or ['?']))}  {(i['titles'][0] if i['titles'] else '')[:60]}".rstrip())
        if items:
            print("upgrade first: " + ", ".join(report["upgrade_first"]))
    worst = min((order[i["severity"]] for i in items), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
