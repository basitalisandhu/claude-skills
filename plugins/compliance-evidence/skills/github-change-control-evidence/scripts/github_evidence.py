#!/usr/bin/env python3
"""Evidence rows for change management and vulnerability management from saved GitHub exports of one repository.

Input folder (file names the skill tells you to save; OWNER/REPO and BRANCH are yours):
  repo.json                    gh api repos/OWNER/REPO
  branch-protection.json       gh api repos/OWNER/REPO/branches/BRANCH/protection
  rules.json                   gh api repos/OWNER/REPO/rules/branches/BRANCH   (optional: rulesets in effect)
  vulnerability-alerts.http    gh api -i repos/OWNER/REPO/vulnerability-alerts   (status line: 204 on, 404 off)
  dependabot-alerts.json       gh api --paginate --slurp "repos/OWNER/REPO/dependabot/alerts?state=open&per_page=100"
  secret-scanning-alerts.json  gh api --paginate --slurp "repos/OWNER/REPO/secret-scanning/alerts?state=open&per_page=100"
                               (a plain list or --slurp's list of pages are both accepted)
  pulls-merged.json            gh pr list --repo OWNER/REPO --state merged --base BRANCH --limit 1000
                                 --json number,author,mergedAt,mergedBy,reviewDecision,reviews
  codeowners.json              gh api repos/OWNER/REPO/contents/.github/CODEOWNERS (or CODEOWNERS, docs/CODEOWNERS)
  commits.json                 gh api "repos/OWNER/REPO/commits?sha=BRANCH&per_page=100"

gh api saves the JSON error body when a call fails. A 403 or 401 body (plan limits, missing admin rights) makes the
row not assessable; a 404 that means "switched off" (Branch not protected, CODEOWNERS Not Found, vulnerability alerts
404) makes it contradicted. A missing or empty file is not assessable.

Rows (check id, ISO/IEC 27001:2022 Annex A identifiers, SOC 2 identifiers):
  GH-BRANCH-PROTECTION   A.8.32        CC8.1  the branch has protection or a ruleset in effect
  GH-REQUIRED-REVIEWS    A.8.32        CC8.1  at least min_reviews approving reviews are required
  GH-ADMINS-INCLUDED     A.8.32 A.8.2  CC8.1  protection applies to administrators
  GH-STATUS-CHECKS       A.8.29 A.8.25 CC8.1  named status checks are required
  GH-FORCE-PUSH-BLOCKED  A.8.32        CC8.1  force pushes are not allowed
  GH-PR-APPROVED         A.8.32        CC8.1  every merged pull request in the period has an approval from someone
                                              other than its author (full population of the export)
  GH-CODEOWNERS          A.8.32        CC8.1  a CODEOWNERS file exists
  GH-SIGNED-COMMITS      A.8.32        CC8.1  the share of verified commit signatures is at least min_signed_ratio
  GH-DEPENDABOT-ALERTS   A.8.8         CC7.1  Dependabot alerts are on
  GH-DEPENDABOT-UPDATES  A.8.8         CC7.1  Dependabot security updates are on
  GH-OPEN-VULN-ALERTS    A.8.8         CC7.1  no open critical or high alert is older than its vuln_sla_days limit
  GH-SECRET-SCANNING     A.8.12 A.5.17 CC6.1  secret scanning is on
  GH-PUSH-PROTECTION     A.8.12        CC6.1  secret scanning push protection is on
  GH-OPEN-SECRET-ALERTS  A.8.12 A.5.17 CC6.1  no open secret scanning alert is older than secret_alert_sla_days

Config (YAML or JSON, optional; defaults shown):
  min_reviews: 1
  min_signed_ratio: 1.0             set 0 if your policy does not require signed commits
  vuln_sla_days: {critical: 15, high: 30}
  secret_alert_sla_days: 7
  period: {start: 2026-07-01, end: 2026-09-30}   limits GH-PR-APPROVED to pull requests merged in the period

States: supported, contradicted, not assessable. A supported or contradicted row always cites a file and field.

Exit codes: 0 rows built, 1 a row matched --fail-on, 2 bad input. Nothing here calls GitHub or the network.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    CONTRADICTED,
    DISCLAIMER,
    NOT_ASSESSABLE,
    SUPPORTED,
    InputError,
    add_common_args,
    as_of_datetime,
    cfg_number,
    citation,
    days_between,
    dumps,
    error_body,
    evidence_row,
    fail_exit,
    is_denied,
    load_config,
    load_json,
    parse_dt,
    redact,
    render_rows,
    state_counts,
)

CONFIG_KEYS = {"min_reviews", "min_signed_ratio", "vuln_sla_days", "secret_alert_sla_days", "period"}
CHANGE = {"iso27001": ["A.8.32"], "soc2": ["CC8.1"]}
CTRL = {
    "GH-BRANCH-PROTECTION": CHANGE,
    "GH-REQUIRED-REVIEWS": CHANGE,
    "GH-ADMINS-INCLUDED": {"iso27001": ["A.8.32", "A.8.2"], "soc2": ["CC8.1"]},
    "GH-STATUS-CHECKS": {"iso27001": ["A.8.29", "A.8.25"], "soc2": ["CC8.1"]},
    "GH-FORCE-PUSH-BLOCKED": CHANGE,
    "GH-PR-APPROVED": CHANGE,
    "GH-CODEOWNERS": CHANGE,
    "GH-SIGNED-COMMITS": CHANGE,
    "GH-DEPENDABOT-ALERTS": {"iso27001": ["A.8.8"], "soc2": ["CC7.1"]},
    "GH-DEPENDABOT-UPDATES": {"iso27001": ["A.8.8"], "soc2": ["CC7.1"]},
    "GH-OPEN-VULN-ALERTS": {"iso27001": ["A.8.8"], "soc2": ["CC7.1"]},
    "GH-SECRET-SCANNING": {"iso27001": ["A.8.12", "A.5.17"], "soc2": ["CC6.1"]},
    "GH-PUSH-PROTECTION": {"iso27001": ["A.8.12"], "soc2": ["CC6.1"]},
    "GH-OPEN-SECRET-ALERTS": {"iso27001": ["A.8.12", "A.5.17"], "soc2": ["CC6.1"]},
}


class Folder:
    """Saved exports. read() returns (status, data, error) with status ok, missing, empty or error."""

    def __init__(self, path: str, prefix: str = ""):
        self.path = Path(path)
        if not self.path.is_dir():
            raise InputError(f"{self.path}: not a folder")
        self.prefix = prefix

    def name(self, file: str) -> str:
        return self.prefix + file

    def read(self, file: str):
        p = self.path / file
        if not p.is_file():
            return "missing", None, None
        if file.endswith(".http"):
            text = p.read_text(encoding="utf-8", errors="replace").strip()
            if not text:
                return "empty", None, None
            first = text.splitlines()[0].split()
            if not first or not first[0].upper().startswith("HTTP/") or len(first) < 2 or not first[1].isdigit():
                raise InputError(f"{p}: expected the output of gh api -i (an HTTP status line first)")
            status = int(first[1])
            return "ok", {"status": status}, None
        data = load_json(p)
        if data is None:
            return "empty", None, None
        err = error_body(data)
        if err:
            return "error", data, err
        return "ok", data, None


def na(check: str, statement: str, gap: str) -> dict:
    return evidence_row(check, CTRL[check], NOT_ASSESSABLE, statement, gaps=[gap])


def unreadable(folder: Folder, check: str, statement: str, file: str, status: str, err: dict | None) -> dict:
    if status == "missing":
        return na(check, statement, f"{folder.name(file)} not exported")
    if status == "empty":
        return na(check, statement, f"{folder.name(file)} is empty")
    msg = f"{err.get('status', '')} {err.get('message', '')}".strip()
    why = "GitHub refused the call (plan, permission or feature not available)" if is_denied(err) else "GitHub returned an error"
    return na(check, statement, f"{folder.name(file)}: {why}: {msg}")


# ---- branch protection and rulesets -----------------------------------------------------------------------------

def rule_types(rules) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in rules if isinstance(rules, list) else []:
        if isinstance(r, dict) and r.get("type"):
            out.setdefault(r["type"], r)
    return out


def protection_rows(folder: Folder, cfg: dict) -> list[dict]:
    rows: list[dict] = []
    min_reviews = int(cfg_number(cfg, "min_reviews", 1))
    bp_status, bp, bp_err = folder.read("branch-protection.json")
    r_status, rules, _ = folder.read("rules.json")
    ruleset = rule_types(rules) if r_status == "ok" else {}
    f_bp, f_rules = folder.name("branch-protection.json"), folder.name("rules.json")
    not_protected = bp_status == "error" and "branch not protected" in (bp_err.get("message", "").lower()) and not is_denied(bp_err)

    # GH-BRANCH-PROTECTION
    s = "The branch is protected by branch protection or a ruleset"
    if bp_status == "ok":
        rows.append(evidence_row("GH-BRANCH-PROTECTION", CTRL["GH-BRANCH-PROTECTION"], SUPPORTED, s,
                                 [citation(f_bp, "url", bp.get("url", "present"))]))
    elif ruleset:
        rows.append(evidence_row("GH-BRANCH-PROTECTION", CTRL["GH-BRANCH-PROTECTION"], SUPPORTED, s,
                                 [citation(f_rules, "[].type", sorted(ruleset))]))
    elif not_protected and r_status in ("ok", "missing"):
        gaps = [] if r_status == "ok" else [f"{f_rules} not exported: a ruleset could still protect the branch"]
        state = CONTRADICTED if r_status == "ok" else NOT_ASSESSABLE
        if state == CONTRADICTED:
            rows.append(evidence_row("GH-BRANCH-PROTECTION", CTRL["GH-BRANCH-PROTECTION"], CONTRADICTED, s,
                                     [citation(f_bp, "message", bp_err["message"]), citation(f_rules, "[]", [])]))
        else:
            rows.append(evidence_row("GH-BRANCH-PROTECTION", CTRL["GH-BRANCH-PROTECTION"], NOT_ASSESSABLE, s,
                                     [citation(f_bp, "message", bp_err["message"])], gaps))
    else:
        rows.append(unreadable(folder, "GH-BRANCH-PROTECTION", s, "branch-protection.json", bp_status, bp_err))

    protected = bp_status == "ok"

    # GH-REQUIRED-REVIEWS
    s = f"Merges need at least {min_reviews} approving review(s)"
    if protected:
        n = (bp.get("required_pull_request_reviews") or {}).get("required_approving_review_count")
        if n is None and not bp.get("required_pull_request_reviews"):
            rows.append(evidence_row("GH-REQUIRED-REVIEWS", CTRL["GH-REQUIRED-REVIEWS"], CONTRADICTED, s,
                                     [citation(f_bp, "required_pull_request_reviews", None)]))
        else:
            ok = isinstance(n, int) and n >= min_reviews
            rows.append(evidence_row("GH-REQUIRED-REVIEWS", CTRL["GH-REQUIRED-REVIEWS"], SUPPORTED if ok else CONTRADICTED, s,
                                     [citation(f_bp, "required_pull_request_reviews.required_approving_review_count", n)]))
    elif "pull_request" in ruleset:
        n = (ruleset["pull_request"].get("parameters") or {}).get("required_approving_review_count")
        ok = isinstance(n, int) and n >= min_reviews
        rows.append(evidence_row("GH-REQUIRED-REVIEWS", CTRL["GH-REQUIRED-REVIEWS"], SUPPORTED if ok else CONTRADICTED, s,
                                 [citation(f_rules, "[type=pull_request].parameters.required_approving_review_count", n)]))
    elif not_protected and r_status == "ok":
        rows.append(evidence_row("GH-REQUIRED-REVIEWS", CTRL["GH-REQUIRED-REVIEWS"], CONTRADICTED, s,
                                 [citation(f_bp, "message", bp_err["message"]), citation(f_rules, "[].type", sorted(ruleset))]))
    else:
        rows.append(na("GH-REQUIRED-REVIEWS", s, "no readable branch protection or ruleset export"))

    # GH-ADMINS-INCLUDED
    s = "Branch protection applies to administrators"
    if protected:
        v = (bp.get("enforce_admins") or {}).get("enabled")
        if v is None:
            rows.append(na("GH-ADMINS-INCLUDED", s, f"{f_bp}: enforce_admins not present in the export"))
        else:
            rows.append(evidence_row("GH-ADMINS-INCLUDED", CTRL["GH-ADMINS-INCLUDED"], SUPPORTED if v is True else CONTRADICTED, s,
                                     [citation(f_bp, "enforce_admins.enabled", v)]))
    else:
        rows.append(na("GH-ADMINS-INCLUDED", s, "only branch protection exports show this; rulesets bypass lists need "
                                               "gh api repos/OWNER/REPO/rulesets/ID, which an admin must read"))

    # GH-STATUS-CHECKS
    s = "Named status checks must pass before merge"
    if protected:
        rsc = bp.get("required_status_checks") or {}
        names = list(rsc.get("contexts") or []) or [c.get("context") for c in rsc.get("checks") or [] if isinstance(c, dict)]
        rows.append(evidence_row("GH-STATUS-CHECKS", CTRL["GH-STATUS-CHECKS"], SUPPORTED if names else CONTRADICTED, s,
                                 [citation(f_bp, "required_status_checks.contexts", names)]))
    elif "required_status_checks" in ruleset:
        checks = (ruleset["required_status_checks"].get("parameters") or {}).get("required_status_checks") or []
        names = [c.get("context") for c in checks if isinstance(c, dict)]
        rows.append(evidence_row("GH-STATUS-CHECKS", CTRL["GH-STATUS-CHECKS"], SUPPORTED if names else CONTRADICTED, s,
                                 [citation(f_rules, "[type=required_status_checks].parameters.required_status_checks", names)]))
    elif not_protected and r_status == "ok":
        rows.append(evidence_row("GH-STATUS-CHECKS", CTRL["GH-STATUS-CHECKS"], CONTRADICTED, s,
                                 [citation(f_bp, "message", bp_err["message"]), citation(f_rules, "[].type", sorted(ruleset))]))
    else:
        rows.append(na("GH-STATUS-CHECKS", s, "no readable branch protection or ruleset export"))

    # GH-FORCE-PUSH-BLOCKED
    s = "Force pushes to the branch are blocked"
    if protected:
        v = (bp.get("allow_force_pushes") or {}).get("enabled")
        if v is None:
            rows.append(na("GH-FORCE-PUSH-BLOCKED", s, f"{f_bp}: allow_force_pushes not present in the export"))
        else:
            rows.append(evidence_row("GH-FORCE-PUSH-BLOCKED", CTRL["GH-FORCE-PUSH-BLOCKED"], SUPPORTED if v is False else CONTRADICTED, s,
                                     [citation(f_bp, "allow_force_pushes.enabled", v)]))
    elif ruleset:
        has = "non_fast_forward" in ruleset
        rows.append(evidence_row("GH-FORCE-PUSH-BLOCKED", CTRL["GH-FORCE-PUSH-BLOCKED"], SUPPORTED if has else CONTRADICTED, s,
                                 [citation(f_rules, "[].type", sorted(ruleset))]))
    elif not_protected and r_status == "ok":
        rows.append(evidence_row("GH-FORCE-PUSH-BLOCKED", CTRL["GH-FORCE-PUSH-BLOCKED"], CONTRADICTED, s,
                                 [citation(f_bp, "message", bp_err["message"])]))
    else:
        rows.append(na("GH-FORCE-PUSH-BLOCKED", s, "no readable branch protection or ruleset export"))
    return rows


# ---- pull requests, CODEOWNERS, commits -------------------------------------------------------------------------

def login(obj) -> str:
    return (obj or {}).get("login", "") if isinstance(obj, dict) else ""


def pr_rows(folder: Folder, cfg: dict, people: set[str]) -> tuple[list[dict], dict]:
    s = "Every merged pull request in the period was approved by someone other than its author"
    status, prs, err = folder.read("pulls-merged.json")
    f = folder.name("pulls-merged.json")
    if status != "ok":
        return [unreadable(folder, "GH-PR-APPROVED", s, "pulls-merged.json", status, err)], {}
    if not isinstance(prs, list):
        raise InputError(f"{f}: expected the JSON list printed by gh pr list --json")
    period = cfg.get("period") or {}
    start = parse_dt(str(period["start"]) + "T00:00:00Z") if period.get("start") else None
    end = parse_dt(str(period["end"]) + "T23:59:59Z") if period.get("end") else None
    in_period, unapproved = [], []
    for pr in prs:
        if not isinstance(pr, dict):
            continue
        merged = parse_dt(pr.get("mergedAt"))
        if (start and (merged is None or merged < start)) or (end and (merged is None or merged > end)):
            continue
        author = login(pr.get("author"))
        people.update(x for x in [author, login(pr.get("mergedBy"))] if x)
        approvers = sorted({login(r.get("author")) for r in pr.get("reviews") or []
                            if isinstance(r, dict) and r.get("state") == "APPROVED" and login(r.get("author")) != author})
        people.update(approvers)
        in_period.append(pr.get("number"))
        if not approvers:
            unapproved.append(pr.get("number"))
    population = {"merged_pull_requests": len(in_period), "without_independent_approval": len(unapproved),
                  "period": {"start": str(period.get("start", "")), "end": str(period.get("end", ""))}}
    if not in_period:
        return [na("GH-PR-APPROVED", s, f"{f}: no merged pull requests in the period; nothing to test")], population
    if unapproved:
        row = evidence_row("GH-PR-APPROVED", CTRL["GH-PR-APPROVED"], CONTRADICTED, s,
                           [citation(f, "[].reviews", f"{len(unapproved)} of {len(in_period)} merged pull requests had no approval "
                                     f"from someone other than the author: #{', #'.join(str(n) for n in unapproved[:20])}")])
    else:
        row = evidence_row("GH-PR-APPROVED", CTRL["GH-PR-APPROVED"], SUPPORTED, s,
                           [citation(f, "[].reviews", f"{len(in_period)} of {len(in_period)} merged pull requests had an independent approval")])
    if len(prs) in (30, 100, 1000):
        row["gaps"].append(f"{f} holds exactly {len(prs)} entries, a common --limit value: confirm the export was not cut short")
    return [row], population


def codeowners_row(folder: Folder) -> dict:
    s = "A CODEOWNERS file names reviewers for the code"
    status, data, err = folder.read("codeowners.json")
    f = folder.name("codeowners.json")
    if status == "ok" and isinstance(data, dict) and data.get("path"):
        return evidence_row("GH-CODEOWNERS", CTRL["GH-CODEOWNERS"], SUPPORTED, s, [citation(f, "path", data["path"])])
    if status == "error" and not is_denied(err) and "not found" in err.get("message", "").lower():
        return evidence_row("GH-CODEOWNERS", CTRL["GH-CODEOWNERS"], CONTRADICTED, s, [citation(f, "message", err["message"])])
    if status == "ok":
        return na("GH-CODEOWNERS", s, f"{f}: not a contents API response (no path field)")
    return unreadable(folder, "GH-CODEOWNERS", s, "codeowners.json", status, err)


def signed_row(folder: Folder, cfg: dict, people: set[str]) -> dict:
    ratio_needed = float(cfg_number(cfg, "min_signed_ratio", 1.0))
    s = f"Recent commits reach a verified-signature share of at least {ratio_needed:g} (1 means every commit)"
    status, commits, err = folder.read("commits.json")
    f = folder.name("commits.json")
    if status != "ok":
        return unreadable(folder, "GH-SIGNED-COMMITS", s, "commits.json", status, err)
    if not isinstance(commits, list) or not commits:
        return na("GH-SIGNED-COMMITS", s, f"{f}: no commits in the export")
    verified = 0
    for c in commits:
        if not isinstance(c, dict):
            continue
        people.update(x for x in [login(c.get("author")), login(c.get("committer"))] if x)
        author = ((c.get("commit") or {}).get("author") or {})
        if author.get("name"):
            people.add(author["name"])
        if ((c.get("commit") or {}).get("verification") or {}).get("verified") is True:
            verified += 1
    ratio = verified / len(commits)
    state = SUPPORTED if ratio >= ratio_needed else CONTRADICTED
    return evidence_row("GH-SIGNED-COMMITS", CTRL["GH-SIGNED-COMMITS"], state, s,
                        [citation(f, "[].commit.verification.verified", f"{verified} of {len(commits)} commits verified")])


# ---- vulnerability management and secrets ------------------------------------------------------------------------

def security_rows(folder: Folder, cfg: dict, now: datetime) -> list[dict]:
    rows: list[dict] = []
    s = "Dependabot alerts are switched on"
    status, data, err = folder.read("vulnerability-alerts.http")
    f = folder.name("vulnerability-alerts.http")
    if status == "ok" and data["status"] == 204:
        rows.append(evidence_row("GH-DEPENDABOT-ALERTS", CTRL["GH-DEPENDABOT-ALERTS"], SUPPORTED, s, [citation(f, "status", 204)]))
    elif status == "ok" and data["status"] == 404:
        rows.append(evidence_row("GH-DEPENDABOT-ALERTS", CTRL["GH-DEPENDABOT-ALERTS"], CONTRADICTED, s, [citation(f, "status", 404)]))
    elif status == "ok":
        rows.append(na("GH-DEPENDABOT-ALERTS", s, f"{f}: HTTP {data['status']}; GitHub did not say whether alerts are on"))
    else:
        rows.append(unreadable(folder, "GH-DEPENDABOT-ALERTS", s, "vulnerability-alerts.http", status, err))

    status, repo, err = folder.read("repo.json")
    f = folder.name("repo.json")
    for check, key, s in (("GH-DEPENDABOT-UPDATES", "dependabot_security_updates", "Dependabot security updates are switched on"),
                          ("GH-SECRET-SCANNING", "secret_scanning", "Secret scanning is switched on"),
                          ("GH-PUSH-PROTECTION", "secret_scanning_push_protection", "Secret scanning push protection is switched on")):
        if status != "ok":
            rows.append(unreadable(folder, check, s, "repo.json", status, err))
            continue
        sa = repo.get("security_and_analysis")
        value = ((sa or {}).get(key) or {}).get("status") if isinstance(sa, dict) else None
        if value is None:
            rows.append(na(check, s, f"{f}: security_and_analysis.{key} is not in the export (it is shown only to admins, "
                                     "and only on plans with the feature)"))
        else:
            rows.append(evidence_row(check, CTRL[check], SUPPORTED if value == "enabled" else CONTRADICTED, s,
                                     [citation(f, f"security_and_analysis.{key}.status", value)]))

    sla = cfg.get("vuln_sla_days", {"critical": 15, "high": 30})
    if not isinstance(sla, dict) or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in sla.values()):
        raise InputError("config vuln_sla_days must map severities to non-negative day counts")
    s = "No open critical or high Dependabot alert is older than its remediation limit (" + \
        ", ".join(f"{k} {v} days" for k, v in sla.items()) + ")"
    rows.append(alert_age_row(folder, "GH-OPEN-VULN-ALERTS", s, "dependabot-alerts.json", now,
                              lambda a: str((a.get("security_advisory") or {}).get("severity")
                                             or (a.get("security_vulnerability") or {}).get("severity") or "").lower(),
                              {k.lower(): v for k, v in sla.items()}))
    days = int(cfg_number(cfg, "secret_alert_sla_days", 7))
    s = f"No open secret scanning alert is older than {days} days"
    rows.append(alert_age_row(folder, "GH-OPEN-SECRET-ALERTS", s, "secret-scanning-alerts.json", now, lambda a: "any", {"any": days}))
    return rows


def alert_age_row(folder: Folder, check: str, s: str, file: str, now: datetime, severity_of, limits: dict) -> dict:
    status, alerts, err = folder.read(file)
    f = folder.name(file)
    if status != "ok":
        return unreadable(folder, check, s, file, status, err)
    if not isinstance(alerts, list):
        raise InputError(f"{f}: expected a JSON list of alerts")
    if alerts and all(isinstance(page, list) for page in alerts):  # gh api --paginate --slurp: a list of pages
        alerts = [a for page in alerts for a in page]
    open_alerts = [a for a in alerts if isinstance(a, dict) and a.get("state", "open") == "open"]
    overdue = []
    for a in open_alerts:
        limit = limits.get(severity_of(a))
        age = days_between(a.get("created_at"), now)
        if limit is not None and age is not None and age > limit:
            overdue.append(f"#{a.get('number')} ({severity_of(a)}, {age} days)")
    if overdue:
        return evidence_row(check, CTRL[check], CONTRADICTED, s,
                            [citation(f, "[].created_at", f"{len(overdue)} overdue of {len(open_alerts)} open: {', '.join(overdue[:15])}")])
    return evidence_row(check, CTRL[check], SUPPORTED, s,
                        [citation(f, "[].created_at", f"0 overdue of {len(open_alerts)} open alerts")])


# ---- main -------------------------------------------------------------------------------------------------------

def evaluate(folder_path: str, cfg: dict, now: datetime, prefix: str = "") -> dict:
    folder = Folder(folder_path, prefix)
    people: set[str] = set()
    rows = protection_rows(folder, cfg)
    pr, population = pr_rows(folder, cfg, people)
    rows += pr + [codeowners_row(folder), signed_row(folder, cfg, people)]
    rows += security_rows(folder, cfg, now)
    status, repo, _ = folder.read("repo.json")
    return {"source": "github", "repository": repo.get("full_name", "") if status == "ok" else "",
            "folder": str(folder.path), "as_of": now.strftime("%Y-%m-%d"), "summary": state_counts(rows),
            "population": population, "rows": rows, "disclaimer": DISCLAIMER, "_people": sorted(people)}


def render(report: dict) -> str:
    s = report["summary"]
    pop = report.get("population") or {}
    lines = [f"# GitHub change-control evidence: {report['repository'] or report['folder']}", "", f"> {DISCLAIMER}", "",
             f"Evaluated as of {report['as_of']}. Rows: {s[SUPPORTED]} supported, {s[CONTRADICTED]} contradicted, "
             f"{s[NOT_ASSESSABLE]} not assessable."]
    if pop:
        lines.append(f"Pull request population: {pop['merged_pull_requests']} merged in the period, "
                     f"{pop['without_independent_approval']} without an independent approval.")
    lines += [""] + render_rows(report["rows"]) + [""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="github_evidence.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved gh exports for one repository")
    ap.add_argument("--config", help="thresholds (YAML or JSON)")
    ap.add_argument("--cite-prefix", default="", help="prefix for cited file names, for example github/ to match paths inside a pack")
    ap.add_argument("--out", help="also write the JSON report to this file")
    add_common_args(ap)
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config, CONFIG_KEYS)
        report = evaluate(args.folder, cfg, as_of_datetime(args.as_of), args.cite_prefix)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    people = set(report.pop("_people"))
    if args.redact:
        report = redact(report, people)
        report["redacted"] = True
    if args.out:
        Path(args.out).write_text(dumps(report) + "\n", encoding="utf-8")
    print(dumps(report) if args.json else render(report))
    return fail_exit(report["rows"], args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
