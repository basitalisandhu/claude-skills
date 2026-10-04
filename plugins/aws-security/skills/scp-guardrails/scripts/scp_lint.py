#!/usr/bin/env python3
"""Lint service control policies (SCPs) for common mistakes before they are attached.

Accepts SCP documents as JSON files, or the output of `aws organizations describe-policy` (the Content string is
parsed). Checks (id, level):

  SCP-STRUCTURE           error    not an object, no Statement, a statement without Effect, Action/NotAction or Resource
  SCP-VERSION             warning  Version is not "2012-10-17"
  SCP-SIZE                error    compact JSON (no whitespace) is over the limit (default 5120 characters)
  SCP-PRINCIPAL           error    Principal or NotPrincipal element (SCPs apply to every principal in the account;
                                   scope with aws:PrincipalArn conditions instead)
  SCP-ALLOW-IN-DENY-LIST  warning  Allow statement other than the full allow in a deny-list strategy; it grants nothing
                                   on its own and usually signals a misunderstanding of how SCPs combine
  SCP-ALLOW-NOTACTION     error    Allow with NotAction: allows every action not listed
  SCP-DENY-ALL            error    Deny "*" on "*" with no Condition: blocks everything in the attached accounts
  SCP-DENY-NOTACTION-BARE warning  Deny with NotAction and no Condition: denies every action not listed, everywhere
  SCP-REGION-BLOCKS-GLOBAL error   region deny (aws:RequestedRegion) that uses Action instead of NotAction with "*"
                                   or a service wildcard, so global services such as IAM, STS and Organizations break
  SCP-REGION-GLOBAL-GAPS  warning  region deny whose NotAction list misses core global services
  SCP-NO-EXEMPTION        info     guardrail on security services or regions without an aws:PrincipalArn exemption,
                                   so no break-glass role can act
  SCP-DUPLICATE-SID       warning  two statements share a Sid

Exit codes: 0 no errors (or no issue at or above --fail-on), 1 issues at or above --fail-on, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCP_LIMIT = 5120
LEVELS = ["error", "warning", "info"]
CORE_GLOBALS = ["iam:*", "sts:*", "organizations:*", "support:*", "route53:*", "cloudfront:*", "budgets:*", "health:*"]
SECURITY_PREFIXES = ("cloudtrail:", "guardduty:", "securityhub:", "config:")


def compact(doc) -> str:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def issue(check: str, level: str, message: str, sid: str | None = None) -> dict:
    return {"id": check, "level": level, "sid": sid, "message": message}


def condition_keys(st: dict) -> set[str]:
    keys: set[str] = set()
    cond = st.get("Condition")
    if isinstance(cond, dict):
        for kv in cond.values():
            if isinstance(kv, dict):
                keys |= {k.lower() for k in kv}
    return keys


def is_full_allow(st: dict) -> bool:
    return st.get("Effect") == "Allow" and as_list(st.get("Action")) == ["*"] and as_list(st.get("Resource")) == ["*"] \
        and "Condition" not in st


def lint_policy(doc, limit: int = SCP_LIMIT, strategy: str = "deny-list") -> list[dict]:
    if not isinstance(doc, dict) or "Statement" not in doc:
        return [issue("SCP-STRUCTURE", "error", "policy must be an object with a Statement element")]
    out: list[dict] = []
    if doc.get("Version") != "2012-10-17":
        out.append(issue("SCP-VERSION", "warning", f"Version is {doc.get('Version')!r}; use \"2012-10-17\""))
    size = len(compact(doc))
    if size > limit:
        out.append(issue("SCP-SIZE", "error", f"{size} characters compact, over the {limit} limit; split the policy"))
    seen: dict[str, int] = {}
    for idx, st in enumerate(as_list(doc["Statement"])):
        if not isinstance(st, dict):
            out.append(issue("SCP-STRUCTURE", "error", f"statement {idx} is not an object"))
            continue
        sid = st.get("Sid") or f"#{idx}"
        if st.get("Sid"):
            if st["Sid"] in seen:
                out.append(issue("SCP-DUPLICATE-SID", "warning", f"Sid {st['Sid']!r} is used more than once", sid))
            seen[st["Sid"]] = idx
        effect = st.get("Effect")
        if effect not in {"Allow", "Deny"}:
            out.append(issue("SCP-STRUCTURE", "error", f"Effect must be Allow or Deny, got {effect!r}", sid))
            continue
        if ("Action" in st) == ("NotAction" in st):
            out.append(issue("SCP-STRUCTURE", "error", "exactly one of Action or NotAction is required", sid))
            continue
        if "Resource" not in st and "NotResource" not in st:
            out.append(issue("SCP-STRUCTURE", "error", "Resource is required", sid))
        if "Principal" in st or "NotPrincipal" in st:
            out.append(issue("SCP-PRINCIPAL", "error", "SCPs do not take Principal or NotPrincipal; use a Condition on "
                                                       "aws:PrincipalArn", sid))
        has_cond = bool(st.get("Condition"))
        actions = [a.lower() for a in as_list(st.get("Action"))]
        not_actions = [a.lower() for a in as_list(st.get("NotAction"))]
        if effect == "Allow":
            if not_actions:
                out.append(issue("SCP-ALLOW-NOTACTION", "error", "Allow with NotAction allows every action not listed; "
                                                                 "list the allowed actions instead", sid))
            elif strategy == "deny-list" and not is_full_allow(st):
                out.append(issue("SCP-ALLOW-IN-DENY-LIST", "warning",
                                 "Allow statement in a deny-list SCP: it does not grant anything by itself (IAM policies "
                                 "grant) and does not restrict anything (only Deny does); remove it or switch to an "
                                 "allow-list strategy deliberately", sid))
            continue
        # Deny statements from here on.
        resources = as_list(st.get("Resource"))
        if actions == ["*"] and resources == ["*"] and not has_cond:
            out.append(issue("SCP-DENY-ALL", "error", "Deny * on * without a Condition blocks every action in the "
                                                      "attached accounts", sid))
        if not_actions and not has_cond:
            out.append(issue("SCP-DENY-NOTACTION-BARE", "warning", "Deny with NotAction and no Condition denies every "
                                                                   "action not listed, in every region", sid))
        keys = condition_keys(st)
        if "aws:requestedregion" in keys:
            if actions:
                broad = [a for a in actions if a == "*" or (a.endswith(":*") and a.split(":")[0] in
                         {g.split(":")[0] for g in CORE_GLOBALS})]
                if broad:
                    out.append(issue("SCP-REGION-BLOCKS-GLOBAL", "error",
                                     f"region deny uses Action {', '.join(broad)}: global services (IAM, STS, "
                                     "Organizations, Route 53, CloudFront, Support) are served from us-east-1 and will "
                                     "be denied; use NotAction with the global service list", sid))
            else:
                missing = [g for g in CORE_GLOBALS if g not in not_actions]
                if missing:
                    out.append(issue("SCP-REGION-GLOBAL-GAPS", "warning",
                                     f"region deny NotAction list misses {', '.join(missing)}", sid))
            if "aws:principalarn" not in keys:
                out.append(issue("SCP-NO-EXEMPTION", "info", "region deny has no aws:PrincipalArn exemption for a "
                                                             "break-glass role", sid))
        elif any(a.startswith(SECURITY_PREFIXES) for a in actions) and "aws:principalarn" not in keys:
            out.append(issue("SCP-NO-EXEMPTION", "info", "security-service guardrail has no aws:PrincipalArn exemption; "
                                                         "even the security team's role cannot change these settings", sid))
    return out


def load_policy(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("Policy"), dict) and "Content" in data["Policy"]:
        content = data["Policy"]["Content"]
        try:
            return json.loads(content) if isinstance(content, str) else content
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: Policy.Content is not JSON: {exc}") from exc
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="SCP JSON files (or describe-policy output)")
    ap.add_argument("--limit", type=int, default=SCP_LIMIT, help="size limit in characters (default 5120)")
    ap.add_argument("--strategy", choices=["deny-list", "allow-list"], default="deny-list",
                    help="SCP strategy in use (default deny-list)")
    ap.add_argument("--fail-on", choices=LEVELS, default="error", help="exit 1 at or above this level (default error)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    results = []
    for f in args.files:
        try:
            doc = load_policy(Path(f))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        results.append({"file": f, "chars_compact": len(compact(doc)), "issues": lint_policy(doc, args.limit, args.strategy)})
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['file']}: {r['chars_compact']}/{args.limit} chars, {len(r['issues'])} issue(s)")
            for i in r["issues"]:
                print(f"  {i['level']:<7} {i['id']:<24} {i['sid'] or '-':<34} {i['message']}")
    threshold = LEVELS.index(args.fail_on)
    return 1 if any(LEVELS.index(i["level"]) <= threshold for r in results for i in r["issues"]) else 0


if __name__ == "__main__":
    sys.exit(main())
