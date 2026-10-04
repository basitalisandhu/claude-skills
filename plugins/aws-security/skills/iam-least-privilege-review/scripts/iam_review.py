#!/usr/bin/env python3
"""Review IAM policy documents for over-broad grants and privilege-escalation paths, offline.

Inputs (one or more files, any mix):
  * a policy document {"Version": ..., "Statement": [...]}
  * `aws iam get-policy-version` output {"PolicyVersion": {"Document": ...}}
  * `aws iam get-account-authorization-details` output (every customer managed default version and every inline
    policy is reviewed; AWS managed policies are skipped unless --include-aws-managed)

Checks on Allow statements (id, severity):
  IAM-FULL-ADMIN            critical  "Action": "*" on "Resource": "*"
  IAM-PRIVESC               critical  the policy allows every action of a known privilege-escalation path
  IAM-NOTACTION-ALLOW       high      Allow with NotAction (allows everything not listed)
  IAM-PASSROLE-UNSCOPED     high      iam:PassRole on "*" or without an iam:PassedToService condition
  IAM-ASSUMEROLE-ANY        high      sts:AssumeRole (or sts:*) on "Resource": "*"
  IAM-SERVICE-WILDCARD      medium    "<service>:*" action
  IAM-WRITE-ON-ANY-RESOURCE medium    write or permissions-management actions on "Resource": "*" with no Condition
  IAM-NOTRESOURCE-ALLOW     medium    Allow with NotResource
  IAM-WILDCARD-ACTION       low       action wildcard inside a verb, such as "s3:Put*"

The privilege-escalation check uses Allow statements whose Resource contains a wildcard (or that use NotResource);
explicit Deny statements without a Condition on "Resource": "*" remove actions before the check.
Conditions are not evaluated: a path is reported even when a Condition might block it, and the finding says so.

For every document the report includes a suggested_policy: the same statements split into read actions (kept on
"*"), and other actions scoped to <placeholder> ARNs, with iam:PassRole narrowed by iam:PassedToService. It is a
template, not a working policy, until the placeholders are replaced.

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from fnmatch import fnmatchcase
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
READ_PREFIXES = ("get", "list", "describe", "head", "view", "search", "query", "scan", "select", "lookup", "batchget")

# Privilege-escalation paths in IAM, from published research (Rhino Security Labs, "AWS IAM Privilege Escalation
# Methods", 2018, and later public write-ups). Each entry is a set of actions that together let a principal gain
# permissions it was not granted.
PRIVESC_PATHS: list[tuple[str, list[str]]] = [
    ("Create a new version of a managed policy and set it as default", ["iam:CreatePolicyVersion"]),
    ("Switch a managed policy to an older, broader version", ["iam:SetDefaultPolicyVersion"]),
    ("Attach any managed policy to a user", ["iam:AttachUserPolicy"]),
    ("Attach any managed policy to a group", ["iam:AttachGroupPolicy"]),
    ("Attach any managed policy to a role and assume it", ["iam:AttachRolePolicy", "sts:AssumeRole"]),
    ("Write an inline policy on a user", ["iam:PutUserPolicy"]),
    ("Write an inline policy on a group", ["iam:PutGroupPolicy"]),
    ("Write an inline policy on a role and assume it", ["iam:PutRolePolicy", "sts:AssumeRole"]),
    ("Add a user to a privileged group", ["iam:AddUserToGroup"]),
    ("Create access keys for another user", ["iam:CreateAccessKey"]),
    ("Create a console password for another user", ["iam:CreateLoginProfile"]),
    ("Change another user's console password", ["iam:UpdateLoginProfile"]),
    ("Rewrite a role's trust policy and assume it", ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"]),
    ("Launch an instance with a privileged role", ["iam:PassRole", "ec2:RunInstances"]),
    ("Create and invoke a Lambda function with a privileged role",
     ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),
    ("Create a Lambda function with a privileged role triggered by an event source",
     ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"]),
    ("Replace the code of an existing Lambda function and run as its role", ["lambda:UpdateFunctionCode"]),
    ("Create a CloudFormation stack that runs as a privileged role", ["iam:PassRole", "cloudformation:CreateStack"]),
    ("Create a Glue development endpoint with a privileged role", ["iam:PassRole", "glue:CreateDevEndpoint"]),
    ("Add an SSH key to an existing Glue development endpoint", ["glue:UpdateDevEndpoint"]),
    ("Create a Data Pipeline that runs as a privileged role",
     ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"]),
    ("Create a CodeBuild project with a privileged role and run it",
     ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"]),
    ("Create a SageMaker notebook with a privileged role and open it",
     ["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"]),
    ("Run commands on instances and use their instance roles", ["ssm:SendCommand"]),
    ("Run an ECS task with a privileged task role", ["iam:PassRole", "ecs:RunTask"]),
]


class InputError(Exception):
    pass


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def decode(doc):
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except json.JSONDecodeError as exc:
            raise InputError(f"policy document string is not JSON: {exc}") from exc
    return doc


def collect(path: Path, include_aws_managed: bool) -> list[tuple[str, dict]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path}: expected a JSON object")
    if "Statement" in data:
        return [(path.name, data)]
    if isinstance(data.get("PolicyVersion"), dict):
        return [(path.name, decode(data["PolicyVersion"].get("Document")))]
    docs: list[tuple[str, dict]] = []
    if any(k in data for k in ("Policies", "UserDetailList", "RoleDetailList", "GroupDetailList")):
        for pol in data.get("Policies", []):
            arn = pol.get("Arn", pol.get("PolicyName", "?"))
            if arn.startswith("arn:aws:iam::aws:policy/") and not include_aws_managed:
                continue
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion"):
                    docs.append((arn, decode(ver.get("Document"))))
        for list_key, name_key, inline_key in (("UserDetailList", "UserName", "UserPolicyList"),
                                               ("GroupDetailList", "GroupName", "GroupPolicyList"),
                                               ("RoleDetailList", "RoleName", "RolePolicyList")):
            for p in data.get(list_key, []):
                owner = p.get("Arn", p.get(name_key, "?"))
                for inline in p.get(inline_key, []):
                    docs.append((f"{owner} inline:{inline.get('PolicyName', '?')}", decode(inline.get("PolicyDocument"))))
        return docs
    raise InputError(f"{path}: not a policy document, get-policy-version output or authorization details")


def matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def is_read(action: str) -> bool:
    verb = action.split(":", 1)[-1].lower()
    if "*" in verb:
        return verb in {"get*", "list*", "describe*"}
    return verb.startswith(READ_PREFIXES)


def action_service(action: str) -> str:
    return action.split(":", 1)[0].lower() if ":" in action else "*"


def finding(check: str, severity: str, title: str, policy: str, sid: str, evidence: str, suggestion: str) -> dict:
    return {"check": check, "severity": severity, "title": title, "policy": policy, "statement": sid,
            "evidence": evidence, "suggestion": suggestion}


def review_document(name: str, doc: dict) -> tuple[list[dict], dict]:
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise InputError(f"{name}: no Statement")
    findings: list[dict] = []
    allowed_patterns: list[str] = []
    denied_patterns: list[str] = []
    conditional_allow = False
    for st in as_list(doc["Statement"]):
        if isinstance(st, dict) and st.get("Effect") == "Deny" and not st.get("Condition") \
                and as_list(st.get("Resource")) == ["*"]:
            denied_patterns += [str(a) for a in as_list(st.get("Action"))]

    def denied(action: str) -> bool:
        return any(matches(d, action) for d in denied_patterns)

    for idx, st in enumerate(as_list(doc["Statement"])):
        if not isinstance(st, dict):
            continue
        sid = st.get("Sid") or f"#{idx}"
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        has_cond = bool(st.get("Condition"))
        if st.get("Effect") == "Deny":
            continue
        if st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            findings.append(finding("IAM-NOTACTION-ALLOW", "high", "Allow with NotAction grants everything not listed", name,
                                    sid, f"NotAction: {as_list(st['NotAction'])}",
                                    "List the actions the principal needs in Action instead"))
            allowed_patterns.append("*")
            continue
        if "NotResource" in st:
            findings.append(finding("IAM-NOTRESOURCE-ALLOW", "medium", "Allow with NotResource applies to every other "
                                    "resource, including ones created later", name, sid,
                                    f"NotResource: {as_list(st['NotResource'])}", "Name the resources in Resource"))
        any_resource = "*" in resources or "NotResource" in st
        if "NotResource" in st or any("*" in r for r in resources):
            # Only wildcard-resource grants feed the escalation check; "arn:...:user/${aws:username}" style
            # self-service statements do not.
            allowed_patterns += actions
            conditional_allow = conditional_allow or has_cond
        if "*" in actions and "*" in resources:
            findings.append(finding("IAM-FULL-ADMIN", "critical", "Full administrator access", name, sid,
                                    '"Action": "*", "Resource": "*"' + (" with a Condition" if has_cond else ""),
                                    "Replace with the actions the workload uses (generate them from CloudTrail with IAM "
                                    "Access Analyzer policy generation) and keep admin only on break-glass roles"))
        passrole = [a for a in actions if matches(a, "iam:PassRole")]
        if passrole and not denied("iam:PassRole"):
            cond_keys = {k.lower() for kv in (st.get("Condition") or {}).values() if isinstance(kv, dict) for k in kv}
            if any_resource or "iam:passedtoservice" not in cond_keys:
                findings.append(finding("IAM-PASSROLE-UNSCOPED", "high", "iam:PassRole is not scoped", name, sid,
                                        f"actions {passrole}, resources {resources or as_list(st.get('NotResource'))}, "
                                        f"condition keys {sorted(cond_keys) or 'none'}",
                                        "Resource: the specific role ARNs; Condition: StringEquals iam:PassedToService "
                                        "<service>.amazonaws.com"))
        assume = [a for a in actions if matches(a, "sts:AssumeRole")]
        if assume and any_resource and not denied("sts:AssumeRole"):
            findings.append(finding("IAM-ASSUMEROLE-ANY", "high", "Can assume any role that trusts this account", name, sid,
                                    f"actions {assume} on {resources}",
                                    "Resource: the role ARNs this principal needs; add aws:ResourceAccount or "
                                    "aws:ResourceOrgID conditions"))
        for a in actions:
            if a == "*":
                continue
            svc, _, verb = a.partition(":")
            if verb == "*":
                findings.append(finding("IAM-SERVICE-WILDCARD", "medium", f"All actions of {svc}", name, sid, a,
                                        f"List the {svc} actions in use"))
            elif "*" in verb:
                findings.append(finding("IAM-WILDCARD-ACTION", "low", "Action wildcard", name, sid, a,
                                        "Expand to the specific actions; wildcards pick up actions AWS adds later"))
        if any_resource and not has_cond and "*" not in actions:
            # PassRole and AssumeRole have their own checks above.
            write = [a for a in actions if not is_read(a) and not matches(a, "iam:PassRole")
                     and not matches(a, "sts:AssumeRole") or a.endswith(":*")]
            if write:
                findings.append(finding("IAM-WRITE-ON-ANY-RESOURCE", "medium", "Write or permissions actions on every resource",
                                        name, sid, f"{write} on \"*\" with no Condition",
                                        "Scope Resource to ARNs, or add aws:ResourceTag, aws:ResourceAccount or "
                                        "aws:RequestedRegion conditions"))
    for title, path in PRIVESC_PATHS:
        if all(any(matches(p, a) for p in allowed_patterns) and not denied(a) for a in path):
            findings.append(finding("IAM-PRIVESC", "critical", f"Privilege-escalation path: {title}", name, "(policy)",
                                    " + ".join(path) + (" (some Allow statements have Conditions that may block this; "
                                                         "verify)" if conditional_allow else ""),
                                    "Remove one action of the path, or scope it to resources that cannot lead to "
                                    "broader permissions (for example a permissions boundary on created roles)"))
    return findings, suggest(doc)


def scoped_resource(service: str) -> str:
    templates = {"s3": "arn:aws:s3:::<bucket-name>/*", "iam": "arn:aws:iam::<account-id>:role/<role-name>",
                 "sts": "arn:aws:iam::<account-id>:role/<role-name>", "lambda": "arn:aws:lambda:<region>:<account-id>:function:<function-name>",
                 "dynamodb": "arn:aws:dynamodb:<region>:<account-id>:table/<table-name>",
                 "sqs": "arn:aws:sqs:<region>:<account-id>:<queue-name>", "sns": "arn:aws:sns:<region>:<account-id>:<topic-name>",
                 "kms": "arn:aws:kms:<region>:<account-id>:key/<key-id>",
                 "secretsmanager": "arn:aws:secretsmanager:<region>:<account-id>:secret:<secret-name>-*",
                 "ec2": "arn:aws:ec2:<region>:<account-id>:instance/*"}
    return templates.get(service, f"arn:aws:{service}:<region>:<account-id>:<resource>")


def suggest(doc: dict) -> dict:
    out: list[dict] = []
    for idx, st in enumerate(as_list(doc.get("Statement"))):
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or "Action" not in st:
            if isinstance(st, dict):
                out.append(st)
            continue
        sid = st.get("Sid") or f"Statement{idx}"
        actions = [str(a) for a in as_list(st["Action"])]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        if "*" not in resources:
            out.append(st)
            continue
        reads = sorted(a for a in actions if a != "*" and is_read(a))
        writes = [a for a in actions if a not in reads]
        if reads:
            out.append({"Sid": f"{sid}Read", "Effect": "Allow", "Action": reads, "Resource": "*",
                        **({"Condition": st["Condition"]} if st.get("Condition") else {})})
        by_service: dict[str, list[str]] = {}
        for a in writes:
            svc = action_service(a) if ":" in a else "unknown"
            if a == "*" or a.endswith(":*"):
                a = f"<list-the-{svc if a != '*' else 'service'}-actions-in-use>"
            by_service.setdefault(svc, []).append(a)
        for svc, acts in sorted(by_service.items()):
            new = {"Sid": f"{sid}{svc.title().replace('-', '')}Scoped", "Effect": "Allow", "Action": sorted(set(acts)),
                   "Resource": scoped_resource(svc) if svc != "unknown" else "<resource-arns>"}
            cond = dict(st.get("Condition") or {})
            if any(matches(a, "iam:PassRole") for a in acts):
                cond.setdefault("StringEquals", {})["iam:PassedToService"] = "<service>.amazonaws.com"
            if cond:
                new["Condition"] = cond
            out.append(new)
    return {"Version": doc.get("Version", "2012-10-17"), "Statement": out}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="policy JSON files")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--include-aws-managed", action="store_true", help="also review AWS managed policies in authorization details")
    ap.add_argument("--no-suggestions", action="store_true", help="omit suggested policies from the output")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                    help="exit 1 when a finding is at or above this severity (default high)")
    args = ap.parse_args(argv)
    findings: list[dict] = []
    suggestions: dict[str, dict] = {}
    try:
        for f in args.files:
            for name, doc in collect(Path(f), args.include_aws_managed):
                fs, sugg = review_document(name, doc)
                findings += fs
                if fs:
                    suggestions[name] = sugg
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings.sort(key=lambda x: (RANK[x["severity"]], x["policy"], x["check"]))
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    report = {"findings": findings, "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
              "note": "Static review of policy text: SCPs, permissions boundaries, resource policies and session "
                      "policies are not considered. Verify each finding before changing a policy."}
    if not args.no_suggestions:
        report["suggested_policies"] = suggestions
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if not findings:
            print("No findings.")
        for f in findings:
            print(f"{f['rank']:>3}. [{f['severity'].upper()}] {f['check']} {f['policy']} {f['statement']}: {f['title']}")
            print(f"     evidence: {f['evidence']}")
            print(f"     suggestion: {f['suggestion']}")
        print("Counts: " + ", ".join(f"{s} {n}" for s, n in report["counts"].items()))
        if suggestions and not args.no_suggestions:
            print("\nSuggested policies (templates: replace every <placeholder> before use):")
            for name, doc in suggestions.items():
                print(f"--- {name}")
                print(json.dumps(doc, indent=2))
        print(report["note"])
    if args.fail_on == "none":
        return 0
    return 1 if any(RANK[f["severity"]] <= RANK[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
