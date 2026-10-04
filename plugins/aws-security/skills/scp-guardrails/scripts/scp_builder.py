#!/usr/bin/env python3
"""Build deny-list service control policies (SCPs) from a small YAML or JSON spec.

Spec keys (all optional; a guardrail is emitted only when its key is set):

  allowed_regions: [ap-southeast-2, us-east-1]     deny requests outside these regions (global services exempt)
  protected_roles: [OrganizationAccountAccessRole]  role names exempt from every guardrail that takes an exemption
  deny_leave_organization: true                     deny organizations:LeaveOrganization
  deny_disable_security_services: true              protect CloudTrail, GuardDuty, Security Hub and AWS Config
  deny_root_user: true                              deny every action by the root user of member accounts
  deny_iam_users_outside: ["111122223333"]          deny IAM user and access key creation outside these account ids
  require_imdsv2: true                              require IMDSv2 on new instances and for role credentials
  deny_public_s3_acls: true                         deny public canned ACLs and changes to the account public access block
  max_policy_chars: 5120                            size limit per document (the AWS SCP limit is 5120)

Each guardrail is one or more statements (see references/scp-catalog.md). Statements are packed in order into as few
documents as fit under the size limit, measured on the compact JSON form (no whitespace), which is what you should
upload. Every document is linted with scp_lint.py before it is written; a lint error stops the build.

Output: scp-01.json, scp-02.json, ... in --out, plus manifest.json listing statements, sizes and the guardrails in
each file. AWS allows at most 5 SCPs attached to one target, including FullAWSAccess, so more than 4 documents is a
warning.

Exit codes: 0 built, 1 lint errors in the generated documents, 2 bad spec.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _miniyaml import YAMLError  # noqa: E402
from _miniyaml import load as yaml_load  # noqa: E402
from scp_lint import compact, lint_policy  # noqa: E402

SCP_LIMIT = 5120
MAX_ATTACHED = 5

# Global and account-level actions exempt from the region guardrail. Based on the example in the AWS Organizations
# documentation ("Deny access to AWS based on the requested AWS Region"); review it against the current page.
GLOBAL_SERVICE_ACTIONS = [
    "a4b:*", "acm:*", "aws-marketplace-management:*", "aws-marketplace:*", "aws-portal:*", "budgets:*", "ce:*",
    "chime:*", "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
    "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*", "health:*", "iam:*",
    "importexport:*", "kms:*", "mobileanalytics:*", "networkmanager:*", "organizations:*", "pricing:*", "route53:*",
    "route53domains:*", "route53-recovery-cluster:*", "route53-recovery-control-config:*",
    "route53-recovery-readiness:*", "s3:GetAccountPublic*", "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints",
    "s3:PutAccountPublic*", "shield:*", "sts:*", "support:*", "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*",
    "wellarchitected:*",
]

SECURITY_SERVICE_ACTIONS = {
    "ProtectCloudTrail": ["cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors", "cloudtrail:StopLogging",
                          "cloudtrail:UpdateTrail"],
    "ProtectGuardDuty": ["guardduty:DeleteDetector", "guardduty:DeleteMembers", "guardduty:DisassociateFromAdministratorAccount",
                         "guardduty:DisassociateFromMasterAccount", "guardduty:DisassociateMembers",
                         "guardduty:StopMonitoringMembers", "guardduty:UpdateDetector"],
    "ProtectSecurityHub": ["securityhub:BatchDisableStandards", "securityhub:DeleteMembers", "securityhub:DisableSecurityHub",
                           "securityhub:DisassociateFromAdministratorAccount", "securityhub:DisassociateFromMasterAccount",
                           "securityhub:DisassociateMembers"],
    "ProtectConfig": ["config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
                      "config:DeleteRetentionConfiguration", "config:StopConfigurationRecorder"],
}

KNOWN_KEYS = {"allowed_regions", "protected_roles", "deny_leave_organization", "deny_disable_security_services",
              "deny_root_user", "deny_iam_users_outside", "require_imdsv2", "deny_public_s3_acls", "max_policy_chars"}


class SpecError(Exception):
    pass


def load_spec(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml_load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        raise SpecError(f"{path}: cannot parse: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError(f"{path}: the spec must be a mapping")
    return data


def validate_spec(spec: dict) -> None:
    unknown = set(spec) - KNOWN_KEYS
    if unknown:
        raise SpecError(f"unknown spec keys: {', '.join(sorted(unknown))}")
    for key in ("allowed_regions", "protected_roles", "deny_iam_users_outside"):
        if key in spec and (not isinstance(spec[key], list) or not all(isinstance(v, str) and v for v in spec[key])):
            raise SpecError(f"{key} must be a list of non-empty strings")
    for acct in spec.get("deny_iam_users_outside", []):
        if not (len(acct) == 12 and acct.isdigit()):
            raise SpecError(f"deny_iam_users_outside: {acct!r} is not a 12-digit account id")
    for role in spec.get("protected_roles", []):
        if "/" in role or ":" in role:
            raise SpecError(f"protected_roles takes role names (optionally with a trailing *), not ARNs or paths: {role!r}")
    if "allowed_regions" in spec and not spec["allowed_regions"]:
        raise SpecError("allowed_regions is empty, which would deny every regional service")


def exemption(spec: dict) -> dict:
    roles = spec.get("protected_roles") or []
    if not roles:
        return {}
    return {"ArnNotLike": {"aws:PrincipalArn": [f"arn:aws:iam::*:role/{r}" for r in roles]}}


def with_condition(statement: dict, condition: dict) -> dict:
    if condition:
        merged = dict(statement.get("Condition", {}))
        for op, kv in condition.items():
            merged.setdefault(op, {}).update(kv)
        statement["Condition"] = merged
    return statement


def build_statements(spec: dict) -> list[tuple[str, dict]]:
    """Return (guardrail name, statement) pairs in a stable order."""
    exempt = exemption(spec)
    out: list[tuple[str, dict]] = []
    if spec.get("deny_leave_organization"):
        out.append(("deny_leave_organization", {"Sid": "DenyLeaveOrganization", "Effect": "Deny",
                                                "Action": "organizations:LeaveOrganization", "Resource": "*"}))
    if spec.get("deny_root_user"):
        out.append(("deny_root_user", {"Sid": "DenyRootUser", "Effect": "Deny", "Action": "*", "Resource": "*",
                                       "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}}))
    if spec.get("deny_disable_security_services"):
        for sid, actions in SECURITY_SERVICE_ACTIONS.items():
            out.append(("deny_disable_security_services",
                        with_condition({"Sid": sid, "Effect": "Deny", "Action": actions, "Resource": "*"}, exempt)))
    if spec.get("allowed_regions"):
        st = {"Sid": "DenyOutsideAllowedRegions", "Effect": "Deny", "NotAction": GLOBAL_SERVICE_ACTIONS, "Resource": "*",
              "Condition": {"StringNotEquals": {"aws:RequestedRegion": spec["allowed_regions"]}}}
        out.append(("allowed_regions", with_condition(st, exempt)))
    if spec.get("deny_iam_users_outside"):
        out.append(("deny_iam_users_outside", {
            "Sid": "DenyIamUsersOutsideIdentityAccount", "Effect": "Deny",
            "Action": ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateUser"], "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:PrincipalAccount": spec["deny_iam_users_outside"]}}}))
    if spec.get("require_imdsv2"):
        out.append(("require_imdsv2", {"Sid": "RequireImdsv2OnLaunch", "Effect": "Deny", "Action": "ec2:RunInstances",
                                       "Resource": "arn:aws:ec2:*:*:instance/*",
                                       "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}}))
        out.append(("require_imdsv2", with_condition({"Sid": "DenyImdsOptionChanges", "Effect": "Deny",
                                                      "Action": "ec2:ModifyInstanceMetadataOptions", "Resource": "*"}, exempt)))
        out.append(("require_imdsv2", {"Sid": "DenyImdsv1RoleCredentials", "Effect": "Deny", "Action": "*", "Resource": "*",
                                       "Condition": {"NumericLessThan": {"ec2:RoleDelivery": "2.0"}}}))
    if spec.get("deny_public_s3_acls"):
        out.append(("deny_public_s3_acls", {
            "Sid": "DenyPublicS3CannedAcls", "Effect": "Deny",
            "Action": ["s3:CreateBucket", "s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"], "Resource": "*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": ["authenticated-read", "public-read", "public-read-write"]}}}))
        out.append(("deny_public_s3_acls", with_condition({"Sid": "ProtectAccountPublicAccessBlock", "Effect": "Deny",
                                                           "Action": "s3:PutAccountPublicAccessBlock", "Resource": "*"}, exempt)))
    return out


def pack(statements: list[tuple[str, dict]], limit: int) -> list[list[tuple[str, dict]]]:
    docs: list[list[tuple[str, dict]]] = []
    for item in statements:
        single = {"Version": "2012-10-17", "Statement": [item[1]]}
        if len(compact(single)) > limit:
            raise SpecError(f"statement {item[1].get('Sid')} alone is {len(compact(single))} chars, over the {limit} limit")
        for doc in docs:
            trial = {"Version": "2012-10-17", "Statement": [s for _, s in doc] + [item[1]]}
            if len(compact(trial)) <= limit:
                doc.append(item)
                break
        else:
            docs.append([item])
    return docs


def build(spec: dict) -> tuple[list[dict], dict]:
    validate_spec(spec)
    limit = int(spec.get("max_policy_chars", SCP_LIMIT))
    statements = build_statements(spec)
    if not statements:
        raise SpecError("the spec enables no guardrail")
    packed = pack(statements, limit)
    documents = [{"Version": "2012-10-17", "Statement": [s for _, s in doc]} for doc in packed]
    manifest = {"limit": limit, "documents": [], "warnings": [], "lint": []}
    for i, (doc, items) in enumerate(zip(documents, packed, strict=True), 1):
        name = f"scp-{i:02d}.json"
        manifest["documents"].append({"file": name, "chars_compact": len(compact(doc)),
                                      "guardrails": sorted({g for g, _ in items}),
                                      "statements": [s.get("Sid") for _, s in items]})
        for issue in lint_policy(doc, limit=limit):
            manifest["lint"].append({"file": name, **issue})
    if len(documents) > MAX_ATTACHED - 1:
        manifest["warnings"].append(f"{len(documents)} documents: AWS allows {MAX_ATTACHED} SCPs per target including "
                                    "FullAWSAccess, so split them across the root and OUs")
    if spec.get("allowed_regions") and not spec.get("protected_roles"):
        manifest["warnings"].append("allowed_regions without protected_roles: no break-glass role can work outside the "
                                    "allowed regions")
    return documents, manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", help="YAML or JSON spec file")
    ap.add_argument("--out", help="directory for scp-NN.json and manifest.json (default: print only)")
    ap.add_argument("--json", action="store_true", help="print the manifest and documents as JSON")
    ap.add_argument("--pretty", action="store_true", help="indent the written documents (size is still measured compact)")
    args = ap.parse_args(argv)
    try:
        documents, manifest = build(load_spec(Path(args.spec)))
    except (SpecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    errors = [i for i in manifest["lint"] if i["level"] == "error"]
    if args.out and not errors:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for meta, doc in zip(manifest["documents"], documents, strict=True):
            text = json.dumps(doc, indent=2) if args.pretty else compact(doc)
            (out / meta["file"]).write_text(text + "\n", encoding="utf-8")
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps({"manifest": manifest, "documents": documents}, indent=2))
    else:
        for meta in manifest["documents"]:
            print(f"{meta['file']}: {meta['chars_compact']}/{manifest['limit']} chars, "
                  f"guardrails: {', '.join(meta['guardrails'])}; statements: {', '.join(meta['statements'])}")
        for w in manifest["warnings"]:
            print(f"warning: {w}")
        for issue in manifest["lint"]:
            print(f"lint {issue['level']}: {issue['file']} {issue['id']} {issue['message']}")
        if args.out and not errors:
            print(f"wrote {len(documents)} document(s) and manifest.json to {args.out}")
        print("Review every document and test it on a non-production OU before attaching it.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
