#!/usr/bin/env python3
"""Offline security audit of one AWS account from saved read-only `aws` CLI output.

The script never calls AWS. It reads the JSON (and one CSV) files that the skill's collection step saved into a
folder, evaluates the checks below, and prints a table or a JSON report.

Expected files in <folder> (names are fixed; see SKILL.md for the commands that produce them):

  account-summary.json              aws iam get-account-summary
  credential-report.csv             aws iam get-credential-report (Content, base64-decoded)
  password-policy.json              aws iam get-account-password-policy ({} when none is set)
  iam-authorization-details.json    aws iam get-account-authorization-details
  cloudtrail-trails.json            aws cloudtrail describe-trails
  cloudtrail-status-<name>.json     aws cloudtrail get-trail-status --name <arn> (optional, one per trail;
                                    <name> is the part of the trail ARN after the last /)
  s3control-public-access-block.json aws s3control get-public-access-block ({} when none is set)
  s3-buckets.json                   aws s3api list-buckets
  s3-public-access-block/<bucket>.json aws s3api get-public-access-block ({} when none is set)

Regional files live in the folder itself (one region) or in regions/<region>/ (several regions):

  guardduty-detectors.json          aws guardduty list-detectors
  securityhub-hub.json              aws securityhub describe-hub ({} when not enabled)
  ec2-security-groups.json          aws ec2 describe-security-groups
  ec2-vpcs.json                     aws ec2 describe-vpcs
  ec2-network-interfaces.json       aws ec2 describe-network-interfaces
  ec2-ebs-encryption-default.json   aws ec2 get-ebs-encryption-by-default

Checks (id, default severity):
  ROOT-MFA               critical  root user has no MFA
  ROOT-ACCESS-KEYS       critical  root user has active access keys
  CT-MULTI-REGION        high      no multi-region CloudTrail trail
  CT-LOG-VALIDATION      medium    multi-region trail without log file validation
  CT-NOT-LOGGING         high      trail status says logging is stopped
  GD-DISABLED            high      no GuardDuty detector in a region
  SH-DISABLED            medium    Security Hub not enabled in a region
  S3-ACCOUNT-PAB         high      account-level S3 public access block missing or partial
  S3-BUCKET-PAB          medium    bucket without a full public access block (low when the account block is full)
  SG-OPEN-ADMIN          high      security group allows 0.0.0.0/0 or ::/0 to port 22 or 3389
  SG-OPEN-ALL            critical  security group allows 0.0.0.0/0 or ::/0 on all traffic
  IAM-CONSOLE-NO-MFA     high      IAM user with a console password and no MFA
  IAM-KEY-AGE            medium    active access key older than --max-key-age days (default 90)
  IAM-ADMIN-POLICY       high      customer managed or inline policy allows "Action": "*" on "Resource": "*"
  VPC-DEFAULT-IN-USE     medium    default VPC has network interfaces (low when it exists but is empty)
  EBS-DEFAULT-ENCRYPTION medium    EBS encryption by default is off in a region
  IAM-PASSWORD-POLICY    medium    no account password policy, or a weak one

A check whose input file is absent is listed under "not_evaluated", never reported as passing.

Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.parse
from datetime import UTC, date, datetime
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class InputError(Exception):
    pass


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc


def finding(check: str, severity: str, title: str, resource: str, evidence: str, fix: str, region: str = "") -> dict:
    return {"check": check, "severity": severity, "title": title, "resource": resource, "region": region,
            "evidence": evidence, "fix": fix}


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def policy_document(doc):
    """The CLI returns decoded documents; the API returns URL-encoded strings. Accept both."""
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except json.JSONDecodeError:
            return {}
    return doc if isinstance(doc, dict) else {}


def revoke_command(group_id: str, protocol: str, ports: tuple[int, int] | None, cidr: str) -> str:
    """Revoke exactly the rule that was found (IPv6 ranges need --ip-permissions)."""
    range_key = f"Ipv6Ranges=[{{CidrIpv6={cidr}}}]" if ":" in cidr else f"IpRanges=[{{CidrIp={cidr}}}]"
    port_part = f"FromPort={ports[0]},ToPort={ports[1]}," if ports else ""
    return (f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
            f"--ip-permissions 'IpProtocol={protocol},{port_part}{range_key}'")


def parse_date(value: str) -> date | None:
    if not value or value in {"N/A", "not_supported", "no_information"}:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


class Audit:
    def __init__(self, folder: Path, as_of: date, max_key_age: int):
        self.folder = folder
        self.as_of = as_of
        self.max_key_age = max_key_age
        self.findings: list[dict] = []
        self.not_evaluated: list[str] = []
        self.evaluated: list[str] = []
        self.account_id = ""

    def file(self, name: str, base: Path | None = None):
        path = (base or self.folder) / name
        if not path.exists():
            return None
        return load_json(path)

    def skip(self, check: str, missing: str, region: str = "") -> None:
        where = f" ({region})" if region else ""
        self.not_evaluated.append(f"{check}{where}: {missing} not found")

    def add(self, *args, **kwargs) -> None:
        self.findings.append(finding(*args, **kwargs))

    # ---- credential report and root -------------------------------------------------------------------------
    def credential_rows(self) -> list[dict] | None:
        path = self.folder / "credential-report.csv"
        if not path.exists():
            return None
        with path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        if rows and "user" not in rows[0]:
            raise InputError(f"{path}: not a credential report (no 'user' column)")
        return rows

    def check_root(self, rows: list[dict] | None) -> None:
        summary = self.file("account-summary.json")
        smap = (summary or {}).get("SummaryMap", {}) if summary is not None else None
        root = next((r for r in rows or [] if r.get("user") == "<root_account>"), None)
        if root is not None and root.get("arn", "").startswith("arn:aws:iam::"):
            self.account_id = root["arn"].split(":")[4]
        if smap is None and root is None:
            self.skip("ROOT-MFA, ROOT-ACCESS-KEYS", "account-summary.json and credential-report.csv")
            return
        self.evaluated += ["ROOT-MFA", "ROOT-ACCESS-KEYS"]
        mfa_off = (smap is not None and smap.get("AccountMFAEnabled") == 0) or (
            root is not None and root.get("mfa_active", "").lower() == "false")
        if mfa_off:
            ev = "AccountMFAEnabled=0" if smap is not None and smap.get("AccountMFAEnabled") == 0 else "credential report mfa_active=false"
            self.add("ROOT-MFA", "critical", "Root user has no MFA device", "root", ev,
                     "Sign in as root and enable a hardware or passkey MFA device (console only; no CLI command exists)")
        keys_on = (smap is not None and smap.get("AccountAccessKeysPresent") == 1) or (
            root is not None and "true" in {root.get("access_key_1_active", "").lower(), root.get("access_key_2_active", "").lower()})
        if keys_on:
            self.add("ROOT-ACCESS-KEYS", "critical", "Root user has access keys", "root",
                     "AccountAccessKeysPresent=1 or access_key_N_active=true for <root_account>",
                     "Sign in as root, delete the access keys under Security credentials, and use roles instead")

    def check_users(self, rows: list[dict] | None) -> None:
        if rows is None:
            self.skip("IAM-CONSOLE-NO-MFA, IAM-KEY-AGE", "credential-report.csv")
            return
        self.evaluated += ["IAM-CONSOLE-NO-MFA", "IAM-KEY-AGE"]
        for r in rows:
            user = r.get("user", "")
            if user == "<root_account>":
                continue
            if r.get("password_enabled", "").lower() == "true" and r.get("mfa_active", "").lower() == "false":
                self.add("IAM-CONSOLE-NO-MFA", "high", "IAM user can sign in to the console without MFA", r.get("arn", user),
                         f"password_enabled=true, mfa_active=false, password_last_used={r.get('password_last_used', '')}",
                         f"aws iam delete-login-profile --user-name {user}   # or enforce MFA, then move the person to IAM Identity Center")
            for n in ("1", "2"):
                if r.get(f"access_key_{n}_active", "").lower() != "true":
                    continue
                rotated = parse_date(r.get(f"access_key_{n}_last_rotated", ""))
                if rotated is None:
                    continue
                age = (self.as_of - rotated).days
                if age > self.max_key_age:
                    self.add("IAM-KEY-AGE", "medium", f"Access key {n} is {age} days old", r.get("arn", user),
                             f"access_key_{n}_last_rotated={rotated.isoformat()}, last used {r.get(f'access_key_{n}_last_used_date', '')}",
                             f"aws iam list-access-keys --user-name {user}   # then create a new key, switch callers, and "
                             f"aws iam update-access-key --user-name {user} --access-key-id <old-key-id> --status Inactive")

    def check_password_policy(self) -> None:
        data = self.file("password-policy.json")
        if data is None:
            self.skip("IAM-PASSWORD-POLICY", "password-policy.json")
            return
        self.evaluated.append("IAM-PASSWORD-POLICY")
        fix = ("aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers "
               "--require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24")
        policy = data.get("PasswordPolicy")
        if not policy:
            self.add("IAM-PASSWORD-POLICY", "medium", "No account password policy is set", "account", "password-policy.json is empty", fix)
            return
        weak = []
        if int(policy.get("MinimumPasswordLength", 0)) < 14:
            weak.append(f"MinimumPasswordLength={policy.get('MinimumPasswordLength')}")
        for key in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"):
            if not policy.get(key):
                weak.append(f"{key}=false")
        if int(policy.get("PasswordReusePrevention", 0) or 0) < 1:
            weak.append("PasswordReusePrevention unset")
        if weak:
            self.add("IAM-PASSWORD-POLICY", "medium", "Account password policy is weak", "account", ", ".join(weak), fix)

    def check_admin_policies(self) -> None:
        data = self.file("iam-authorization-details.json")
        if data is None:
            self.skip("IAM-ADMIN-POLICY", "iam-authorization-details.json")
            return
        self.evaluated.append("IAM-ADMIN-POLICY")
        docs: list[tuple[str, str, dict]] = []
        for pol in data.get("Policies", []):
            arn = pol.get("Arn", pol.get("PolicyName", "?"))
            if arn.startswith("arn:aws:iam::aws:policy/"):
                continue
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion") or ver.get("VersionId") == pol.get("DefaultVersionId"):
                    docs.append((arn, "managed", policy_document(ver.get("Document"))))
        for kind, list_key, name_key, inline_key in (("user", "UserDetailList", "UserName", "UserPolicyList"),
                                                     ("group", "GroupDetailList", "GroupName", "GroupPolicyList"),
                                                     ("role", "RoleDetailList", "RoleName", "RolePolicyList")):
            for principal in data.get(list_key, []):
                owner = principal.get("Arn", principal.get(name_key, "?"))
                for inline in principal.get(inline_key, []):
                    docs.append((f"{owner} inline:{inline.get('PolicyName', '?')}", f"{kind} inline",
                                 policy_document(inline.get("PolicyDocument"))))
        for name, kind, doc in docs:
            for st in as_list(doc.get("Statement")):
                if not isinstance(st, dict) or st.get("Effect") != "Allow" or "Condition" in st:
                    continue
                if "*" in as_list(st.get("Action")) and "*" in as_list(st.get("Resource")):
                    sid = st.get("Sid", "")
                    self.add("IAM-ADMIN-POLICY", "high", f"{kind} policy grants full administrator access", name,
                             f'Statement {sid or "(no Sid)"}: "Action": "*", "Resource": "*" with no Condition',
                             "Replace with scoped actions (see the iam-least-privilege-review skill); keep full admin "
                             "only on break-glass roles that require MFA")
                    break

    # ---- CloudTrail and S3 -----------------------------------------------------------------------------------
    def check_cloudtrail(self) -> None:
        data = self.file("cloudtrail-trails.json")
        if data is None:
            self.skip("CT-MULTI-REGION, CT-LOG-VALIDATION, CT-NOT-LOGGING", "cloudtrail-trails.json")
            return
        self.evaluated += ["CT-MULTI-REGION", "CT-LOG-VALIDATION", "CT-NOT-LOGGING"]
        trails = data.get("trailList", [])
        multi = [t for t in trails if t.get("IsMultiRegionTrail")]
        if not multi:
            self.add("CT-MULTI-REGION", "high", "No multi-region CloudTrail trail", "account",
                     f"{len(trails)} trail(s), none with IsMultiRegionTrail=true",
                     "aws cloudtrail create-trail --name org-audit --s3-bucket-name <log-bucket> --is-multi-region-trail "
                     "--enable-log-file-validation && aws cloudtrail start-logging --name org-audit")
        for t in multi:
            if not t.get("LogFileValidationEnabled"):
                self.add("CT-LOG-VALIDATION", "medium", "Trail has log file validation off", t.get("TrailARN", t.get("Name", "?")),
                         "LogFileValidationEnabled=false",
                         f"aws cloudtrail update-trail --name {t.get('Name', '<trail>')} --enable-log-file-validation")
        for t in trails:
            # Shadow trails can report an ARN as Name; the collection loop names files after the last ARN segment.
            status = self.file(f"cloudtrail-status-{str(t.get('Name', '')).split('/')[-1]}.json")
            if status is not None and status.get("IsLogging") is False:
                self.add("CT-NOT-LOGGING", "high", "Trail is not logging", t.get("TrailARN", t.get("Name", "?")),
                         "get-trail-status IsLogging=false", f"aws cloudtrail start-logging --name {t.get('Name', '<trail>')}")

    def check_s3(self) -> None:
        acct = self.file("s3control-public-access-block.json")
        account_full = False
        if acct is None:
            self.skip("S3-ACCOUNT-PAB", "s3control-public-access-block.json")
        else:
            self.evaluated.append("S3-ACCOUNT-PAB")
            cfg = acct.get("PublicAccessBlockConfiguration") or {}
            off = [k for k in PAB_KEYS if not cfg.get(k)]
            account_full = not off
            if off:
                self.add("S3-ACCOUNT-PAB", "high", "Account-level S3 public access block is missing or partial", "account",
                         "off: " + ", ".join(off),
                         f"aws s3control put-public-access-block --account-id {self.account_id or '<account-id>'} "
                         "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                         "BlockPublicPolicy=true,RestrictPublicBuckets=true")
        buckets = self.file("s3-buckets.json")
        if buckets is None:
            self.skip("S3-BUCKET-PAB", "s3-buckets.json")
            return
        self.evaluated.append("S3-BUCKET-PAB")
        pab_dir = self.folder / "s3-public-access-block"
        for b in buckets.get("Buckets", []):
            name = b.get("Name", "?")
            path = pab_dir / f"{name}.json"
            if not path.exists():
                self.not_evaluated.append(f"S3-BUCKET-PAB: s3-public-access-block/{name}.json not found")
                continue
            cfg = (load_json(path).get("PublicAccessBlockConfiguration")) or {}
            off = [k for k in PAB_KEYS if not cfg.get(k)]
            if off:
                sev = "low" if account_full else "medium"
                note = " (account-level block is full, so this is defence in depth)" if account_full else ""
                self.add("S3-BUCKET-PAB", sev, "Bucket has no full public access block" + note, f"arn:aws:s3:::{name}",
                         "off: " + ", ".join(off),
                         f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration "
                         "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")

    # ---- regional checks -------------------------------------------------------------------------------------
    def regions(self) -> list[tuple[str, Path]]:
        rdir = self.folder / "regions"
        if rdir.is_dir():
            found = sorted((d.name, d) for d in rdir.iterdir() if d.is_dir())
            if found:
                return found
        return [("", self.folder)]

    def check_regional(self) -> None:
        for region, base in self.regions():
            self.check_guardduty(region, base)
            self.check_securityhub(region, base)
            self.check_security_groups(region, base)
            self.check_default_vpc(region, base)
            self.check_ebs(region, base)

    def check_guardduty(self, region: str, base: Path) -> None:
        data = self.file("guardduty-detectors.json", base)
        if data is None:
            self.skip("GD-DISABLED", "guardduty-detectors.json", region)
            return
        self.evaluated.append("GD-DISABLED")
        if not data.get("DetectorIds"):
            self.add("GD-DISABLED", "high", "GuardDuty is not enabled", "account", "list-detectors returned no DetectorIds",
                     f"aws guardduty create-detector --enable{' --region ' + region if region else ''}   "
                     "# or enable it org-wide from the delegated administrator", region=region)

    def check_securityhub(self, region: str, base: Path) -> None:
        data = self.file("securityhub-hub.json", base)
        if data is None:
            self.skip("SH-DISABLED", "securityhub-hub.json", region)
            return
        self.evaluated.append("SH-DISABLED")
        if not data.get("HubArn"):
            self.add("SH-DISABLED", "medium", "Security Hub is not enabled", "account", "describe-hub returned no HubArn",
                     f"aws securityhub enable-security-hub --enable-default-standards{' --region ' + region if region else ''}",
                     region=region)

    def check_security_groups(self, region: str, base: Path) -> None:
        data = self.file("ec2-security-groups.json", base)
        if data is None:
            self.skip("SG-OPEN-ADMIN, SG-OPEN-ALL", "ec2-security-groups.json", region)
            return
        self.evaluated += ["SG-OPEN-ADMIN", "SG-OPEN-ALL"]
        for sg in data.get("SecurityGroups", []):
            gid = sg.get("GroupId", "?")
            for perm in sg.get("IpPermissions", []):
                cidrs = {r.get("CidrIp") for r in perm.get("IpRanges", [])} | {r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])}
                open_cidrs = sorted(c for c in cidrs if c in OPEN_CIDRS)
                if not open_cidrs:
                    continue
                proto = str(perm.get("IpProtocol", ""))
                cidr = open_cidrs[0]
                if proto == "-1":
                    self.add("SG-OPEN-ALL", "critical", "Security group allows all traffic from the internet",
                             f"{gid} ({sg.get('GroupName', '')})", f"IpProtocol=-1 from {', '.join(open_cidrs)}",
                             revoke_command(gid, "-1", None, cidr), region=region)
                    continue
                if proto not in {"tcp", "6"}:
                    continue
                lo, hi = perm.get("FromPort"), perm.get("ToPort")
                if lo is None or hi is None:
                    continue
                for port, label in ADMIN_PORTS.items():
                    if lo <= port <= hi:
                        self.add("SG-OPEN-ADMIN", "high", f"Security group allows {label} from the internet",
                                 f"{gid} ({sg.get('GroupName', '')})", f"tcp {lo}-{hi} from {', '.join(open_cidrs)}",
                                 revoke_command(gid, "tcp", (lo, hi), cidr) + "   # then use SSM Session Manager or a VPN range", region=region)

    def check_default_vpc(self, region: str, base: Path) -> None:
        vpcs = self.file("ec2-vpcs.json", base)
        if vpcs is None:
            self.skip("VPC-DEFAULT-IN-USE", "ec2-vpcs.json", region)
            return
        self.evaluated.append("VPC-DEFAULT-IN-USE")
        enis = self.file("ec2-network-interfaces.json", base)
        for vpc in vpcs.get("Vpcs", []):
            if not vpc.get("IsDefault"):
                continue
            vid = vpc.get("VpcId", "?")
            if enis is None:
                self.add("VPC-DEFAULT-IN-USE", "low", "Default VPC exists (usage not checked)", vid,
                         "IsDefault=true; ec2-network-interfaces.json not collected",
                         f"aws ec2 describe-network-interfaces --filters Name=vpc-id,Values={vid}", region=region)
                continue
            used = [e.get("NetworkInterfaceId", "?") for e in enis.get("NetworkInterfaces", []) if e.get("VpcId") == vid]
            if used:
                self.add("VPC-DEFAULT-IN-USE", "medium", "Default VPC is in use", vid,
                         f"{len(used)} network interface(s): {', '.join(used[:5])}",
                         "Move the workloads into a purpose-built VPC, then delete the default VPC", region=region)
            else:
                self.add("VPC-DEFAULT-IN-USE", "low", "Default VPC exists but is unused", vid, "IsDefault=true, no network interfaces",
                         f"aws ec2 delete-vpc --vpc-id {vid}   # delete its subnets, internet gateway and route tables first",
                         region=region)

    def check_ebs(self, region: str, base: Path) -> None:
        data = self.file("ec2-ebs-encryption-default.json", base)
        if data is None:
            self.skip("EBS-DEFAULT-ENCRYPTION", "ec2-ebs-encryption-default.json", region)
            return
        self.evaluated.append("EBS-DEFAULT-ENCRYPTION")
        if not data.get("EbsEncryptionByDefault"):
            self.add("EBS-DEFAULT-ENCRYPTION", "medium", "EBS encryption by default is off", "account", "EbsEncryptionByDefault=false",
                     f"aws ec2 enable-ebs-encryption-by-default{' --region ' + region if region else ''}", region=region)

    def run(self) -> dict:
        if not self.folder.is_dir():
            raise InputError(f"{self.folder}: not a directory")
        rows = self.credential_rows()
        self.check_root(rows)
        self.check_users(rows)
        self.check_password_policy()
        self.check_admin_policies()
        self.check_cloudtrail()
        self.check_s3()
        self.check_regional()
        if not self.evaluated:
            raise InputError(f"{self.folder}: no recognised input files (see --help for the expected names)")
        self.findings.sort(key=lambda f: (RANK[f["severity"]], f["check"], f["region"], f["resource"]))
        counts = {s: sum(1 for f in self.findings if f["severity"] == s) for s in SEVERITIES}
        return {"account_id": self.account_id or None, "as_of": self.as_of.isoformat(), "counts": counts,
                "findings": self.findings, "checks_evaluated": sorted(set(self.evaluated)),
                "not_evaluated": self.not_evaluated,
                "note": "Findings come from saved CLI output and need human verification before any change."}


def render_table(report: dict) -> str:
    lines = [f"AWS account audit ({report['account_id'] or 'account id unknown'}), as of {report['as_of']}", ""]
    if not report["findings"]:
        lines.append("No findings in the evaluated checks.")
    else:
        rows = [("SEVERITY", "CHECK", "REGION", "RESOURCE", "FINDING")]
        rows += [(f["severity"].upper(), f["check"], f["region"] or "-", f["resource"][:60], f["title"]) for f in report["findings"]]
        widths = [max(len(r[i]) for r in rows) for i in range(4)]
        for r in rows:
            lines.append("  ".join(r[i].ljust(widths[i]) for i in range(4)) + "  " + r[4])
        lines.append("")
        for i, f in enumerate(report["findings"], 1):
            lines.append(f"{i}. [{f['severity'].upper()}] {f['check']} {f['resource']}")
            lines.append(f"   evidence: {f['evidence']}")
            lines.append(f"   fix (review before running): {f['fix']}")
    lines.append("")
    lines.append("Counts: " + ", ".join(f"{s} {n}" for s, n in report["counts"].items()))
    if report["not_evaluated"]:
        lines.append("Not evaluated (input missing):")
        lines += [f"  - {n}" for n in report["not_evaluated"]]
    lines.append(report["note"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder holding the saved CLI JSON files")
    ap.add_argument("--json", action="store_true", help="print the JSON report instead of the table")
    ap.add_argument("--output", help="also write the JSON report to this path")
    ap.add_argument("--as-of", help="evaluation date YYYY-MM-DD for key age (default: today, UTC)")
    ap.add_argument("--max-key-age", type=int, default=90, help="access key age limit in days (default 90)")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                    help="exit 1 when a finding is at or above this severity (default high)")
    args = ap.parse_args(argv)
    try:
        as_of = date.fromisoformat(args.as_of) if args.as_of else datetime.now(UTC).date()
    except ValueError:
        print(f"error: --as-of must be YYYY-MM-DD, got {args.as_of!r}", file=sys.stderr)
        return 2
    try:
        report = Audit(Path(args.folder), as_of, args.max_key_age).run()
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2) if args.json else render_table(report))
    if args.fail_on == "none":
        return 0
    return 1 if any(RANK[f["severity"]] <= RANK[args.fail_on] for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
