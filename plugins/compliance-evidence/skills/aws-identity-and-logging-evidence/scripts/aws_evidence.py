#!/usr/bin/env python3
"""Evidence rows for logging, access control and backup from saved aws CLI output of one AWS account.

Input folder (save each command's stderr next to its output as <name>.err, so that "access denied" is never read as
"not configured"; an empty .err means the call succeeded):
  account-summary.json               aws iam get-account-summary
  credential-report.csv              aws iam get-credential-report --query Content --output text | base64 --decode
  password-policy.json               aws iam get-account-password-policy          (NoSuchEntity in .err: no policy)
  cloudtrail-trails.json             aws cloudtrail describe-trails
  cloudtrail-status-<name>.json      aws cloudtrail get-trail-status --name <arn>  (one per trail; <name> is the part
                                     of the trail ARN after the last /)
  s3control-public-access-block.json aws s3control get-public-access-block --account-id <id>
                                     (NoSuchPublicAccessBlockConfiguration in .err: not set)
Regional files, directly in the folder (one region) or in regions/<region>/ (several):
  guardduty-detectors.json           aws guardduty list-detectors
  guardduty-detector-<id>.json       aws guardduty get-detector --detector-id <id>   (optional; Status)
  config-recorders.json              aws configservice describe-configuration-recorders
  config-recorder-status.json        aws configservice describe-configuration-recorder-status
  backup-plans.json                  aws backup list-backup-plans

Rows (check id, ISO/IEC 27001:2022 Annex A identifiers, SOC 2 identifiers):
  AWS-CT-MULTI-REGION   A.8.15        CC7.2       a multi-region CloudTrail trail exists
  AWS-CT-VALIDATION     A.8.15        CC7.2       a multi-region trail has log file validation on
  AWS-CT-LOGGING        A.8.15        CC7.2       every multi-region trail's status says it is logging
  AWS-ROOT-MFA          A.8.5 A.8.2   CC6.1       the root user has MFA
  AWS-ROOT-ACCESS-KEYS  A.8.2         CC6.1       the root user has no access keys
  AWS-CONSOLE-MFA       A.8.5         CC6.1       every IAM user with a console password has MFA
  AWS-ACCESS-KEY-AGE    A.5.17        CC6.1       no active access key is older than max_key_age_days
  AWS-PASSWORD-POLICY   A.5.17        CC6.1       a password policy exists with at least min_password_length characters
  AWS-GUARDDUTY         A.8.16        CC7.2       a GuardDuty detector exists (and is ENABLED when get-detector was saved)
                                                  in every exported region
  AWS-CONFIG-RECORDER   A.8.9         CC7.1       an AWS Config recorder exists and is recording in every exported region
  AWS-S3-ACCOUNT-PAB    A.5.15        CC6.1 CC6.6 all four account-level S3 public access block settings are on
  AWS-BACKUP-PLANS      A.8.13        A1.2        at least one AWS Backup plan exists (none is not assessable, never
                                                  contradicted: backups can be taken in other ways)

Config (YAML or JSON, optional; defaults shown):
  max_key_age_days: 90
  min_password_length: 14
  regions: [us-east-1, eu-west-1]   regions in scope; a listed region with no exported folder is a gap

States: supported, contradicted, not assessable. A supported or contradicted row always cites a file and field.

Exit codes: 0 rows built, 1 a row matched --fail-on, 2 bad input. Nothing here calls AWS or the network.
"""
from __future__ import annotations

import argparse
import csv
import io
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
    evidence_row,
    fail_exit,
    load_config,
    load_json,
    redact,
    render_rows,
    state_counts,
    worst_state,
)

CONFIG_KEYS = {"max_key_age_days", "min_password_length", "regions"}
CTRL = {
    "AWS-CT-MULTI-REGION": {"iso27001": ["A.8.15"], "soc2": ["CC7.2"]},
    "AWS-CT-VALIDATION": {"iso27001": ["A.8.15"], "soc2": ["CC7.2"]},
    "AWS-CT-LOGGING": {"iso27001": ["A.8.15"], "soc2": ["CC7.2"]},
    "AWS-ROOT-MFA": {"iso27001": ["A.8.5", "A.8.2"], "soc2": ["CC6.1"]},
    "AWS-ROOT-ACCESS-KEYS": {"iso27001": ["A.8.2"], "soc2": ["CC6.1"]},
    "AWS-CONSOLE-MFA": {"iso27001": ["A.8.5"], "soc2": ["CC6.1"]},
    "AWS-ACCESS-KEY-AGE": {"iso27001": ["A.5.17"], "soc2": ["CC6.1"]},
    "AWS-PASSWORD-POLICY": {"iso27001": ["A.5.17"], "soc2": ["CC6.1"]},
    "AWS-GUARDDUTY": {"iso27001": ["A.8.16"], "soc2": ["CC7.2"]},
    "AWS-CONFIG-RECORDER": {"iso27001": ["A.8.9"], "soc2": ["CC7.1"]},
    "AWS-S3-ACCOUNT-PAB": {"iso27001": ["A.5.15"], "soc2": ["CC6.1", "CC6.6"]},
    "AWS-BACKUP-PLANS": {"iso27001": ["A.8.13"], "soc2": ["A1.2"]},
}
DENIED = ("accessdenied", "unauthorizedoperation", "not authorized", "unrecognizedclient", "expiredtoken",
          "invalidclienttokenid", "subscriptionrequired", "optinrequired")
ABSENT = ("nosuchentity", "nosuchpublicaccessblockconfiguration")
REGIONAL = ("guardduty-detectors.json", "config-recorders.json", "config-recorder-status.json", "backup-plans.json")


class Folder:
    def __init__(self, path: str, prefix: str = ""):
        self.path = Path(path)
        if not self.path.is_dir():
            raise InputError(f"{self.path}: not a folder")
        self.prefix = prefix

    def name(self, rel: str) -> str:
        return self.prefix + rel

    def read(self, rel: str):
        """Return (status, data, message). Status: ok, missing, empty, denied, absent, error."""
        p = self.path / rel
        err = p.with_suffix(".err")
        err_text = err.read_text(encoding="utf-8", errors="replace").strip() if err.is_file() else ""
        if err_text:
            low = err_text.lower().replace(" ", "")
            if any(k.replace(" ", "") in low for k in DENIED):
                return "denied", None, err_text
            if any(k in low for k in ABSENT):
                return "absent", None, err_text
            return "error", None, err_text
        if not p.is_file():
            return "missing", None, ""
        if rel.endswith(".csv"):
            text = p.read_text(encoding="utf-8-sig", errors="replace")
            if not text.strip():
                return "empty", None, ""
            return "ok", list(csv.DictReader(io.StringIO(text))), ""
        data = load_json(p)
        if data is None:
            return "empty", None, ""
        return "ok", data, ""

    def regions(self, expected: list[str]) -> tuple[dict[str, str], list[str]]:
        """Return ({region: relative folder}, gaps)."""
        found: dict[str, str] = {}
        rdir = self.path / "regions"
        if rdir.is_dir():
            for d in sorted(rdir.iterdir()):
                if d.is_dir():
                    found[d.name] = f"regions/{d.name}/"
        if any((self.path / f).is_file() or (self.path / f).with_suffix(".err").is_file() for f in REGIONAL):
            found.setdefault("(folder root)", "")
        gaps = [f"region {r} is in scope but has no exported folder regions/{r}/" for r in expected if r not in found]
        return found, gaps


def na(check: str, statement: str, gaps: list[str], cites: list[dict] | None = None) -> dict:
    return evidence_row(check, CTRL[check], NOT_ASSESSABLE, statement, cites, gaps)


def unreadable(folder: Folder, check: str, statement: str, rel: str, status: str, msg: str) -> dict:
    f = folder.name(rel)
    text = {"missing": f"{f} not exported", "empty": f"{f} is empty",
            "denied": f"{f}: the collecting role was not allowed to read this: {msg[:200]}",
            "error": f"{f}: the export failed: {msg[:200]}"}.get(status, f"{f}: {status}")
    return na(check, statement, [text])


# ---- CloudTrail -------------------------------------------------------------------------------------------------

def cloudtrail_rows(folder: Folder) -> list[dict]:
    rows: list[dict] = []
    status, data, msg = folder.read("cloudtrail-trails.json")
    f = folder.name("cloudtrail-trails.json")
    statements = {"AWS-CT-MULTI-REGION": "A CloudTrail trail records activity in every region",
                  "AWS-CT-VALIDATION": "A multi-region trail has log file integrity validation on",
                  "AWS-CT-LOGGING": "Every multi-region trail is logging"}
    if status != "ok":
        return [unreadable(folder, c, s, "cloudtrail-trails.json", status, msg) for c, s in statements.items()]
    trails = [t for t in (data.get("trailList") or []) if isinstance(t, dict)] if isinstance(data, dict) else []
    multi = [t for t in trails if t.get("IsMultiRegionTrail") is True]
    names = [t.get("Name") for t in multi]
    rows.append(evidence_row("AWS-CT-MULTI-REGION", CTRL["AWS-CT-MULTI-REGION"], SUPPORTED if multi else CONTRADICTED,
                             statements["AWS-CT-MULTI-REGION"],
                             [citation(f, "trailList[].IsMultiRegionTrail", f"{len(multi)} of {len(trails)} trails: {names}")]))
    if not multi:
        rows.append(evidence_row("AWS-CT-VALIDATION", CTRL["AWS-CT-VALIDATION"], CONTRADICTED, statements["AWS-CT-VALIDATION"],
                                 [citation(f, "trailList[].IsMultiRegionTrail", "no multi-region trail")]))
        rows.append(evidence_row("AWS-CT-LOGGING", CTRL["AWS-CT-LOGGING"], CONTRADICTED, statements["AWS-CT-LOGGING"],
                                 [citation(f, "trailList[].IsMultiRegionTrail", "no multi-region trail")]))
        return rows
    validated = [t.get("Name") for t in multi if t.get("LogFileValidationEnabled") is True]
    rows.append(evidence_row("AWS-CT-VALIDATION", CTRL["AWS-CT-VALIDATION"], SUPPORTED if validated else CONTRADICTED,
                             statements["AWS-CT-VALIDATION"],
                             [citation(f, "trailList[].LogFileValidationEnabled", f"on for {validated or 'none'} of {names}")]))
    states, cites, gaps = [], [], []
    for t in multi:
        tname = str(t.get("TrailARN") or t.get("Name") or "").rsplit("/", 1)[-1]
        rel = f"cloudtrail-status-{tname}.json"
        st, sdata, smsg = folder.read(rel)
        if st != "ok" or not isinstance(sdata, dict) or "IsLogging" not in sdata:
            states.append(NOT_ASSESSABLE)
            gaps.append(unreadable(folder, "AWS-CT-LOGGING", "", rel, st, smsg)["gaps"][0] if st != "ok"
                        else f"{folder.name(rel)}: no IsLogging field")
            continue
        logging_on = sdata["IsLogging"] is True
        states.append(SUPPORTED if logging_on else CONTRADICTED)
        cites.append(citation(folder.name(rel), "IsLogging", sdata["IsLogging"]))
    rows.append(evidence_row("AWS-CT-LOGGING", CTRL["AWS-CT-LOGGING"], worst_state(states), statements["AWS-CT-LOGGING"], cites, gaps))
    return rows


# ---- IAM --------------------------------------------------------------------------------------------------------

def iam_rows(folder: Folder, cfg: dict, now: datetime, people: set[str]) -> list[dict]:
    rows: list[dict] = []
    max_age = int(cfg_number(cfg, "max_key_age_days", 90))
    min_len = int(cfg_number(cfg, "min_password_length", 14))
    s_status, summary, s_msg = folder.read("account-summary.json")
    c_status, report, c_msg = folder.read("credential-report.csv")
    sm = (summary or {}).get("SummaryMap", {}) if s_status == "ok" and isinstance(summary, dict) else {}
    f_sum, f_cred = folder.name("account-summary.json"), folder.name("credential-report.csv")
    users = report if c_status == "ok" else []
    root = next((u for u in users if u.get("user") == "<root_account>"), None)
    for u in users:
        if u.get("user") and u.get("user") != "<root_account>":
            people.add(u["user"])

    s = "The root user has MFA"
    if "AccountMFAEnabled" in sm:
        rows.append(evidence_row("AWS-ROOT-MFA", CTRL["AWS-ROOT-MFA"], SUPPORTED if sm["AccountMFAEnabled"] == 1 else CONTRADICTED, s,
                                 [citation(f_sum, "SummaryMap.AccountMFAEnabled", sm["AccountMFAEnabled"])]))
    elif root is not None:
        rows.append(evidence_row("AWS-ROOT-MFA", CTRL["AWS-ROOT-MFA"], SUPPORTED if root.get("mfa_active") == "true" else CONTRADICTED, s,
                                 [citation(f_cred, "<root_account>.mfa_active", root.get("mfa_active"))]))
    else:
        rows.append(unreadable(folder, "AWS-ROOT-MFA", s, "account-summary.json", s_status, s_msg))

    s = "The root user has no access keys"
    if "AccountAccessKeysPresent" in sm:
        rows.append(evidence_row("AWS-ROOT-ACCESS-KEYS", CTRL["AWS-ROOT-ACCESS-KEYS"],
                                 SUPPORTED if sm["AccountAccessKeysPresent"] == 0 else CONTRADICTED, s,
                                 [citation(f_sum, "SummaryMap.AccountAccessKeysPresent", sm["AccountAccessKeysPresent"])]))
    elif root is not None:
        active = [k for k in ("access_key_1_active", "access_key_2_active") if root.get(k) == "true"]
        rows.append(evidence_row("AWS-ROOT-ACCESS-KEYS", CTRL["AWS-ROOT-ACCESS-KEYS"], CONTRADICTED if active else SUPPORTED, s,
                                 [citation(f_cred, "<root_account>.access_key_1_active", root.get("access_key_1_active")),
                                  citation(f_cred, "<root_account>.access_key_2_active", root.get("access_key_2_active"))]))
    else:
        rows.append(unreadable(folder, "AWS-ROOT-ACCESS-KEYS", s, "account-summary.json", s_status, s_msg))

    s = "Every IAM user with a console password has MFA"
    if c_status != "ok":
        rows.append(unreadable(folder, "AWS-CONSOLE-MFA", s, "credential-report.csv", c_status, c_msg))
    else:
        console = [u for u in users if u.get("user") != "<root_account>" and u.get("password_enabled") == "true"]
        missing = [u["user"] for u in console if u.get("mfa_active") != "true"]
        value = (f"{len(missing)} of {len(console)} console users without MFA: {', '.join(missing)}" if missing
                 else f"0 of {len(console)} console users without MFA")
        rows.append(evidence_row("AWS-CONSOLE-MFA", CTRL["AWS-CONSOLE-MFA"], CONTRADICTED if missing else SUPPORTED, s,
                                 [citation(f_cred, "[].mfa_active", value)]))

    s = f"No active access key is older than {max_age} days"
    if c_status != "ok":
        rows.append(unreadable(folder, "AWS-ACCESS-KEY-AGE", s, "credential-report.csv", c_status, c_msg))
    else:
        old, active_count = [], 0
        for u in users:
            for n in ("1", "2"):
                if u.get(f"access_key_{n}_active") != "true":
                    continue
                active_count += 1
                age = days_between(u.get(f"access_key_{n}_last_rotated"), now)
                if age is not None and age > max_age:
                    old.append(f"{u.get('user')} key {n} ({age} days)")
        value = (f"{len(old)} of {active_count} active keys over the limit: {', '.join(old)}" if old
                 else f"0 of {active_count} active keys over the limit")
        rows.append(evidence_row("AWS-ACCESS-KEY-AGE", CTRL["AWS-ACCESS-KEY-AGE"], CONTRADICTED if old else SUPPORTED, s,
                                 [citation(f_cred, "[].access_key_N_last_rotated", value)]))

    s = f"An IAM password policy requires at least {min_len} characters"
    p_status, policy, p_msg = folder.read("password-policy.json")
    f_pp = folder.name("password-policy.json")
    if p_status == "absent":
        rows.append(evidence_row("AWS-PASSWORD-POLICY", CTRL["AWS-PASSWORD-POLICY"], CONTRADICTED, s,
                                 [citation(folder.name("password-policy.err"), "error", p_msg[:200])]))
    elif p_status == "ok" and isinstance(policy, dict) and isinstance(policy.get("PasswordPolicy"), dict):
        n = policy["PasswordPolicy"].get("MinimumPasswordLength")
        ok = isinstance(n, int) and n >= min_len
        rows.append(evidence_row("AWS-PASSWORD-POLICY", CTRL["AWS-PASSWORD-POLICY"], SUPPORTED if ok else CONTRADICTED, s,
                                 [citation(f_pp, "PasswordPolicy.MinimumPasswordLength", n)]))
    elif p_status == "ok":
        rows.append(na("AWS-PASSWORD-POLICY", s, [f"{f_pp}: no PasswordPolicy object; save the .err file so a missing policy "
                                                  "can be told apart from a failed call"]))
    else:
        rows.append(unreadable(folder, "AWS-PASSWORD-POLICY", s, "password-policy.json", p_status, p_msg))
    return rows


# ---- regional services and S3 -----------------------------------------------------------------------------------

def regional_rows(folder: Folder, cfg: dict) -> list[dict]:
    expected = cfg.get("regions") or []
    if not isinstance(expected, list) or not all(isinstance(r, str) for r in expected):
        raise InputError("config regions must be a list of region names")
    regions, region_gaps = folder.regions(expected)
    rows: list[dict] = []

    # GuardDuty
    s = "A GuardDuty detector is enabled in every exported region"
    states, cites, gaps = [], [], list(region_gaps)
    for region, base in regions.items():
        st, data, msg = folder.read(base + "guardduty-detectors.json")
        if st != "ok":
            states.append(NOT_ASSESSABLE)
            gaps.append(f"{region}: " + unreadable(folder, "AWS-GUARDDUTY", s, base + "guardduty-detectors.json", st, msg)["gaps"][0])
            continue
        ids = [d for d in (data.get("DetectorIds") or [])] if isinstance(data, dict) else []
        if not ids:
            states.append(CONTRADICTED)
            cites.append(citation(folder.name(base + "guardduty-detectors.json"), "DetectorIds", []))
            continue
        disabled = []
        for d in ids:
            dst, ddata, _ = folder.read(f"{base}guardduty-detector-{d}.json")
            if dst == "ok" and isinstance(ddata, dict) and ddata.get("Status") and ddata["Status"] != "ENABLED":
                disabled.append(d)
                cites.append(citation(folder.name(f"{base}guardduty-detector-{d}.json"), "Status", ddata["Status"]))
        states.append(CONTRADICTED if disabled and len(disabled) == len(ids) else SUPPORTED)
        cites.append(citation(folder.name(base + "guardduty-detectors.json"), "DetectorIds", ids))
    if region_gaps:
        states.append(NOT_ASSESSABLE)
    rows.append(_region_row("AWS-GUARDDUTY", s, states, cites, gaps, regions))

    # AWS Config
    s = "An AWS Config recorder is recording in every exported region"
    states, cites, gaps = [], [], list(region_gaps)
    for region, base in regions.items():
        st, data, msg = folder.read(base + "config-recorders.json")
        if st != "ok":
            states.append(NOT_ASSESSABLE)
            gaps.append(f"{region}: " + unreadable(folder, "AWS-CONFIG-RECORDER", s, base + "config-recorders.json", st, msg)["gaps"][0])
            continue
        recs = data.get("ConfigurationRecorders") or [] if isinstance(data, dict) else []
        if not recs:
            states.append(CONTRADICTED)
            cites.append(citation(folder.name(base + "config-recorders.json"), "ConfigurationRecorders", []))
            continue
        st2, sdata, msg2 = folder.read(base + "config-recorder-status.json")
        if st2 != "ok" or not isinstance(sdata, dict):
            states.append(NOT_ASSESSABLE)
            cites.append(citation(folder.name(base + "config-recorders.json"), "ConfigurationRecorders[].name", [r.get("name") for r in recs]))
            gaps.append(f"{region}: recorder exists but its status was not exported, so recording cannot be confirmed")
            continue
        recording = [r.get("name") for r in sdata.get("ConfigurationRecordersStatus") or [] if r.get("recording") is True]
        states.append(SUPPORTED if recording else CONTRADICTED)
        cites.append(citation(folder.name(base + "config-recorder-status.json"), "ConfigurationRecordersStatus[].recording",
                              f"recording: {recording or 'none'}"))
    if region_gaps:
        states.append(NOT_ASSESSABLE)
    rows.append(_region_row("AWS-CONFIG-RECORDER", s, states, cites, gaps, regions))

    # AWS Backup
    s = "At least one AWS Backup plan exists"
    plans, cites, gaps = [], [], list(region_gaps)
    any_read = False
    for region, base in regions.items():
        st, data, msg = folder.read(base + "backup-plans.json")
        if st != "ok":
            gaps.append(f"{region}: " + unreadable(folder, "AWS-BACKUP-PLANS", s, base + "backup-plans.json", st, msg)["gaps"][0])
            continue
        any_read = True
        names = [p.get("BackupPlanName") for p in (data.get("BackupPlansList") or [])] if isinstance(data, dict) else []
        plans += names
        cites.append(citation(folder.name(base + "backup-plans.json"), "BackupPlansList[].BackupPlanName", names))
    if plans:
        rows.append(evidence_row("AWS-BACKUP-PLANS", CTRL["AWS-BACKUP-PLANS"], SUPPORTED, s, cites,
                                 gaps + ["plans show backups are scheduled; restore tests are not visible in these exports"]))
    elif any_read:
        rows.append(na("AWS-BACKUP-PLANS", s, gaps + ["AWS Backup has no plans in the exported regions; backups may be taken "
                                                      "another way (database automated backups, snapshots), which needs other evidence"], cites))
    else:
        rows.append(na("AWS-BACKUP-PLANS", s, gaps or ["no backup-plans.json exported"]))

    # S3 account public access block (global)
    s = "All four account-level S3 public access block settings are on"
    st, data, msg = folder.read("s3control-public-access-block.json")
    f = folder.name("s3control-public-access-block.json")
    if st == "absent":
        rows.append(evidence_row("AWS-S3-ACCOUNT-PAB", CTRL["AWS-S3-ACCOUNT-PAB"], CONTRADICTED, s,
                                 [citation(folder.name("s3control-public-access-block.err"), "error", msg[:200])]))
    elif st == "ok" and isinstance(data, dict) and isinstance(data.get("PublicAccessBlockConfiguration"), dict):
        cfgv = data["PublicAccessBlockConfiguration"]
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        off = [k for k in keys if cfgv.get(k) is not True]
        rows.append(evidence_row("AWS-S3-ACCOUNT-PAB", CTRL["AWS-S3-ACCOUNT-PAB"], CONTRADICTED if off else SUPPORTED, s,
                                 [citation(f, "PublicAccessBlockConfiguration", {k: cfgv.get(k) for k in keys})]))
    elif st == "ok":
        rows.append(na("AWS-S3-ACCOUNT-PAB", s, [f"{f}: no PublicAccessBlockConfiguration object"]))
    else:
        rows.append(unreadable(folder, "AWS-S3-ACCOUNT-PAB", s, "s3control-public-access-block.json", st, msg))
    return rows


def _region_row(check: str, s: str, states: list[str], cites: list[dict], gaps: list[str], regions: dict) -> dict:
    if not regions:
        return na(check, s, gaps or ["no regional exports found (expected in the folder or regions/<region>/)"])
    state = worst_state(states)
    if state != NOT_ASSESSABLE and not cites:
        state = NOT_ASSESSABLE
    return evidence_row(check, CTRL[check], state, s, cites, gaps)


# ---- main -------------------------------------------------------------------------------------------------------

def evaluate(folder_path: str, cfg: dict, now: datetime, prefix: str = "") -> dict:
    folder = Folder(folder_path, prefix)
    people: set[str] = set()
    rows = cloudtrail_rows(folder) + iam_rows(folder, cfg, now, people) + regional_rows(folder, cfg)
    regions, _ = folder.regions(cfg.get("regions") or [])
    return {"source": "aws", "folder": str(folder.path), "as_of": now.strftime("%Y-%m-%d"),
            "regions": sorted(regions), "summary": state_counts(rows), "rows": rows, "disclaimer": DISCLAIMER,
            "_people": sorted(people)}


def render(report: dict) -> str:
    s = report["summary"]
    lines = [f"# AWS identity, logging and backup evidence: {report['folder']}", "", f"> {DISCLAIMER}", "",
             f"Evaluated as of {report['as_of']}. Regions read: {', '.join(report['regions']) or 'none'}.",
             f"Rows: {s[SUPPORTED]} supported, {s[CONTRADICTED]} contradicted, {s[NOT_ASSESSABLE]} not assessable.", ""]
    lines += render_rows(report["rows"]) + [""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aws_evidence.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder of saved aws CLI output for one account")
    ap.add_argument("--config", help="thresholds and regions in scope (YAML or JSON)")
    ap.add_argument("--cite-prefix", default="", help="prefix for cited file names, for example aws/ to match paths inside a pack")
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
