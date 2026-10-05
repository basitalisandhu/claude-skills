#!/usr/bin/env python3
"""Decide whether a saved Terraform plan is safe to apply under a team's written policy.

Reads the JSON form of a saved plan (`terraform show -json tf.plan`) and a small YAML or JSON policy, and prints
one verdict, allow, ask or block, with a reason per resource and a summary of the planned actions.

Checks (id: verdict when it fires):
  forbidden-destroy   block  a delete or replace of a resource type listed in forbid_destroy (globs allowed)
  protected-name      block  a delete or replace of an address matching protected_names (globs allowed)
  provider-not-allowed block a change through a provider not in allowed_providers (when the list is set)
  max-replace         block  more replacements than max_replace
  max-destroy         block  more deletes (including replacements) than max_destroy
  plan-errored        block  the plan was saved from a failed run ("errored": true)
  destroy             ask    any other delete or replace, unless ask_on_destroy is false
  missing-tags        ask    a create or update of a taggable resource without every key in required_tags
  unknown-tags        ask    tags are only known after apply, so the required keys cannot be checked

Policy keys (all optional): forbid_destroy (list), protected_names (list), allowed_providers (list),
required_tags (list), max_replace (int), max_destroy (int), ask_on_destroy (bool, default true),
tag_types (list of type globs that must carry tags; default: every resource whose planned values hold tags).
Unknown keys are bad input, so a typo cannot switch a rule off silently.

Usage:
    terraform_apply_gate.py PLAN_JSON [--policy FILE] [--json] [--out FILE]

Exit codes: 0 allow, 1 ask or block (a human decides), 2 bad input.
Standard library only. Read-only (writes only --out). No network. It never runs terraform.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _miniyaml import YAMLError, load  # noqa: E402

VERSION = "0.1.0"
POLICY_LISTS = ("forbid_destroy", "protected_names", "allowed_providers", "required_tags", "tag_types")
POLICY_INTS = ("max_replace", "max_destroy")
POLICY_BOOLS = ("ask_on_destroy",)
RANK = {"allow": 0, "ask": 1, "block": 2}


class BadInput(ValueError):
    pass


def load_policy(text: str) -> dict:
    """Parse and check a policy; raise BadInput on unknown keys or wrong types."""
    try:
        data = load(text) if text.strip() else {}
    except YAMLError as exc:
        raise BadInput(f"policy is not valid YAML: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise BadInput("policy must be a mapping of rule names to values")
    known = set(POLICY_LISTS) | set(POLICY_INTS) | set(POLICY_BOOLS)
    unknown = sorted(set(data) - known)
    if unknown:
        raise BadInput(f"unknown policy keys: {', '.join(unknown)} (known: {', '.join(sorted(known))})")
    policy: dict = {"ask_on_destroy": True}
    for key in POLICY_LISTS:
        value = data.get(key, [])
        if value is None:
            value = []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise BadInput(f"policy {key} must be a list of strings")
        policy[key] = value
    for key in POLICY_INTS:
        value = data.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise BadInput(f"policy {key} must be a whole number of 0 or more")
        policy[key] = value
    for key in POLICY_BOOLS:
        if key in data:
            if not isinstance(data[key], bool):
                raise BadInput(f"policy {key} must be true or false")
            policy[key] = data[key]
    return policy


def kind_of(actions: list[str]) -> str:
    """Map Terraform's action list to one word: create, update, delete, replace, read or no-op."""
    acts = list(actions or [])
    if "delete" in acts and "create" in acts:
        return "replace"
    if acts == ["delete"]:
        return "delete"
    if acts == ["create"]:
        return "create"
    if acts == ["update"]:
        return "update"
    if acts == ["read"]:
        return "read"
    return "no-op"


def matches(value: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if fnmatch.fnmatchcase(value, pattern):
            return pattern
    return None


def provider_allowed(provider: str, allowed: list[str]) -> bool:
    for entry in allowed:
        if provider == entry or provider.endswith("/" + entry):
            return True
    return False


def tag_state(change: dict) -> tuple[str, set[str]]:
    """Return ("absent" | "unknown" | "known", keys) for the planned tags of one resource."""
    after = change.get("after") or {}
    after_unknown = change.get("after_unknown") or {}
    for attr in ("tags_all", "tags"):
        if after_unknown.get(attr) is True:
            return "unknown", set()
    if "tags_all" not in after and "tags" not in after:
        return "absent", set()
    keys: set[str] = set()
    for attr in ("tags_all", "tags"):
        value = after.get(attr)
        if isinstance(value, dict):
            keys |= set(value)
    return "known", keys


def evaluate(plan: dict, policy: dict) -> dict:
    if not isinstance(plan, dict) or "resource_changes" not in plan and "planned_values" not in plan:
        raise BadInput("not a saved plan in JSON: no resource_changes (use terraform show -json on a plan file)")
    changes = plan.get("resource_changes") or []
    if not isinstance(changes, list):
        raise BadInput("resource_changes must be a list")
    findings: list[dict] = []
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "read": 0, "no-op": 0}

    def add(rule: str, verdict: str, address: str, reason: str) -> None:
        findings.append({"rule": rule, "verdict": verdict, "address": address, "reason": reason})

    if plan.get("errored") is True:
        add("plan-errored", "block", "(plan)", "the plan was saved from a failed run; fix the errors and plan again")
    for rc in changes:
        if not isinstance(rc, dict) or not isinstance(rc.get("change"), dict):
            raise BadInput("every resource_changes entry needs a change object")
        if rc.get("mode", "managed") != "managed":
            continue
        address = str(rc.get("address", "?"))
        rtype = str(rc.get("type", ""))
        change = rc["change"]
        kind = kind_of(change.get("actions") or [])
        counts[kind] += 1
        if kind in {"no-op", "read"}:
            continue
        provider = str(rc.get("provider_name", ""))
        if policy["allowed_providers"] and not provider_allowed(provider, policy["allowed_providers"]):
            add(
                "provider-not-allowed", "block", address, f"provider {provider or '(none)'} is not in allowed_providers"
            )
        if kind in {"delete", "replace"}:
            why = f" ({rc['action_reason']})" if rc.get("action_reason") else ""
            hit_type = matches(rtype, policy["forbid_destroy"])
            hit_name = matches(address, policy["protected_names"])
            if hit_type:
                add("forbidden-destroy", "block", address, f"{kind} of type {rtype} is forbidden by '{hit_type}'{why}")
            if hit_name:
                add("protected-name", "block", address, f"{kind} of a protected address (matches '{hit_name}'){why}")
            if not hit_type and not hit_name and policy["ask_on_destroy"]:
                add("destroy", "ask", address, f"{kind} of {rtype}{why}")
        if kind in {"create", "update", "replace"} and policy["required_tags"]:
            if policy["tag_types"] and not matches(rtype, policy["tag_types"]):
                continue
            state, keys = tag_state(change)
            if state == "unknown":
                add("unknown-tags", "ask", address, "tags are known only after apply; required keys cannot be checked")
            elif state == "known" or policy["tag_types"]:
                missing = [t for t in policy["required_tags"] if t not in keys]
                if missing:
                    add("missing-tags", "ask", address, f"missing required tags: {', '.join(missing)}")
    replaced = counts["replace"]
    destroyed = counts["delete"] + counts["replace"]
    if policy["max_replace"] is not None and replaced > policy["max_replace"]:
        add("max-replace", "block", "(plan)", f"{replaced} replacements, the policy allows {policy['max_replace']}")
    if policy["max_destroy"] is not None and destroyed > policy["max_destroy"]:
        add(
            "max-destroy",
            "block",
            "(plan)",
            f"{destroyed} deletes or replacements, the policy allows {policy['max_destroy']}",
        )
    findings.sort(key=lambda f: (-RANK[f["verdict"]], f["address"], f["rule"]))
    verdict = "allow"
    for f in findings:
        if RANK[f["verdict"]] > RANK[verdict]:
            verdict = f["verdict"]
    return {
        "version": VERSION,
        "verdict": verdict,
        "summary": counts,
        "terraform_version": plan.get("terraform_version"),
        "findings": findings,
    }


def render(report: dict) -> str:
    c = report["summary"]
    lines = [
        f"terraform-apply-gate {report['version']}: verdict {report['verdict'].upper()}",
        f"plan: {c['create']} to create, {c['update']} to update, {c['replace']} to replace, {c['delete']} to delete,"
        f" {c['no-op']} unchanged",
    ]
    for f in report["findings"]:
        lines.append(f"  [{f['verdict']}] {f['rule']}: {f['address']}: {f['reason']}")
    if not report["findings"]:
        lines.append("  no rule fired")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__
    )
    ap.add_argument("plan", help="plan JSON from `terraform show -json tf.plan > plan.json`")
    ap.add_argument("--policy", help="YAML or JSON policy file (default: ask on every delete or replace)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    try:
        plan_path = Path(args.plan)
        if not plan_path.is_file():
            raise BadInput(f"plan file not found: {plan_path}")
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BadInput(f"plan is not JSON: {exc}") from exc
        policy_text = ""
        if args.policy:
            policy_path = Path(args.policy)
            if not policy_path.is_file():
                raise BadInput(f"policy file not found: {policy_path}")
            policy_text = policy_path.read_text(encoding="utf-8")
        report = evaluate(plan, load_policy(policy_text))
    except BadInput as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report["plan_file"] = Path(args.plan).as_posix()
    text = json.dumps(report, indent=2) + "\n" if args.json else render(report)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0 if report["verdict"] == "allow" else 1


if __name__ == "__main__":
    sys.exit(main())
