#!/usr/bin/env python3
"""Generate the ordered runbook for switching off one agent identity, and check it covers every credential and grant.

usage: kill_switch_runbook.py INVENTORY --identity ID [--template FILE] [--gateway TEXT] [--as-of YYYY-MM-DD]
                              [--json] [--out FILE]

INVENTORY is the JSON written by nhi_inventory.py --json; ID is an identity id from it (for example
entra:<appId>, aws-user:<name>, aws-role:<name>, github-app:<slug>, github-deploy-key:<repo>#<id>, register:<id>).

The runbook has six phases, always in this order:
  1 stop new actions   disable the service principal, attach a deny-all policy, suspend the installation
  2 end sessions       revoke role sessions issued before now, remove delegated grants, note token lifetimes
  3 credentials        deactivate or delete every secret, certificate, key and federated credential
  4 access             remove every application permission, policy, group and repository grant
  5 gateway            block the identity at the gateway or proxy it calls through (--gateway or the register)
  6 confirm            read-only audit log queries that show nothing succeeded after the switch-off
Every step pairs a change for a person to run (or a portal path) with a read-only verification command. The script
runs nothing.

Coverage check: every credential and every assignment recorded for the identity in the inventory must be named by a
step. Anything the runbook does not cover is listed under "Not covered" and the exit code is 1. A custom --template
is a Markdown file with the placeholders {{name}}, {{identity}}, {{type}}, {{owners}}, {{generated}}, {{steps}} and
{{coverage}}; a template without {{steps}} leaves everything uncovered.

Key ids appear as their last four characters only, as in the inventory; the verification commands list the full ids
for the person running the step.

Exit codes: 0 runbook covers everything, 1 something is not covered, 2 bad input (identity not in the inventory).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

PHASES = ("stop new actions", "end sessions", "credentials", "access", "gateway", "confirm")
DEFAULT_TEMPLATE = """# Kill switch runbook: {{name}}

Identity `{{identity}}` ({{type}}). Owners: {{owners}}. Prepared {{generated}}.

Run the steps in order and tick each one. A change is for a person to read and run; it is never run by this
runbook. Each verification command only reads. Keep the output of every verification for the incident record.

{{steps}}

## Coverage

{{coverage}}

## Record

- Switch-off started (UTC) and by whom: ____
- Last step verified (UTC) and by whom: ____
- Ticket or incident reference: ____
"""


class InputError(Exception):
    """Bad input: exit code 2."""


def step(phase: str, title: str, change: str, verify: str, covers: list[str] | None = None) -> dict:
    return {"phase": phase, "title": title, "change": change, "verify": verify, "covers": covers or []}


def ending(key) -> str:
    """Placeholder for a full key id the person looks up with the verification command."""
    key = str(key or "")
    return f"<key id ending {key[-4:]}>" if key.startswith("****") and len(key) > 4 else f"<key id: {key or 'unknown'}>"


def cred_ref(c: dict) -> str:
    return f"credential {c.get('kind')} {c.get('key_id')}"


def asg_ref(a: dict) -> str:
    return f"{a.get('kind')} {a.get('name')}"


def gateway_step(ident: dict, gateway: str | None) -> dict:
    where = gateway or (ident.get("refs") or {}).get("gateway") or "<gateway, proxy or MCP gateway this agent calls>"
    return step(
        "gateway",
        f"Block the identity at {where}",
        f"Add a deny rule for `{ident['id']}` (and its client id, key or token) at {where}.",
        f"Read the gateway's rule list and its log for `{ident['id']}`; requests after the switch-off show as denied.",
    )


def entra_steps(ident: dict) -> list[dict]:
    refs = ident.get("refs") or {}
    app_id = refs.get("app_id") or "<appId>"
    sp = refs.get("service_principal_id") or "<service principal object id>"
    creds, asgs = ident.get("credentials") or [], ident.get("assignments") or []
    graph = "https://graph.microsoft.com"
    steps = [
        step(
            PHASES[0],
            "Disable the service principal so no new tokens are issued",
            f"az ad sp update --id {sp} --set accountEnabled=false   (managed identity: remove it from its Azure "
            "resource instead)",
            f"az ad sp show --id {sp} --query accountEnabled   (expect false)",
        ),
        step(
            PHASES[1],
            "Let issued access tokens run out and remove delegated grants",
            "Access tokens already issued stay valid until they expire (usually within an hour, longer for "
            "continuous access evaluation clients); record the disable time. Remove each delegated grant: "
            f"az rest --method DELETE --url {graph}/v1.0/oauth2PermissionGrants/<grant id>",
            f"az rest --method GET --url \"{graph}/v1.0/oauth2PermissionGrants?$filter=clientId eq '{sp}'\""
            "   (expect an empty list)",
            [asg_ref(a) for a in asgs if a.get("kind") == "delegated-permission"],
        ),
    ]
    for c in creds:
        kind, key = c.get("kind"), c.get("key_id")
        if kind in ("client-secret", "certificate"):
            cert = " --cert" if kind == "certificate" else ""
            steps.append(
                step(
                    PHASES[2],
                    f"Delete the {kind} {key} on the app registration",
                    f"az ad app credential delete --id {app_id} --key-id {ending(key)}{cert}",
                    f'az ad app credential list --id {app_id}{cert} --query "[].keyId"',
                    [cred_ref(c)],
                )
            )
        elif kind in ("sp-secret", "sp-certificate"):
            cert = " --cert" if kind == "sp-certificate" else ""
            steps.append(
                step(
                    PHASES[2],
                    f"Delete the {kind} {key} on the service principal",
                    f"az ad sp credential delete --id {sp} --key-id {ending(key)}{cert}",
                    f'az ad sp credential list --id {sp}{cert} --query "[].keyId"',
                    [cred_ref(c)],
                )
            )
        elif kind == "federated":
            steps.append(
                step(
                    PHASES[2],
                    f"Delete the federated credential {key}",
                    f"az ad app federated-credential delete --id {app_id} --federated-credential-id {ending(key)}",
                    f"az ad app federated-credential list --id {app_id}",
                    [cred_ref(c)],
                )
            )
    app_perms = [asg_ref(a) for a in asgs if a.get("kind") == "application-permission"]
    if app_perms:
        steps.append(
            step(
                PHASES[3],
                "Remove the application permissions (app role assignments)",
                f"az rest --method DELETE --url {graph}/v1.0/servicePrincipals/{sp}/appRoleAssignments/"
                "<assignment id>   (one call per assignment)",
                f"az rest --method GET --url {graph}/v1.0/servicePrincipals/{sp}/appRoleAssignments",
                app_perms,
            )
        )
    steps.append(
        step(
            PHASES[3],
            "Check Azure role assignments, which the inventory does not hold",
            f"az role assignment delete --assignee {app_id} --role <role> --scope <scope>",
            f"az role assignment list --assignee {app_id} --all --output table",
        )
    )
    return steps


def entra_confirm(ident: dict) -> dict:
    app_id = (ident.get("refs") or {}).get("app_id") or "<appId>"
    graph = "https://graph.microsoft.com"
    return step(
        PHASES[5],
        "Confirm in the sign-in and audit logs that nothing succeeded after the switch-off",
        "None (read only).",
        f"az rest --method GET --url \"{graph}/beta/auditLogs/signIns?$filter=appId eq '{app_id}' and "
        "signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge <switch-off time>\"; "
        f'az rest --method GET --url "{graph}/v1.0/auditLogs/directoryAudits?$filter=initiatedBy/app/appId eq '
        f"'{app_id}' and activityDateTime ge <switch-off time>\"   (save both and run agent_action_timeline.py)",
    )


def aws_user_steps(ident: dict) -> list[dict]:
    refs = ident.get("refs") or {}
    user = refs.get("user_name") or ident["name"]
    asgs = ident.get("assignments") or []
    steps = [
        step(
            PHASES[0],
            "Attach the AWS managed deny-all policy (it also stops session credentials the user issued)",
            f"aws iam attach-user-policy --user-name {user} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
            f"aws iam list-attached-user-policies --user-name {user}   (expect AWSDenyAll)",
        ),
    ]
    for c in ident.get("credentials") or []:
        key = str(c.get("key_id"))
        steps.append(
            step(
                PHASES[2],
                f"Deactivate access key {key}, delete it once the evidence is kept",
                f"aws iam update-access-key --user-name {user} --access-key-id {ending(key)} "
                "--status Inactive; later aws iam delete-access-key with the same arguments",
                f"aws iam list-access-keys --user-name {user}   (expect Inactive or gone)",
                [cred_ref(c)],
            )
        )
    if refs.get("console_password"):
        steps.append(
            step(
                PHASES[2],
                "Remove the console password",
                f"aws iam delete-login-profile --user-name {user}",
                f"aws iam get-login-profile --user-name {user}   (expect NoSuchEntity)",
            )
        )
    for kind, change, verify in (
        (
            "managed-policy",
            "aws iam detach-user-policy --user-name {u} --policy-arn {ref}",
            "aws iam list-attached-user-policies --user-name {u}",
        ),
        (
            "inline-policy",
            "aws iam delete-user-policy --user-name {u} --policy-name {name}",
            "aws iam list-user-policies --user-name {u}",
        ),
        (
            "group",
            "aws iam remove-user-from-group --user-name {u} --group-name {name}",
            "aws iam list-groups-for-user --user-name {u}",
        ),
    ):
        for a in [a for a in asgs if a.get("kind") == kind]:
            steps.append(
                step(
                    PHASES[3],
                    f"Remove {kind} {a.get('name')}",
                    change.format(u=user, ref=a.get("ref") or "<policy arn>", name=a.get("name")),
                    verify.format(u=user),
                    [asg_ref(a)],
                )
            )
    steps.append(gateway_step(ident, None))
    steps.append(
        step(
            PHASES[5],
            "Confirm in CloudTrail that nothing succeeded after the switch-off",
            "None (read only).",
            f"aws cloudtrail lookup-events --start-time <switch-off time> --lookup-attributes "
            f"AttributeKey=Username,AttributeValue={user} --output json > after.json   (repeat with "
            "AttributeKey=AccessKeyId for each key, then run agent_action_timeline.py)",
        )
    )
    return steps


def aws_role_steps(ident: dict) -> list[dict]:
    refs = ident.get("refs") or {}
    role = refs.get("role_name") or ident["name"]
    asgs = ident.get("assignments") or []
    revoke = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",'
        '"Condition":{"DateLessThan":{"aws:TokenIssueTime":"<switch-off time, ISO 8601 UTC>"}}}]}'
    )
    trust = '{"Version":"2012-10-17","Statement":[]}'
    steps = [
        step(
            PHASES[0],
            "Stop new role assumption by emptying the trust policy (save the current one first)",
            f"aws iam get-role --role-name {role} --query Role.AssumeRolePolicyDocument > trust-before.json; "
            f"aws iam update-assume-role-policy --role-name {role} --policy-document '{trust}'",
            f"aws iam get-role --role-name {role} --query Role.AssumeRolePolicyDocument   (expect no statements)",
        ),
        step(
            PHASES[1],
            "Revoke every session issued before the switch-off (the console's Revoke active sessions)",
            f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions --policy-document "
            f"'{revoke}'",
            f"aws iam get-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions",
        ),
    ]
    for kind, change, verify in (
        (
            "managed-policy",
            "aws iam detach-role-policy --role-name {r} --policy-arn {ref}",
            "aws iam list-attached-role-policies --role-name {r}",
        ),
        (
            "inline-policy",
            "aws iam delete-role-policy --role-name {r} --policy-name {name}",
            "aws iam list-role-policies --role-name {r}",
        ),
    ):
        for a in [a for a in asgs if a.get("kind") == kind]:
            steps.append(
                step(
                    PHASES[3],
                    f"Remove {kind} {a.get('name')}",
                    change.format(r=role, ref=a.get("ref") or "<policy arn>", name=a.get("name")),
                    verify.format(r=role),
                    [asg_ref(a)],
                )
            )
    steps.append(gateway_step(ident, None))
    steps.append(
        step(
            PHASES[5],
            "Confirm in CloudTrail that nothing succeeded after the switch-off",
            "None (read only).",
            "aws cloudtrail lookup-events --start-time <switch-off time> --lookup-attributes "
            f"AttributeKey=ResourceName,AttributeValue={refs.get('arn') or role} --output json > after.json"
            "   (and the role's session names as Username; then run agent_action_timeline.py)",
        )
    )
    return steps


def github_steps(ident: dict) -> list[dict]:
    refs = ident.get("refs") or {}
    asgs = ident.get("assignments") or []
    if ident.get("type") == "github-deploy-key":
        repo, key_id = refs.get("repository") or "<owner/repo>", refs.get("deploy_key_id") or "<key id>"
        return [
            step(
                PHASES[2],
                f"Delete the deploy key from {repo}",
                f"gh api -X DELETE repos/{repo}/keys/{key_id}",
                f"gh api repos/{repo}/keys --jq '.[].id'   (expect {key_id} gone)",
                [cred_ref(c) for c in ident.get("credentials") or []] + [asg_ref(a) for a in asgs],
            ),
            gateway_step(ident, None),
            step(
                PHASES[5],
                "Confirm in the audit log that the key was removed and not used after",
                "None (read only).",
                f'gh api --paginate "/orgs/{repo.split("/")[0]}/audit-log?phrase=repo:{repo}+created:>=<switch-off '
                'date>" > after.json',
            ),
        ]
    account = refs.get("account") or "<organisation>"
    inst = refs.get("installation_id") or "<installation id>"
    return [
        step(
            PHASES[0],
            "Suspend the app installation (all its tokens stop working)",
            f"Organisation settings > GitHub Apps > {ident['name']} > Configure > Suspend (an organisation owner)",
            f"gh api /orgs/{account}/installations --jq '.installations[] | select(.id=={inst}) | .suspended_at'"
            "   (expect a time)",
            [asg_ref(a) for a in asgs],
        ),
        step(
            PHASES[2],
            "If your organisation owns the app, revoke its private keys and client secrets",
            f"Developer settings > GitHub Apps > {ident['name']} > Private keys: delete each key",
            "Re-open the same page: no private key is listed",
            [cred_ref(c) for c in ident.get("credentials") or []],
        ),
        gateway_step(ident, None),
        step(
            PHASES[5],
            "Confirm in the audit log that nothing ran after the suspension",
            "None (read only).",
            f'gh api --paginate "/orgs/{account}/audit-log?phrase=actor:{ident["name"]}[bot]+created:>=<switch-off '
            'date>" > after.json   (then run agent_action_timeline.py)',
        ),
    ]


def generic_steps(ident: dict) -> list[dict]:
    platform = (ident.get("refs") or {}).get("platform") or "<platform that issued it>"
    return [
        step(
            PHASES[0],
            "Remove the agent or connector from every configuration that starts it",
            "Delete its entry from the MCP client configuration, agent runtime or plugin list it runs from.",
            "Read the configuration back and list the servers or agents it starts; the entry is gone.",
        ),
        step(
            PHASES[2],
            f"Revoke its keys and tokens at {platform}",
            f"Revoke each key or token in {platform}'s console or API (one per credential below).",
            f"List the keys or tokens in {platform}; the revoked ones show as revoked or are gone.",
            [cred_ref(c) for c in ident.get("credentials") or []],
        ),
        step(
            PHASES[3],
            "Withdraw the access it was granted",
            "Remove each declared permission or scope at the system that granted it.",
            "List the grants at that system; none remains for this identity.",
            [asg_ref(a) for a in ident.get("assignments") or []],
        ),
    ]


def plan(ident: dict, gateway: str | None) -> list[dict]:
    kind = str(ident.get("type") or "")
    if kind.startswith("entra"):
        steps = entra_steps(ident) + [gateway_step(ident, gateway), entra_confirm(ident)]
    elif kind == "aws-iam-user":
        steps = aws_user_steps(ident)
    elif kind == "aws-iam-role":
        steps = aws_role_steps(ident)
    elif kind.startswith("github"):
        steps = github_steps(ident)
    else:
        steps = generic_steps(ident) + [
            gateway_step(ident, gateway),
            step(
                PHASES[5],
                "Confirm in the application log that nothing ran after the switch-off",
                "None (read only).",
                "Save the application log from the switch-off time onwards and run agent_action_timeline.py with "
                f"--identity {ident['id'].split(':', 1)[-1]}",
            ),
        ]
    if gateway:
        for s in steps:
            if s["phase"] == "gateway":
                s.update(gateway_step(ident, gateway))
    steps.sort(key=lambda s: PHASES.index(s["phase"]))
    for n, s in enumerate(steps, start=1):
        s["n"] = n
    return steps


def render_steps(steps: list[dict]) -> str:
    out = []
    for s in steps:
        out += [
            f"### Step {s['n']} ({s['phase']}): {s['title']}",
            "",
            f"- [ ] Change: {s['change']}",
            f"- [ ] Verify (read only): `{s['verify']}`",
        ]
        if s["covers"]:
            out.append("- Covers: " + "; ".join(s["covers"]))
        out.append("")
    return "\n".join(out).rstrip()


def build(args) -> tuple[dict, str]:
    try:
        data = json.loads(Path(args.inventory).read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{args.inventory}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{args.inventory}: not valid JSON: {exc}") from exc
    rows = data.get("identities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise InputError(f"{args.inventory}: expected nhi_inventory.py JSON with an identities list")
    ident = next((r for r in rows if isinstance(r, dict) and r.get("id") == args.identity), None)
    if ident is None:
        raise InputError(f"identity {args.identity!r} is not in the inventory")
    template = DEFAULT_TEMPLATE
    if args.template:
        try:
            template = Path(args.template).read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise InputError(f"{args.template}: cannot read: {exc}") from exc
    try:
        generated = date.fromisoformat(args.as_of).isoformat() if args.as_of else date.today().isoformat()
    except ValueError as exc:
        raise InputError(f"--as-of {args.as_of!r} is not YYYY-MM-DD") from exc
    steps = plan(ident, args.gateway)
    needed = [cred_ref(c) for c in ident.get("credentials") or []] + [
        asg_ref(a) for a in ident.get("assignments") or []
    ]
    in_template = "{{steps}}" in template
    covered = {c for s in steps for c in s["covers"]} if in_template else set()
    missing = [n for n in needed if n not in covered]
    coverage = (
        f"{len(needed) - len(missing)} of {len(needed)} credentials and assignments in the inventory are covered."
        + ("" if in_template else " The template has no {{steps}} placeholder.")
        + (
            "\n\nNot covered (add a manual step for each):\n\n" + "\n".join(f"- {m}" for m in missing)
            if missing
            else ""
        )
    )
    values = {
        "{{name}}": str(ident.get("name") or ident["id"]),
        "{{identity}}": ident["id"],
        "{{type}}": str(ident.get("type") or "unknown type"),
        "{{owners}}": ", ".join(ident.get("owners") or []) or "none recorded",
        "{{generated}}": generated,
        "{{steps}}": render_steps(steps),
        "{{coverage}}": coverage,
    }
    text = template
    for key, value in values.items():
        text = text.replace(key, value)
    doc = {
        "identity": ident["id"],
        "type": ident.get("type"),
        "generated": generated,
        "steps": steps,
        "coverage": {"needed": needed, "missing": missing, "template_has_steps": in_template},
    }
    return doc, text if text.endswith("\n") else text + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="kill_switch_runbook.py",
        description="Ordered switch-off runbook for one agent identity from the inventory, with a coverage check.",
        epilog="Exit codes: 0 every credential and assignment is covered, 1 something is not, 2 bad input.",
    )
    ap.add_argument("inventory", help="inventory JSON from nhi_inventory.py --json")
    ap.add_argument("--identity", required=True, help="identity id from the inventory")
    ap.add_argument("--template", help="Markdown template with {{steps}} and the other placeholders")
    ap.add_argument("--gateway", help="name of the gateway or proxy to block the identity at")
    ap.add_argument("--as-of", help="date printed as the preparation date, YYYY-MM-DD (default today)")
    ap.add_argument("--json", action="store_true", help="print the steps and coverage as JSON")
    ap.add_argument("--out", help="write to this file instead of standard output")
    args = ap.parse_args(argv)
    try:
        doc, text = build(args)
    except InputError as exc:
        print(f"kill_switch_runbook.py: {exc}", file=sys.stderr)
        return 2
    output = json.dumps(doc, indent=2) + "\n" if args.json else text
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 1 if doc["coverage"]["missing"] else 0


if __name__ == "__main__":
    sys.exit(main())
