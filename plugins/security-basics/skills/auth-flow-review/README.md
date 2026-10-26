# auth-flow-review

Find the weaknesses in an application's whole sign-in, login and session design (passwords, sessions and cookies, OAuth and OIDC with PKCE, state and redirect URIs, MFA, password reset, account enumeration, rate limiting), then report findings by severity with the corrected flow.

Use it when asked "is our login flow secure?", when designing or reviewing authentication, integrating an identity provider, or after an account takeover.
Not for decoding one token (jwt-inspector), in-app authorization rules, or implementing cryptography.

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/checklist.md`](references/checklist.md), [`references/flows.md`](references/flows.md), and states what it could not check.

## Example requests

- "Is our login flow secure? Here is how sessions and password reset work"
- "We are adding OIDC with an identity provider, review the redirect URIs, state and PKCE handling"
- "An attacker took over an account last week, look for weaknesses in the whole sign-in and session design"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
