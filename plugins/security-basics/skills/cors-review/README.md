# cors-review

Review a CORS configuration (allowed origins, Access-Control-Allow-Origin with credentials, methods, headers, preflight caching, exposed headers) against the mistakes that leak data cross-site or break real clients, and write the correct config for Express, nginx or the gateway in use.

Use it when a browser says "blocked by CORS policy", when an API must be callable from another domain, or when a scanner flags a permissive CORS policy.
Not for CSRF defence in general, CSP or other security headers (http-security-headers).

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference files [`references/checklist.md`](references/checklist.md), [`references/snippets.md`](references/snippets.md), and states what it could not check.

## Example requests

- "The browser says blocked by CORS policy when my frontend calls the API, what is wrong?"
- "Is Access-Control-Allow-Origin: * with credentials safe here? Review our config"
- "A scanner flagged our permissive CORS policy, write the correct config for Express"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
