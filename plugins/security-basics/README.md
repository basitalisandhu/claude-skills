# Security Basics

Six lightweight security skills for everyday development: a secrets scan, an audit report reader, an HTTP security header check, a JWT inspector, a CORS review and an auth flow review. Agent and MCP security lives in the agent-security-skills marketplace.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install security-basics@claude-dev-skills
```

Skills then appear as `/security-basics:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `secrets-hygiene` | check for secrets, pre-commit, after a leak | `secrets_scan.py` redacted findings, baseline, rotation steps |
| `dependency-audit-reader` | npm audit or pip-audit fails CI | `audit_reader.py` ranked packages, upgrade and override plan |
| `http-security-headers` | are our headers secure, scanner finding | `headers_check.py` grade and the server configuration |
| `jwt-inspector` | what is in this token, is our JWT setup safe | `jwt_inspect.py` decoded claims (unverified) and findings |
| `cors-review` | CORS error, allow the frontend, permissive policy | checklist findings and the allowlist configuration |
| `auth-flow-review` | design login, review auth, account takeover | per-flow findings with severity and corrected flows |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.
