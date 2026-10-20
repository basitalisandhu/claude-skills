# Security Basics

Seven lightweight security skills for everyday development: a secrets scan, an audit report reader, an HTTP security header check, a JWT inspector, a CORS review, an auth flow review and a security review of a diff. Agent and MCP security lives in the agent-security-skills marketplace.

Find this when you search for: OWASP Top 10, npm audit fix, security review of a pull request.

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
| `diff-security-review` | is this PR safe security-wise, pre-merge security pass | `diff_security_scan.py` findings on added lines, read with the code around them |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.

## Sample output

`dependency-audit-reader` on an `npm audit --json` report (npm 7 or later) with a direct, a transitive and an unfixable advisory:

```text
$ python3 "${CLAUDE_PLUGIN_ROOT}/skills/dependency-audit-reader/scripts/audit_reader.py" audit.json
dependency-audit-reader 0.1.0: npm: 3 vulnerable packages critical=2, high=1; 2 fixable, 1 without a fix
severity  package                      installed        direct fix                      advisories
critical  minimist                     <0.2.4           no     no                       1097, GHSA-xvch-5gv4-984h  Prototype Pollution in minimist
critical  mkdirp                       0.4.1 - 0.5.1    yes    yes                      via minimist
high      lodash                       <4.17.21         yes    lodash@4.17.21           1096, GHSA-35jh-r3h4-6jhm  Command Injection in lodash
upgrade first: minimist, mkdirp, lodash
exit 1
```

`--ignore GHSA-35jh-r3h4-6jhm` (or the npm source number `1096`) drops the lodash advisory; a package leaves the list only when every advisory on it is ignored.
