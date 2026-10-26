# http-security-headers

Grade the security headers in a saved HTTP response (HSTS, CSP, nosniff, frame protection, Referrer-Policy, Permissions-Policy, cookie flags, disclosure, caching) with a bundled script, then write the header config for nginx, the server or the framework.

Use it when asked "are our security headers ok?", to check the headers in a response, to fix a scanner finding such as missing HSTS, or to set headers for a new app.
Not for fetching live sites, a strict CSP for a large single-page app, or a CORS setup (cors-review).

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/security-basics/skills/http-security-headers/scripts/headers_check.py tests/fixtures/http-security-headers/response.txt
```

Inside Claude Code the skill runs `headers_check.py` from `${CLAUDE_PLUGIN_ROOT}/skills/http-security-headers/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/http-security-headers/` (synthetic data):

<!-- sample: --lines=30 plugins/security-basics/skills/http-security-headers/scripts/headers_check.py tests/fixtures/http-security-headers/response.txt -->
```text
http-security-headers 0.1.0: grade F, 18 findings critical=1, high=4, medium=4, low=7, info=2 (HTTP/1.1 200 OK)
  [critical] HDR-009 Access-Control-Allow-Origin: Wildcard origin with credentials
      fix: Echo an allowlisted origin instead of *, or drop Allow-Credentials.
  [high    ] HDR-002 Content-Security-Policy: Missing
      fix: Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
  [high    ] HDR-007 Set-Cookie: Cookie session without Secure
      fix: Add Secure.
  [high    ] HDR-007 Set-Cookie: Cookie session without HttpOnly
      fix: Add HttpOnly unless JavaScript must read it.
  [high    ] HDR-001 Strict-Transport-Security: Missing
      fix: Strict-Transport-Security: max-age=31536000; includeSubDomains
  [medium  ] HDR-013 Cache-Control: Response with cookies or sensitive data is cacheable
      fix: Cache-Control: no-store (and Pragma: no-cache for old proxies).
  [medium  ] HDR-007 Set-Cookie: Cookie session without SameSite
      fix: Add SameSite=Lax (or Strict).
  [medium  ] HDR-003 X-Content-Type-Options: Missing or not nosniff
      fix: X-Content-Type-Options: nosniff
  [medium  ] HDR-004 X-Frame-Options: No clickjacking protection
      fix: Add CSP frame-ancestors 'none' (or 'self'), plus X-Frame-Options: DENY for older browsers.
  [low     ] HDR-012 Content-Type: text/html without charset
      fix: Content-Type: text/html; charset=utf-8
  [low     ] HDR-011 Cross-Origin-Opener-Policy: Missing
      fix: Cross-Origin-Opener-Policy: same-origin
  [low     ] HDR-011 Cross-Origin-Resource-Policy: Missing
      fix: Cross-Origin-Resource-Policy: same-origin (or same-site)
  [low     ] HDR-006 Permissions-Policy: Missing
      fix: Permissions-Policy: camera=(), microphone=(), geolocation=()
  [low     ] HDR-005 Referrer-Policy: Missing
      fix: Referrer-Policy: strict-origin-when-cross-origin
  [low     ] HDR-008 server: Reveals software: nginx/1.18.0
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
