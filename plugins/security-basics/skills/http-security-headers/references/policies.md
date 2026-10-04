# Starting policies and server snippets

## Header set for a typical web application

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>'; style-src 'self' 'nonce-<random>'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store            (authenticated or personalised responses only)
```

Cookies: `Set-Cookie: __Host-session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax`.

## CSP rollout

1. Deploy as `Content-Security-Policy-Report-Only` with `report-to` (or `report-uri`) pointing at an endpoint that stores reports.
2. Use the app for a week; group reports by `blocked-uri` and `violated-directive`; add legitimate sources, remove inline scripts (move to files or add nonces), and fix `eval` uses.
3. Switch the header name to `Content-Security-Policy`; keep report-only alongside for a stricter candidate policy.
4. Never add `'unsafe-inline'` to `script-src` to make a violation go away; use a nonce or a hash. `'strict-dynamic'` with nonces simplifies policies for apps that load scripts dynamically.

API responses (JSON) need a minimal policy that disables everything: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.

## nginx

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
server_tokens off;
# CSP with nonces is set by the application; a static CSP for static sites can go here.
```

`add_header` in a `location` block replaces all inherited `add_header` lines; repeat the set or use an include file.

## Caddy

```
header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    X-Content-Type-Options nosniff
    X-Frame-Options DENY
    Referrer-Policy strict-origin-when-cross-origin
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
    -Server
}
```

## Apache

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
ServerTokens Prod
ServerSignature Off
```

## Frameworks

- Express: `helmet()` sets most of these; configure `contentSecurityPolicy` with a per-request nonce (`res.locals.cspNonce`), and the session cookie with `secure`, `httpOnly`, `sameSite: 'lax'`.
- Django: `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = "DENY"`, `SECURE_REFERRER_POLICY`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `CSRF_COOKIE_SECURE`; `django-csp` for CSP with nonces.
- Rails: `config.force_ssl = true` (HSTS), the `content_security_policy` initializer with `content_security_policy_nonce_generator`, `config.action_dispatch.default_headers`.
- Spring Security: `http.headers()` enables HSTS, nosniff and frame options by default; add `contentSecurityPolicy`, `referrerPolicy`, `permissionsPolicy`.
- ASP.NET Core: `app.UseHsts()`, `app.UseHttpsRedirection()`, a middleware that adds the remaining headers; the NWebsec package for CSP with nonces.
