# CORS checklist

| # | Check | Severity if failed | Why |
|---|---|---|---|
| 1 | `Access-Control-Allow-Origin: *` is never combined with `Access-Control-Allow-Credentials: true` | critical | Browsers reject the combination for credentialed requests, so developers "fix" it by reflecting the origin (check 2) |
| 2 | The origin is never reflected back unless it matches an explicit allowlist (exact string compare of scheme, host, port) | critical | Reflection equals `*` with credentials: any site can read authenticated responses |
| 3 | `null` origin is not allowed | high | Sandboxed iframes, `file://` pages and some redirects send `Origin: null`; allowing it lets any attacker page in |
| 4 | Allowlist matching is not a substring or an unanchored regex (`example.com` must not match `notexample.com` or `example.com.evil.net`) | high | Common bypass |
| 5 | Subdomain wildcards are deliberate: every subdomain must be trusted (an XSS on any of them reads the API) | medium | |
| 6 | `Vary: Origin` is sent when the response depends on the origin, so caches and CDNs do not serve one origin's headers to another | medium | Cache poisoning of the CORS headers |
| 7 | Preflight (`OPTIONS`) is answered before authentication and without a body, with status 204 or 200 | medium | A preflight that gets 401 blocks every cross-origin call |
| 8 | `Access-Control-Allow-Methods` and `-Headers` list only what clients use; no `*` with credentials (browsers treat `*` literally then) | low | Least privilege |
| 9 | `Access-Control-Max-Age` is set (300 to 7200 seconds) to avoid a preflight per request, and lowered during policy changes | low | Performance; browsers cap it anyway |
| 10 | `Access-Control-Expose-Headers` lists only headers the client reads (pagination, rate limit, request id); never `Set-Cookie` or internal headers | low | Information exposure |
| 11 | Only one layer sets CORS headers (gateway or framework) | medium | Duplicate values cause browser rejection and confusion about which policy applies |
| 12 | Public, non-credentialed, non-sensitive endpoints may use `*` with credentials off; everything else uses the allowlist | info | |
| 13 | Private network access: an API on an internal address called from a public page needs `Access-Control-Allow-Private-Network: true` and should probably not be reachable that way at all | medium | |
| 14 | CSRF is handled separately: `SameSite` cookies, CSRF tokens, or a required custom header on state-changing requests; CORS alone does not stop a cross-site `POST` with a form content type | high | CORS controls reading responses, not sending requests |
| 15 | WebSocket endpoints check `Origin` themselves (CORS does not apply to the handshake) | high | Cross-site WebSocket hijacking |
| 16 | Error responses (4xx, 5xx) carry the same CORS headers as success, so the client can read the error | low | Debuggability |
