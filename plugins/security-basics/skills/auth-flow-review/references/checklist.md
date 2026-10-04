# Authentication review checklist

## A. Passwords

| # | Check | Severity if failed |
|---|---|---|
| A1 | Hashed with Argon2id (preferred), scrypt or bcrypt with current parameters; never a plain or salted fast hash | critical |
| A2 | Minimum length 8 or more, maximum generous (64 or more), no composition rules that encourage patterns; checked against breached-password lists | medium |
| A3 | Login response and timing do not reveal whether the account exists (same message, dummy hash when the user is unknown) | high |
| A4 | Rate limited per account and per source; lockouts cannot be used to lock out victims (progressive delays or CAPTCHA rather than hard lockout, or lockout scoped to the attacker's source) | high |
| A5 | Credential-stuffing detection (bursts of failures across accounts) alerts someone | medium |
| A6 | Password change requires the current password (or a fresh re-authentication) and revokes other sessions | high |

## B. Sessions and cookies

| # | Check | Severity if failed |
|---|---|---|
| B1 | A new session id is issued at login (no fixation) and at privilege changes | high |
| B2 | Session cookie: `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict`, `__Host-` prefix, `Path=/`, no `Domain` unless needed | high |
| B3 | Logout invalidates the session server-side; the cookie is cleared; the back button shows nothing authenticated | high |
| B4 | Idle timeout and absolute timeout appropriate to the data; "remember me" uses a separate long-lived token that only re-creates a session, never a long session itself | medium |
| B5 | Sessions are revocable per user (list and revoke devices) and revoked on password change, reset, and MFA changes | high |
| B6 | Session identifiers are random (128 bits or more) and never derived from user data | critical |

## C. Tokens (JWT access and refresh)

| # | Check | Severity if failed |
|---|---|---|
| C1 | Access tokens short-lived (minutes to an hour); refresh tokens rotated on use with reuse detection (a replayed refresh token revokes the family) | high |
| C2 | Verifier pins algorithms and validates `iss`, `aud`, `exp`, `nbf`, `typ`; keys from a controlled JWKS; see `jwt-inspector` | critical |
| C3 | Tokens stored in `HttpOnly` cookies for browser sessions, or in memory for single-page apps with refresh via a cookie; never in `localStorage` for session tokens | high |
| C4 | Revocation path exists (short lifetime plus denylist by `jti`, or opaque tokens checked against a store) | high |

## D. OAuth 2.0 and OpenID Connect (as a client)

| # | Check | Severity if failed |
|---|---|---|
| D1 | Authorization code flow with PKCE (`S256`); no implicit flow; no resource owner password flow | high |
| D2 | `state` is random per request, bound to the session, and verified on return | high |
| D3 | `redirect_uri` registered exactly and matched exactly by the server; the client never accepts a redirect target from the request | critical |
| D4 | OIDC `nonce` generated and verified in the ID token | high |
| D5 | ID token validated: signature against the provider's JWKS, `iss`, `aud` equals the client id, `exp`, `nonce`; `email_verified` checked before trusting e-mail | critical |
| D6 | Account linking by e-mail only when the provider verifies e-mail and the user confirms; otherwise an attacker with a same-e-mail account at a lax provider takes over | critical |
| D7 | Scopes minimal; provider tokens stored encrypted if kept; client secret never in a browser or mobile app (use PKCE public clients) | high |
| D8 | Logout handles the provider session as intended, and `post_logout_redirect_uri` is registered | low |

## E. Password reset and e-mail change

| # | Check | Severity if failed |
|---|---|---|
| E1 | Reset token random (128 bits or more), stored hashed, single use, expires in 15 to 60 minutes, bound to the account, invalidated by a newer request and by a password change | critical |
| E2 | Reset request response identical for known and unknown e-mails; rate limited | high |
| E3 | Reset page does not leak the token through `Referer` (no third-party resources on it, `Referrer-Policy: no-referrer`) | medium |
| E4 | Completing a reset logs the user in with a new session and revokes all others; notifies the account e-mail | high |
| E5 | E-mail change requires re-authentication, confirms via the new address, and notifies the old address with an undo link | high |
| E6 | Security questions are not used as a recovery factor | medium |

## F. Multi-factor authentication

| # | Check | Severity if failed |
|---|---|---|
| F1 | Enrolment requires a fresh authentication; disabling MFA requires MFA or recovery codes | high |
| F2 | The MFA step cannot be skipped by navigating directly to a post-login URL (session is marked pre-MFA until verified) | critical |
| F3 | Codes are rate limited (TOTP: a few attempts per window); SMS treated as the weakest factor; passkeys or TOTP preferred | high |
| F4 | Recovery codes: one-time, hashed at rest, regenerable, shown once | medium |
| F5 | Trusted-device tokens are per device, revocable, and expire | medium |

## G. API keys and service credentials

| # | Check | Severity if failed |
|---|---|---|
| G1 | Keys are random, shown once, stored hashed, prefixed for secret scanning (`sk_live_`), scoped, and revocable; last-used time recorded | high |
| G2 | Service-to-service auth uses short-lived credentials (workload identity, mTLS, OIDC federation) rather than static keys where the platform allows | medium |

## H. Logging and monitoring

| # | Check | Severity if failed |
|---|---|---|
| H1 | Login success and failure, MFA events, password and e-mail changes, resets, token issuance and revocation are logged with user id, source, user agent, request id; never with credentials or full tokens | medium |
| H2 | Alerts on failure bursts, logins from new countries or devices, and mass resets | medium |
| H3 | Users are notified of new logins, password changes, and MFA changes | low |

## I. Authorization hand-off

| # | Check | Severity if failed |
|---|---|---|
| I1 | Every endpoint checks authorization after authentication (object-level: this order belongs to this user); the review lists the endpoints where this is missing for the separate authorization review | critical when absent |
