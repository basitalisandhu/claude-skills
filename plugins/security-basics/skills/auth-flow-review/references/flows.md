# Reference flows

## Password login with session cookie

1. `GET /login` renders the form with a CSRF token.
2. `POST /login` with e-mail and password: look up the user; always run the password hash comparison (against a dummy hash when the user is unknown) so timing is uniform; on failure return one generic message and apply the per-account and per-source rate limit; on success, if MFA is enrolled, create a pre-MFA session and redirect to the challenge; otherwise create a new session id, store it server-side with user id, created time, last-seen, ip and user agent, set `__Host-session` with `Secure; HttpOnly; SameSite=Lax; Path=/`, log the event, redirect to the destination (validated as a local path).
3. Every request: load the session, check idle and absolute timeouts, extend last-seen, mark the request with the user.
4. `POST /logout`: delete the server-side session, clear the cookie, log.

## MFA challenge

A pre-MFA session can only reach the challenge and logout. `POST /mfa/verify` is rate-limited (5 attempts, then delay); on success upgrade the session (new id, `mfa_verified_at`), log. Recovery codes are consumed on use. "Trust this device" sets a separate `__Host-device` cookie with a random token stored hashed, expiring in 30 days, listed and revocable in settings.

## Password reset

1. `POST /reset` with e-mail: always respond "if an account exists, an e-mail was sent"; rate limit per e-mail and per source; if the user exists, generate 32 random bytes, store `sha256(token)` with user id, expiry (30 min) and `used = false`, invalidate older unused tokens for the user, e-mail a link `https://app/reset/<token>`.
2. `GET /reset/<token>`: look up by hash; if missing, used or expired, show a generic error; the page has no third-party resources and `Referrer-Policy: no-referrer`.
3. `POST /reset/<token>` with the new password: re-check, set the password (new hash), mark used, revoke all sessions and refresh tokens for the user, create a new session, e-mail "your password was changed", log.

## OAuth 2.0 authorization code with PKCE (web client)

1. Generate `state` (random, stored in the session with the intended destination) and `code_verifier` (random 43 to 128 chars); compute `code_challenge = base64url(sha256(verifier))`; for OIDC also a `nonce` stored in the session.
2. Redirect to the provider's authorization endpoint with `response_type=code`, `client_id`, `redirect_uri` (exactly the registered one), `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, `nonce`.
3. On the callback: verify `state` equals the stored value (then delete it); exchange `code` at the token endpoint with `code_verifier` and the client credentials (server side); validate the ID token (signature via JWKS, `iss`, `aud`, `exp`, `nonce`), read `sub` as the stable identifier (never e-mail as the key); link to a local account only if `email_verified` is true and the e-mail matches an account the user has confirmed, otherwise create a new account or ask the user to log in to link; create a local session as in the password flow.
4. Store provider tokens only if needed, encrypted, with refresh handled server-side.

## Refresh token rotation (single-page app)

Access token (15 min) kept in memory; refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to the `/auth/refresh` path. `POST /auth/refresh` issues a new access token and a new refresh token, marks the old one used; presenting a used refresh token revokes the whole family and logs a security event. Logout revokes the family.

## API keys

Generate `prefix_` plus 32 random bytes base62; show once; store `sha256(key)` with scopes, owner, created, expiry, last-used; look up by hash on each request; revocation deletes the row; list keys in settings with prefix and last-used.

## Attack tests to automate against staging

1. Login timing and message: unknown e-mail versus wrong password.
2. Reset link reuse; reset link after password change; two concurrent resets (only the newest works).
3. Session cookie reuse after logout and after password change.
4. `redirect_uri` variants: suffix domain, path suffix, different scheme, open redirector on the allowed host.
5. OAuth callback without `state`, with a replayed `state`, with an ID token for another `aud`.
6. Direct navigation to a post-MFA page with a pre-MFA session.
7. 500 login attempts in a minute against one account and across many accounts.
8. Token with `alg: none`, expired token, token signed with the wrong key.
