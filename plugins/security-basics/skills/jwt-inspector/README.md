# jwt-inspector

Decode a JWT or bearer access token without verifying it, with a bundled script that prints the header, claims and expiry, and flags unsafe settings (alg none, empty signature, long or missing expiry, jku or x5u, suspicious kid, HS256 and other symmetric algorithms, email or other sensitive claims in the payload); then check whether the token design is safe.

Use it when asked to "decode this JWT", "when does this token expire?", or when debugging a 401.
Not for verifying signatures, a whole login and session flow (auth-flow-review) or OAuth servers.

Claude follows [SKILL.md](SKILL.md); it is part of the `security-basics` plugin (`/plugin install security-basics@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/security-basics/skills/jwt-inspector/scripts/jwt_inspect.py eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiazEifQ.eyJzdWIiOiAidSIsICJleHAiOiAxNzcyMzcwMDAwLCAiZW1haWwiOiAiYUBiLmMifQ.c2ln --now 2026-03-01T12:00:00+00:00
```

Inside Claude Code the skill runs `jwt_inspect.py` from `${CLAUDE_PLUGIN_ROOT}/skills/jwt-inspector/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/jwt-inspector/` (synthetic data):

<!-- sample: plugins/security-basics/skills/jwt-inspector/scripts/jwt_inspect.py eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiazEifQ.eyJzdWIiOiAidSIsICJleHAiOiAxNzcyMzcwMDAwLCAiZW1haWwiOiAiYUBiLmMifQ.c2ln --now 2026-03-01T12:00:00+00:00 -->
```text
jwt-inspector 0.1.0: SIGNATURE NOT VERIFIED (no key; decode only)
header:
  alg: "HS256"
  typ: "JWT"
  kid: "k1"
payload:
  sub: "u"  (subject (the principal))
  exp: 2026-03-01T13:00:00+00:00 (in 1h)  (expires at)
  email: "a@b.c"
signature: present; size 130 bytes; segments 3
findings:
  [medium  ] JWT-004 Symmetric algorithm HS256
      fix: Fine for a single issuer-verifier pair with a long random secret; use RS256/ES256 when several services verify.
  [low     ] JWT-005 No iss claim
      fix: Set iss so verifiers can pin the issuer.
  [low     ] JWT-005 No aud claim
      fix: Set aud so a token for one service is rejected by another.
  [info    ] JWT-007 Personal data claim 'email' in the payload
      fix: Keep PII out of access tokens unless the consumer needs it; consider a JWE or an opaque token.
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
