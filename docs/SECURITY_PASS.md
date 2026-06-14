# Security Pass (Phase 8)

Date: 2026-06-15. Scope: the OAuth 2.1 + OIDC platform after Phases 0–8.

This is the Phase 8 "security pass" deliverable: dependency audit, headers review, and a
pen-test checklist mapping each item to what is implemented vs. accepted/deferred. It
complements the in-code controls and the audit-log + alerting + key-rotation work.

## 1. Dependency audit (`npm audit`)

- **Backend:** `0 vulnerabilities` (prod and dev).
- **Frontend:** the reported advisories (`postcss`, `flatted`, `glob`, `minimatch`, `ajv`,
  `brace-expansion`) are all transitive through **Next.js 14 build/lint tooling**
  (`eslint-config-next`, postcss), not the runtime request path. None are reachable by an
  attacker against the running app (no untrusted CSS is processed; glob/minimatch/flatted/ajv
  are build/lint-time). The only fix offered is a major upgrade to Next 16 (breaking).
  **Decision:** tracked, not force-upgraded in this phase; revisit with a planned Next major
  upgrade.

## 2. Security headers

- **Backend (helmet):** CSP (`default-src 'self'`, `script-src 'self'`), HSTS
  (1y/includeSubDomains/preload), `X-Content-Type-Options`, `X-Frame-Options`, COOP/CORP,
  Referrer-Policy. CORS is an explicit origin allowlist with credentials.
- **Frontend (next.config.js):** CSP with `connect-src`/`form-action` scoped to the API,
  `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, Referrer-Policy.
  `'unsafe-eval'`/`ws:` are enabled **in dev only** (Next HMR); production CSP omits eval.
- **Token/userinfo/revoke** responses set `Cache-Control: no-store`.

## 3. Pen-test checklist

| Area | Control | Status |
|------|---------|--------|
| Algorithm confusion (`alg:none`/HS256) | jose verifier pins RS256; no symmetric path | ✅ implemented, live-tested |
| Token type confusion (ID token at /userinfo) | `aud` separation + RS256 pin | ✅ live-tested (401) |
| PKCE downgrade | S256 enforced (DB CHECK + request validation); verifier length/charset validated | ✅ |
| Authorization code replay | hashed, single-use (atomic), client/redirect/PKCE-bound; reuse → alert+audit | ✅ |
| Refresh token theft/replay | rotating single-use, family revocation on reuse, absolute family cap | ✅ |
| Open redirect (redirect_uri) | exact match, no wildcards, fragment rejected, http only loopback | ✅ |
| Open redirect (frontend return_to) | `safeReturnTo` allowlist | ✅ |
| Client auth | confidential secret Argon2id; uniform `invalid_client`; per-client grant types enforced | ✅ |
| SQL injection | all queries parameterized | ✅ |
| Secrets at rest | passwords/secrets Argon2id; JWT private key AES-256-GCM; tokens stored as SHA-256 | ✅ |
| Session security | HttpOnly + SameSite=Lax + Secure(prod), server-side (Redis), no fixation | ✅ |
| Brute force | Argon2id, account lockout, per-(IP,email) + per-IP login limits, MFA single-use challenge | ✅ |
| Rate limiting | per-endpoint + platform-wide per-IP backstop | ✅ |
| Audit trail | append-only `audit_logs` (login/consent/issue/refresh/revoke/reuse), no PII/secrets | ✅ |
| Alerting | reuse (immediate), login-failure & signature-failure spikes (threshold); logs + `ALERT_WEBHOOK_URL` sink | ✅ wired (webhook) |
| Key rotation | zero-downtime overlap; JWKS serves old+new; cache TTL for fleet pickup | ✅ |
| `trust proxy` spoofing | configurable `TRUST_PROXY` (must match real topology) | ✅ |

## 4. Accepted / deferred (post-Phase-8)

- **No revocation of already-issued access tokens** — they are short-lived (15 min) stateless
  JWTs; revocation acts on the refresh-token family. Add token introspection / a short-TTL
  Redis deny-list if immediate access-token kill is required.
- **CSRF on the JSON API** relies on CORS allowlist + `SameSite=Lax` + JSON content-type; the
  one cross-service HTML form (consent → `/authorize`) is re-validated server-side. A
  double-submit CSRF token is not yet added.
- **CSP nonces** — frontend uses `'unsafe-inline'` for scripts/styles; tighten to nonces.
- **Alert sink** — wired: logs always, plus an outbound webhook when `ALERT_WEBHOOK_URL` is set
  (verified live: a refresh-token reuse delivered a `critical` alert to a local receiver). Point it
  at a Slack/PagerDuty/SIEM endpoint in prod.
- **External pen-test & DDoS/WAF** — infra-level, out of repo scope.
- **Frontend Next major upgrade** — clears the dev-tooling advisories above.

## 5. Operational runbooks

- **Key rotation:** `npm run rotate:keys` (retires current key with a 24h JWKS overlap; running
  servers pick up the new signing key within ~60s via the active-key cache TTL). Schedule
  monthly.
- **Demo/data:** `npm run seed:demo` creates an admin demo user + client (dev only).
- **Incident — token theft:** rotate keys (invalidates nothing already valid, but stops new
  signing with a suspect key), revoke refresh-token families via `/revoke`, invalidate sessions.
