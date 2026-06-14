# Phase Implementation Guide

This guide provides a detailed roadmap for implementing each phase of the OAuth 2.1 + OIDC Authorization & Identity Platform. Each phase has strict boundaries to prevent security mistakes.

## Table of Contents

- [Phase 0: Foundation](#phase-0-foundation)
- [Phase 1: Identity Core](#phase-1-identity-core)
- [Phase 2: Client & Trust Modeling](#phase-2-client--trust-modeling)
- [Phase 3: Authorization Code Flow](#phase-3-authorization-code-flow)
- [Phase 4: Token Service](#phase-4-token-service)
- [Phase 5: Refresh Tokens & Revocation](#phase-5-refresh-tokens--revocation)
- [Phase 6: OpenID Connect](#phase-6-openid-connect)
- [Phase 7: Frontend & UX](#phase-7-frontend--ux)
- [Phase 8: Hardening & Operations](#phase-8-hardening--operations)

---

## Phase 0: Foundation

**Status**: ✅ Completed

### Purpose
Prevent irreversible architectural mistakes by establishing solid foundations.

### What Was Implemented
- ✅ Project directory structure
- ✅ Backend: Node.js + Express + TypeScript
- ✅ Frontend: Next.js 14 + TypeScript
- ✅ Configuration management with validation
- ✅ Security middleware (Helmet, CORS)
- ✅ Docker Compose (PostgreSQL + Redis)
- ✅ Security decisions documentation
- ✅ Health check endpoint

### What Was NOT Implemented
- ❌ User authentication
- ❌ OAuth endpoints
- ❌ Token generation
- ❌ Database schema
- ❌ Login UI

### Files Created
- `backend/src/server.ts` - Express server
- `backend/src/config/index.ts` - Configuration management
- `frontend/app/page.tsx` - Placeholder homepage
- `docs/SECURITY_DECISIONS.md` - Security architecture

### Validation
```bash
# Backend health check
curl http://localhost:3001/health

# Expected: {"status":"healthy","phase":"PHASE_0_FOUNDATION"}
```

---

## Phase 1: Identity Core

**Status**: ✅ Completed (2026-06-13)

> Implemented: DB pool + custom migration runner, Redis client, zod validation, typed
> errors, Argon2id passwords, Redis-backed hashed sessions, TOTP + single-use backup-code
> MFA, per-account lockout + per-IP/email rate limiting, and auth routes
> (`register/login/mfa/logout/me`). 22 tests passing. See `PLAN.md` → Phase 1 Handoff Notes
> for design decisions and the MFA endpoint deviation.

### Purpose
Build secure authentication independent of OAuth.

### What to Implement

#### Database Schema
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  locked_at TIMESTAMP,
  failed_login_attempts INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE mfa_secrets (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  totp_secret VARCHAR(255) NOT NULL,
  backup_codes TEXT[], -- Array of hashed backup codes
  enabled_at TIMESTAMP
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

#### Backend Endpoints
```
POST /api/v1/auth/register
  Body: { email, password }
  Response: { userId, message }

POST /api/v1/auth/login
  Body: { email, password }
  Response: Set-Cookie (session token)

POST /api/v1/auth/logout
  Headers: Cookie (session token)
  Response: { message }

POST /api/v1/auth/mfa/enable
  Headers: Cookie (session token)
  Response: { qrCode, backupCodes }

POST /api/v1/auth/mfa/verify
  Body: { code }
  Response: { success }
```

#### Components to Create
- `backend/src/services/auth.service.ts` - Authentication logic
- `backend/src/services/password.service.ts` - Argon2id hashing
- `backend/src/services/session.service.ts` - Session management
- `backend/src/services/mfa.service.ts` - TOTP and backup codes
- `backend/src/middleware/auth.middleware.ts` - Session validation
- `backend/src/middleware/rateLimit.middleware.ts` - Brute force protection
- `backend/src/routes/auth.routes.ts` - Authentication routes

#### Dependencies to Add
```json
{
  "argon2": "^0.31.2",
  "speakeasy": "^2.0.0",
  "qrcode": "^1.5.3",
  "express-session": "^1.17.3",
  "connect-redis": "^7.1.0"
}
```

### What to NOT Implement
- ❌ OAuth endpoints (`/authorize`, `/token`)
- ❌ JWT generation
- ❌ OAuth clients
- ❌ Access/refresh tokens
- ❌ Consent screens

### Security Checklist
- [x] Passwords hashed with Argon2id (m=64MB, t=3, p=4)
- [x] Rate limiting: Max 5 login attempts per 15 minutes per IP (+email)
- [x] Account lockout: Lock after 5 failed attempts, unlock after 1 hour
- [x] Session tokens: 32 bytes random, stored hashed (sha256) in Redis
- [x] Session expiry: 24 hours, sliding window
- [x] MFA: TOTP (6-digit, 30s window)
- [x] Backup codes: 10 codes, single-use, hashed

### Testing
```bash
# Register user
curl -X POST http://localhost:3001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePassword123!"}'

# Login
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePassword123!"}' \
  -c cookies.txt

# Test rate limiting (should fail after 5 attempts)
for i in {1..10}; do
  curl -X POST http://localhost:3001/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
```

---

## Phase 2: Client & Trust Modeling

**Status**: ✅ Completed (2026-06-13)

> Implemented: `oauth_clients` / `oauth_scopes` / `user_consents` (migration 002),
> client.service (create/get/list/delete, Argon2id secret hash, exact redirect-URI
> validation, scope-catalogue checks, `verifyClientSecret`), consent.service, and
> admin-only client routes. PKCE is forced on for all clients. 41 tests passing.
> See `PLAN.md` → Phase 2 Handoff Notes.

### Purpose
Define who is allowed to request access.

### Database Schema
```sql
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255), -- NULL for public clients
  client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
  redirect_uris TEXT[] NOT NULL, -- Array of exact URIs
  allowed_scopes TEXT[],
  allowed_grant_types TEXT[] DEFAULT ARRAY['authorization_code'],
  require_pkce BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE oauth_scopes (
  name VARCHAR(100) PRIMARY KEY,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_consents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  scopes TEXT[],
  granted_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, client_id)
);
```

### Backend Endpoints
```
POST /api/v1/clients (Admin only)
  Body: { name, redirectUris, allowedScopes, clientType }
  Response: { clientId, clientSecret }

GET /api/v1/clients/:clientId (Admin only)
  Response: { client details }

DELETE /api/v1/clients/:clientId (Admin only)
  Response: { success }
```

### What to NOT Implement
- ❌ `/authorize` endpoint
- ❌ Authorization codes
- ❌ Tokens

### Security Checklist
- [x] Client secrets hashed with Argon2id
- [x] Redirect URIs: Exact match only, no wildcards
- [x] Public clients: PKCE mandatory
- [x] Confidential clients: PKCE mandatory (stricter than "recommended" — forced for all)
- [x] Scope validation: Client can only request allowed scopes (subset of seeded catalogue)

---

## Phase 3: Authorization Code Flow

**Status**: ✅ Completed (2026-06-13)

> Implemented: migration 003 (`authorization_codes`, sha256-hashed + single-use + 10-min
> TTL + S256-only CHECK), authcode.service (`issueCode` / atomic single-use `consumeCode`),
> and `GET`/`POST /api/v1/oauth/authorize`. Strict error semantics (no redirect on bad
> client/redirect_uri; OAuth error redirects otherwise), PKCE S256 enforced, scope allow-list
> checked, consent recorded. Consent prompt is JSON for now (frontend is Phase 7). 57 tests
> passing. See `PLAN.md` → Phase 3 Handoff Notes (incl. exactly what Phase 4 consumes).

### Purpose
Issue authorization codes securely (NO TOKENS YET).

### Database Schema
```sql
CREATE TABLE authorization_codes (
  code_hash VARCHAR(255) PRIMARY KEY,
  client_id UUID NOT NULL REFERENCES oauth_clients(id),
  user_id UUID NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  scopes TEXT[],
  code_challenge VARCHAR(255) NOT NULL,
  code_challenge_method VARCHAR(10) NOT NULL CHECK (code_challenge_method = 'S256'),
  used BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_authz_codes_expires ON authorization_codes(expires_at);
```

### Backend Endpoints
```
GET /api/v1/oauth/authorize
  Query: client_id, redirect_uri, response_type=code, scope, state, code_challenge, code_challenge_method
  Response: Redirect to login (if not authenticated) or consent page

POST /api/v1/oauth/authorize (consent submission)
  Body: { clientId, scopes, approved }
  Response: Redirect to redirect_uri?code=XXX&state=YYY
```

### Authorization Code Requirements
- **Lifetime**: 10 minutes maximum
- **Single-use**: Marked as `used=true` after exchange
- **Hashed**: SHA-256 hash stored, not plaintext
- **Bound to**: client_id, redirect_uri, PKCE challenge

### What to NOT Implement
- ❌ `/token` endpoint
- ❌ Access tokens
- ❌ Refresh tokens
- ❌ JWT generation

### Security Checklist
- [x] PKCE: code_challenge_method MUST be S256 (not plain)
- [x] State parameter validated (echoed back verbatim; CSRF protection — PKCE is primary)
- [x] Redirect URI exact match
- [x] Authorization code expires in 10 minutes
- [x] Authorization code single-use enforced (atomic conditional UPDATE)
- [x] User consent stored

---

## Phase 4: Token Service

**Status**: ✅ Completed (2026-06-13)

> Implemented: migration 004 (`jwt_keys`, private key AES-256-GCM encrypted at rest),
> key.service (RSA-2048 generation + encrypted storage + active-key cache), token.service
> (`signAccessToken`/`verifyAccessToken` via `jose`, RS256 pinned), and `POST /oauth/token`
> (authorization_code grant: client auth, redirect match, PKCE verifier check, single-use code
> consumption → RS256 JWT, 15-min, `Cache-Control: no-store`). 69 tests passing. See
> `PLAN.md` → Phase 4 Handoff Notes for the Phase 5/6 seams.

### Purpose
Issue short-lived access tokens.

### Database Schema
```sql
CREATE TABLE jwt_keys (
  kid VARCHAR(255) PRIMARY KEY,
  algorithm VARCHAR(10) NOT NULL,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL, -- Encrypted at rest
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP, -- For key rotation
  active BOOLEAN DEFAULT TRUE
);
```

### Backend Endpoints
```
POST /api/v1/oauth/token
  Body: grant_type=authorization_code, code, client_id, client_secret, redirect_uri, code_verifier
  Response: { access_token, token_type: "Bearer", expires_in: 900 }
```

### JWT Structure
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-2026-02-02"
  },
  "payload": {
    "iss": "https://auth.example.com",
    "sub": "user-uuid",
    "aud": "resource-server",
    "exp": 1234567890,
    "iat": 1234567000,
    "scope": "read:profile write:profile",
    "client_id": "client-uuid"
  }
}
```

### What to NOT Implement (Yet)
- ❌ Refresh tokens (Phase 5)
- ❌ ID tokens (Phase 6)
- ❌ UserInfo endpoint (Phase 6)

### Security Checklist
- [x] Private keys never in version control (stored encrypted in DB, never on disk)
- [x] Private keys encrypted at rest (AES-256-GCM)
- [x] RS256 or ES256 only (RS256; HS256/none structurally rejected via jose alg pinning)
- [x] Access token lifetime ≤ 15 minutes (900s)
- [x] Code verifier validated (PKCE S256)
- [x] Authorization code invalidated after use (atomic single-use consume)
- [x] Claims validated: iss, aud, exp, iat

---

## Phase 5: Refresh Tokens & Revocation

**Status**: ✅ Completed (2026-06-14)

> Implemented: migration 005 (`refresh_tokens`, sha256-hashed PK, `token_family_id` +
> `parent_token_hash`, `used`/`revoked` flags, 30-day TTL, FK CASCADE), refreshtoken.service
> (`issueRefreshToken` / atomic single-use `rotateRefreshToken` with reuse detection +
> `revokeFamily` / `revokeRefreshToken`). `/token` now also mints a rotating refresh token at
> code exchange and accepts `grant_type=refresh_token` (rotate → new access + child refresh in
> the same family; replay of a used/revoked token revokes the whole family and logs
> `refresh_token_reuse`). Added `POST /api/v1/oauth/revoke` (RFC 7009; always 200, client-scoped).
> 79 tests passing. See `PLAN.md` → Phase 5 Handoff Notes.

### Database Schema
```sql
CREATE TABLE refresh_tokens (
  token_hash VARCHAR(255) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  client_id UUID NOT NULL REFERENCES oauth_clients(id),
  scopes TEXT[],
  token_family_id UUID NOT NULL, -- For reuse detection
  parent_token_hash VARCHAR(255), -- Previous token in family
  used BOOLEAN DEFAULT FALSE,
  revoked BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(token_family_id);
```

### Token Endpoint Update
```
POST /api/v1/oauth/token
  (New grant type)
  Body: grant_type=refresh_token, refresh_token, client_id, client_secret
  Response: { access_token, refresh_token, expires_in }
```

### Refresh Token Rotation Logic
```typescript
// Pseudocode
function rotateRefreshToken(oldToken: string) {
  const dbToken = findToken(hash(oldToken));
  
  if (dbToken.used) {
    // REUSE DETECTED - Revoke entire family
    revokeTokenFamily(dbToken.token_family_id);
    throw new Error('refresh_token_reused');
  }
  
  markAsUsed(dbToken);
  
  const newAccessToken = generateAccessToken();
  const newRefreshToken = generateRefreshToken({
    familyId: dbToken.token_family_id,
    parentHash: hash(oldToken),
  });
  
  return { newAccessToken, newRefreshToken };
}
```

### Security Checklist
- [x] Refresh tokens rotate on every use (old token marked `used`, child minted in same family)
- [x] Refresh token reuse detection (atomic single-use claim; replay → family revoked)
- [x] Token family revocation (`revokeFamily` on reuse, revoked-token replay, and `/revoke`)
- [x] Refresh tokens hashed in database (sha256; raw token never stored)
- [x] Refresh token lifetime: 30 days maximum — enforced as an ABSOLUTE per-family deadline
      (`family_expires_at`, migration 006); rotation never extends it. Per-token inactivity TTL is
      `oauthConfig.refreshTokens.lifetime`, capped by `maxFamilyLifetime`.
- [x] Per-client grant-type enforcement at `/token` (`unauthorized_client`); refresh tokens minted
      only for clients allowed the `refresh_token` grant.

---

## Phase 6: OpenID Connect

**Status**: ✅ Completed (2026-06-14)

> Implemented: migration 007 (`nonce` on `authorization_codes`), `signIdToken` (same key/alg as
> access tokens, `aud`=client_id, `typ`=JWT, nonce embedded), `lib/oidc.ts` scope→claims map
> shared by ID token and userinfo, `key.service.getPublicJwks` (jose `exportJWK`), and the
> endpoints: ID token minted at `/token` for the `openid` scope (code + refresh), `GET
> /oauth/userinfo` (Bearer access token → `sub` + scope-gated claims), and the root-mounted
> `GET /.well-known/openid-configuration` + `GET /.well-known/jwks.json`. 92 tests passing.
> See `PLAN.md` → Phase 6 Handoff Notes.

### Purpose
Turn OAuth into an identity provider.

### Backend Endpoints
```
GET /api/v1/oauth/authorize?response_type=code&scope=openid profile email...
  (Existing endpoint extended)

POST /api/v1/oauth/token
  Response: { access_token, id_token, refresh_token, token_type, expires_in }

GET /api/v1/oauth/userinfo
  Headers: Authorization: Bearer <access_token>
  Response: { sub, name, email, email_verified, ... }

GET /.well-known/openid-configuration
  Response: OIDC discovery document

GET /.well-known/jwks.json
  Response: { keys: [ { kty, use, kid, n, e } ] }
```

### ID Token Structure
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567000,
  "nonce": "client-provided-nonce",
  "email": "user@example.com",
  "email_verified": true
}
```

### Security Checklist
- [x] Nonce carried (auth request → hashed single-use code → ID token) for client-side replay detection
- [x] ID token signed same as access token (same `key.service`/`token.service` RS256 path)
- [x] UserInfo requires valid access token (Bearer; `verifyAccessToken` pins RS256/iss/aud)
- [x] JWKS endpoint public (no authentication); exposes public params only (no `d`/`p`/`q`)
- [x] Claims released based on scope (`lib/oidc.ts` map, shared by ID token + userinfo; `sub` always)

---

## Phase 7: Frontend & UX

**Status**: ✅ Completed (2026-06-14)

> Implemented: Next.js 14 app-router UI — `/login` (password + MFA step), `/register`,
> `/consent`, `/dashboard` (admin client CRUD), `/profile` (MFA enrollment + logout), a
> credentialed `lib/api.ts` (no token ever in JS), and shared inline-style tokens. Backend
> integration: `GET /authorize` now redirects the browser to the consent UI (was JSON) and a
> new read-only `GET /oauth/consent-info` feeds it client name + scope descriptions; the consent
> decision is a top-level form POST to `/authorize`. CSP added in `next.config.js` (incl.
> `form-action`/`connect-src` for the backend). Verified live end-to-end (unauth→login→consent→
> code→token); grep confirms no `localStorage`/`sessionStorage`. 95 backend tests passing.

### Purpose
Expose secure flows to users and developers.

### Components to Build
- Login page (`/login`)
- Consent page (`/consent`)
- Developer dashboard (`/dashboard`)
- Client management UI
- User profile page
- MFA setup page

### Security Rules
- [x] NO tokens in localStorage (grep-verified — `lib/api.ts` only ever sees JSON, never the session)
- [x] NO tokens in sessionStorage (grep-verified)
- [x] HTTP-only cookies ONLY (backend `sid` cookie; all fetches `credentials: 'include'`)
- [x] CSRF protection — JSON API is guarded by the CORS allowlist + `SameSite=Lax`; the one
      cross-service form (consent → backend `/authorize`) is intentional and re-validated server-side.
      (Explicit double-submit CSRF tokens deferred — see Phase 8 follow-ups in PLAN.)
- [x] CSP headers (`next.config.js`: `default-src 'self'`, scoped `connect-src`/`form-action` to the API)

---

## Phase 8: Hardening & Operations

**Status**: ✅ Completed (2026-06-15)

> Implemented: immutable `audit_logs` (migration 008, append-only trigger; events wired for
> login/MFA/consent/code-issue/token-issue/refresh-rotate/reuse/revoke; no PII or secrets), a
> pluggable alerting hook (`lib/alerts.ts` — immediate on reuse, threshold on login- &
> signature-failure spikes), zero-downtime JWT key rotation (`key.service.rotateSigningKey` +
> `npm run rotate:keys`; retired key served via JWKS for a 24h overlap; 60s active-key cache
> TTL for fleet pickup), a platform-wide per-IP rate-limit backstop plus PKCE verifier
> length/charset validation, and a dependency/headers/pen-test `docs/SECURITY_PASS.md`. 105
> backend tests passing.

### Purpose
Production readiness.

### Implementation
- [x] Immutable audit logging (all OAuth events) — `audit_logs` append-only (migration 008)
- [x] Key rotation automation — `rotateSigningKey` + `npm run rotate:keys`, JWKS overlap window
- [x] Monitoring and alerting — `lib/alerts.ts` hooks (reuse, login/signature spikes); wire the sink
- [x] Rate limiting on all endpoints — per-endpoint limiters + platform-wide per-IP backstop
- [ ] DDoS protection — infra/WAF level (out of repo scope; rate-limit backstop is the app layer)
- [ ] Penetration testing — external engagement (checklist in `docs/SECURITY_PASS.md`)
- [x] Security audit — `docs/SECURITY_PASS.md` (deps, headers, pen-test checklist, deferrals)

---

## Phase Transition Checklist

Before moving from Phase N to Phase N+1:

- [ ] All Phase N features implemented
- [ ] All Phase N tests passing
- [ ] Security checklist completed
- [ ] Code review completed
- [ ] Documentation updated
- [ ] No shortcuts taken
- [ ] No Phase N+1 code accidentally added

---

## Emergency Rollback

If a security issue is discovered:

1. **Stop deployment** immediately
2. **Revoke all tokens** (if in Phase 4+)
3. **Invalidate sessions** (if in Phase 1+)
4. **Fix the issue**
5. **Security review**
6. **Redeploy with fix**
7. **Post-mortem documentation**

---

Last Updated: 2026-02-02 (Phase 0 Complete)
