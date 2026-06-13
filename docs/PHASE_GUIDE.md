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

**Status**: ⏳ Not Started

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
- [ ] Private keys never in version control
- [ ] Private keys encrypted at rest
- [ ] RS256 or ES256 only
- [ ] Access token lifetime ≤ 15 minutes
- [ ] Code verifier validated (PKCE)
- [ ] Authorization code invalidated after use
- [ ] Claims validated: iss, aud, exp, iat

---

## Phase 5: Refresh Tokens & Revocation

**Status**: ⏳ Not Started

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
- [ ] Refresh tokens rotate on every use
- [ ] Refresh token reuse detection
- [ ] Token family revocation
- [ ] Refresh tokens hashed in database
- [ ] Refresh token lifetime: 30 days maximum

---

## Phase 6: OpenID Connect

**Status**: ⏳ Not Started

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
- [ ] Nonce validated (replay protection)
- [ ] ID token signed same as access token
- [ ] UserInfo requires valid access token
- [ ] JWKS endpoint public (no authentication)
- [ ] Claims released based on scope

---

## Phase 7: Frontend & UX

**Status**: ⏳ Not Started

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
- ❌ NO tokens in localStorage
- ❌ NO tokens in sessionStorage
- ✅ HTTP-only cookies ONLY
- ✅ CSRF tokens on forms
- ✅ CSP headers

---

## Phase 8: Hardening & Operations

**Status**: ⏳ Not Started

### Purpose
Production readiness.

### Implementation
- Immutable audit logging (all OAuth events)
- Key rotation automation
- Monitoring and alerting
- Rate limiting on all endpoints
- DDoS protection
- Penetration testing
- Security audit

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
