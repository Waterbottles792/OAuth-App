# Security Decisions Documentation

This document records all security-critical architectural decisions for the OAuth 2.1 + OpenID Connect Authorization & Identity Platform. These decisions form the security foundation and must be preserved throughout all implementation phases.

## Document Purpose

- **Accountability**: Every security decision is justified and traceable
- **Auditability**: Security reviews can validate implementation against documented decisions
- **Immutability**: Prevents accidental security degradation during development
- **Knowledge Transfer**: Ensures all developers understand security rationale

---

## 🔒 Non-Negotiable Security Decisions

These decisions are **LOCKED** and must never be changed without comprehensive security review.

### 1. Token Format: JWT Only

**Decision**: All tokens (access tokens, refresh tokens, ID tokens) MUST use JWT format.

**Rationale**:
- **Self-contained**: Reduces database lookups for token validation
- **Standardized**: Industry-standard format with widespread library support
- **Verifiable**: Can be validated without network calls using public key
- **Extensible**: Supports custom claims while maintaining compatibility

**Security Implications**:
- ✅ Stateless validation reduces attack surface on validation endpoints
- ✅ Tamper-evident through cryptographic signatures
- ⚠️ Cannot be revoked without additional infrastructure (addressed in Phase 5)
- ⚠️ Larger token size than opaque tokens (acceptable tradeoff)

**Implementation Phase**: Phase 4

---

### 2. Signing Algorithm: Asymmetric (RS256 or ES256)

**Decision**: ONLY asymmetric algorithms (RS256 or ES256) are permitted. Symmetric algorithms (HS256) are forbidden.

**Rationale**:
- **Key Distribution**: Public keys can be shared; private keys remain server-side only
- **Multi-service Architecture**: Resource servers can validate tokens without shared secrets
- **JWKS Compatibility**: Public keys can be published via JWKS endpoint (Phase 6)
- **Security Margin**: Eliminates risk of secret key leakage to clients

**Forbidden Algorithms**:
- ❌ HS256 (requires shared secret between authorization and resource servers)
- ❌ HS384, HS512 (same issue)
- ❌ none (no signature)

**Allowed Algorithms**:
- ✅ RS256 (RSA-2048 minimum, recommended for maximum compatibility)
- ✅ ES256 (ECDSA P-256, smaller signatures, better performance)

**Key Rotation**: Keys must be rotated at least annually (Phase 8)

**Implementation Phase**: Phase 4

---

### 3. Access Token Lifetime: ≤ 15 Minutes

**Decision**: Access tokens MUST expire within 15 minutes maximum.

**Rationale**:
- **Credential Theft Mitigation**: Stolen tokens have limited validity window
- **Scope Change Propagation**: Permission changes take effect within 15 minutes
- **Account Compromise**: Account lockout/suspension affects access quickly
- **Compliance**: Aligns with NIST 800-63B recommendations

**Implementation**:
```typescript
const ACCESS_TOKEN_LIFETIME = 900; // 15 minutes in seconds (LOCKED)
```

**Business Impact**:
- Users experience seamless refreshing via refresh tokens (invisible to UX)
- Resource servers must be prepared for frequent token expiration

**Implementation Phase**: Phase 4

---

### 4. Refresh Tokens: Rotating, Single-Use

**Decision**: Refresh tokens MUST be single-use and rotate on every use.

**Rationale**:
- **Replay Attack Prevention**: Used refresh token immediately becomes invalid
- **Breach Detection**: Reuse of a refresh token indicates token theft
- **Forward Secrecy**: Compromised old refresh tokens cannot be used
- **OAuth 2.1 Compliance**: Required by OAuth 2.1 specification

**Implementation Strategy**:
1. Client presents refresh token RT1
2. Server validates RT1 and marks it as used
3. Server issues new access token + new refresh token RT2
4. RT1 is permanently invalidated
5. If RT1 is presented again → revoke entire token family (Phase 5)

**Token Family Revocation**:
- If a refresh token is reused, **ALL** tokens in the family are revoked
- User must re-authenticate
- Prevents stolen token from being used even once

**Implementation Phase**: Phase 5

---

### 5. Grant Type: Authorization Code + PKCE Only

**Decision**: ONLY the Authorization Code flow with PKCE is permitted. All other flows are forbidden.

**Forbidden Flows**:
- ❌ Implicit Flow (deprecated in OAuth 2.1)
- ❌ Resource Owner Password Credentials (anti-pattern)
- ❌ Client Credentials (different use case, may be added separately)

**PKCE (Proof Key for Code Exchange)**:
- **Required for ALL clients** (including confidential clients)
- **Code verifier**: Random 43-128 character string
- **Code challenge**: SHA-256 hash of code verifier
- **Method**: `S256` only (plain method forbidden)

**Rationale**:
- **Authorization Code Interception**: PKCE prevents code theft
- **Public Client Security**: No client secret needed
- **Cross-Device Attacks**: Code cannot be used without verifier
- **Future-Proof**: OAuth 2.1 mandates PKCE

**Implementation Phase**: Phase 3

---

### 6. No Implicit Flow

**Decision**: The Implicit Flow is completely forbidden and will never be implemented.

**Rationale**:
- **OAuth 2.1 Deprecation**: Officially deprecated
- **URL Exposure**: Access tokens in URL fragment (browser history, logs)
- **No Refresh Tokens**: Cannot implement refresh token security
- **CORS Complexity**: Increases attack surface unnecessarily

**Migration Path for Legacy Clients**:
- Use Authorization Code + PKCE instead
- For SPAs: Use Authorization Code + PKCE (standard approach)

**Implementation Phase**: Never (actively prevented)

---

### 7. No Wildcard Redirect URIs

**Decision**: Redirect URIs MUST be exact-matched. Wildcards, pattern matching, and substring matching are forbidden.

**Rationale**:
- **Open Redirect Prevention**: Prevents authorization code theft
- **Exact Match**: `https://app.example.com/callback` ≠ `https://app.example.com/callback/evil`
- **No Subdomain Wildcards**: `*.example.com` forbidden (subdomain takeover risk)
- **No Path Wildcards**: `https://example.com/*` forbidden (path traversal)

**Allowed**:
```
https://app.example.com/auth/callback
https://localhost:3000/callback (development only)
```

**Forbidden**:
```
https://*.example.com/callback
https://example.com/*
http://localhost:* (wildcard port)
```

**Implementation**:
```typescript
if (redirectUri !== registeredRedirectUri) {
  throw new Error('redirect_uri exact match failed');
}
```

**Implementation Phase**: Phase 2 (validation), Phase 3 (enforcement)

---

### 8. Server-Side Sessions Only

**Decision**: Authentication sessions MUST be stored server-side. Client-side session storage (JWT in localStorage, etc.) is forbidden.

**Rationale**:
- **XSS Protection**: Session tokens not accessible to JavaScript
- **Revocation**: Server can invalidate sessions immediately
- **Session Fixation**: Server controls session lifecycle
- **CSRF Protection**: Combined with SameSite cookies

**Storage**:
- Redis for high-performance session lookup (Phase 1)
- PostgreSQL as fallback/persistent storage

**Implementation Phase**: Phase 1

---

### 9. HTTP-Only, SameSite Cookies

**Decision**: All session and authentication cookies MUST have `HttpOnly`, `Secure`, and `SameSite` flags.

**Cookie Configuration**:
```typescript
{
  httpOnly: true,      // Prevent JavaScript access (XSS protection)
  secure: true,        // HTTPS only (production)
  sameSite: 'lax',     // CSRF protection
  path: '/',
  maxAge: 86400000,    // 24 hours
  domain: undefined,   // Same-origin only
}
```

**Rationale**:
- **HttpOnly**: Prevents XSS attacks from stealing session tokens
- **Secure**: Prevents MITM attacks via unencrypted connections
- **SameSite=Lax**: Prevents CSRF while allowing OAuth redirects
- **SameSite=Strict**: Too restrictive for OAuth flows

**Implementation Phase**: Phase 1

---

## 🛡️ Additional Security Principles

### 10. Defense in Depth

**Principle**: Multiple layers of security controls, so a single failure doesn't compromise the system.

**Layers**:
1. **Network**: HTTPS/TLS 1.3, no plaintext transmission
2. **Application**: Input validation, output encoding, parameterized queries
3. **Session**: HTTP-only cookies, SameSite, server-side storage
4. **Authentication**: MFA, rate limiting, account lockout
5. **Authorization**: Explicit consent, scope validation, token expiry
6. **Monitoring**: Audit logging, anomaly detection, alerting

---

### 11. Principle of Least Privilege

**Scopes**: OAuth scopes represent the minimum permissions required.

**Example**:
- ❌ `admin:*` (too broad)
- ✅ `read:profile`, `write:profile` (granular)

**Implementation Phase**: Phase 2

---

### 12. Zero Trust Architecture

**Assumptions**:
- ❌ Don't trust client-side validation
- ❌ Don't trust client-provided timestamps
- ❌ Don't trust redirect URIs without validation
- ✅ Validate every request
- ✅ Verify every token
- ✅ Log every decision

---

### 13. Secure by Default

**Configuration**:
- Default to most restrictive settings
- Opt-in for relaxed security (with justification)
- Fail securely (deny access on errors)

**Example**:
```typescript
// Default: Deny access
if (!isAuthorized) {
  throw new ForbiddenError();
}
```

---

## 🚨 Threat Model

### Threat Actors

1. **External Attackers**: Credential theft, account takeover, token theft
2. **Malicious Clients**: Phishing, open redirect exploitation
3. **Insider Threats**: Admin abuse, data exfiltration
4. **Compromised Dependencies**: Supply chain attacks

### Attack Scenarios

#### 1. Authorization Code Interception
**Attack**: Attacker intercepts authorization code during redirect.
**Mitigation**: PKCE (code verifier prevents code reuse)

#### 2. Token Theft (XSS)
**Attack**: JavaScript injection steals access token from localStorage.
**Mitigation**: HTTP-only cookies (tokens never exposed to JavaScript)

#### 3. Token Replay
**Attack**: Stolen access token used repeatedly.
**Mitigation**: Short token lifetime (15 min) + refresh token rotation

#### 4. Refresh Token Theft
**Attack**: Stolen refresh token used to generate new access tokens.
**Mitigation**: Single-use refresh tokens + reuse detection + family revocation

#### 5. Open Redirect
**Attack**: Malicious redirect_uri steals authorization code.
**Mitigation**: Exact-match redirect URI validation

#### 6. CSRF (Cross-Site Request Forgery)
**Attack**: Attacker tricks user into initiating OAuth flow to attacker's account.
**Mitigation**: State parameter validation + SameSite cookies

#### 7. Clickjacking
**Attack**: Invisible iframe tricks user into clicking "Authorize".
**Mitigation**: X-Frame-Options: DENY + CSP frame-ancestors

#### 8. Phishing
**Attack**: Fake authorization page steals credentials.
**Mitigation**: HTTPS enforcement + domain verification + user education

---

## 📋 Security Checklist (Per Phase)

### Phase 1: Identity Core ✅ (2026-06-13)
- [x] Passwords hashed with Argon2id (not bcrypt, not SHA)
- [x] Rate limiting on login endpoint (prevent brute force)
- [x] Account lockout after N failed attempts
- [x] MFA (TOTP + backup codes)
- [x] Session tokens in HTTP-only cookies
- [x] Redis session storage with TTL

### Phase 2: Client Management ✅ (2026-06-13)
- [x] Client secrets hashed (not plaintext)
- [x] Redirect URI exact-match validation
- [x] Client allow-list for scopes
- [x] Client metadata validated

### Phase 3: Authorization Code Flow ✅ (2026-06-13)
- [x] PKCE code_challenge validated (S256 only)
- [x] State parameter validated (echoed back verbatim)
- [x] Authorization code single-use
- [x] Authorization code short-lived (10 minutes max)
- [x] Authorization code bound to client_id + redirect_uri + PKCE

### Phase 4: Access Tokens ✅ (2026-06-13)
- [x] JWT signed with RS256/ES256 (RS256; alg pinned on verify)
- [x] Access token lifetime ≤ 15 minutes
- [x] Token claims validated (iss, aud, exp, iat)
- [x] Private keys stored securely (AES-256-GCM encrypted; never in version control)

### Phase 5: Refresh Tokens
- [ ] Refresh tokens rotate on use
- [ ] Refresh token reuse detected and revoked
- [ ] Token family revocation on suspicious activity
- [ ] Refresh tokens bound to client

### Phase 6: OpenID Connect
- [ ] ID token includes nonce (replay protection)
- [ ] JWKS endpoint serves public keys
- [ ] Userinfo endpoint requires valid access token
- [ ] OIDC discovery endpoint published

### Phase 7: Frontend
- [ ] No tokens in localStorage/sessionStorage
- [ ] HTTP-only cookies only
- [ ] CSRF tokens on state-changing operations
- [ ] CSP headers configured

### Phase 8: Hardening
- [ ] Immutable audit logs
- [ ] Key rotation implemented
- [ ] Monitoring and alerting
- [ ] Rate limiting on all endpoints
- [ ] DDoS protection

---

## 🔐 Cryptographic Standards

### Password Hashing
- **Algorithm**: Argon2id
- **Parameters**: m=64MB, t=3, p=4
- **Salt**: 16 bytes random
- **Forbidden**: MD5, SHA-1, SHA-256 (not password hashing), bcrypt (inferior to Argon2)

### JWT Signing
- **Algorithm**: RS256 (RSA-2048) or ES256 (ECDSA P-256)
- **Key Size**: 2048-bit minimum (RSA), 256-bit (ECDSA)
- **Forbidden**: HS256 (symmetric), none

### Random Token Generation
- **Source**: Cryptographically secure PRNG
- **Node.js**: `crypto.randomBytes(32)`
- **Forbidden**: `Math.random()`, timestamp-based

### TLS Configuration
- **Version**: TLS 1.3 (fallback to TLS 1.2)
- **Forbidden**: TLS 1.0, TLS 1.1, SSL (all versions)
- **Cipher Suites**: AEAD only (AES-GCM, ChaCha20-Poly1305)

---

## 📚 Compliance References

- **OAuth 2.1**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11
- **OpenID Connect Core 1.0**: https://openid.net/specs/openid-connect-core-1_0.html
- **PKCE (RFC 7636)**: https://datatracker.ietf.org/doc/html/rfc7636
- **JWT (RFC 7519)**: https://datatracker.ietf.org/doc/html/rfc7519
- **NIST 800-63B**: Digital Identity Guidelines (Authentication)
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

---

## 🔄 Change History

| Date | Phase | Decision | Rationale |
|------|-------|----------|-----------|
| 2026-02-02 | Phase 0 | All decisions documented | Initial security architecture |
| 2026-06-13 | 1–4 review | Security audit + hardening | See note below |

### Security review (2026-06-13, after Phase 4)

Audited Phases 0–4. Confirmed **no private keys or secrets are committed** (JWT private keys
are AES-256-GCM encrypted in Postgres; `.env` is gitignored). Fixed:
- **Dependencies:** patched transitive `qs`/`express` DoS and `minimatch` ReDoS → **0 npm audit vulnerabilities** (prod + dev).
- **NODE_ENV footgun:** `validateConfig` now requires real `SESSION_SECRET`,
  `JWT_KEY_ENCRYPTION_SECRET`, and DB/Redis passwords in **any** env that isn't explicitly
  `development`/`test` (production, staging, or unset all fail loudly) — no more silent fallback to dev keys.
- **Registration enumeration:** `/register` is now enumeration- and timing-resistant
  (always hashes, uniform `202` response, notifies the address owner instead of returning `409`).
- **Rate limiting:** added per-IP limiters to `/register`, `/mfa/login`, and `/token`
  (login was already limited).

Deferred (documented, not yet implemented): CSRF token on the consent `POST` (currently
mitigated by `SameSite=Lax`) lands with the Phase 7 frontend; email-verification enforcement
and platform-wide rate limiting are Phase 7/8.

---

## ✅ Review and Approval

**Security Review Required**: Any modification to decisions in this document requires:
1. Threat model impact assessment
2. Security team review
3. Penetration testing
4. Documentation update

**Last Reviewed**: 2026-02-02
**Next Review**: Before Phase 1 implementation
