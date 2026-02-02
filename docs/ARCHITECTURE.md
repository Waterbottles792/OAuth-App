# System Architecture

OAuth 2.1 + OpenID Connect Authorization & Identity Platform

## Overview

This document describes the high-level architecture of the authorization and identity platform, including component responsibilities, data flows, and security boundaries.

## System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         End Users                                │
│                    (Resource Owners)                             │
└────────────┬────────────────────────────────────┬────────────────┘
             │                                    │
             │ (1) Login/Consent                  │ (2) Access Resources
             │                                    │
             v                                    v
┌────────────────────────────┐     ┌──────────────────────────────┐
│   Frontend Application     │     │    Resource Server           │
│   (Next.js SPA)            │     │    (Your API)                │
│                            │     │                              │
│ - Login UI                 │     │ - Validates Access Tokens    │
│ - Consent UI               │     │ - Enforces Scopes            │
│ - Developer Dashboard      │     │ - Serves Protected Data      │
│ - Client Management        │     │                              │
└────────────┬───────────────┘     └────────────┬─────────────────┘
             │                                  │
             │ (3) OAuth Endpoints              │ (4) Token Validation
             │                                  │     (JWKS)
             v                                  v
┌───────────────────────────────────────────────────────────────────┐
│            Authorization Server (Backend - Express)               │
│                                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │
│  │ Identity Core   │  │ OAuth 2.1 Engine │  │ OIDC Provider   │ │
│  │ (Phase 1)       │  │ (Phase 3-5)      │  │ (Phase 6)       │ │
│  │                 │  │                  │  │                 │ │
│  │ - Registration  │  │ - /authorize     │  │ - ID Tokens     │ │
│  │ - Login         │  │ - /token         │  │ - /userinfo     │ │
│  │ - MFA           │  │ - Code Flow      │  │ - JWKS          │ │
│  │ - Sessions      │  │ - PKCE           │  │ - Discovery     │ │
│  └─────────────────┘  └──────────────────┘  └─────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │               Security Middleware                            ││
│  │  - Rate Limiting  - CORS  - Helmet  - Input Validation      ││
│  └──────────────────────────────────────────────────────────────┘│
└────────────┬──────────────────────────────────────┬──────────────┘
             │                                      │
             v                                      v
┌────────────────────────┐         ┌───────────────────────────────┐
│   PostgreSQL           │         │        Redis                  │
│                        │         │                               │
│ - Users                │         │ - Sessions (Phase 1)          │
│ - OAuth Clients        │         │ - Rate Limiting               │
│ - Authorization Codes  │         │ - Temporary Data              │
│ - Tokens (metadata)    │         │                               │
│ - Consents             │         │                               │
│ - Audit Logs           │         │                               │
└────────────────────────┘         └───────────────────────────────┘
```

## Component Responsibilities

### Frontend Application (Next.js)
- **Phase 0**: Placeholder homepage
- **Phase 7**: Full implementation
  - User login interface
  - OAuth consent screens
  - Developer dashboard for managing OAuth clients
  - User profile management
  - MFA enrollment

**Security Boundaries**:
- ❌ NO tokens stored in localStorage/sessionStorage
- ✅ HTTP-only cookies for sessions
- ✅ CSRF protection on all forms

---

### Authorization Server (Backend)

#### Identity Core (Phase 1)
Handles user authentication independently of OAuth.

**Responsibilities**:
- User registration with email verification
- Password authentication (Argon2id)
- Multi-factor authentication (TOTP + backup codes)
- Server-side session management
- Account lockout and rate limiting

**Storage**:
- PostgreSQL: User accounts, MFA secrets
- Redis: Active sessions, rate limit counters

#### OAuth 2.1 Engine (Phases 2-5)
Implements OAuth 2.1 authorization framework.

**Responsibilities**:
- Client registration and validation
- Authorization code issuance (PKCE)
- Access token generation (JWT)
- Refresh token rotation
- Consent management
- Token revocation

**Key Endpoints**:
- `GET /api/v1/oauth/authorize` - Authorization endpoint
- `POST /api/v1/oauth/token` - Token endpoint
- `POST /api/v1/oauth/revoke` - Revocation endpoint

#### OpenID Connect Provider (Phase 6)
Extends OAuth with identity layer.

**Responsibilities**:
- ID token issuance
- UserInfo endpoint
- OIDC discovery
- JWKS publication

**Key Endpoints**:
- `GET /api/v1/oauth/userinfo` - User info endpoint
- `GET /.well-known/openid-configuration` - Discovery
- `GET /.well-known/jwks.json` - Public keys

---

### Database Layer

#### PostgreSQL
Primary data store for persistent data.

**Schema Evolution by Phase**:

**Phase 1**: Users, Sessions, MFA
```sql
- users
- sessions
- mfa_secrets
```

**Phase 2**: OAuth Clients
```sql
- oauth_clients
- oauth_scopes
- user_consents
```

**Phase 3**: Authorization Codes
```sql
- authorization_codes
```

**Phase 4**: JWT Keys
```sql
- jwt_keys
```

**Phase 5**: Refresh Tokens
```sql
- refresh_tokens
```

**Phase 8**: Audit Logs
```sql
- audit_logs (immutable)
```

#### Redis
High-performance cache for ephemeral data.

**Usage**:
- Session tokens (Phase 1)
- Rate limiting counters (Phase 1)
- Authorization code temporary storage (Phase 3)
- Token blacklist (Phase 5)

---

## Data Flows

### Flow 1: User Registration (Phase 1)

```
User → Frontend → POST /api/v1/auth/register
                     ↓
                  Validate input
                     ↓
                  Hash password (Argon2id)
                     ↓
                  Store in PostgreSQL
                     ↓
                  Send verification email
                     ↓
                  Return success
```

### Flow 2: User Login (Phase 1)

```
User → Frontend → POST /api/v1/auth/login
                     ↓
                  Validate credentials
                     ↓
                  Check account lockout
                     ↓
                  Verify password hash
                     ↓
                  Create session token
                     ↓
                  Store in Redis (with TTL)
                     ↓
                  Set HTTP-only cookie
                     ↓
                  Return success
```

### Flow 3: OAuth Authorization Code Flow (Phases 1-3)

```
1. User clicks "Login with OAuth" on Client App
   ↓
2. Client redirects to:
   GET /authorize?response_type=code&client_id=X&redirect_uri=Y&
       scope=read:profile&state=ABC&code_challenge=HASH&
       code_challenge_method=S256
   ↓
3. Authorization Server checks if user is authenticated
   ↓
4. If not authenticated → Redirect to /login
   ↓
5. User logs in (Session established)
   ↓
6. Authorization Server shows consent screen
   ↓
7. User approves consent
   ↓
8. Authorization Server generates authorization code
   ↓
9. Redirect to: redirect_uri?code=AUTHZ_CODE&state=ABC
   ↓
10. Client exchanges code for token:
    POST /token
    Body: { grant_type: authorization_code, code, client_id,
            client_secret, redirect_uri, code_verifier }
    ↓
11. Authorization Server validates:
    - Code exists and not used
    - Client credentials
    - Redirect URI matches
    - Code verifier matches challenge (PKCE)
    ↓
12. Generate JWT access token (RS256)
    ↓
13. Return: { access_token, token_type: "Bearer", expires_in: 900 }
```

### Flow 4: Token Refresh (Phase 5)

```
Client → POST /api/v1/oauth/token
         Body: { grant_type: refresh_token, refresh_token, client_id }
         ↓
      Validate refresh token (hash lookup)
         ↓
      Check if token already used (reuse detection)
         ↓
      If reused → Revoke entire token family
         ↓
      Mark current token as used
         ↓
      Generate new access token + new refresh token
         ↓
      Return: { access_token, refresh_token, expires_in }
```

### Flow 5: Resource Access (Phases 4+)

```
Client → GET /api/protected/resource
         Headers: Authorization: Bearer <JWT>
         ↓
Resource Server validates JWT:
  - Verify signature using JWKS
  - Check expiration (exp)
  - Verify issuer (iss)
  - Verify audience (aud)
  - Check scopes
         ↓
      Serve protected resource
```

---

## Security Boundaries

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Trusted Zone (Authorization Server)                   │
│  - Private keys                                         │
│  - User passwords (hashed)                              │
│  - Session tokens (hashed)                              │
│  - Database credentials                                 │
└─────────────────────────────────────────────────────────┘
                      ↑
                      │ HTTPS/TLS 1.3
                      ↓
┌─────────────────────────────────────────────────────────┐
│  Semi-Trusted Zone (Frontend, Resource Servers)        │
│  - Access tokens (JWT)                                  │
│  - Public keys (JWKS)                                   │
└─────────────────────────────────────────────────────────┘
                      ↑
                      │ HTTPS/TLS 1.3
                      ↓
┌─────────────────────────────────────────────────────────┐
│  Untrusted Zone (End Users, Clients)                   │
│  - Authorization codes (short-lived)                    │
│  - Refresh tokens (encrypted in transit)                │
└─────────────────────────────────────────────────────────┘
```

### Data Classification

| Data Type | Classification | Storage | Transmission | Retention |
|-----------|----------------|---------|--------------|-----------|
| User passwords | Secret | Hashed (Argon2id) | Never transmitted | Until account deletion |
| Private keys | Secret | Encrypted at rest | Never transmitted | Until rotation |
| Session tokens | Confidential | Hashed in Redis | HTTP-only cookie (HTTPS) | 24 hours |
| Authorization codes | Confidential | Hashed in PostgreSQL | HTTPS redirect | 10 minutes |
| Access tokens | Confidential | Not stored | HTTPS | 15 minutes (in JWT) |
| Refresh tokens | Confidential | Hashed in PostgreSQL | HTTPS | 30 days |
| Client secrets | Secret | Hashed (Argon2id) | HTTPS (once, on creation) | Until client deletion |
| Public keys | Public | Plain text | HTTPS (JWKS) | Until rotation |

---

## Deployment Architecture

### Development Environment

```
┌─────────────────────────────────────────────────┐
│  localhost                                      │
│                                                 │
│  ┌─────────────┐  ┌──────────────┐             │
│  │ Frontend    │  │ Backend      │             │
│  │ :3000       │  │ :3001        │             │
│  └─────────────┘  └──────────────┘             │
│                                                 │
│  ┌─────────────┐  ┌──────────────┐             │
│  │ PostgreSQL  │  │ Redis        │             │
│  │ :5432       │  │ :6379        │             │
│  └─────────────┘  └──────────────┘             │
│                                                 │
│  (Docker Compose)                               │
└─────────────────────────────────────────────────┘
```

### Production Environment (Future)

```
                    ┌───────────────┐
                    │  Load Balancer│
                    │  (HTTPS)      │
                    └───────┬───────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
    ┌───────v──────┐              ┌────────v──────┐
    │  Backend     │              │  Backend      │
    │  Instance 1  │              │  Instance 2   │
    └───────┬──────┘              └────────┬──────┘
            │                               │
            └───────────────┬───────────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
    ┌───────v────────┐            ┌────────v──────┐
    │  PostgreSQL    │            │  Redis        │
    │  (Primary)     │            │  Cluster      │
    │  + Replica     │            │               │
    └────────────────┘            └───────────────┘
```

---

## Scalability Considerations

### Session Storage (Redis)
- Redis cluster for high availability
- Session replication across nodes
- TTL-based automatic cleanup

### Database (PostgreSQL)
- Read replicas for token validation queries
- Connection pooling (max 20 connections per instance)
- Indexed queries on:
  - `users.email`
  - `sessions.user_id`
  - `authorization_codes.expires_at`
  - `refresh_tokens.token_family_id`

### Token Validation
- Resource servers validate JWTs using JWKS (no database call)
- JWKS cached with TTL
- Signature verification is CPU-bound (use RS256 or ES256)

---

## Monitoring and Observability

### Metrics to Track (Phase 8)
- Request rate per endpoint
- Token issuance rate
- Token validation failures
- Login success/failure rate
- MFA enrollment rate
- Session creation/expiration rate

### Alerts
- High login failure rate (potential brute force)
- Refresh token reuse detected (potential token theft)
- Authorization code reuse (potential attack)
- JWT signature verification failures
- Database connection pool exhausted

---

## Disaster Recovery

### Backup Strategy
- PostgreSQL: Daily full backup + WAL archiving
- Redis: AOF (Append-Only File) for persistence
- Private keys: Encrypted backup in separate location

### Recovery Procedures
1. Restore PostgreSQL from backup
2. Restore Redis from AOF
3. Restore private keys from encrypted backup
4. Restart Authorization Server
5. Validate JWKS endpoint
6. Monitor for anomalies

---

**Last Updated**: 2026-02-02 (Phase 0)
**Next Review**: Before Phase 1 implementation
