# OAuth 2.1 + OpenID Connect Authorization & Identity Platform

A production-grade identity and authorization platform implementing the OAuth 2.1 and
OpenID Connect (OIDC) specifications with a security-first architecture. All nine
development phases (0 through 8) are complete.

## Overview

This system provides:

- **OAuth 2.1 Authorization Server** - Secure authorization code issuance, token issuance,
  validation, rotation, and revocation.
- **OpenID Connect (OIDC) Identity Provider** - ID tokens, a UserInfo endpoint, JWKS, and
  discovery metadata (`/.well-known/openid-configuration`).
- **Client, Consent, and Policy Management** - A client registry with per-client grant types
  and scopes, plus a user consent model.
- **Security-by-design architecture** - Protocol-compliant, audited at every phase, with
  layered controls and operational tooling for production use.

## Architecture

```
├── backend/              OAuth 2.1 / OIDC Authorization Server (Node.js / Express, TypeScript)
├── frontend/             User-facing login, consent, and account UI (Next.js)
├── docs/                 Security documentation and architecture decisions
└── docker-compose.yml    Local development infrastructure (PostgreSQL, Redis)
```

## Security Principles

The platform is built in dependency order, lower layers first:

- Identity comes before OAuth.
- OAuth comes before tokens.
- Tokens come before the frontend.
- Security correctness takes priority over speed.
- No shortcuts and no temporary hacks in security-critical code.

## Non-Negotiable Security Decisions

- **Token format**: JWT only.
- **Signing**: Asymmetric, RS256 (pinned). There is no symmetric (HS256) or `alg: none` code
  path, so algorithm-confusion attacks are structurally impossible.
- **Access token lifetime**: 15 minutes or less.
- **Refresh tokens**: Rotating and single-use, with automatic family revocation on reuse and an
  absolute family lifetime cap.
- **Grant type**: Authorization Code with PKCE (S256) only. The implicit flow is not supported.
- **Redirect URIs**: Exact match only; no wildcards, no fragments.
- **Sessions**: Server-side (Redis), HttpOnly, SameSite cookies; Secure in production.
- **Secrets at rest**: Passwords and client secrets hashed with Argon2id; the JWT private key
  encrypted with AES-256-GCM; authorization codes and refresh tokens stored as SHA-256 hashes.

## Capabilities

- Authorization Code flow with mandatory PKCE (S256), state, and nonce handling.
- Single-use authorization codes, bound to client, redirect URI, and PKCE challenge, with
  reuse detection.
- Rotating single-use refresh tokens with family revocation and an absolute lifetime cap.
- Access-token revocation via a Redis `jti` deny-list (TTL equals the token's remaining life),
  enforced during verification.
- Token introspection (RFC 7662) and token revocation (RFC 7009) endpoints.
- OpenID Connect: ID tokens, UserInfo (gated on the `openid` scope), JWKS, and discovery.
- Zero-downtime signing-key rotation with a JWKS overlap window.
- Append-only audit logging (database-enforced), with no PII, secrets, or raw tokens recorded.
- Real-time security alerting (refresh-token reuse, login-failure and signature-failure
  spikes) to logs and an optional outbound webhook sink.
- Per-endpoint and platform-wide rate limiting, account lockout, and MFA.
- Layered CSRF protection (CORS origin allowlist, SameSite cookies, and a route-level Origin
  check on the consent submission).

## Technology Stack

- **Backend**: Node.js with Express (TypeScript)
- **Frontend**: Next.js 14 (App Router, TypeScript)
- **Database**: PostgreSQL 14+
- **Cache and sessions**: Redis
- **Package manager**: npm

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 0 | Complete | Foundation - project structure, configuration, security documentation |
| Phase 1 | Complete | Identity core - user registration, authentication, MFA, sessions |
| Phase 2 | Complete | Client and trust modeling - OAuth client registry, consent model |
| Phase 3 | Complete | Authorization Code flow - PKCE, state validation, code issuance |
| Phase 4 | Complete | Token service - JWT creation, access token issuance |
| Phase 5 | Complete | Refresh tokens and revocation - token rotation, reuse detection |
| Phase 6 | Complete | OpenID Connect - ID tokens, UserInfo endpoint, OIDC discovery |
| Phase 7 | Complete | Frontend and UX - login UI, consent UI, account dashboard |
| Phase 8 | Complete | Hardening and operations - audit logging, key rotation, alerting, introspection |

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Docker and Docker Compose
- PostgreSQL 14+ and Redis (provided via Docker Compose for local development)

### Setup

1. Install dependencies:

   ```bash
   # Backend
   cd backend
   npm install

   # Frontend
   cd ../frontend
   npm install
   ```

2. Start infrastructure:

   ```bash
   docker-compose up -d
   ```

3. Configure environment:

   ```bash
   # Backend
   cp backend/.env.example backend/.env

   # Frontend
   cp frontend/.env.example frontend/.env
   ```

4. Apply database migrations:

   ```bash
   cd backend
   npm run migrate
   ```

5. (Optional) Seed a demo user and client for end-to-end testing:

   ```bash
   npm run seed:demo
   ```

6. Run the applications:

   ```bash
   # Backend (http://localhost:3001)
   cd backend
   npm run dev

   # Frontend (http://localhost:3000)
   cd frontend
   npm run dev
   ```

## Operations

- **Tests**: `cd backend && npm test` (full suite, run against the local Postgres and Redis).
- **Type check and lint**: `npm run type-check` and `npm run lint` in `backend`.
- **Migration status**: `npm run migrate:status`.
- **Signing-key rotation**: `npm run rotate:keys` retires the current key with a JWKS overlap
  window; running servers pick up the new key within about 60 seconds via the active-key cache.
  Schedule this monthly.

## Documentation

- [Security Decisions](docs/SECURITY_DECISIONS.md) - Rationale for all security-critical choices.
- [Security Pass](docs/SECURITY_PASS.md) - Dependency audit, headers review, and pen-test checklist.
- [Phase Guide](docs/PHASE_GUIDE.md) - Detailed implementation roadmap.
- [Architecture](docs/ARCHITECTURE.md) - System design and component overview.

## Security Notice

This is security infrastructure, not an application feature.

Every decision has been vetted against OAuth 2.1, OpenID Connect Core 1.0, and modern security
best practices. Do not modify security-critical code without thorough threat modeling. See the
Security Pass document for accepted and deferred items (for example, CSP nonces and a future
Next.js major upgrade).

## License

To be determined.

## Contributing

This project follows a strict phase-gated development process. See the
[Phase Guide](docs/PHASE_GUIDE.md) for contribution guidelines.
