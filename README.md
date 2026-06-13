# OAuth 2.1 + OpenID Connect Authorization & Identity Platform

A production-grade Identity and Authorization Platform implementing OAuth 2.1 and OpenID Connect (OIDC) specifications with commercial-level security and compliance.

## Overview

This system provides:
- **OAuth 2.1 Authorization Server** - Secure token issuance and validation
- **OpenID Connect (OIDC) Identity Provider** - Enterprise-grade identity management
- **Client, Consent, and Policy Management** - Fine-grained access control
- **Security-by-design architecture** - Protocol-compliant and commercially viable

## Architecture

```
├── backend/         OAuth 2.1 Authorization Server (Node.js/Express)
├── frontend/        Admin UI and User Consent UI (Next.js)
├── docs/            Security documentation and architecture decisions
└── docker-compose.yml   Local development infrastructure
```

## Security Principles

This platform follows strict security principles:
- ✅ Identity comes before OAuth
- ✅ OAuth comes before tokens
- ✅ Tokens come before frontend
- ✅ Security correctness over speed
- ❌ No shortcuts, no temporary hacks

## Non-Negotiable Security Decisions

- **Token Format**: JWT only
- **Signing**: Asymmetric (RS256 or ES256)
- **Access Token Lifetime**: ≤ 15 minutes
- **Refresh Tokens**: Rotating, single-use
- **Grant Type**: Authorization Code + PKCE only
- **No Implicit Flow**: Explicitly forbidden
- **No Wildcard Redirect URIs**: Exact match only
- **Sessions**: Server-side only, HTTP-only, SameSite cookies

## Technology Stack

- **Backend**: Node.js with Express (TypeScript)
- **Frontend**: Next.js 14+ (App Router, TypeScript)
- **Database**: PostgreSQL 14+
- **Cache/Sessions**: Redis
- **Package Manager**: npm

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 0** | ✅ Complete | Foundation - Project structure, configuration, security documentation |
| **Phase 1** | ✅ Complete | Identity Core - User registration, authentication, MFA, sessions |
| **Phase 2** | ✅ Complete | Client & Trust Modeling - OAuth client registry, consent model |
| **Phase 3** | ✅ Complete | Authorization Code Flow - PKCE, state validation, code issuance |
| **Phase 4** | ⏳ Pending | Token Service - JWT creation, access token issuance |
| **Phase 5** | ⏳ Pending | Refresh Tokens & Revocation - Token rotation, reuse detection |
| **Phase 6** | ⏳ Pending | OpenID Connect - ID tokens, UserInfo endpoint, OIDC discovery |
| **Phase 7** | ⏳ Pending | Frontend & UX - Login UI, consent UI, developer dashboard |
| **Phase 8** | ⏳ Pending | Hardening & Operations - Audit logging, key rotation, monitoring |

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Docker and Docker Compose
- PostgreSQL 14+
- Redis

### Setup

1. **Clone and install dependencies**
   ```bash
   # Backend
   cd backend
   npm install
   
   # Frontend
   cd ../frontend
   npm install
   ```

2. **Start infrastructure**
   ```bash
   docker-compose up -d
   ```

3. **Configure environment**
   ```bash
   # Backend
   cp backend/.env.example backend/.env
   
   # Frontend
   cp frontend/.env.example frontend/.env
   ```

4. **Run applications**
   ```bash
   # Backend (http://localhost:3001)
   cd backend
   npm run dev
   
   # Frontend (http://localhost:3000)
   cd frontend
   npm run dev
   ```

## Documentation

- [Security Decisions](docs/SECURITY_DECISIONS.md) - Rationale for all security-critical choices
- [Phase Guide](docs/PHASE_GUIDE.md) - Detailed implementation roadmap
- [Architecture](docs/ARCHITECTURE.md) - System design and component overview

## Security Notice

⚠️ **This is security infrastructure, not an application feature.**

Every decision has been vetted against OAuth 2.1 (RFC 9500+), OpenID Connect Core 1.0, and modern security best practices. Do not modify security-critical code without thorough threat modeling.

## License

[To be determined]

## Contributing

This project follows a strict phase-gated development process. See [PHASE_GUIDE.md](docs/PHASE_GUIDE.md) for contribution guidelines.
