# PLAN.md — Execution Roadmap & Context Anchor

> **This file is the single source of truth for "what to do next."**
> It is written so that any phase can be picked up cold — after a `/clear`, a new
> session, or by a different person — without needing the history of how earlier
> phases were built. Each phase block below is self-contained: it states what must
> already exist, what to build, and how to know you're done.

---

## How to use this file across context resets

The project is split into **independent phases**. Phases are sequential in
*dependency* but self-contained in *execution* — once Phase N is committed, you do
**not** need Phase N's conversation context to do Phase N+1. The code + this file
carry all the state forward.

**Workflow for each work session:**

1. **Orient (always do this first after a `/clear`):**
   - Read this file's **Current Status** table below.
   - Read the **one** phase block you're about to work on.
   - Read the referenced detail in `docs/PHASE_GUIDE.md` and `docs/SECURITY_DECISIONS.md`.
   - Skim the files listed under that phase's **"Files that already exist"**.
2. **Build** following the phase's steps. Do not implement anything from a later phase.
3. **Verify** against the phase's **Acceptance Criteria**.
4. **Close out before you `/clear`:**
   - Update the **Current Status** table (mark the phase ✅ and update "Last verified").
   - Tick the phase's **Definition of Done** checkboxes.
   - Add a one-line note under the phase's **Handoff Notes** for anything the next
     session must know that isn't obvious from the code (decisions, gotchas, deferrals).
   - Commit with a `feat: Phase N - <summary>` message.

**Safe-to-`/clear` rule:** You can clear context between any two phases. You should
*not* `/clear` in the middle of a phase — finish the phase's Definition of Done first,
because partial work that isn't committed + recorded here is the only thing that loses
quality on a reset.

---

## Project assessment (read once, then it's just context)

**What this is:** A from-scratch OAuth 2.1 + OpenID Connect authorization server and
identity provider, built phase-by-phase with a security-first, no-shortcuts philosophy.
Backend is Node/Express/TypeScript; frontend is Next.js 14; PostgreSQL + Redis via Docker.

**Honest state today (Phase 0 complete):**
- ✅ **Documentation is genuinely excellent** — `SECURITY_DECISIONS.md`, `ARCHITECTURE.md`,
  and `PHASE_GUIDE.md` are more thorough than most production projects. The locked
  security decisions (RS256-only, PKCE-mandatory, exact redirect match, rotating
  refresh tokens, server-side sessions) are all correct and modern.
- ✅ **Scaffolding is clean** — `backend/src/server.ts` + `backend/src/config/index.ts`
  have sensible Helmet/CORS/config-validation. `.env` is gitignored (verified). Good hygiene.
- ⚠️ **It is still 100% scaffolding.** There is no database connection, no migrations,
  no auth, no tests, no validation layer. Everything below this line is greenfield.

**Gaps the docs don't yet resolve (decisions to lock in Phase 1, see Phase 1 block):**
- **No migration tooling chosen.** Recommend plain SQL files + `node-pg-migrate` (or a
  tiny custom runner). Pick one in Phase 1 and never look back.
- **No test framework.** Recommend `vitest` + `supertest`. Security code without tests
  is a liability — add it in Phase 1 so every later phase ships with tests.
- **No input-validation library.** Recommend `zod` for all request bodies/queries.
- **No DB client wiring.** `pg` is a dependency but no pool is created. Phase 1 owns this.
- **Email delivery is unspecified** (registration says "send verification email").
  Recommend deferring real email: in dev, log the verification link; abstract behind a
  `mailer` interface so production SMTP drops in later.
- **`argon2` is a native module** — fine on this Linux box, just be aware on CI.

**Overall:** Strong foundation, realistic and well-sequenced plan. The main risk is
scope ambition vs. follow-through. The phase-gating is the right antidote; this file
makes it survivable across context resets.

---

## Current Status

| Phase | Title | Status | Last verified |
|------:|-------|--------|---------------|
| 0 | Foundation | ✅ Complete | 2026-02-02 |
| 1 | Identity Core (+ project infra: DB layer, migrations, tests, validation) | ✅ Complete | 2026-06-13 |
| 2 | Client & Trust Modeling | ✅ Complete | 2026-06-13 |
| 3 | Authorization Code Flow (PKCE) | ⏳ Not started | — |
| 4 | Token Service (JWT issuance) | ⏳ Not started | — |
| 5 | Refresh Tokens & Revocation | ⏳ Not started | — |
| 6 | OpenID Connect | ⏳ Not started | — |
| 7 | Frontend & UX | ⏳ Not started | — |
| 8 | Hardening & Operations | ⏳ Not started | — |

**Dependency graph (what truly blocks what):**
```
0 ──> 1 ──> 2 ──> 3 ──> 4 ──> 5 ──> 6
                              │
                              └────────> 7 (needs 1; richer with 2–6)
                                          8 (cross-cutting; do last)
```
- Phases 1→6 are a strict chain (each builds on the prior).
- **Phase 7 (frontend)** only hard-depends on Phase 1; it can be built incrementally
  alongside 2–6. Treat it as a parallel track if you prefer UI feedback early.
- **Phase 8 (hardening)** is cross-cutting and intentionally last.

---

## Conventions that apply to every phase (the "house rules")

These are stable across the whole project — internalize once.

- **Source of detail:** `docs/PHASE_GUIDE.md` holds the SQL schemas, endpoint shapes,
  and security checklists per phase. This file points to it; it is not duplicated here.
- **Locked decisions:** `docs/SECURITY_DECISIONS.md` decisions are non-negotiable.
  Re-read the relevant ones at the start of each phase. Never weaken them for convenience.
- **Backend layout** (target structure, created incrementally):
  ```
  backend/src/
    config/        index.ts (exists)
    db/            pool.ts, migrate.ts, migrations/*.sql   (Phase 1 creates)
    services/      *.service.ts   (business logic, no Express types)
    middleware/    *.middleware.ts
    routes/        *.routes.ts    (thin; delegate to services)
    lib/           crypto, validation schemas (zod), errors
    __tests__/     or *.test.ts colocated
  ```
- **Validation:** every external input goes through a `zod` schema. No raw `req.body`.
- **Errors:** throw typed errors (e.g. `AppError` with an OAuth-style code); the global
  handler in `server.ts` maps them to safe responses. Never leak stack traces in prod.
- **Secrets/keys:** never written to the repo. `keys/`, `*.pem`, `*.key` are gitignored.
- **Tests:** each phase ships with tests for its security-critical paths. A phase isn't
  "done" if its security checklist items are untested.
- **Don't bleed phases:** if you find yourself writing `/token` logic during Phase 3, stop.

---

## Phase 1 — Identity Core (+ foundational infra)

**Goal:** Secure user authentication that is completely independent of OAuth. This phase
*also* lays the project-wide infrastructure (DB pool, migration runner, test harness,
validation) because Phase 1 is the first phase that touches the database.

**Status:** ⏳ Not started

### Files that already exist (your starting point)
- `backend/src/server.ts` — Express app, Helmet, CORS, logging, error handlers. You will
  mount new routers here and add `cookie-parser` + rate limiting.
- `backend/src/config/index.ts` — `databaseConfig`, `redisConfig`, `securityConfig.session`
  already defined (currently unused). Wire them up; don't redefine them.
- `docker-compose.yml` — Postgres 14 + Redis 7 already configured (creds in the file).
- `docs/PHASE_GUIDE.md` → "Phase 1" — has the **exact SQL** for `users`, `sessions`,
  `mfa_secrets`, the endpoint list, and the security checklist. **Build to that.**
- `docs/SECURITY_DECISIONS.md` → decisions #8 (server-side sessions) and #9 (cookies).

### Decisions to lock at the start of this phase (then record under Handoff Notes)
- Migration tool: **recommend** plain `.sql` files in `backend/src/db/migrations/` run by
  a small `migrate.ts` (or adopt `node-pg-migrate`). Pick one.
- Test runner: **recommend** `vitest` + `supertest`. Add `npm test` script.
- Validation: add `zod`. Session store: `connect-redis` + `express-session`, or a custom
  Redis-backed session service (PHASE_GUIDE lists `express-session`/`connect-redis` deps).

### Build steps
1. **Infra:** create `backend/src/db/pool.ts` (pg Pool from `databaseConfig`), a migration
   runner, and the Phase-1 migration with the three tables from PHASE_GUIDE. Add a Redis
   client. Add `vitest` + `supertest` and a smoke test hitting `/health`.
2. **Password service** (`services/password.service.ts`) — Argon2id, params m=64MB, t=3, p=4.
3. **Session service** (`services/session.service.ts`) — 32-byte random token, stored
   **hashed** in Redis with TTL; sliding 24h expiry; cookie flags from `securityConfig`.
4. **MFA service** (`services/mfa.service.ts`) — TOTP (`speakeasy`), QR (`qrcode`), 10
   single-use hashed backup codes.
5. **Auth service + routes** — `register`, `login`, `logout`, `mfa/enable`, `mfa/verify`
   per PHASE_GUIDE endpoint shapes.
6. **Middleware** — `auth.middleware.ts` (validate session cookie → attach user),
   `rateLimit.middleware.ts` (5 login attempts / 15 min / IP; account lockout after 5,
   unlock after 1h).
7. Mount routers in `server.ts`; add `cookie-parser`.

### Acceptance criteria
- [ ] `docker-compose up -d` + migration creates `users`, `sessions`, `mfa_secrets`.
- [ ] Register → login → access an auth-protected test route → logout, all work via cookies.
- [ ] Passwords stored as Argon2id hashes; no plaintext anywhere.
- [ ] Session token is **hashed** in Redis; cookie is `HttpOnly`, `SameSite=Lax`.
- [ ] 6th failed login within window is rate-limited; account locks after 5 fails.
- [ ] MFA enable returns QR + backup codes; verify accepts a valid TOTP and rejects reuse.
- [ ] Tests cover: password hash/verify, session create/validate/expire, rate-limit, MFA.
- [ ] **No** OAuth/token/client code added.

### Definition of Done
- [x] All acceptance criteria pass and `npm test` is green. **22/22 passing.**
- [x] Phase 1 security checklist in `docs/PHASE_GUIDE.md` fully ticked.
- [x] Update Current Status table + Last verified date in this file.
- [x] Handoff Notes filled in. Commit `feat: Phase 1 - Identity Core`.

### Handoff Notes (filled in 2026-06-13)
- **Migration tool chosen:** plain `.sql` files in `backend/src/db/migrations/` run by a
  custom runner `backend/src/db/migrate.ts` (tracks applied files in `schema_migrations`,
  each migration in a transaction). Scripts: `npm run migrate`, `npm run migrate:status`.
  First migration: `001_identity_core.sql`.
- **Test runner chosen:** `vitest` + `supertest`. Config `backend/vitest.config.ts` runs
  **serially / single fork** (shared dev Postgres+Redis). Global setup
  `backend/src/test/setup.ts` runs migrations once, then per-test TRUNCATEs `users`
  (cascades) and clears Redis keys (`session:*`, `mfa_challenge:*`, `ratelimit:*`).
  Run with `npm test`. **Tests hit the live dev DB/Redis** — don't point them at real data.
- **Library / design choices:**
  - Sessions are a **custom Redis-backed service** (not `express-session`). Raw 32-byte
    token in a signed `HttpOnly; SameSite=Lax` cookie named `sid`; only `sha256(token)` is
    stored (Redis is source of truth + a Postgres `sessions` audit row). Sliding 24h TTL.
  - Cookie signing uses `cookie-parser` with `SESSION_SECRET` (dev fallback in config;
    **required in production** by `validateConfig`).
  - Argon2id params live in `authConfig` (`config/index.ts`): m=64MB, t=3, p=4.
  - **MFA endpoint deviation from PHASE_GUIDE:** enrollment is two steps —
    `POST /mfa/enable` (returns QR + 10 backup codes, not yet active) then
    `POST /mfa/verify` (confirms a TOTP, flips `enabled_at`). Login second-factor is a
    **separate** endpoint `POST /mfa/login` driven by a short-lived `mfa_pending` cookie
    (Redis challenge), so no real session exists until MFA passes. Backup codes are
    single-use (consumed on use).
  - Defense in depth on brute force: **per-account DB lockout** (5 fails → `locked_at`, 1h)
    AND **per-IP+email Redis rate limit** (5 / 15 min) in middleware (fail-open if Redis down).
  - Typed errors in `lib/errors.ts` (`AppError` + subclasses). **Gotcha fixed:** the base
    constructor must use `Object.setPrototypeOf(this, new.target.prototype)` or subclass
    `instanceof` breaks after TS downleveling — this silently broke the rate limiter.
  - Email verification is **stubbed**: `lib/mailer.ts` dev mailer logs the link to console;
    `users.email_verified` defaults false and is **not yet enforced** at login. Real SMTP +
    a `/verify-email` handler + enforcement are deferred (revisit in Phase 7/8).
  - Added `is_admin` column to `users` now (used by `requireAdmin` middleware) so Phase 2's
    admin-only client routes have a guard ready.
- **Anything Phase 2 needs to know:** reuse `db/pool.ts` (`query`, `withTransaction`),
  `db/redis.ts`, `lib/validation.ts` (zod + `validate()`), `lib/errors.ts`, and the
  `requireAuth` / `requireAdmin` middleware. Add migration `002_*.sql`. Don't re-scaffold
  infra. To make an admin in dev: `UPDATE users SET is_admin = true WHERE email = '...'`.

---

## Phase 2 — Client & Trust Modeling

**Goal:** Define *who* is allowed to request access. OAuth client registry + scopes +
consent records. **Still no `/authorize`, no codes, no tokens.**

**Status:** ⏳ Not started

### Prerequisites
- Phase 1 done: there is a `users` table, an admin-capable auth/session system, the DB
  pool, migration runner, validation, and test harness. (If any is missing, you cleared
  too early — check the Phase 1 Handoff Notes / Current Status before proceeding.)

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 2" — exact SQL for `oauth_clients`, `oauth_scopes`,
  `user_consents`, the admin endpoint shapes, and the checklist.
- `docs/SECURITY_DECISIONS.md` → #5 (PKCE), #7 (exact redirect URIs).
- Reuse the Phase 1 DB pool, migration runner, validation, and auth middleware. Do not
  re-scaffold infrastructure.

### Build steps
1. New migration: `oauth_clients`, `oauth_scopes`, `user_consents` (per PHASE_GUIDE).
2. `services/client.service.ts` — create client (generate `client_id`; for confidential
   clients generate a secret and store **only its Argon2id hash**, return plaintext once),
   get, delete. Validate redirect URIs are **exact** (no `*`, no wildcard ports).
3. `services/consent.service.ts` — record/lookup per (user, client) granted scopes.
4. Admin-only routes (`routes/clients.routes.ts`) guarded by auth middleware + an admin check.
5. Seed a few default scopes (e.g. `read:profile`, `write:profile`, `openid`, `email`).

### Acceptance criteria
- [ ] Admin can create a confidential client and receives the secret exactly once.
- [ ] Client secret is stored hashed; redirect URIs reject wildcards on create.
- [ ] Public clients have `require_pkce = true`; scope requests are validated against the
      client's `allowed_scopes`.
- [ ] Consent records are unique per (user, client) and store granted scopes.
- [ ] Tests cover client create/validate, redirect-URI exact-match, secret hashing.
- [ ] **No** `/authorize`, codes, or tokens added.

### Definition of Done
- [x] Acceptance criteria pass; Phase 2 checklist in PHASE_GUIDE ticked. **41/41 tests pass.**
- [x] Update Current Status + Handoff Notes. Commit `feat: Phase 2 - Client & Trust Modeling`.

### Handoff Notes (filled in 2026-06-13)
- **Migration:** `002_oauth_clients.sql` → `oauth_clients`, `oauth_scopes`, `user_consents`.
  A DB CHECK constraint enforces "confidential ⇒ has secret hash, public ⇒ no secret hash".
  Test setup now truncates `users, oauth_clients` (cascades to consents/sessions/mfa);
  seeded `oauth_scopes` are left intact.
- **Default scopes seeded:** `openid`, `profile`, `email`, `read:profile`, `write:profile`.
  A client's `allowedScopes` must be a subset of these (validated in `client.service`).
- **Admin-role mechanism:** a boolean `is_admin` column on `users` (added in Phase 1's
  migration). `requireAdmin` middleware guards the client routes. **To make an admin in dev:**
  `UPDATE users SET is_admin = true WHERE email = '...'`. No self-serve admin signup (by design).
- **Client model & rules:**
  - `client_id` = `client_<random>` (public id); confidential clients also get a
    `client_secret` (random 32B) returned **once** at creation and stored only as an
    **Argon2id hash** (reuses `password.service.hashPassword`/`verifyPassword`).
  - **PKCE is forced `require_pkce = TRUE` for every client** (honors SEC_DECISIONS #5,
    which is stricter than PHASE_GUIDE's "recommended for confidential"). Clients cannot
    disable it. Noted as a deliberate deviation.
  - **Redirect URIs** validated at registration (`lib/oauth.ts`): absolute http/https only,
    no `*`, no URL fragment, http allowed only for loopback hosts. Exact-match (no wildcards).
- **New shared helpers for Phase 3** (already written + unit-tested, not yet enforced):
  `lib/oauth.ts` → `validateRedirectUri`, `redirectUriMatches(registered, provided)`,
  `scopesNotAllowed(requested, allowed)`. `client.service.verifyClientSecret` exists for the
  Phase 4 token endpoint. `consent.service` → `recordConsent` / `getConsent` /
  `hasConsentFor` / `revokeConsent` (keyed on the oauth_clients **UUID** `id`, not the
  public `client_id` string — important).
- **Endpoints added:** `POST/GET /api/v1/clients`, `GET/DELETE /api/v1/clients/:clientId`,
  all behind `requireAuth + requireAdmin` (mounted in `server.ts`).
- **Anything Phase 3 needs:** read a client with `client.service.getClientByClientId(clientId)`
  (returns the full record incl. `redirect_uris`, `allowed_scopes`, `require_pkce`). Use the
  `lib/oauth.ts` helpers to validate the incoming `redirect_uri` (exact match) and that the
  requested `scope` ⊆ `allowed_scopes`. Write consent with `consent.service` using the
  client's UUID `id`. Add migration `003_*.sql` for `authorization_codes`. Still **no tokens**.

---

## Phase 3 — Authorization Code Flow (PKCE)

**Goal:** Issue authorization codes securely via `/authorize`. **Codes only — still NO tokens.**

**Status:** ⏳ Not started

### Prerequisites
- Phase 2 done: `oauth_clients`, `oauth_scopes`, `user_consents` exist; client + consent
  services work; auth middleware can tell whether a user is logged in.

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 3" — `authorization_codes` SQL, `/authorize` GET+POST
  shapes, code requirements, checklist.
- `docs/SECURITY_DECISIONS.md` → #5 (PKCE S256 only), #6 (no implicit), #7 (exact redirect).
- `docs/ARCHITECTURE.md` → "Flow 3" — the full step-by-step authorize sequence.

### Build steps
1. Migration: `authorization_codes` (code stored as **SHA-256 hash**, bound to client_id,
   redirect_uri, PKCE challenge; 10-min expiry; single-use flag).
2. `GET /api/v1/oauth/authorize` — validate `client_id`, **exact** `redirect_uri`,
   `response_type=code`, `scope` ⊆ client scopes, `state`, `code_challenge`,
   `code_challenge_method=S256` (reject `plain`). If not authenticated → redirect to login.
   If consent missing → show/return consent step.
3. `POST /api/v1/oauth/authorize` (consent submission) — on approve, generate code, store
   hashed, redirect to `redirect_uri?code=…&state=…`.
4. Errors must use OAuth error redirects (`error=…&state=…`) where the redirect_uri is valid.

### Acceptance criteria
- [ ] Unauthenticated authorize request redirects to login, then resumes.
- [ ] `code_challenge_method=plain` is rejected; only `S256` accepted.
- [ ] Mismatched/wildcard `redirect_uri` is rejected (no redirect to attacker URI).
- [ ] `state` is echoed back unchanged; missing `state` handled per policy.
- [ ] Code is single-use, 10-min TTL, stored hashed, bound to client+redirect+challenge.
- [ ] Tests cover PKCE method enforcement, redirect exact-match, code single-use/expiry.
- [ ] **No** `/token` endpoint, no JWTs.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 3 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status + Handoff Notes. Commit `feat: Phase 3 - Authorization Code Flow`.

### Handoff Notes
- _Consent UX approach for now (API-only vs minimal page):_ …
- _Where the code-challenge is persisted for Phase 4 verification:_ …
- _Anything Phase 4 needs:_ …

---

## Phase 4 — Token Service (JWT issuance)

**Goal:** Exchange an authorization code for a short-lived JWT access token at `/token`.
**Access tokens only — no refresh tokens (Phase 5), no ID tokens (Phase 6).**

**Status:** ⏳ Not started

### Prerequisites
- Phase 3 done: `/authorize` issues valid, hashed, PKCE-bound authorization codes.

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 4" — `jwt_keys` SQL, `/token` shape, JWT structure, checklist.
- `docs/SECURITY_DECISIONS.md` → #1 (JWT), #2 (RS256/ES256 only, never HS256/none),
  #3 (≤15 min lifetime). `config.oauthConfig.tokens` already encodes these — read it.

### Build steps
1. Migration: `jwt_keys` (kid, alg, public_key, **encrypted** private_key, active, rotation).
2. Key management: generate an RS256 (or ES256) keypair on first run; store the private key
   **encrypted at rest** (key from env), never in the repo (`keys/` is gitignored). Expose
   the current signing `kid`.
3. `services/token.service.ts` — `signAccessToken(claims)` with `iss/sub/aud/exp/iat/scope/
   client_id`, `exp = iat + 900` (use `oauthConfig.tokens.accessTokenLifetime`, do not hardcode).
4. `POST /api/v1/oauth/token` (`grant_type=authorization_code`) — validate: code exists &
   unused & unexpired; client credentials (confidential); `redirect_uri` matches; **PKCE
   `code_verifier` hashes to the stored `code_challenge`**. On success: mark code used,
   return `{ access_token, token_type: "Bearer", expires_in: 900 }`.

### Acceptance criteria
- [ ] Valid code + correct `code_verifier` returns a verifiable RS256/ES256 JWT.
- [ ] Wrong `code_verifier` → rejected. Reused code → rejected (and ideally flags abuse).
- [ ] JWT verifies against the public key; `alg` is RS256/ES256; `exp − iat = 900`.
- [ ] Private key is encrypted at rest and absent from version control.
- [ ] `HS256` and `alg: none` are impossible to produce or accept.
- [ ] Tests cover code→token happy path, PKCE failure, code reuse, JWT claim/exp/signature.
- [ ] **No** refresh tokens, ID tokens, or userinfo.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 4 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status + Handoff Notes. Commit `feat: Phase 4 - Token Service`.

### Handoff Notes
- _Algorithm chosen (RS256/ES256) & key-encryption approach:_ …
- _Current signing `kid`:_ …
- _Anything Phase 5/6 needs (esp. how to add a `refresh_token` grant later):_ …

---

## Phase 5 — Refresh Tokens & Revocation

**Goal:** Add rotating, single-use refresh tokens with reuse detection and token-family
revocation. Add `/revoke`.

**Status:** ⏳ Not started

### Prerequisites
- Phase 4 done: `/token` issues access-token JWTs; key management exists.

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 5" — `refresh_tokens` SQL, the rotation pseudocode, checklist.
- `docs/SECURITY_DECISIONS.md` → #4 (rotating single-use refresh tokens + family revocation).
- `docs/ARCHITECTURE.md` → "Flow 4".

### Build steps
1. Migration: `refresh_tokens` (token **hash** PK, user_id, client_id, scopes,
   `token_family_id`, `parent_token_hash`, `used`, `revoked`, 30-day `expires_at`).
2. Extend code→token exchange (Phase 4) to also issue a refresh token (new family).
3. Add `grant_type=refresh_token` to `/token`: look up by hash → if `used` or `revoked`,
   **revoke the whole family** and reject (reuse detection) → else mark used, issue new
   access + new refresh token in the same family (set `parent_token_hash`).
4. `POST /api/v1/oauth/revoke` — revoke a token (and its family where appropriate).

### Acceptance criteria
- [ ] Refresh rotates: each use returns a new refresh token; the old one is now invalid.
- [ ] Presenting an already-used refresh token revokes the entire family.
- [ ] Refresh tokens are hashed in the DB; 30-day max lifetime enforced.
- [ ] `/revoke` invalidates tokens; revoked tokens can't mint access tokens.
- [ ] Tests cover rotation, reuse→family-revocation, expiry, revoke.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 5 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status + Handoff Notes. Commit `feat: Phase 5 - Refresh Tokens & Revocation`.

### Handoff Notes
- _How families are keyed; any Redis blacklist used for access tokens:_ …
- _Anything Phase 6 needs:_ …

---

## Phase 6 — OpenID Connect

**Goal:** Layer identity on top of OAuth: ID tokens, `/userinfo`, discovery, JWKS.

**Status:** ⏳ Not started

### Prerequisites
- Phase 5 done (or at minimum Phase 4): access tokens + key management exist.

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 6" — endpoints, ID token structure, checklist.
- `docs/SECURITY_DECISIONS.md` → #2 (same signing as access tokens).
- `docs/ARCHITECTURE.md` → "Flow 5" (resource access / JWT validation via JWKS).

### Build steps
1. Support `scope=openid …` in `/authorize`; thread `nonce` through code → ID token.
2. ID token issuance in `/token` when `openid` scope present (`iss/sub/aud/exp/iat/nonce`
   + scope-gated `email`, `email_verified`, etc.). Sign with the same keys as access tokens.
3. `GET /api/v1/oauth/userinfo` — requires a valid access token; returns scope-gated claims.
4. `GET /.well-known/openid-configuration` — discovery document.
5. `GET /.well-known/jwks.json` — public keys (kty/use/kid/n/e), **no auth**.

### Acceptance criteria
- [ ] `openid` scope yields a signed ID token containing the request's `nonce`.
- [ ] `/userinfo` rejects missing/invalid tokens; returns only scope-permitted claims.
- [ ] JWKS serves the current public key(s); discovery doc validates against an OIDC validator.
- [ ] ID token signature verifies via the JWKS endpoint.
- [ ] Tests cover nonce passthrough, userinfo auth, JWKS/discovery correctness.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 6 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status + Handoff Notes. Commit `feat: Phase 6 - OpenID Connect`.

### Handoff Notes
- _`iss` value used; claim-to-scope mapping:_ …
- _Anything Phase 7 needs (endpoints to call):_ …

---

## Phase 7 — Frontend & UX

**Goal:** User-facing login, consent, and a developer dashboard for client management.
**Parallel-track friendly:** needs only Phase 1 to start; gets richer as 2–6 land.

**Status:** ⏳ Not started

### Prerequisites
- Phase 1 (auth) for login/MFA screens. Consent screen needs Phase 3; client dashboard
  needs Phase 2; "sign in with" demo needs Phase 4+/6.

### Files / refs that matter
- `frontend/app/page.tsx`, `frontend/app/layout.tsx` — current placeholder app.
- `docs/PHASE_GUIDE.md` → "Phase 7"; `docs/ARCHITECTURE.md` → frontend security boundaries.
- `docs/SECURITY_DECISIONS.md` → #8, #9 (no tokens in localStorage; HttpOnly cookies only).

### Build steps
1. `/login` (+ MFA prompt), `/consent`, `/dashboard` (client CRUD), profile, MFA setup.
2. All session state via the backend's **HttpOnly cookies** — never store tokens in JS.
3. CSRF tokens on state-changing forms; configure CSP; ensure same-origin/credentialed fetches.

### Acceptance criteria
- [ ] Login/consent/dashboard flows work end-to-end against the backend.
- [ ] No token or session value is ever placed in `localStorage`/`sessionStorage` (grep to prove it).
- [ ] CSRF protection on forms; CSP headers present.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 7 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status + Handoff Notes. Commit `feat: Phase 7 - Frontend & UX`.

### Handoff Notes
- _Which backend phases the UI currently exercises:_ …

---

## Phase 8 — Hardening & Operations

**Goal:** Production readiness: audit logging, key rotation, monitoring, full rate limiting.

**Status:** ⏳ Not started

### Prerequisites
- The flows you intend to ship (ideally 1–6) are implemented.

### Files / refs that matter
- `docs/PHASE_GUIDE.md` → "Phase 8"; `docs/ARCHITECTURE.md` → monitoring, DR, scalability.

### Build steps
1. Immutable `audit_logs` table; log every auth/OAuth decision (login, consent, issue,
   refresh, revoke, reuse-detected).
2. Automated JWT key rotation (overlap window; old `kid` still served via JWKS until expiry).
3. Rate limiting on **all** endpoints; alerting hooks for the anomalies in ARCHITECTURE.md
   (login-failure spikes, refresh reuse, code reuse, signature failures).
4. Security pass: dependency audit, headers review, pen-test checklist.

### Acceptance criteria
- [ ] Audit log is append-only and captures the full event set; no PII/secret leakage in logs.
- [ ] Key rotation works with zero-downtime validation (old + new keys both verify during overlap).
- [ ] Rate limits enforced platform-wide; alert conditions fire in tests.

### Definition of Done
- [ ] Acceptance criteria pass; Phase 8 checklist in PHASE_GUIDE ticked.
- [ ] Update Current Status. Commit `feat: Phase 8 - Hardening & Operations`.

### Handoff Notes
- _Rotation cadence & overlap window; log sink:_ …

---

## Quick reference

- **Start backend:** `cd backend && npm run dev` → http://localhost:3001
- **Start frontend:** `cd frontend && npm run dev` → http://localhost:3000
- **Infra:** `docker-compose up -d` (Postgres :5432, Redis :6379)
- **Health:** `curl http://localhost:3001/health`
- **Detail docs:** `docs/PHASE_GUIDE.md` (how) · `docs/SECURITY_DECISIONS.md` (why/locked) · `docs/ARCHITECTURE.md` (shape)

_Last updated: 2026-06-13 (plan created; project at Phase 0 complete)._
