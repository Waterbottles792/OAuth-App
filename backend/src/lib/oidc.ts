/**
 * OpenID Connect helpers (Phase 6).
 *
 * The scope → claims mapping is the single source of truth for which identity claims are
 * released, and is shared by both the ID token and the /userinfo endpoint so the two can
 * never disagree. `sub` (the subject identifier) is always present and is added by the
 * callers, not here.
 *
 * The schema currently only holds `email` / `email_verified`, so `profile` yields no extra
 * claims yet; add to the `profile` branch when profile fields are introduced.
 */

/** The minimal user shape needed to populate identity claims. */
export interface ClaimsSource {
    email: string;
    email_verified: boolean;
}

export type IdentityClaims = Record<string, unknown>;

/** Build the scope-gated identity claims (excluding `sub`) for a user. */
export function buildIdentityClaims(user: ClaimsSource, scopes: string[]): IdentityClaims {
    const granted = new Set(scopes);
    const claims: IdentityClaims = {};

    if (granted.has('email')) {
        claims.email = user.email;
        claims.email_verified = user.email_verified;
    }
    // `profile` intentionally adds nothing yet — no profile columns exist.

    return claims;
}
