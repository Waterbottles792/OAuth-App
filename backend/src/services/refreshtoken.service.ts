/**
 * Refresh token issuance, rotation & revocation (Phase 5).
 *
 * Refresh tokens are opaque random strings (NOT JWTs). The raw token is returned to the
 * client once; only its SHA-256 hash is stored, so a DB dump never yields usable tokens.
 *
 * Security model (SECURITY_DECISIONS #4):
 *   - Single-use & rotating: every successful refresh marks the presented token `used` and
 *     mints a NEW token in the same family (parent_token_hash links the chain).
 *   - Reuse detection: presenting an already-`used` (or `revoked`) token means the chain was
 *     replayed — likely theft. We revoke the ENTIRE family so neither the attacker's nor the
 *     legitimate client's tokens keep working.
 *   - Bound to the issuing client: rotation only succeeds for the client the token was issued
 *     to (a mismatched client never burns or reveals the token).
 *   - 30-day max lifetime (oauthConfig.refreshTokens.lifetime).
 */

import { query } from '../db/pool';
import { oauthConfig } from '../config';
import { randomToken, sha256 } from '../lib/crypto';

const LIFETIME = oauthConfig.refreshTokens.lifetime; // seconds (30 days, LOCKED)

export interface RefreshTokenRecord {
    token_hash: string;
    user_id: string;
    client_id: string; // oauth_clients.id (UUID)
    scopes: string[];
    token_family_id: string;
    parent_token_hash: string | null;
    used: boolean;
    revoked: boolean;
    expires_at: Date;
    created_at: Date;
}

export interface IssueRefreshInput {
    userId: string;
    clientDbId: string; // oauth_clients.id (UUID), not the public client_id
    scopes: string[];
    /** Continue an existing rotation chain; omit to start a brand-new family. */
    familyId?: string;
    parentTokenHash?: string;
}

export interface IssuedRefreshToken {
    refreshToken: string; // raw token (returned to the client once)
    record: RefreshTokenRecord;
}

/**
 * Mint a refresh token, persist its hash, and return the raw token. If `familyId` is omitted
 * a new family is created (DB generates the UUID); otherwise the token joins that family as a
 * child of `parentTokenHash`.
 */
export async function issueRefreshToken(input: IssueRefreshInput): Promise<IssuedRefreshToken> {
    const token = randomToken(32);
    const tokenHash = sha256(token);

    const { rows } = await query<RefreshTokenRecord>(
        `INSERT INTO refresh_tokens
           (token_hash, user_id, client_id, scopes, token_family_id, parent_token_hash, expires_at)
         VALUES ($1, $2, $3, $4, COALESCE($5::uuid, gen_random_uuid()), $6,
                 NOW() + ($7 || ' seconds')::interval)
         RETURNING token_hash, user_id, client_id, scopes, token_family_id,
                   parent_token_hash, used, revoked, expires_at, created_at`,
        [
            tokenHash,
            input.userId,
            input.clientDbId,
            input.scopes,
            input.familyId ?? null,
            input.parentTokenHash ?? null,
            String(LIFETIME),
        ],
    );

    return { refreshToken: token, record: rows[0] };
}

/** Revoke every token in a family (idempotent). Used on reuse detection and by /revoke. */
export async function revokeFamily(familyId: string): Promise<void> {
    await query('UPDATE refresh_tokens SET revoked = TRUE WHERE token_family_id = $1', [familyId]);
}

export interface RotateResult {
    ok: boolean;
    reason?: 'not_found' | 'expired' | 'reused' | 'revoked' | 'client_mismatch';
    record?: RefreshTokenRecord;
}

/**
 * Atomically claim a refresh token for rotation. The token is valid only if it exists, was
 * issued to `clientDbId`, and is currently unused, unrevoked, and unexpired. On success it is
 * marked `used` (single-use) and its record is returned so the caller can mint the next token
 * in the family.
 *
 * The single-use flip is a conditional UPDATE, so two concurrent refreshes cannot both win.
 * On failure the reason is diagnosed; a `reused` or `revoked` token triggers family-wide
 * revocation (theft response).
 */
export async function rotateRefreshToken(rawToken: string, clientDbId: string): Promise<RotateResult> {
    const tokenHash = sha256(rawToken);

    const { rows } = await query<RefreshTokenRecord>(
        `UPDATE refresh_tokens
            SET used = TRUE
          WHERE token_hash = $1 AND client_id = $2
            AND used = FALSE AND revoked = FALSE AND expires_at > NOW()
        RETURNING token_hash, user_id, client_id, scopes, token_family_id,
                  parent_token_hash, used, revoked, expires_at, created_at`,
        [tokenHash, clientDbId],
    );

    if (rows[0]) return { ok: true, record: rows[0] };

    // Diagnose the failure (and, for reuse/revoked, revoke the whole family).
    const { rows: existing } = await query<{
        client_id: string;
        used: boolean;
        revoked: boolean;
        token_family_id: string;
        expired: boolean;
    }>(
        `SELECT client_id, used, revoked, token_family_id, (expires_at <= NOW()) AS expired
           FROM refresh_tokens WHERE token_hash = $1`,
        [tokenHash],
    );

    const row = existing[0];
    if (!row) return { ok: false, reason: 'not_found' };
    // Wrong client: never reveal or burn a token that isn't theirs.
    if (row.client_id !== clientDbId) return { ok: false, reason: 'client_mismatch' };
    if (row.revoked) {
        await revokeFamily(row.token_family_id);
        return { ok: false, reason: 'revoked' };
    }
    if (row.used) {
        // REUSE DETECTED — replay of a rotated token. Burn the family.
        await revokeFamily(row.token_family_id);
        return { ok: false, reason: 'reused' };
    }
    return { ok: false, reason: 'expired' };
}

export interface RevokeResult {
    found: boolean;
    familyId?: string;
}

/**
 * Revoke a single refresh token and its family, but only if it belongs to `clientDbId`
 * (RFC 7009: a client may only revoke its own tokens). Always safe to call; returns whether a
 * matching token existed. The /revoke endpoint responds 200 regardless, per the RFC.
 */
export async function revokeRefreshToken(rawToken: string, clientDbId: string): Promise<RevokeResult> {
    const tokenHash = sha256(rawToken);
    const { rows } = await query<{ token_family_id: string }>(
        'SELECT token_family_id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2',
        [tokenHash, clientDbId],
    );
    if (!rows[0]) return { found: false };
    await revokeFamily(rows[0].token_family_id);
    return { found: true, familyId: rows[0].token_family_id };
}
