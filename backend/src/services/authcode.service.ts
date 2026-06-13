/**
 * Authorization code issuance & consumption (Phase 3).
 *
 * The raw code is returned to the caller (to be put in the redirect) and only its SHA-256
 * hash is stored. A code is single-use and short-lived, and carries everything the token
 * endpoint (Phase 4) will need to validate the exchange: the bound client, user, redirect
 * URI, granted scopes, and the PKCE code_challenge (method is always S256 — enforced by a
 * DB CHECK constraint).
 *
 * NOTE: this is the data layer only. There is intentionally NO token endpoint here — the
 * PKCE code_verifier check and token issuance happen in Phase 4.
 */

import { query } from '../db/pool';
import { oauthFlowConfig } from '../config';
import { randomToken, sha256 } from '../lib/crypto';

export interface IssueCodeInput {
    clientDbId: string; // oauth_clients.id (UUID), not the public client_id
    userId: string;
    redirectUri: string;
    scopes: string[];
    codeChallenge: string;
}

export interface AuthorizationCodeRecord {
    code_hash: string;
    client_id: string;
    user_id: string;
    redirect_uri: string;
    scopes: string[];
    code_challenge: string;
    code_challenge_method: string;
    used: boolean;
    expires_at: Date;
    created_at: Date;
}

/** Create a code, persist its hash, and return the raw code for the redirect. */
export async function issueCode(input: IssueCodeInput): Promise<string> {
    const code = randomToken(32);
    const codeHash = sha256(code);
    const ttl = oauthFlowConfig.authorizationCodeTtlSeconds;

    await query(
        `INSERT INTO authorization_codes
           (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'S256', NOW() + ($7 || ' seconds')::interval)`,
        [
            codeHash,
            input.clientDbId,
            input.userId,
            input.redirectUri,
            input.scopes,
            input.codeChallenge,
            String(ttl),
        ],
    );

    return code;
}

export interface ConsumeResult {
    ok: boolean;
    reason?: 'not_found' | 'expired' | 'already_used';
    record?: AuthorizationCodeRecord;
}

/**
 * Atomically consume a code: it is valid only if it exists, is unused, and is unexpired.
 * On success it is marked used (single-use) and the record is returned. This is the
 * function Phase 4's token endpoint will call before verifying the PKCE verifier.
 *
 * Implemented as a conditional UPDATE so concurrent exchanges can't both win the race.
 */
export async function consumeCode(rawCode: string): Promise<ConsumeResult> {
    const codeHash = sha256(rawCode);

    // Single round-trip: flip used=true only if currently unused & unexpired, returning the row.
    const { rows } = await query<AuthorizationCodeRecord>(
        `UPDATE authorization_codes
            SET used = TRUE
          WHERE code_hash = $1 AND used = FALSE AND expires_at > NOW()
        RETURNING code_hash, client_id, user_id, redirect_uri, scopes,
                  code_challenge, code_challenge_method, used, expires_at, created_at`,
        [codeHash],
    );

    if (rows[0]) return { ok: true, record: rows[0] };

    // Distinguish why it failed (for logging / reuse detection in Phase 4).
    const { rows: existing } = await query<{ used: boolean; expired: boolean }>(
        `SELECT used, (expires_at <= NOW()) AS expired FROM authorization_codes WHERE code_hash = $1`,
        [codeHash],
    );
    if (!existing[0]) return { ok: false, reason: 'not_found' };
    if (existing[0].used) return { ok: false, reason: 'already_used' };
    return { ok: false, reason: 'expired' };
}
