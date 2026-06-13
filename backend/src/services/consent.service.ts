/**
 * User consent records (Phase 2).
 *
 * Stores, per (user, client), the set of scopes the user has granted. Phase 3's
 * authorization endpoint will read this to decide whether the consent screen can be
 * skipped, and write to it when the user approves. The (user_id, client_id) pair is unique,
 * so granting again replaces the prior record.
 *
 * Note: `clientDbId` here is the oauth_clients.id (UUID), not the public client_id string.
 */

import { query } from '../db/pool';
import { scopesNotAllowed } from '../lib/oauth';

export interface ConsentRecord {
    user_id: string;
    client_id: string;
    scopes: string[];
    granted_at: Date;
}

/** Record (or replace) the scopes a user has granted to a client. */
export async function recordConsent(
    userId: string,
    clientDbId: string,
    scopes: string[],
): Promise<void> {
    await query(
        `INSERT INTO user_consents (user_id, client_id, scopes)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, client_id)
           DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = NOW()`,
        [userId, clientDbId, scopes],
    );
}

export async function getConsent(
    userId: string,
    clientDbId: string,
): Promise<ConsentRecord | null> {
    const { rows } = await query<ConsentRecord>(
        'SELECT user_id, client_id, scopes, granted_at FROM user_consents WHERE user_id = $1 AND client_id = $2',
        [userId, clientDbId],
    );
    return rows[0] ?? null;
}

/**
 * True if the user has already consented to every scope in `requiredScopes` for this client.
 * Used in Phase 3 to skip the consent screen when nothing new is being requested.
 */
export async function hasConsentFor(
    userId: string,
    clientDbId: string,
    requiredScopes: string[],
): Promise<boolean> {
    const consent = await getConsent(userId, clientDbId);
    if (!consent) return requiredScopes.length === 0;
    return scopesNotAllowed(requiredScopes, consent.scopes).length === 0;
}

export async function revokeConsent(userId: string, clientDbId: string): Promise<void> {
    await query('DELETE FROM user_consents WHERE user_id = $1 AND client_id = $2', [
        userId,
        clientDbId,
    ]);
}
