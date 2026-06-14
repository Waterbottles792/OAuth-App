/**
 * OAuth client registry (Phase 2).
 *
 * Clients are the applications allowed to request access. Two types:
 *   - confidential: can keep a secret (server-side apps). Gets a client_secret, stored only
 *     as an Argon2id hash; the plaintext is returned exactly once at creation.
 *   - public: cannot keep a secret (SPAs, mobile). No secret; PKCE is mandatory.
 *
 * Security rules enforced here:
 *   - redirect URIs are validated for exact-match safety (no wildcards) — SEC_DECISIONS #7
 *   - PKCE is required for ALL clients — SEC_DECISIONS #5 (require_pkce is forced TRUE)
 *   - requested allowed_scopes must exist in the oauth_scopes catalogue
 */

import { query } from '../db/pool';
import { ValidationError, ConflictError } from '../lib/errors';
import { randomToken } from '../lib/crypto';
import { validateRedirectUri } from '../lib/oauth';
import { hashPassword, verifyPassword } from './password.service';

export type ClientType = 'confidential' | 'public';

export interface ClientRecord {
    id: string;
    client_id: string;
    name: string;
    client_secret_hash: string | null;
    client_type: ClientType;
    redirect_uris: string[];
    allowed_scopes: string[];
    allowed_grant_types: string[];
    require_pkce: boolean;
    created_at: Date;
}

/** Public view of a client — never includes the secret hash. */
export type ClientPublic = Omit<ClientRecord, 'client_secret_hash'>;

/** Grant types this authorization server supports (and therefore can be granted to a client). */
export const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;

export interface CreateClientInput {
    name: string;
    clientType: ClientType;
    redirectUris: string[];
    allowedScopes?: string[];
    /** Defaults to the full supported set; refresh tokens are only issued/honored if included. */
    allowedGrantTypes?: string[];
}

const PUBLIC_COLUMNS =
    'id, client_id, name, client_type, redirect_uris, allowed_scopes, allowed_grant_types, require_pkce, created_at';

function toPublic(row: ClientRecord): ClientPublic {
    // Strip the secret hash explicitly.
    const { client_secret_hash: _omit, ...rest } = row;
    return rest;
}

/** Throw unless every requested scope exists in the oauth_scopes catalogue. */
async function assertScopesExist(scopes: string[]): Promise<void> {
    if (scopes.length === 0) return;
    const { rows } = await query<{ name: string }>('SELECT name FROM oauth_scopes WHERE name = ANY($1)', [
        scopes,
    ]);
    const known = new Set(rows.map((r: { name: string }) => r.name));
    const unknown = scopes.filter((s) => !known.has(s));
    if (unknown.length) {
        throw new ValidationError(`Unknown scope(s): ${unknown.join(', ')}`);
    }
}

export async function createClient(
    input: CreateClientInput,
): Promise<{ client: ClientPublic; clientSecret?: string }> {
    const redirectUris = input.redirectUris ?? [];
    if (redirectUris.length === 0) {
        throw new ValidationError('At least one redirect_uri is required');
    }
    redirectUris.forEach(validateRedirectUri); // throws on any invalid URI

    const allowedScopes = input.allowedScopes ?? [];
    await assertScopesExist(allowedScopes);

    const allowedGrantTypes = input.allowedGrantTypes ?? [...SUPPORTED_GRANT_TYPES];
    if (allowedGrantTypes.length === 0) {
        throw new ValidationError('At least one grant type is required');
    }
    const unsupportedGrants = allowedGrantTypes.filter(
        (g) => !SUPPORTED_GRANT_TYPES.includes(g as (typeof SUPPORTED_GRANT_TYPES)[number]),
    );
    if (unsupportedGrants.length) {
        throw new ValidationError(`Unsupported grant type(s): ${unsupportedGrants.join(', ')}`);
    }
    // refresh_token is only meaningful alongside a flow that mints one (authorization_code).
    if (allowedGrantTypes.includes('refresh_token') && !allowedGrantTypes.includes('authorization_code')) {
        throw new ValidationError('refresh_token grant requires the authorization_code grant');
    }

    const clientId = `client_${randomToken(16)}`;

    // Public clients have no secret; confidential clients get one (returned once).
    let clientSecret: string | undefined;
    let secretHash: string | null = null;
    if (input.clientType === 'confidential') {
        clientSecret = randomToken(32);
        secretHash = await hashPassword(clientSecret);
    }

    let row: ClientRecord;
    try {
        const result = await query<ClientRecord>(
            `INSERT INTO oauth_clients
               (client_id, name, client_secret_hash, client_type, redirect_uris, allowed_scopes,
                allowed_grant_types, require_pkce)
             VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
             RETURNING ${PUBLIC_COLUMNS}, client_secret_hash`,
            [clientId, input.name, secretHash, input.clientType, redirectUris, allowedScopes, allowedGrantTypes],
        );
        row = result.rows[0];
    } catch (err) {
        // Unique violation on client_id is astronomically unlikely but handled for safety.
        if ((err as { code?: string }).code === '23505') {
            throw new ConflictError('Client identifier collision, please retry');
        }
        throw err;
    }

    return { client: toPublic(row), clientSecret };
}

export async function getClientByClientId(clientId: string): Promise<ClientRecord | null> {
    const { rows } = await query<ClientRecord>(
        `SELECT ${PUBLIC_COLUMNS}, client_secret_hash FROM oauth_clients WHERE client_id = $1`,
        [clientId],
    );
    return rows[0] ?? null;
}

export async function getPublicClient(clientId: string): Promise<ClientPublic | null> {
    const row = await getClientByClientId(clientId);
    return row ? toPublic(row) : null;
}

export async function listClients(): Promise<ClientPublic[]> {
    const { rows } = await query<ClientRecord>(
        `SELECT ${PUBLIC_COLUMNS} FROM oauth_clients ORDER BY created_at DESC`,
    );
    return rows.map(toPublic);
}

export async function deleteClient(clientId: string): Promise<boolean> {
    const { rowCount } = await query('DELETE FROM oauth_clients WHERE client_id = $1', [clientId]);
    return (rowCount ?? 0) > 0;
}

/**
 * Authenticate a confidential client by its secret (used by the token endpoint in Phase 4).
 * Returns the client on success, null on any failure. Constant-ish time via Argon2 verify.
 */
export async function verifyClientSecret(
    clientId: string,
    secret: string,
): Promise<ClientRecord | null> {
    const client = await getClientByClientId(clientId);
    if (!client || !client.client_secret_hash) return null;
    const ok = await verifyPassword(client.client_secret_hash, secret);
    return ok ? client : null;
}
