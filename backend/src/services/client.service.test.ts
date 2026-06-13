import { describe, it, expect } from 'vitest';
import { query } from '../db/pool';
import {
    createClient,
    getClientByClientId,
    listClients,
    deleteClient,
    verifyClientSecret,
} from './client.service';
import { recordConsent, getConsent, hasConsentFor } from './consent.service';
import { ValidationError } from '../lib/errors';

const VALID_URIS = ['https://app.example.com/callback'];

describe('client.service — creation & secrets', () => {
    it('creates a confidential client, returns the secret once, stores only its hash', async () => {
        const { client, clientSecret } = await createClient({
            name: 'Test App',
            clientType: 'confidential',
            redirectUris: VALID_URIS,
            allowedScopes: ['openid', 'email'],
        });

        expect(clientSecret).toBeTruthy();
        expect(client.client_id).toMatch(/^client_/);
        expect(client.require_pkce).toBe(true);
        expect((client as Record<string, unknown>).client_secret_hash).toBeUndefined();

        // DB stores an argon2id hash, never the plaintext secret.
        const row = await getClientByClientId(client.client_id);
        expect(row?.client_secret_hash?.startsWith('$argon2id$')).toBe(true);
        expect(row?.client_secret_hash).not.toContain(clientSecret!);
    });

    it('creates a public client with no secret and PKCE required', async () => {
        const { client, clientSecret } = await createClient({
            name: 'SPA',
            clientType: 'public',
            redirectUris: VALID_URIS,
        });
        expect(clientSecret).toBeUndefined();
        expect(client.require_pkce).toBe(true);

        const row = await getClientByClientId(client.client_id);
        expect(row?.client_secret_hash).toBeNull();
    });

    it('verifies a correct client secret and rejects a wrong one', async () => {
        const { client, clientSecret } = await createClient({
            name: 'Test App',
            clientType: 'confidential',
            redirectUris: VALID_URIS,
        });
        expect(await verifyClientSecret(client.client_id, clientSecret!)).not.toBeNull();
        expect(await verifyClientSecret(client.client_id, 'wrong-secret')).toBeNull();
    });
});

describe('client.service — redirect URI validation (exact match, no wildcards)', () => {
    const mk = (uris: string[]) =>
        createClient({ name: 'X', clientType: 'public', redirectUris: uris });

    it('rejects wildcard redirect URIs', async () => {
        await expect(mk(['https://*.example.com/cb'])).rejects.toBeInstanceOf(ValidationError);
    });
    it('rejects http for non-localhost hosts', async () => {
        await expect(mk(['http://app.example.com/cb'])).rejects.toBeInstanceOf(ValidationError);
    });
    it('rejects redirect URIs containing a fragment', async () => {
        await expect(mk(['https://app.example.com/cb#x'])).rejects.toBeInstanceOf(ValidationError);
    });
    it('rejects a non-URL redirect value', async () => {
        await expect(mk(['not-a-url'])).rejects.toBeInstanceOf(ValidationError);
    });
    it('requires at least one redirect URI', async () => {
        await expect(mk([])).rejects.toBeInstanceOf(ValidationError);
    });
    it('accepts https and http-localhost', async () => {
        const { client } = await createClient({
            name: 'X',
            clientType: 'public',
            redirectUris: ['https://app.example.com/cb', 'http://localhost:3000/cb'],
        });
        expect(client.redirect_uris).toHaveLength(2);
    });
});

describe('client.service — scope validation, list, delete', () => {
    it('rejects unknown scopes', async () => {
        await expect(
            createClient({
                name: 'X',
                clientType: 'public',
                redirectUris: VALID_URIS,
                allowedScopes: ['openid', 'not_a_real_scope'],
            }),
        ).rejects.toBeInstanceOf(ValidationError);
    });

    it('lists and deletes clients', async () => {
        const { client } = await createClient({
            name: 'X',
            clientType: 'public',
            redirectUris: VALID_URIS,
        });
        expect((await listClients()).some((c) => c.client_id === client.client_id)).toBe(true);
        expect(await deleteClient(client.client_id)).toBe(true);
        expect(await deleteClient(client.client_id)).toBe(false); // already gone
    });
});

describe('consent.service', () => {
    async function makeUserAndClient() {
        const { rows } = await query<{ id: string }>(
            "INSERT INTO users (email, password_hash) VALUES ('c@example.com','x') RETURNING id",
        );
        const { client } = await createClient({
            name: 'X',
            clientType: 'public',
            redirectUris: VALID_URIS,
            allowedScopes: ['openid', 'email', 'profile'],
        });
        const row = await getClientByClientId(client.client_id);
        return { userId: rows[0].id, clientDbId: row!.id };
    }

    it('records, replaces (unique per user+client), and checks subset consent', async () => {
        const { userId, clientDbId } = await makeUserAndClient();

        await recordConsent(userId, clientDbId, ['openid', 'email']);
        expect((await getConsent(userId, clientDbId))?.scopes.sort()).toEqual(['email', 'openid']);
        expect(await hasConsentFor(userId, clientDbId, ['openid'])).toBe(true);
        expect(await hasConsentFor(userId, clientDbId, ['profile'])).toBe(false);

        // Re-granting replaces rather than duplicating.
        await recordConsent(userId, clientDbId, ['openid', 'email', 'profile']);
        expect(await hasConsentFor(userId, clientDbId, ['profile'])).toBe(true);

        const { rows } = await query<{ count: string }>(
            'SELECT COUNT(*)::text AS count FROM user_consents WHERE user_id = $1 AND client_id = $2',
            [userId, clientDbId],
        );
        expect(rows[0].count).toBe('1');
    });
});
