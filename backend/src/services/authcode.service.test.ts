import { describe, it, expect } from 'vitest';
import { query } from '../db/pool';
import { createClient } from './client.service';
import { issueCode, consumeCode } from './authcode.service';
import { sha256 } from '../lib/crypto';

async function makeUserAndClient() {
    const { rows } = await query<{ id: string }>(
        "INSERT INTO users (email, password_hash) VALUES ('owner@example.com','x') RETURNING id",
    );
    const { client } = await createClient({
        name: 'App',
        clientType: 'public',
        redirectUris: ['https://client.example.com/cb'],
        allowedScopes: ['openid', 'email'],
    });
    return { userId: rows[0].id, clientDbId: client.id };
}

const baseInput = (userId: string, clientDbId: string) => ({
    clientDbId,
    userId,
    redirectUri: 'https://client.example.com/cb',
    scopes: ['openid', 'email'],
    codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
});

describe('authcode.service', () => {
    it('stores only the SHA-256 hash of the code, bound to the request', async () => {
        const { userId, clientDbId } = await makeUserAndClient();
        const code = await issueCode(baseInput(userId, clientDbId));

        const { rows } = await query<{ code_hash: string; scopes: string[]; code_challenge_method: string }>(
            'SELECT code_hash, scopes, code_challenge_method FROM authorization_codes',
        );
        expect(rows[0].code_hash).toBe(sha256(code));
        expect(rows[0].code_hash).not.toContain(code);
        expect(rows[0].code_challenge_method).toBe('S256');
        expect(rows[0].scopes.sort()).toEqual(['email', 'openid']);
    });

    it('consumes a valid code once and rejects reuse (single-use)', async () => {
        const { userId, clientDbId } = await makeUserAndClient();
        const code = await issueCode(baseInput(userId, clientDbId));

        const first = await consumeCode(code);
        expect(first.ok).toBe(true);
        expect(first.record?.user_id).toBe(userId);

        const second = await consumeCode(code);
        expect(second.ok).toBe(false);
        expect(second.reason).toBe('already_used');
    });

    it('rejects an expired code', async () => {
        const { userId, clientDbId } = await makeUserAndClient();
        const code = await issueCode(baseInput(userId, clientDbId));
        await query("UPDATE authorization_codes SET expires_at = NOW() - interval '1 minute'");

        const result = await consumeCode(code);
        expect(result.ok).toBe(false);
        expect(result.reason).toBe('expired');
    });

    it('rejects an unknown code', async () => {
        const result = await consumeCode('does-not-exist');
        expect(result.ok).toBe(false);
        expect(result.reason).toBe('not_found');
    });
});
