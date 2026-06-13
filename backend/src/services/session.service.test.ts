import { describe, it, expect } from 'vitest';
import { query } from '../db/pool';
import { getRedis } from '../db/redis';
import { sha256 } from '../lib/crypto';
import {
    createSession,
    getSession,
    destroySession,
    createMfaChallenge,
    consumeMfaChallenge,
} from './session.service';

async function makeUser(email = 'sess@example.com'): Promise<string> {
    const { rows } = await query<{ id: string }>(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
        [email],
    );
    return rows[0].id;
}

describe('session.service', () => {
    it('creates a session whose RAW token is never stored (only its hash)', async () => {
        const userId = await makeUser();
        const token = await createSession(userId, { ip: '127.0.0.1' });

        const redis = await getRedis();
        // The raw token must not exist as a key; the hashed key must.
        expect(await redis.get(`session:${token}`)).toBeNull();
        expect(await redis.get(`session:${sha256(token)}`)).not.toBeNull();

        // Postgres stores the hash, not the raw token.
        const { rows } = await query<{ token_hash: string }>(
            'SELECT token_hash FROM sessions WHERE user_id = $1',
            [userId],
        );
        expect(rows[0].token_hash).toBe(sha256(token));
    });

    it('resolves a valid token to its user and destroys on logout', async () => {
        const userId = await makeUser();
        const token = await createSession(userId);

        const session = await getSession(token);
        expect(session?.userId).toBe(userId);

        await destroySession(token);
        expect(await getSession(token)).toBeNull();
    });

    it('returns null for unknown/empty tokens', async () => {
        expect(await getSession('')).toBeNull();
        expect(await getSession('bogus')).toBeNull();
    });

    it('mfa challenge is single-use', async () => {
        const userId = await makeUser();
        const challenge = await createMfaChallenge(userId);
        expect(await consumeMfaChallenge(challenge)).toBe(userId);
        expect(await consumeMfaChallenge(challenge)).toBeNull();
    });
});
