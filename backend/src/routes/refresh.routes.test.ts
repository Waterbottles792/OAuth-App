import { describe, it, expect } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import app from '../server';
import { createClient } from '../services/client.service';
import { verifyAccessToken } from '../services/token.service';
import { query } from '../db/pool';
import { sha256 } from '../lib/crypto';

const AUTHORIZE = '/api/v1/oauth/authorize';
const TOKEN = '/api/v1/oauth/token';
const REVOKE = '/api/v1/oauth/revoke';
const REDIRECT = 'https://client.example.com/cb';
const PASSWORD = 'CorrectHorse123';

function pkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

/** Logged-in owner + a confidential client (returns its one-time secret). */
async function setup() {
    await request(app).post('/api/v1/auth/register').send({ email: 'owner@example.com', password: PASSWORD });
    const agent = request.agent(app);
    await agent.post('/api/v1/auth/login').send({ email: 'owner@example.com', password: PASSWORD });
    const { client, clientSecret } = await createClient({
        name: 'Confidential App',
        clientType: 'confidential',
        redirectUris: [REDIRECT],
        allowedScopes: ['openid', 'email', 'profile'],
    });
    return { agent, clientId: client.client_id, clientSecret: clientSecret! };
}

async function getCode(agent: ReturnType<typeof request.agent>, clientId: string, challenge: string) {
    const res = await agent.post(AUTHORIZE).send({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT,
        scope: 'openid email',
        state: 's1',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        approved: true,
    });
    return new URL(res.headers.location).searchParams.get('code')!;
}

/** Run the full authorization_code exchange and return the token response body. */
async function exchangeForTokens() {
    const { agent, clientId, clientSecret } = await setup();
    const { verifier, challenge } = pkce();
    const code = await getCode(agent, clientId, challenge);
    const res = await request(app).post(TOKEN).send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        client_id: clientId,
        client_secret: clientSecret,
        code_verifier: verifier,
    });
    return { res, clientId, clientSecret };
}

describe('Phase 5 — refresh tokens', () => {
    it('issues a refresh token alongside the access token at code exchange', async () => {
        const { res } = await exchangeForTokens();
        expect(res.status).toBe(200);
        expect(res.body.refresh_token).toBeTruthy();
        expect(res.body.access_token).toBeTruthy();
        expect(res.body.token_type).toBe('Bearer');
    });

    it('rotates: a refresh returns a new refresh token and a fresh access token', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const original = res.body.refresh_token;

        const refreshed = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: original,
            client_id: clientId,
            client_secret: clientSecret,
        });

        expect(refreshed.status).toBe(200);
        expect(refreshed.headers['cache-control']).toContain('no-store');
        expect(refreshed.body.refresh_token).toBeTruthy();
        expect(refreshed.body.refresh_token).not.toBe(original);
        expect(refreshed.body.scope).toBe('openid email');

        const payload = await verifyAccessToken(refreshed.body.access_token);
        expect(payload.client_id).toBe(clientId);
        expect(payload.scope).toBe('openid email');
    });

    it('invalidates the old refresh token after rotation', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const original = res.body.refresh_token;

        const first = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: original,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(first.status).toBe(200);

        // Re-presenting the now-rotated token must fail.
        const reuse = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: original,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(reuse.status).toBe(400);
        expect(reuse.body.error).toBe('invalid_grant');
    });

    it('reuse detection: replaying a rotated token revokes the whole family', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const t0 = res.body.refresh_token;

        // Rotate once: t0 -> t1.
        const r1 = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: t0,
            client_id: clientId,
            client_secret: clientSecret,
        });
        const t1 = r1.body.refresh_token;

        // Attacker replays the already-used t0: detected -> family revoked.
        const replay = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: t0,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(replay.status).toBe(400);

        // The legitimately-rotated t1 is now dead too (family revocation).
        const useT1 = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: t1,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(useT1.status).toBe(400);
        expect(useT1.body.error).toBe('invalid_grant');
    });

    it('refresh tokens are stored hashed, never in plaintext', async () => {
        const { res } = await exchangeForTokens();
        const raw = res.body.refresh_token;

        const byRaw = await query('SELECT 1 FROM refresh_tokens WHERE token_hash = $1', [raw]);
        expect(byRaw.rowCount).toBe(0);
        const byHash = await query('SELECT 1 FROM refresh_tokens WHERE token_hash = $1', [sha256(raw)]);
        expect(byHash.rowCount).toBe(1);
    });

    it('rejects an expired refresh token', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const raw = res.body.refresh_token;

        await query('UPDATE refresh_tokens SET expires_at = NOW() - interval \'1 second\' WHERE token_hash = $1', [
            sha256(raw),
        ]);

        const refreshed = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: raw,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(refreshed.status).toBe(400);
        expect(refreshed.body.error).toBe('invalid_grant');
    });

    it('rejects a refresh token presented by a different client', async () => {
        const { res } = await exchangeForTokens();
        const raw = res.body.refresh_token;

        const { client: other, clientSecret: otherSecret } = await createClient({
            name: 'Other App',
            clientType: 'confidential',
            redirectUris: ['https://other.example.com/cb'],
            allowedScopes: ['openid'],
        });

        const refreshed = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: raw,
            client_id: other.client_id,
            client_secret: otherSecret,
        });
        expect(refreshed.status).toBe(400);
        expect(refreshed.body.error).toBe('invalid_grant');
    });
});

describe('Phase 5 — /revoke (RFC 7009)', () => {
    it('revokes a refresh token so it can no longer mint access tokens', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const raw = res.body.refresh_token;

        const revoke = await request(app).post(REVOKE).send({
            token: raw,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(revoke.status).toBe(200);

        const refreshed = await request(app).post(TOKEN).send({
            grant_type: 'refresh_token',
            refresh_token: raw,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(refreshed.status).toBe(400);
        expect(refreshed.body.error).toBe('invalid_grant');
    });

    it('responds 200 for an unknown token (no validity oracle)', async () => {
        const { clientId, clientSecret } = await exchangeForTokens();
        const revoke = await request(app).post(REVOKE).send({
            token: 'a-token-that-was-never-issued',
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(revoke.status).toBe(200);
    });

    it('rejects an unauthenticated confidential client with invalid_client', async () => {
        const { res, clientId } = await exchangeForTokens();
        const revoke = await request(app).post(REVOKE).send({
            token: res.body.refresh_token,
            client_id: clientId,
            client_secret: 'wrong-secret',
        });
        expect(revoke.status).toBe(401);
        expect(revoke.body.error).toBe('invalid_client');
    });
});
