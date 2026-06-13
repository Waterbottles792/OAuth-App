import { describe, it, expect } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import app from '../server';
import { createClient } from '../services/client.service';
import { verifyAccessToken } from '../services/token.service';

const AUTHORIZE = '/api/v1/oauth/authorize';
const TOKEN = '/api/v1/oauth/token';
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

/** Run /authorize (approve) and return the issued authorization code. */
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

describe('POST /token — authorization_code grant', () => {
    it('exchanges a valid code + PKCE verifier for a verifiable access token', async () => {
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

        expect(res.status).toBe(200);
        expect(res.headers['cache-control']).toContain('no-store');
        expect(res.body.token_type).toBe('Bearer');
        expect(res.body.expires_in).toBe(900);
        expect(res.body.scope).toBe('openid email');

        const payload = await verifyAccessToken(res.body.access_token);
        expect(payload.client_id).toBe(clientId);
        expect(payload.scope).toBe('openid email');
        expect(payload.sub).toBeTruthy();
    });

    it('rejects a wrong PKCE verifier with invalid_grant', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);

        const res = await request(app).post(TOKEN).send({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT,
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: 'the-wrong-verifier',
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('invalid_grant');
    });

    it('rejects reuse of an authorization code (single-use)', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);
        const body = {
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT,
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: verifier,
        };

        const first = await request(app).post(TOKEN).send(body);
        expect(first.status).toBe(200);
        const second = await request(app).post(TOKEN).send(body);
        expect(second.status).toBe(400);
        expect(second.body.error).toBe('invalid_grant');
    });

    it('rejects a wrong client secret with invalid_client (401)', async () => {
        const { agent, clientId } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);

        const res = await request(app).post(TOKEN).send({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT,
            client_id: clientId,
            client_secret: 'wrong-secret',
            code_verifier: verifier,
        });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('invalid_client');
    });

    it('rejects an unsupported grant_type', async () => {
        const res = await request(app).post(TOKEN).send({ grant_type: 'password', client_id: 'x' });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('unsupported_grant_type');
    });

    it('rejects a code redeemed with a mismatched redirect_uri', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);

        const res = await request(app).post(TOKEN).send({
            grant_type: 'authorization_code',
            code,
            redirect_uri: 'https://client.example.com/OTHER',
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: verifier,
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('invalid_grant');
    });
});
