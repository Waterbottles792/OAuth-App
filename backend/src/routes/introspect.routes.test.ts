import { describe, it, expect } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import app from '../server';
import { createClient } from '../services/client.service';

const AUTHORIZE = '/api/v1/oauth/authorize';
const TOKEN = '/api/v1/oauth/token';
const REVOKE = '/api/v1/oauth/revoke';
const INTROSPECT = '/api/v1/oauth/introspect';
const USERINFO = '/api/v1/oauth/userinfo';
const REDIRECT = 'https://client.example.com/cb';
const PASSWORD = 'CorrectHorse123';

function pkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

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

describe('Phase 8 — access-token revocation (deny-list)', () => {
    it('revokes an access token so /userinfo rejects it', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const accessToken = res.body.access_token;

        // The token works first.
        const before = await request(app).get(USERINFO).set('Authorization', `Bearer ${accessToken}`);
        expect(before.status).toBe(200);

        const revoke = await request(app).post(REVOKE).send({
            token: accessToken,
            token_type_hint: 'access_token',
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(revoke.status).toBe(200);

        // After revocation the same (still-unexpired, validly-signed) token is rejected.
        const after = await request(app).get(USERINFO).set('Authorization', `Bearer ${accessToken}`);
        expect(after.status).toBe(401);
        expect(after.body.error).toBe('invalid_token');
    });

    it('a different client cannot revoke another client\'s access token', async () => {
        const { res } = await exchangeForTokens();
        const accessToken = res.body.access_token;

        const { client: other, clientSecret: otherSecret } = await createClient({
            name: 'Other App',
            clientType: 'confidential',
            redirectUris: ['https://other.example.com/cb'],
            allowedScopes: ['openid'],
        });

        const revoke = await request(app).post(REVOKE).send({
            token: accessToken,
            client_id: other.client_id,
            client_secret: otherSecret,
        });
        expect(revoke.status).toBe(200); // no oracle

        // The token is still valid for its real owner.
        const after = await request(app).get(USERINFO).set('Authorization', `Bearer ${accessToken}`);
        expect(after.status).toBe(200);
    });
});

describe('Phase 8 — token introspection (RFC 7662)', () => {
    it('reports active=true with claims for a valid access token', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const r = await request(app).post(INTROSPECT).send({
            token: res.body.access_token,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(r.status).toBe(200);
        expect(r.body.active).toBe(true);
        expect(r.body.client_id).toBe(clientId);
        expect(r.body.scope).toBe('openid email');
        expect(r.body.sub).toBeTruthy();
    });

    it('reports active=false after the token is revoked', async () => {
        const { res, clientId, clientSecret } = await exchangeForTokens();
        const accessToken = res.body.access_token;

        await request(app).post(REVOKE).send({ token: accessToken, client_id: clientId, client_secret: clientSecret });

        const r = await request(app).post(INTROSPECT).send({
            token: accessToken,
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(r.status).toBe(200);
        expect(r.body.active).toBe(false);
    });

    it('reports active=false for a garbage token (no oracle)', async () => {
        const { clientId, clientSecret } = await exchangeForTokens();
        const r = await request(app).post(INTROSPECT).send({
            token: 'not.a.jwt',
            client_id: clientId,
            client_secret: clientSecret,
        });
        expect(r.status).toBe(200);
        expect(r.body.active).toBe(false);
    });

    it('reports active=false for a token issued to a different client', async () => {
        const { res } = await exchangeForTokens();
        const { client: other, clientSecret: otherSecret } = await createClient({
            name: 'Other App',
            clientType: 'confidential',
            redirectUris: ['https://other.example.com/cb'],
            allowedScopes: ['openid'],
        });
        const r = await request(app).post(INTROSPECT).send({
            token: res.body.access_token,
            client_id: other.client_id,
            client_secret: otherSecret,
        });
        expect(r.status).toBe(200);
        expect(r.body.active).toBe(false);
    });

    it('requires client authentication', async () => {
        const { res, clientId } = await exchangeForTokens();
        const r = await request(app).post(INTROSPECT).send({
            token: res.body.access_token,
            client_id: clientId,
            client_secret: 'wrong',
        });
        expect(r.status).toBe(401);
        expect(r.body.error).toBe('invalid_client');
    });
});

describe('Phase 8 — Origin CSRF check on POST /authorize', () => {
    it('rejects a consent POST carrying a disallowed Origin (no code issued)', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent
            .post(AUTHORIZE)
            .set('Origin', 'https://evil.example.com')
            .send({
                response_type: 'code',
                client_id: clientId,
                redirect_uri: REDIRECT,
                scope: 'openid email',
                state: 's1',
                code_challenge: challenge,
                code_challenge_method: 'S256',
                approved: true,
            });
        // A cross-origin consent POST must NOT succeed. The CORS allowlist rejects it server-side
        // before the route runs; the route's own Origin check (originAllowed) is defence-in-depth
        // using the same allowlist. Either way: the request is blocked and no auth code is issued.
        expect(res.status).toBeGreaterThanOrEqual(400);
        expect(res.headers.location).toBeUndefined();
    });

    it('allows a consent POST with no Origin header (non-browser / same-site)', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
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
        expect(res.status).toBe(302);
        expect(new URL(res.headers.location).searchParams.get('code')).toBeTruthy();
    });
});
