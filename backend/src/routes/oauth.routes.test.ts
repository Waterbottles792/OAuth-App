import { describe, it, expect } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import app from '../server';
import { createClient } from '../services/client.service';

const AUTHORIZE = '/api/v1/oauth/authorize';
const REDIRECT = 'https://client.example.com/cb';
const PASSWORD = 'CorrectHorse123';
const STATE = 'opaque-state-123';

function pkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

/** A logged-in resource owner + a registered client. */
async function setup(email = 'owner@example.com') {
    await request(app).post('/api/v1/auth/register').send({ email, password: PASSWORD });
    const agent = request.agent(app);
    await agent.post('/api/v1/auth/login').send({ email, password: PASSWORD });
    const { client } = await createClient({
        name: 'Demo Client',
        clientType: 'public',
        redirectUris: [REDIRECT],
        allowedScopes: ['openid', 'email', 'profile'],
    });
    return { agent, clientId: client.client_id };
}

function authQuery(clientId: string, challenge: string, overrides: Record<string, string | undefined> = {}) {
    return {
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT,
        scope: 'openid email',
        state: STATE,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        ...overrides,
    };
}

describe('/authorize — errors that must NOT redirect (untrusted target)', () => {
    it('unknown client_id -> 400 page error, no redirect', async () => {
        const { challenge } = pkce();
        const res = await request(app).get(AUTHORIZE).query(authQuery('client_nope', challenge));
        expect(res.status).toBe(400);
        expect(res.headers.location).toBeUndefined();
        expect(res.body.error).toBe('invalid_client');
    });

    it('redirect_uri mismatch -> 400 page error, no redirect to attacker URI', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent
            .get(AUTHORIZE)
            .query(authQuery(clientId, challenge, { redirect_uri: 'https://evil.example.com/cb' }));
        expect(res.status).toBe(400);
        expect(res.headers.location).toBeUndefined();
        expect(res.body.error).toBe('invalid_request');
    });
});

describe('/authorize — errors that redirect back with state', () => {
    async function expectRedirectError(query: Record<string, string | undefined>, expectedError: string) {
        const { agent } = await setup();
        const res = await agent.get(AUTHORIZE).query(query);
        expect(res.status).toBe(302);
        const loc = new URL(res.headers.location);
        expect(loc.origin + loc.pathname).toBe(REDIRECT);
        expect(loc.searchParams.get('error')).toBe(expectedError);
        expect(loc.searchParams.get('state')).toBe(STATE);
        expect(loc.searchParams.get('code')).toBeNull();
    }

    it('rejects PKCE method "plain" (only S256 allowed)', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent
            .get(AUTHORIZE)
            .query(authQuery(clientId, challenge, { code_challenge_method: 'plain' }));
        const loc = new URL(res.headers.location);
        expect(loc.searchParams.get('error')).toBe('invalid_request');
        expect(loc.searchParams.get('state')).toBe(STATE);
    });

    it('rejects a missing code_challenge', async () => {
        const { clientId } = await setup();
        await expectRedirectError(authQuery(clientId, '', { code_challenge: undefined }), 'invalid_request');
    });

    it('rejects an unsupported response_type', async () => {
        const { clientId } = await setup();
        const { challenge } = pkce();
        await expectRedirectError(authQuery(clientId, challenge, { response_type: 'token' }), 'unsupported_response_type');
    });

    it('rejects a scope outside the client allow-list', async () => {
        const { clientId } = await setup();
        const { challenge } = pkce();
        await expectRedirectError(authQuery(clientId, challenge, { scope: 'openid admin:all' }), 'invalid_scope');
    });
});

describe('/authorize — authentication & consent flow', () => {
    it('unauthenticated request redirects to the login page with return_to', async () => {
        const { clientId } = await setup();
        const { challenge } = pkce();
        // No agent/cookie -> not authenticated.
        const res = await request(app).get(AUTHORIZE).query(authQuery(clientId, challenge));
        expect(res.status).toBe(302);
        const loc = new URL(res.headers.location);
        expect(loc.origin + loc.pathname).toBe('http://localhost:3000/login');
        expect(loc.searchParams.get('return_to')).toContain('/oauth/authorize');
    });

    it('authenticated user without prior consent gets a consent prompt', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent.get(AUTHORIZE).query(authQuery(clientId, challenge));
        expect(res.status).toBe(200);
        expect(res.body.consent_required).toBe(true);
        expect(res.body.scopes.sort()).toEqual(['email', 'openid']);
        expect(res.body.authorization_request.code_challenge).toBe(challenge);
    });

    it('approving consent issues a code and echoes state', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent
            .post(AUTHORIZE)
            .send({ ...authQuery(clientId, challenge), approved: true });
        expect(res.status).toBe(302);
        const loc = new URL(res.headers.location);
        expect(loc.origin + loc.pathname).toBe(REDIRECT);
        expect(loc.searchParams.get('code')).toBeTruthy();
        expect(loc.searchParams.get('state')).toBe(STATE);
        expect(loc.searchParams.get('error')).toBeNull();
    });

    it('denying consent redirects with access_denied', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        const res = await agent
            .post(AUTHORIZE)
            .send({ ...authQuery(clientId, challenge), approved: false });
        expect(res.status).toBe(302);
        const loc = new URL(res.headers.location);
        expect(loc.searchParams.get('error')).toBe('access_denied');
        expect(loc.searchParams.get('state')).toBe(STATE);
    });

    it('a previously-consented user skips the consent screen and gets a code directly', async () => {
        const { agent, clientId } = await setup();
        const { challenge } = pkce();
        // First approve to record consent.
        await agent.post(AUTHORIZE).send({ ...authQuery(clientId, challenge), approved: true });
        // Subsequent GET should issue a code without a consent prompt.
        const res = await agent.get(AUTHORIZE).query(authQuery(clientId, challenge));
        expect(res.status).toBe(302);
        expect(new URL(res.headers.location).searchParams.get('code')).toBeTruthy();
    });

    it('rejects an unauthenticated consent POST with 401', async () => {
        const { clientId } = await setup();
        const { challenge } = pkce();
        const res = await request(app)
            .post(AUTHORIZE)
            .send({ ...authQuery(clientId, challenge), approved: true });
        expect(res.status).toBe(401);
    });
});
