import { describe, it, expect } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import { createLocalJWKSet, jwtVerify, decodeJwt } from 'jose';
import app from '../server';
import { createClient } from '../services/client.service';
import { oauthFlowConfig } from '../config';

const AUTHORIZE = '/api/v1/oauth/authorize';
const TOKEN = '/api/v1/oauth/token';
const USERINFO = '/api/v1/oauth/userinfo';
const REDIRECT = 'https://client.example.com/cb';
const PASSWORD = 'CorrectHorse123';
const EMAIL = 'owner@example.com';

function pkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

async function setup() {
    await request(app).post('/api/v1/auth/register').send({ email: EMAIL, password: PASSWORD });
    const agent = request.agent(app);
    await agent.post('/api/v1/auth/login').send({ email: EMAIL, password: PASSWORD });
    const { client, clientSecret } = await createClient({
        name: 'OIDC App',
        clientType: 'confidential',
        redirectUris: [REDIRECT],
        allowedScopes: ['openid', 'email', 'profile'],
    });
    return { agent, clientId: client.client_id, clientSecret: clientSecret! };
}

async function getCode(
    agent: ReturnType<typeof request.agent>,
    clientId: string,
    challenge: string,
    scope: string,
    nonce?: string,
) {
    const res = await agent.post(AUTHORIZE).send({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT,
        scope,
        state: 's1',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        nonce,
        approved: true,
    });
    return new URL(res.headers.location).searchParams.get('code')!;
}

/** Full openid flow → token response body. */
async function exchange(scope = 'openid email', nonce?: string) {
    const { agent, clientId, clientSecret } = await setup();
    const { verifier, challenge } = pkce();
    const code = await getCode(agent, clientId, challenge, scope, nonce);
    const res = await request(app).post(TOKEN).send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        client_id: clientId,
        client_secret: clientSecret,
        code_verifier: verifier,
    });
    return { res, clientId };
}

describe('Phase 6 — ID token', () => {
    it('issues an ID token for the openid scope, carrying the nonce', async () => {
        const nonce = 'n-' + crypto.randomBytes(8).toString('hex');
        const { res, clientId } = await exchange('openid email', nonce);

        expect(res.status).toBe(200);
        expect(res.body.id_token).toBeTruthy();

        const claims = decodeJwt(res.body.id_token);
        expect(claims.iss).toBe(oauthFlowConfig.issuer);
        expect(claims.aud).toBe(clientId);
        expect(claims.sub).toBeTruthy();
        expect(claims.nonce).toBe(nonce);
        expect(claims.email).toBe(EMAIL);
        expect(claims.email_verified).toBe(false);
    });

    it('does NOT issue an ID token when openid scope is absent', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        // 'email' alone is allowed for the client but not 'openid'.
        const code = await getCode(agent, clientId, challenge, 'email');
        const res = await request(app).post(TOKEN).send({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT,
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: verifier,
        });
        expect(res.status).toBe(200);
        expect(res.body.id_token).toBeUndefined();
    });

    it('ID token signature verifies against the JWKS endpoint', async () => {
        const { res, clientId } = await exchange('openid email');

        const jwksRes = await request(app).get('/.well-known/jwks.json');
        expect(jwksRes.status).toBe(200);
        const jwks = createLocalJWKSet(jwksRes.body);

        const { payload, protectedHeader } = await jwtVerify(res.body.id_token, jwks, {
            issuer: oauthFlowConfig.issuer,
            audience: clientId,
        });
        expect(protectedHeader.alg).toBe('RS256');
        expect(payload.sub).toBeTruthy();
    });
});

describe('Phase 6 — /userinfo', () => {
    it('returns sub + scope-gated claims for a valid access token', async () => {
        const { res } = await exchange('openid email');
        const info = await request(app).get(USERINFO).set('Authorization', `Bearer ${res.body.access_token}`);

        expect(info.status).toBe(200);
        expect(info.body.sub).toBeTruthy();
        expect(info.body.email).toBe(EMAIL);
        expect(info.body.email_verified).toBe(false);
    });

    it('omits email when the email scope was not granted', async () => {
        const { res } = await exchange('openid');
        const info = await request(app).get(USERINFO).set('Authorization', `Bearer ${res.body.access_token}`);
        expect(info.status).toBe(200);
        expect(info.body.sub).toBeTruthy();
        expect(info.body.email).toBeUndefined();
    });

    it('rejects a missing token with 401', async () => {
        const info = await request(app).get(USERINFO);
        expect(info.status).toBe(401);
        expect(info.headers['www-authenticate']).toContain('Bearer');
    });

    it('rejects an invalid token with 401 invalid_token', async () => {
        const info = await request(app).get(USERINFO).set('Authorization', 'Bearer not.a.real.token');
        expect(info.status).toBe(401);
        expect(info.body.error).toBe('invalid_token');
    });
});

describe('Phase 6 — discovery', () => {
    it('serves a discovery document with a matching issuer and required metadata', async () => {
        const res = await request(app).get('/.well-known/openid-configuration');
        expect(res.status).toBe(200);
        expect(res.body.issuer).toBe(oauthFlowConfig.issuer);
        expect(res.body.authorization_endpoint).toContain('/oauth/authorize');
        expect(res.body.token_endpoint).toContain('/oauth/token');
        expect(res.body.userinfo_endpoint).toContain('/oauth/userinfo');
        expect(res.body.jwks_uri).toContain('/.well-known/jwks.json');
        expect(res.body.id_token_signing_alg_values_supported).toContain('RS256');
        expect(res.body.code_challenge_methods_supported).toEqual(['S256']);
        expect(res.body.scopes_supported).toContain('openid');
        expect(res.body.grant_types_supported).toContain('refresh_token');
    });

    it('serves a JWKS with public RSA keys only (no private material)', async () => {
        const res = await request(app).get('/.well-known/jwks.json');
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body.keys)).toBe(true);
        expect(res.body.keys.length).toBeGreaterThanOrEqual(1);
        const jwk = res.body.keys[0];
        expect(jwk.kty).toBe('RSA');
        expect(jwk.kid).toBeTruthy();
        expect(jwk.use).toBe('sig');
        expect(jwk.n).toBeTruthy();
        expect(jwk.e).toBeTruthy();
        // No private RSA parameters must ever be present.
        expect(jwk.d).toBeUndefined();
        expect(jwk.p).toBeUndefined();
        expect(jwk.q).toBeUndefined();
    });
});
