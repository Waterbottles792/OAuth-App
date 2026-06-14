import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import app from '../server';
import { createClient } from '../services/client.service';
import { query } from '../db/pool';
import { recordAudit } from '../services/audit.service';
import { setAlertHandler, resetAlertHandler, SecurityAlert } from '../lib/alerts';

const AUTHORIZE = '/api/v1/oauth/authorize';
const TOKEN = '/api/v1/oauth/token';
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
        name: 'Audit App',
        clientType: 'confidential',
        redirectUris: [REDIRECT],
        allowedScopes: ['openid', 'email'],
    });
    return { agent, clientId: client.client_id, clientSecret: clientSecret! };
}

async function getCode(agent: ReturnType<typeof request.agent>, clientId: string, challenge: string) {
    const res = await agent.post(AUTHORIZE).send({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT,
        scope: 'openid email',
        state: 's',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        approved: true,
    });
    return new URL(res.headers.location).searchParams.get('code')!;
}

async function eventsFor(event: string) {
    const { rows } = await query<{ event: string; result: string }>(
        'SELECT event, result FROM audit_logs WHERE event = $1 ORDER BY id',
        [event],
    );
    return rows;
}

describe('Phase 8 — audit log', () => {
    afterEach(() => resetAlertHandler());

    it('is append-only: UPDATE and DELETE are rejected', async () => {
        await recordAudit({ event: 'login', result: 'success' });
        await expect(query('UPDATE audit_logs SET result = $1', ['failure'])).rejects.toThrow();
        await expect(query('DELETE FROM audit_logs')).rejects.toThrow();
        const { rows } = await query('SELECT COUNT(*)::int AS n FROM audit_logs');
        expect((rows[0] as { n: number }).n).toBeGreaterThan(0);
    });

    it('records login success and the full token-issuance event set', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);
        await request(app).post(TOKEN).send({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT,
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: verifier,
        });

        expect((await eventsFor('login')).some((r) => r.result === 'success')).toBe(true);
        expect((await eventsFor('authz_code_issued')).length).toBe(1);
        expect((await eventsFor('access_token_issued')).length).toBe(1);
    });

    it('never stores raw secrets/tokens in the audit detail', async () => {
        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);
        await request(app).post(TOKEN).send({
            grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
            client_id: clientId, client_secret: clientSecret, code_verifier: verifier,
        });
        const { rows } = await query<{ blob: string }>(
            "SELECT coalesce(detail::text,'') AS blob FROM audit_logs",
        );
        const all = rows.map((r) => r.blob).join('\n');
        expect(all).not.toContain(clientSecret);
        expect(all).not.toContain(code);
        expect(all).not.toContain(verifier);
    });
});

describe('Phase 8 — security alerts', () => {
    afterEach(() => resetAlertHandler());

    it('fires an alert AND writes a detected audit row on refresh-token reuse', async () => {
        const alerts: SecurityAlert[] = [];
        setAlertHandler((a) => alerts.push(a));

        const { agent, clientId, clientSecret } = await setup();
        const { verifier, challenge } = pkce();
        const code = await getCode(agent, clientId, challenge);
        const tok = await request(app).post(TOKEN).send({
            grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
            client_id: clientId, client_secret: clientSecret, code_verifier: verifier,
        });
        const rt = tok.body.refresh_token;

        // rotate, then replay the old token -> reuse detected
        await request(app).post(TOKEN).send({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId, client_secret: clientSecret });
        await request(app).post(TOKEN).send({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId, client_secret: clientSecret });

        expect(alerts.some((a) => a.kind === 'refresh_token_reuse')).toBe(true);
        expect((await eventsFor('refresh_token_reuse')).some((r) => r.result === 'detected')).toBe(true);
    });
});
