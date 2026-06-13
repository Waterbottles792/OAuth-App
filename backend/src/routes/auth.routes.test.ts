import { describe, it, expect } from 'vitest';
import request from 'supertest';
import speakeasy from 'speakeasy';
import app from '../server';
import { query } from '../db/pool';

const API = '/api/v1/auth';
const EMAIL = 'user@example.com';
const PASSWORD = 'CorrectHorse123';

async function totpSecretFor(email: string): Promise<string> {
    const { rows } = await query<{ totp_secret: string }>(
        'SELECT m.totp_secret FROM mfa_secrets m JOIN users u ON u.id = m.user_id WHERE u.email = $1',
        [email],
    );
    return rows[0].totp_secret;
}

function totpNow(secret: string): string {
    return speakeasy.totp({ secret, encoding: 'base32' });
}

describe('auth routes — registration & validation', () => {
    it('registers a new user with a uniform, non-enumerating response', async () => {
        const res = await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        expect(res.status).toBe(202);
        expect(res.body.message).toBeTruthy();
        // Must NOT leak whether an account was created.
        expect(res.body.userId).toBeUndefined();
    });

    it('rejects a weak password', async () => {
        const res = await request(app).post(`${API}/register`).send({ email: EMAIL, password: 'short' });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('invalid_request');
    });

    it('returns the SAME response for a duplicate registration (no enumeration)', async () => {
        const first = await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        const second = await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        // Identical status + body whether or not the email already existed.
        expect(second.status).toBe(first.status);
        expect(second.status).toBe(202);
        expect(second.body).toEqual(first.body);
    });
});

describe('auth routes — login, session, logout', () => {
    it('logs in, sets an HttpOnly session cookie, serves /me, and logs out', async () => {
        await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });

        const agent = request.agent(app);
        const login = await agent.post(`${API}/login`).send({ email: EMAIL, password: PASSWORD });
        expect(login.status).toBe(200);
        expect(login.body.user.email).toBe(EMAIL);

        const setCookie = ([] as string[]).concat(login.headers['set-cookie']).join(';');
        expect(setCookie).toMatch(/sid=/);
        expect(setCookie.toLowerCase()).toContain('httponly');
        expect(setCookie.toLowerCase()).toContain('samesite=lax');

        const me = await agent.get(`${API}/me`);
        expect(me.status).toBe(200);
        expect(me.body.user.email).toBe(EMAIL);

        const logout = await agent.post(`${API}/logout`);
        expect(logout.status).toBe(200);

        const after = await agent.get(`${API}/me`);
        expect(after.status).toBe(401);
    });

    it('rejects /me without a session', async () => {
        const res = await request(app).get(`${API}/me`);
        expect(res.status).toBe(401);
    });

    it('rejects a wrong password', async () => {
        await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        const res = await request(app).post(`${API}/login`).send({ email: EMAIL, password: 'WrongPassword123' });
        expect(res.status).toBe(401);
    });

    it('rate-limits repeated login attempts (6th is 429)', async () => {
        await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        let last = 0;
        for (let i = 0; i < 6; i++) {
            const res = await request(app)
                .post(`${API}/login`)
                .send({ email: EMAIL, password: 'WrongPassword123' });
            last = res.status;
        }
        expect(last).toBe(429);
    });
});

describe('auth routes — MFA enrollment & login', () => {
    async function registerAndSession() {
        await request(app).post(`${API}/register`).send({ email: EMAIL, password: PASSWORD });
        const agent = request.agent(app);
        await agent.post(`${API}/login`).send({ email: EMAIL, password: PASSWORD });
        return agent;
    }

    it('enrolls TOTP, then requires the second factor on next login', async () => {
        const agent = await registerAndSession();

        const enable = await agent.post(`${API}/mfa/enable`).send({});
        expect(enable.status).toBe(200);
        expect(enable.body.qrCode).toMatch(/^data:image\/png;base64,/);
        expect(enable.body.backupCodes).toHaveLength(10);

        const secret = await totpSecretFor(EMAIL);
        const confirm = await agent.post(`${API}/mfa/verify`).send({ code: totpNow(secret) });
        expect(confirm.status).toBe(200);
        expect(confirm.body.success).toBe(true);

        // Fresh login now demands MFA instead of returning a session.
        const mfaAgent = request.agent(app);
        const login = await mfaAgent.post(`${API}/login`).send({ email: EMAIL, password: PASSWORD });
        expect(login.status).toBe(200);
        expect(login.body.mfaRequired).toBe(true);
        expect(login.body.user).toBeUndefined();

        const complete = await mfaAgent.post(`${API}/mfa/login`).send({ code: totpNow(secret) });
        expect(complete.status).toBe(200);
        expect(complete.body.user.email).toBe(EMAIL);

        const me = await mfaAgent.get(`${API}/me`);
        expect(me.status).toBe(200);
    });

    it('accepts a backup code once and rejects its reuse', async () => {
        const agent = await registerAndSession();
        const enable = await agent.post(`${API}/mfa/enable`).send({});
        const backupCode = enable.body.backupCodes[0];

        const secret = await totpSecretFor(EMAIL);
        await agent.post(`${API}/mfa/verify`).send({ code: totpNow(secret) });

        // First login via backup code succeeds.
        const a1 = request.agent(app);
        await a1.post(`${API}/login`).send({ email: EMAIL, password: PASSWORD });
        const ok = await a1.post(`${API}/mfa/login`).send({ code: backupCode });
        expect(ok.status).toBe(200);

        // Reusing the same backup code fails.
        const a2 = request.agent(app);
        await a2.post(`${API}/login`).send({ email: EMAIL, password: PASSWORD });
        const reused = await a2.post(`${API}/mfa/login`).send({ code: backupCode });
        expect(reused.status).toBe(401);
    });

    it('rejects an invalid TOTP code at enrollment confirmation', async () => {
        const agent = await registerAndSession();
        await agent.post(`${API}/mfa/enable`).send({});
        const res = await agent.post(`${API}/mfa/verify`).send({ code: '000000' });
        expect(res.status).toBe(401);
    });
});
