import { describe, it, expect } from 'vitest';
import request from 'supertest';
import app from '../server';
import { query } from '../db/pool';

const API = '/api/v1';
const PASSWORD = 'CorrectHorse123';

/** Register a user, optionally promote to admin, and return a cookie-bearing agent. */
async function agentFor(email: string, admin: boolean) {
    await request(app).post(`${API}/auth/register`).send({ email, password: PASSWORD });
    if (admin) {
        await query('UPDATE users SET is_admin = TRUE WHERE email = $1', [email]);
    }
    const agent = request.agent(app);
    await agent.post(`${API}/auth/login`).send({ email, password: PASSWORD });
    return agent;
}

const CLIENT_BODY = {
    name: 'My App',
    clientType: 'confidential',
    redirectUris: ['https://app.example.com/callback'],
    allowedScopes: ['openid', 'email'],
};

describe('client routes — admin authorization', () => {
    it('rejects anonymous requests with 401', async () => {
        const res = await request(app).get(`${API}/clients`);
        expect(res.status).toBe(401);
    });

    it('rejects non-admin users with 403', async () => {
        const user = await agentFor('plain@example.com', false);
        const res = await user.get(`${API}/clients`);
        expect(res.status).toBe(403);
    });
});

describe('client routes — CRUD (admin)', () => {
    it('creates a confidential client and returns the secret exactly once', async () => {
        const admin = await agentFor('admin@example.com', true);

        const create = await admin.post(`${API}/clients`).send(CLIENT_BODY);
        expect(create.status).toBe(201);
        expect(create.body.clientId).toMatch(/^client_/);
        expect(create.body.clientSecret).toBeTruthy();
        expect(create.body.client.require_pkce).toBe(true);

        // Fetching the client later never exposes the secret.
        const get = await admin.get(`${API}/clients/${create.body.clientId}`);
        expect(get.status).toBe(200);
        expect(get.body.client.clientSecret).toBeUndefined();
        expect(get.body.client.client_secret_hash).toBeUndefined();
    });

    it('creates a public client with no secret', async () => {
        const admin = await agentFor('admin@example.com', true);
        const res = await admin
            .post(`${API}/clients`)
            .send({ ...CLIENT_BODY, clientType: 'public' });
        expect(res.status).toBe(201);
        expect(res.body.clientSecret).toBeUndefined();
    });

    it('rejects a wildcard redirect URI with 400', async () => {
        const admin = await agentFor('admin@example.com', true);
        const res = await admin
            .post(`${API}/clients`)
            .send({ ...CLIENT_BODY, redirectUris: ['https://*.evil.com/cb'] });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('invalid_request');
    });

    it('rejects an unknown scope with 400', async () => {
        const admin = await agentFor('admin@example.com', true);
        const res = await admin
            .post(`${API}/clients`)
            .send({ ...CLIENT_BODY, allowedScopes: ['openid', 'bogus:scope'] });
        expect(res.status).toBe(400);
    });

    it('lists and deletes clients; 404 after deletion', async () => {
        const admin = await agentFor('admin@example.com', true);
        const created = await admin.post(`${API}/clients`).send(CLIENT_BODY);
        const id = created.body.clientId;

        const list = await admin.get(`${API}/clients`);
        expect(list.body.clients.some((c: { client_id: string }) => c.client_id === id)).toBe(true);

        expect((await admin.delete(`${API}/clients/${id}`)).status).toBe(200);
        expect((await admin.get(`${API}/clients/${id}`)).status).toBe(404);
        expect((await admin.delete(`${API}/clients/${id}`)).status).toBe(404);
    });
});
