import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { rateLimit } from './rateLimit.middleware';

/**
 * Exercises the rate-limit middleware that backs every limiter, including the platform-wide
 * globalRateLimit applied in server.ts. A tiny app with a low cap keeps it fast.
 */
describe('Phase 8 — rate limit middleware', () => {
    it('allows up to `max` requests per window then returns 429', async () => {
        const app = express();
        const key = `k-${Math.random()}`; // stable key across the burst
        app.use(rateLimit({ keyPrefix: 'rltest', max: 3, windowSeconds: 60, keyFn: () => key }));
        app.get('/x', (_req, res) => res.json({ ok: true }));

        const codes: number[] = [];
        for (let i = 0; i < 4; i++) {
            codes.push((await request(app).get('/x')).status);
        }
        expect(codes.slice(0, 3)).toEqual([200, 200, 200]);
        expect(codes[3]).toBe(429);
    });
});
