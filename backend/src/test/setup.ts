
/**
 * Vitest global setup for Identity Core tests.
 *
 * - Applies migrations once before the suite.
 * - Resets state between tests: TRUNCATE users (cascades to sessions/mfa_secrets) and
 *   clears our Redis keyspace (sessions, mfa challenges, rate-limit counters).
 * - Closes the DB pool and Redis after the suite so the process can exit.
 *
 * Talks to the same dev Postgres/Redis as `npm run dev`. Safe on a dev box; do not point
 * these tests at a database with data you care about.
 */

import { afterAll, afterEach, beforeAll } from 'vitest';
import { runMigrations } from '../db/migrate';
import { closePool, query } from '../db/pool';
import { getRedis, closeRedis } from '../db/redis';

const REDIS_PATTERNS = ['session:*', 'mfa_challenge:*', 'ratelimit:*', 'alert:*', 'denylist:*'];

beforeAll(async () => {
    await runMigrations();
});

afterEach(async () => {
    // Cascades to sessions, mfa_secrets, oauth_clients-owned consents. Seeded oauth_scopes
    // are intentionally left in place.
    await query('TRUNCATE users, oauth_clients, audit_logs RESTART IDENTITY CASCADE');
    const redis = await getRedis();
    for (const pattern of REDIS_PATTERNS) {
        const keys = await redis.keys(pattern);
        if (keys.length) await redis.del(keys);
    }
});

afterAll(async () => {
    await closeRedis();
    await closePool();
});
