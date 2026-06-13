/**
 * Server-side session management (SECURITY_DECISIONS #8, #9).
 *
 * - The raw session token is 32 bytes of CSPRNG entropy and is returned to the caller to
 *   be set as an HttpOnly cookie. It is NEVER stored anywhere in raw form.
 * - Redis is the source of truth (`session:<sha256(token)>` -> { userId, ... }) with a TTL.
 *   The TTL is refreshed on every successful lookup (sliding 24h window).
 * - Postgres `sessions` holds a parallel audit row (also keyed by token hash).
 * - A short-lived "pending MFA" challenge is stored the same way, between password success
 *   and second-factor completion, so no real session exists until MFA passes.
 */

import { query } from '../db/pool';
import { getRedis } from '../db/redis';
import { authConfig } from '../config';
import { randomToken, sha256 } from '../lib/crypto';

const SESSION_PREFIX = 'session:';
const MFA_PREFIX = 'mfa_challenge:';

export interface SessionData {
    userId: string;
    createdAt: number; // epoch ms
}

export interface SessionContext {
    ip?: string;
    userAgent?: string;
}

function sessionKey(tokenHash: string): string {
    return SESSION_PREFIX + tokenHash;
}

/** Create a session, persist it (Redis + Postgres), and return the raw cookie token. */
export async function createSession(userId: string, ctx: SessionContext = {}): Promise<string> {
    const token = randomToken(32);
    const tokenHash = sha256(token);
    const ttl = authConfig.session.ttlSeconds;
    const data: SessionData = { userId, createdAt: Date.now() };

    const redis = await getRedis();
    await redis.set(sessionKey(tokenHash), JSON.stringify(data), { EX: ttl });

    await query(
        `INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent)
         VALUES ($1, $2, NOW() + ($3 || ' seconds')::interval, $4, $5)`,
        [userId, tokenHash, String(ttl), ctx.ip ?? null, ctx.userAgent ?? null],
    );

    return token;
}

/**
 * Look up a session by its raw token. On hit, refresh the TTL (sliding window) and return
 * the session data; on miss/expiry, return null.
 */
export async function getSession(token: string): Promise<SessionData | null> {
    if (!token) return null;
    const tokenHash = sha256(token);
    const redis = await getRedis();
    const raw = await redis.get(sessionKey(tokenHash));
    if (!raw) return null;

    const ttl = authConfig.session.ttlSeconds;
    await redis.expire(sessionKey(tokenHash), ttl);
    await query(
        `UPDATE sessions SET expires_at = NOW() + ($1 || ' seconds')::interval WHERE token_hash = $2`,
        [String(ttl), tokenHash],
    );

    return JSON.parse(raw) as SessionData;
}

/** Destroy a single session (logout). Idempotent. */
export async function destroySession(token: string): Promise<void> {
    if (!token) return;
    const tokenHash = sha256(token);
    const redis = await getRedis();
    await redis.del(sessionKey(tokenHash));
    await query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
}

/** Destroy every session for a user (e.g. password change, account lock). */
export async function destroyAllForUser(userId: string): Promise<void> {
    const { rows } = await query<{ token_hash: string }>(
        'SELECT token_hash FROM sessions WHERE user_id = $1',
        [userId],
    );
    const redis = await getRedis();
    if (rows.length) {
        await redis.del(rows.map((r: { token_hash: string }) => sessionKey(r.token_hash)));
    }
    await query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

// ---------------------------------------------------------------------------
// Pending MFA challenge (ephemeral, Redis-only — no real session yet)
// ---------------------------------------------------------------------------

/** Create a short-lived challenge after password success; returns the raw challenge token. */
export async function createMfaChallenge(userId: string): Promise<string> {
    const token = randomToken(32);
    const redis = await getRedis();
    await redis.set(MFA_PREFIX + sha256(token), userId, {
        EX: authConfig.mfa.pendingChallengeTtlSeconds,
    });
    return token;
}

/** Consume a challenge token, returning the userId once (single-use), or null if invalid. */
export async function consumeMfaChallenge(token: string): Promise<string | null> {
    if (!token) return null;
    const key = MFA_PREFIX + sha256(token);
    const redis = await getRedis();
    const userId = await redis.get(key);
    if (!userId) return null;
    await redis.del(key);
    return userId;
}
