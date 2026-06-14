/**
 * Redis-backed rate limiting (fixed window).
 *
 * Used to throttle brute-force login attempts per IP+email. This is separate from, and
 * complementary to, the per-account lockout in auth.service.
 *
 * Fail-open posture: if Redis is unreachable we let the request through rather than locking
 * everyone out of auth. The account lockout still provides a backstop.
 */

import { Request, Response, NextFunction } from 'express';
import { getRedis } from '../db/redis';
import { authConfig } from '../config';
import { RateLimitError } from '../lib/errors';

interface RateLimitOptions {
    keyPrefix: string;
    max: number;
    windowSeconds: number;
    keyFn: (req: Request) => string;
}

export function rateLimit(opts: RateLimitOptions) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const key = `ratelimit:${opts.keyPrefix}:${opts.keyFn(req)}`;
            const redis = await getRedis();

            const count = await redis.incr(key);
            if (count === 1) {
                await redis.expire(key, opts.windowSeconds);
            }

            if (count > opts.max) {
                const ttl = await redis.ttl(key);
                res.setHeader('Retry-After', String(ttl > 0 ? ttl : opts.windowSeconds));
                throw new RateLimitError('Too many attempts. Please try again later.', ttl);
            }
            next();
        } catch (err) {
            if (err instanceof RateLimitError) return next(err);
            // Redis failure: fail open.
            next();
        }
    };
}

const byIp = (req: { ip?: string }) => req.ip ?? 'unknown';

/** Login limiter keyed on client IP + submitted email. */
export const loginRateLimit = rateLimit({
    keyPrefix: 'login',
    max: authConfig.loginRateLimit.maxAttempts,
    windowSeconds: authConfig.loginRateLimit.windowSeconds,
    keyFn: (req) => {
        const email = typeof req.body?.email === 'string' ? req.body.email.toLowerCase() : 'unknown';
        return `${req.ip}:${email}`;
    },
});

/** Global per-IP login limiter — catches password spraying across many accounts from one IP. */
export const loginIpRateLimit = rateLimit({
    keyPrefix: 'login_ip',
    max: authConfig.loginIpRateLimit.max,
    windowSeconds: authConfig.loginIpRateLimit.windowSeconds,
    keyFn: byIp,
});

/** Registration limiter (per IP) — throttles account-creation spam. */
export const registerRateLimit = rateLimit({
    keyPrefix: 'register',
    max: authConfig.registerRateLimit.max,
    windowSeconds: authConfig.registerRateLimit.windowSeconds,
    keyFn: byIp,
});

/** MFA challenge limiter (per IP) — throttles second-factor guessing. */
export const mfaRateLimit = rateLimit({
    keyPrefix: 'mfa',
    max: authConfig.mfaRateLimit.max,
    windowSeconds: authConfig.mfaRateLimit.windowSeconds,
    keyFn: byIp,
});

/** Token endpoint limiter (per IP) — throttles code/secret guessing and DoS. */
export const tokenRateLimit = rateLimit({
    keyPrefix: 'token',
    max: authConfig.tokenRateLimit.max,
    windowSeconds: authConfig.tokenRateLimit.windowSeconds,
    keyFn: byIp,
});

/** Coarse per-IP limiter applied to every request (platform-wide backstop). */
export const globalRateLimit = rateLimit({
    keyPrefix: 'global',
    max: authConfig.globalRateLimit.max,
    windowSeconds: authConfig.globalRateLimit.windowSeconds,
    keyFn: byIp,
});
