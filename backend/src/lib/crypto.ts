/**
 * Cryptographic helpers for token generation and hashing.
 *
 * - Random tokens use crypto.randomBytes (CSPRNG), never Math.random.
 * - Tokens handed to clients are stored only as SHA-256 hashes server-side, so a dump of
 *   Redis/Postgres never reveals usable tokens.
 * - Constant-time comparison for any secret-equality check.
 */

import crypto from 'crypto';

/** Cryptographically random token, URL-safe base64, ~`bytes` of entropy. */
export function randomToken(bytes = 32): string {
    return crypto.randomBytes(bytes).toString('base64url');
}

/** SHA-256 hex digest. Used to hash session tokens, backup codes, etc. before storage. */
export function sha256(input: string): string {
    return crypto.createHash('sha256').update(input).digest('hex');
}

/** Constant-time string comparison (avoids timing side-channels on secret comparisons). */
export function safeEqual(a: string, b: string): boolean {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}
