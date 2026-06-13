/**
 * Password hashing service — Argon2id only.
 *
 * Decision (SECURITY_DECISIONS #cryptographic-standards): Argon2id with m=64MB, t=3, p=4.
 * Never bcrypt, never a plain hash. Parameters come from authConfig so they live in one place.
 */

import argon2 from 'argon2';
import { authConfig } from '../config';

const ARGON2_OPTIONS: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: authConfig.argon2.memoryCost,
    timeCost: authConfig.argon2.timeCost,
    parallelism: authConfig.argon2.parallelism,
};

export async function hashPassword(plain: string): Promise<string> {
    return argon2.hash(plain, ARGON2_OPTIONS);
}

/**
 * Verify a password against a stored hash. Returns false on any malformed-hash error
 * rather than throwing, so callers get a uniform "wrong credentials" path.
 */
export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
    try {
        return await argon2.verify(hash, plain);
    } catch {
        return false;
    }
}
