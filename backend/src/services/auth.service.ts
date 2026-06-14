/**
 * Authentication orchestration: registration, login (with account lockout + MFA branch),
 * MFA-login completion, and lookups. This service ties together password/session/mfa.
 *
 * Account lockout (DB-level, per account) is distinct from login rate limiting
 * (Redis-level, per IP+email, in middleware) — defense in depth, both required by the
 * Phase 1 checklist.
 */

import { query } from '../db/pool';
import { authConfig, serverConfig } from '../config';
import { UnauthorizedError } from '../lib/errors';
import { randomToken } from '../lib/crypto';
import { mailer } from '../lib/mailer';
import { hashPassword, verifyPassword } from './password.service';
import { createSession, createMfaChallenge, consumeMfaChallenge, SessionContext } from './session.service';
import { isMfaEnabled, verifyChallenge } from './mfa.service';
import { recordAudit } from './audit.service';
import { recordLoginFailure } from '../lib/alerts';

export interface User {
    id: string;
    email: string;
    email_verified: boolean;
    is_admin: boolean;
    locked_at: Date | null;
    failed_login_attempts: number;
}

interface UserWithHash extends User {
    password_hash: string;
}

const PUBLIC_COLUMNS = 'id, email, email_verified, is_admin, locked_at, failed_login_attempts';

export async function getUserById(id: string): Promise<User | null> {
    const { rows } = await query<User>(`SELECT ${PUBLIC_COLUMNS} FROM users WHERE id = $1`, [id]);
    return rows[0] ?? null;
}

async function getUserByEmail(email: string): Promise<UserWithHash | null> {
    const { rows } = await query<UserWithHash>(
        `SELECT ${PUBLIC_COLUMNS}, password_hash FROM users WHERE email = $1`,
        [email],
    );
    return rows[0] ?? null;
}

/**
 * Register a new user. Email is assumed pre-normalized (lowercased/trimmed) by validation.
 *
 * Enumeration-resistant: the caller gets the same outcome whether or not the email was
 * already taken (the route returns a uniform response). The password is ALWAYS hashed first,
 * so response timing doesn't reveal account existence either. If the email already exists we
 * notify the address owner instead of confirming existence to the requester.
 */
export async function register(
    email: string,
    password: string,
): Promise<{ created: boolean; userId: string | null }> {
    // Always hash, even when the email is taken, to keep timing uniform.
    const passwordHash = await hashPassword(password);

    let userId: string;
    try {
        const { rows } = await query<{ id: string }>(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
            [email, passwordHash],
        );
        userId = rows[0].id;
    } catch (err) {
        if ((err as { code?: string }).code === '23505') {
            // Email already registered — do NOT reveal this. Notify the address owner.
            await mailer.send(
                email,
                'Registration attempt',
                'Someone tried to register an account with this email. If this was you, you already ' +
                    'have an account — try signing in or resetting your password.',
            );
            return { created: false, userId: null };
        }
        throw err;
    }

    // Dev email verification: log a link. (Verification enforcement is deferred — see notes.)
    const verifyToken = randomToken(32);
    await mailer.send(
        email,
        'Verify your email',
        `Confirm your account:\nhttp://localhost:${serverConfig.port}/api/v1/auth/verify-email?token=${verifyToken}`,
    );

    return { created: true, userId };
}

function isLocked(user: { locked_at: Date | null }): boolean {
    if (!user.locked_at) return false;
    const unlockAt = user.locked_at.getTime() + authConfig.lockout.lockDurationSeconds * 1000;
    return Date.now() < unlockAt;
}

async function recordFailedAttempt(user: UserWithHash): Promise<void> {
    const attempts = user.failed_login_attempts + 1;
    if (attempts >= authConfig.lockout.maxFailedAttempts) {
        await query('UPDATE users SET failed_login_attempts = $1, locked_at = NOW() WHERE id = $2', [
            attempts,
            user.id,
        ]);
    } else {
        await query('UPDATE users SET failed_login_attempts = $1 WHERE id = $2', [attempts, user.id]);
    }
}

async function clearFailures(userId: string): Promise<void> {
    await query(
        'UPDATE users SET failed_login_attempts = 0, locked_at = NULL WHERE id = $1',
        [userId],
    );
}

export type LoginResult =
    | { status: 'authenticated'; sessionToken: string; user: User }
    | { status: 'mfa_required'; challengeToken: string };

/**
 * Verify credentials. On success, either issues a session or (if MFA is enabled) returns a
 * pending challenge. Uses a uniform UnauthorizedError for unknown-user and wrong-password
 * so the two are indistinguishable to a caller.
 */
export async function login(
    email: string,
    password: string,
    ctx: SessionContext = {},
): Promise<LoginResult> {
    const user = await getUserByEmail(email);

    if (!user) {
        // Spend roughly-equivalent time to a real verify to blunt timing enumeration.
        await verifyPassword(
            '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            password,
        );
        // No actor (don't log the attempted email — that's PII). IP + reason only.
        await recordAudit({ event: 'login', result: 'failure', ip: ctx.ip, detail: { reason: 'unknown_user' } });
        if (ctx.ip) await recordLoginFailure(ctx.ip);
        throw new UnauthorizedError('Invalid email or password');
    }

    if (isLocked(user)) {
        await recordAudit({ event: 'login', result: 'failure', actorUserId: user.id, ip: ctx.ip, detail: { reason: 'locked' } });
        throw new UnauthorizedError('Account is temporarily locked. Try again later.');
    }

    const ok = await verifyPassword(user.password_hash, password);
    if (!ok) {
        await recordFailedAttempt(user);
        await recordAudit({ event: 'login', result: 'failure', actorUserId: user.id, ip: ctx.ip, detail: { reason: 'bad_password' } });
        if (ctx.ip) await recordLoginFailure(ctx.ip);
        throw new UnauthorizedError('Invalid email or password');
    }

    // Success: clear any prior failures / expired lock.
    if (user.failed_login_attempts > 0 || user.locked_at) {
        await clearFailures(user.id);
    }

    const publicUser: User = {
        id: user.id,
        email: user.email,
        email_verified: user.email_verified,
        is_admin: user.is_admin,
        locked_at: null,
        failed_login_attempts: 0,
    };

    if (await isMfaEnabled(user.id)) {
        const challengeToken = await createMfaChallenge(user.id);
        await recordAudit({ event: 'login', result: 'success', actorUserId: user.id, ip: ctx.ip, detail: { step: 'mfa_required' } });
        return { status: 'mfa_required', challengeToken };
    }

    const sessionToken = await createSession(user.id, ctx);
    await recordAudit({ event: 'login', result: 'success', actorUserId: user.id, ip: ctx.ip });
    return { status: 'authenticated', sessionToken, user: publicUser };
}

/** Complete a login that required MFA: validate the second factor, then issue a session. */
export async function completeMfaLogin(
    challengeToken: string,
    code: string,
    ctx: SessionContext = {},
): Promise<{ sessionToken: string; user: User }> {
    const userId = await consumeMfaChallenge(challengeToken);
    if (!userId) throw new UnauthorizedError('MFA challenge expired or invalid');

    const verified = await verifyChallenge(userId, code);
    if (!verified) {
        await recordAudit({ event: 'mfa_login', result: 'failure', actorUserId: userId, ip: ctx.ip });
        throw new UnauthorizedError('Invalid MFA code');
    }

    const user = await getUserById(userId);
    if (!user) throw new UnauthorizedError('Account not found');

    const sessionToken = await createSession(userId, ctx);
    await recordAudit({ event: 'mfa_login', result: 'success', actorUserId: userId, ip: ctx.ip });
    return { sessionToken, user };
}
