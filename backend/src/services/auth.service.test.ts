import { describe, it, expect } from 'vitest';
import { query } from '../db/pool';
import { register, login, getUserById } from './auth.service';
import { UnauthorizedError } from '../lib/errors';

const EMAIL = 'lockme@example.com';
const PASSWORD = 'CorrectHorse123';

async function lockedAt(email: string): Promise<Date | null> {
    const { rows } = await query<{ locked_at: Date | null }>(
        'SELECT locked_at FROM users WHERE email = $1',
        [email],
    );
    return rows[0]?.locked_at ?? null;
}

describe('auth.service', () => {
    it('registers a user and is enumeration-resistant on duplicates', async () => {
        const first = await register(EMAIL, PASSWORD);
        expect(first.created).toBe(true);
        const user = await getUserById(first.userId!);
        expect(user?.email).toBe(EMAIL);

        // Re-registering the same email does NOT throw or reveal existence; no second row.
        const dup = await register(EMAIL, PASSWORD);
        expect(dup.created).toBe(false);
        expect(dup.userId).toBeNull();

        const { rows } = await query<{ count: string }>(
            'SELECT COUNT(*)::text AS count FROM users WHERE email = $1',
            [EMAIL],
        );
        expect(rows[0].count).toBe('1');
    });

    it('locks the account after 5 failed attempts and then refuses a correct password', async () => {
        await register(EMAIL, PASSWORD);

        for (let i = 0; i < 5; i++) {
            await expect(login(EMAIL, 'WrongPassword123')).rejects.toBeInstanceOf(UnauthorizedError);
        }
        expect(await lockedAt(EMAIL)).not.toBeNull();

        // Even the correct password is refused while locked.
        await expect(login(EMAIL, PASSWORD)).rejects.toThrow(/locked/i);
    });

    it('gives an indistinguishable error for unknown user vs wrong password', async () => {
        await register(EMAIL, PASSWORD);
        const unknown = await login('nobody@example.com', PASSWORD).catch((e) => e);
        const wrong = await login(EMAIL, 'WrongPassword123').catch((e) => e);
        expect(unknown).toBeInstanceOf(UnauthorizedError);
        expect(wrong).toBeInstanceOf(UnauthorizedError);
        expect(unknown.message).toBe(wrong.message);
    });

    it('authenticates with the correct password and resets failure counters', async () => {
        await register(EMAIL, PASSWORD);
        await login(EMAIL, 'WrongPassword123').catch(() => undefined); // 1 failure
        const result = await login(EMAIL, PASSWORD);
        expect(result.status).toBe('authenticated');

        const { rows } = await query<{ failed_login_attempts: number }>(
            'SELECT failed_login_attempts FROM users WHERE email = $1',
            [EMAIL],
        );
        expect(rows[0].failed_login_attempts).toBe(0);
    });
});
