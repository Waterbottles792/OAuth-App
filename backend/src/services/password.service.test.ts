import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword } from './password.service';

describe('password.service', () => {
    it('hashes to an argon2id string and verifies the correct password', async () => {
        const hash = await hashPassword('CorrectHorse123');
        expect(hash.startsWith('$argon2id$')).toBe(true);
        expect(await verifyPassword(hash, 'CorrectHorse123')).toBe(true);
    });

    it('rejects an incorrect password', async () => {
        const hash = await hashPassword('CorrectHorse123');
        expect(await verifyPassword(hash, 'WrongHorse123')).toBe(false);
    });

    it('produces distinct hashes for the same input (random salt)', async () => {
        const a = await hashPassword('CorrectHorse123');
        const b = await hashPassword('CorrectHorse123');
        expect(a).not.toEqual(b);
    });

    it('returns false (no throw) for a malformed hash', async () => {
        expect(await verifyPassword('not-a-hash', 'whatever')).toBe(false);
    });
});
