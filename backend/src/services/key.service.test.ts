import { describe, it, expect } from 'vitest';
import { query } from '../db/pool';
import { getActiveSigningKey, getPublicKeyPem, clearKeyCache } from './key.service';

describe('key.service', () => {
    it('generates an RSA key on first use and stores the private key ENCRYPTED at rest', async () => {
        await query('DELETE FROM jwt_keys');
        clearKeyCache();

        const key = await getActiveSigningKey();
        expect(key.kid).toMatch(/^key_/);
        expect(key.algorithm).toBe('RS256');
        expect(key.publicKeyPem).toContain('BEGIN PUBLIC KEY');
        expect(key.privateKeyPem).toContain('BEGIN PRIVATE KEY');

        const { rows } = await query<{ private_key_enc: string; public_key: string }>(
            'SELECT private_key_enc, public_key FROM jwt_keys WHERE kid = $1',
            [key.kid],
        );
        // Stored private key is ciphertext (iv.tag.ciphertext), NOT the PEM.
        expect(rows[0].private_key_enc).not.toContain('BEGIN PRIVATE KEY');
        expect(rows[0].private_key_enc.split('.')).toHaveLength(3);
        // Public key is stored in the clear and matches.
        expect(rows[0].public_key).toBe(key.publicKeyPem);
        expect(await getPublicKeyPem(key.kid)).toBe(key.publicKeyPem);
    });

    it('reuses the single active key (idempotent, only one active row)', async () => {
        const a = await getActiveSigningKey();
        const b = await getActiveSigningKey();
        expect(a.kid).toBe(b.kid);

        const { rows } = await query<{ count: string }>(
            'SELECT COUNT(*)::text AS count FROM jwt_keys WHERE active = TRUE',
        );
        expect(rows[0].count).toBe('1');
    });
});
