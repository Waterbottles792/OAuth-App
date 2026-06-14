import { describe, it, expect } from 'vitest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { signAccessToken, verifyAccessToken } from './token.service';
import { getActiveSigningKey, rotateSigningKey, getPublicJwks, clearKeyCache } from './key.service';

describe('Phase 8 — zero-downtime key rotation', () => {
    it('keeps old tokens verifiable while new tokens use the new key', async () => {
        clearKeyCache();
        const oldKey = await getActiveSigningKey();
        const oldToken = await signAccessToken({ userId: 'u1', clientId: 'c1', scopes: ['openid'] });

        const newKey = await rotateSigningKey();
        expect(newKey.kid).not.toBe(oldKey.kid);

        // Old token (signed by the retired key) STILL verifies during the overlap window.
        const oldPayload = await verifyAccessToken(oldToken.accessToken);
        expect(oldPayload.sub).toBe('u1');

        // New tokens are signed by the new key.
        const newToken = await signAccessToken({ userId: 'u2', clientId: 'c1', scopes: ['openid'] });
        const newHeaderKid = JSON.parse(
            Buffer.from(newToken.accessToken.split('.')[0], 'base64url').toString('utf8'),
        ).kid;
        expect(newHeaderKid).toBe(newKey.kid);
    });

    it('publishes both the retired and new key in JWKS during the overlap', async () => {
        const before = await getActiveSigningKey();
        const token = await signAccessToken({ userId: 'u3', clientId: 'c1', scopes: ['openid'] });
        const after = await rotateSigningKey();

        const jwks = await getPublicJwks();
        const kids = jwks.keys.map((k) => k.kid);
        expect(kids).toContain(before.kid); // retired, still in overlap
        expect(kids).toContain(after.kid); // new active

        // The pre-rotation token verifies against the published JWKS.
        const localJwks = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
        const { payload } = await jwtVerify(token.accessToken, localJwks);
        expect(payload.sub).toBe('u3');
    });
});
