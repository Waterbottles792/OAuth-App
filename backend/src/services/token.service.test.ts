import { describe, it, expect } from 'vitest';
import { SignJWT } from 'jose';
import { signAccessToken, verifyAccessToken } from './token.service';
import { getActiveSigningKey } from './key.service';
import { oauthFlowConfig } from '../config';

function decodeHeader(token: string): Record<string, unknown> {
    return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

describe('token.service', () => {
    it('signs a verifiable RS256 access token with the right claims and 15-min lifetime', async () => {
        const t = await signAccessToken({
            userId: 'user-123',
            clientId: 'client_abc',
            scopes: ['openid', 'email'],
        });
        expect(t.tokenType).toBe('Bearer');
        expect(t.expiresIn).toBe(900);

        const header = decodeHeader(t.accessToken);
        expect(header.alg).toBe('RS256');
        expect(header.kid).toBeTruthy();
        expect(header.typ).toBe('at+jwt');

        const payload = await verifyAccessToken(t.accessToken);
        expect(payload.sub).toBe('user-123');
        expect(payload.client_id).toBe('client_abc');
        expect(payload.scope).toBe('openid email');
        expect(payload.iss).toBe(oauthFlowConfig.issuer);
        expect(payload.aud).toBe(oauthFlowConfig.accessTokenAudience);
        expect((payload.exp as number) - (payload.iat as number)).toBe(900);
    });

    it('rejects an HS256 token even with a valid kid (algorithm pinning)', async () => {
        const key = await getActiveSigningKey();
        const forged = await new SignJWT({ scope: 'openid' })
            .setProtectedHeader({ alg: 'HS256', kid: key.kid })
            .setIssuer(oauthFlowConfig.issuer)
            .setAudience(oauthFlowConfig.accessTokenAudience)
            .setSubject('attacker')
            .setIssuedAt()
            .setExpirationTime('15m')
            .sign(new TextEncoder().encode('a'.repeat(32)));

        await expect(verifyAccessToken(forged)).rejects.toBeDefined();
    });

    it('rejects an alg:none token', async () => {
        const key = await getActiveSigningKey();
        const header = Buffer.from(JSON.stringify({ alg: 'none', kid: key.kid, typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(
            JSON.stringify({
                sub: 'attacker',
                iss: oauthFlowConfig.issuer,
                aud: oauthFlowConfig.accessTokenAudience,
                exp: Math.floor(Date.now() / 1000) + 900,
            }),
        ).toString('base64url');
        const noneToken = `${header}.${payload}.`;

        await expect(verifyAccessToken(noneToken)).rejects.toBeDefined();
    });

    it('rejects a tampered token', async () => {
        const t = await signAccessToken({ userId: 'u', clientId: 'c', scopes: [] });
        const tampered = t.accessToken.slice(0, -3) + 'AAA';
        await expect(verifyAccessToken(tampered)).rejects.toBeDefined();
    });
});
