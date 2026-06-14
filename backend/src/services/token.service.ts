/**
 * Access token issuance & verification (Phase 4).
 *
 * Access tokens are JWTs signed with the active RS256 key. They are short-lived
 * (oauthConfig.tokens.accessTokenLifetime — 15 min, LOCKED) and self-contained: a resource
 * server can verify them with the public key (JWKS in Phase 6) without calling back.
 *
 * `jose` requires the verifier to pin the accepted algorithm(s), so HS256 / `alg: none`
 * tokens are structurally unacceptable — there is no code path that signs or verifies them.
 *
 * NOTE: access tokens only. No refresh tokens (Phase 5), no ID tokens (Phase 6).
 */

import { SignJWT, jwtVerify, importPKCS8, importSPKI, JWTPayload } from 'jose';
import { oauthConfig, oauthFlowConfig } from '../config';
import { getActiveSigningKey, getPublicKeyPem } from './key.service';

const ALG = oauthConfig.tokens.algorithm; // 'RS256' (LOCKED)
const LIFETIME = oauthConfig.tokens.accessTokenLifetime; // 900s (LOCKED)
const ID_LIFETIME = oauthConfig.tokens.idTokenLifetime; // OIDC ID token lifetime (Phase 6)

export interface AccessTokenInput {
    userId: string; // -> sub
    clientId: string; // public client_id -> client_id claim
    scopes: string[]; // -> scope claim (space-delimited)
}

export interface IssuedToken {
    accessToken: string;
    tokenType: 'Bearer';
    expiresIn: number;
    scope: string;
}

/** Mint a signed access token. exp = iat + LIFETIME (never hardcoded here). */
export async function signAccessToken(input: AccessTokenInput): Promise<IssuedToken> {
    const key = await getActiveSigningKey();
    const privateKey = await importPKCS8(key.privateKeyPem, ALG);

    const nowSec = Math.floor(Date.now() / 1000);
    const scope = input.scopes.join(' ');

    const accessToken = await new SignJWT({ scope, client_id: input.clientId })
        .setProtectedHeader({ alg: ALG, kid: key.kid, typ: 'at+jwt' })
        .setIssuer(oauthFlowConfig.issuer)
        .setSubject(input.userId)
        .setAudience(oauthFlowConfig.accessTokenAudience)
        .setIssuedAt(nowSec)
        .setExpirationTime(nowSec + LIFETIME)
        .sign(privateKey);

    return { accessToken, tokenType: 'Bearer', expiresIn: LIFETIME, scope };
}

export interface IdTokenInput {
    userId: string; // -> sub
    clientId: string; // public client_id -> aud (OIDC: the ID token's audience IS the client)
    nonce?: string | null; // replay protection — echoed verbatim from the auth request
    claims?: Record<string, unknown>; // scope-gated identity claims (email, ...)
}

/**
 * Mint a signed OIDC ID token. Signed with the SAME key/alg as access tokens (one signing
 * path), but `aud` is the client_id and `typ` is plain JWT. The nonce, when present, is
 * embedded so the client can detect replay.
 */
export async function signIdToken(input: IdTokenInput): Promise<string> {
    const key = await getActiveSigningKey();
    const privateKey = await importPKCS8(key.privateKeyPem, ALG);

    const nowSec = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = { ...(input.claims ?? {}) };
    if (input.nonce) payload.nonce = input.nonce;

    return new SignJWT(payload)
        .setProtectedHeader({ alg: ALG, kid: key.kid, typ: 'JWT' })
        .setIssuer(oauthFlowConfig.issuer)
        .setSubject(input.userId)
        .setAudience(input.clientId)
        .setIssuedAt(nowSec)
        .setExpirationTime(nowSec + ID_LIFETIME)
        .sign(privateKey);
}

/**
 * Verify an access token's signature and standard claims, pinning the algorithm to the
 * configured asymmetric alg. Resolves the public key by the token's `kid`. Throws on any
 * invalid token (bad signature, expired, wrong iss/aud, or a non-RS256 alg).
 */
export async function verifyAccessToken(token: string): Promise<JWTPayload> {
    // Read the kid from the header WITHOUT trusting the token, to select the public key.
    const headerB64 = token.split('.')[0];
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8')) as {
        kid?: string;
        alg?: string;
    };
    if (!header.kid) throw new Error('missing kid');

    const publicKeyPem = await getPublicKeyPem(header.kid);
    if (!publicKeyPem) throw new Error('unknown kid');
    const publicKey = await importSPKI(publicKeyPem, ALG);

    const { payload } = await jwtVerify(token, publicKey, {
        algorithms: [ALG], // pin: rejects HS256 / none / anything else
        issuer: oauthFlowConfig.issuer,
        audience: oauthFlowConfig.accessTokenAudience,
    });
    return payload;
}
