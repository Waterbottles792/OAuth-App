/**
 * OAuth 2.1 Authorization Endpoint (Phase 3).
 *
 *   GET  /oauth/authorize   start the flow; validate, then login / consent / issue code
 *   POST /oauth/authorize   consent submission; on approval, issue a code
 *
 * This is a FRONT-CHANNEL endpoint (browser redirects). It issues authorization codes only
 * — there is NO token endpoint here (Phase 4).
 *
 * Critical error-handling rule (RFC 6749 §4.1.2.1): if `client_id` or `redirect_uri` is
 * invalid we must NOT redirect (the redirect target can't be trusted) — we show an error
 * directly. Every other error is reported by redirecting back to the validated redirect_uri
 * with `error`/`error_description`/`state`.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { loadUser, requireAuth } from '../middleware/auth.middleware';
import { tokenRateLimit } from '../middleware/rateLimit.middleware';
import { oauthFlowConfig } from '../config';
import {
    redirectUriMatches,
    scopesNotAllowed,
    parseScopes,
    verifyPkceS256,
} from '../lib/oauth';
import { getClientByClientId, verifyClientSecret, ClientRecord } from '../services/client.service';
import { hasConsentFor, recordConsent } from '../services/consent.service';
import { issueCode, consumeCode } from '../services/authcode.service';
import { signAccessToken, signIdToken, verifyAccessToken } from '../services/token.service';
import {
    issueRefreshToken,
    rotateRefreshToken,
    revokeRefreshToken,
} from '../services/refreshtoken.service';
import { getUserById } from '../services/auth.service';
import { buildIdentityClaims } from '../lib/oidc';
import { logger } from '../lib/logger';

const router = Router();

const h =
    (fn: (req: Request, res: Response) => Promise<void>) =>
    (req: Request, res: Response, next: NextFunction) =>
        fn(req, res).catch(next);

interface RawParams {
    clientId?: string;
    redirectUri?: string;
    responseType?: string;
    scope?: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    nonce?: string;
}

type Validation =
    // client_id / redirect_uri invalid -> show a page, never redirect.
    | { kind: 'page_error'; status: number; error: string; description: string }
    // any later error -> redirect back to redirect_uri with error params.
    | { kind: 'redirect_error'; redirectUri: string; error: string; description: string; state?: string }
    | {
          kind: 'ok';
          client: ClientRecord;
          redirectUri: string;
          scopes: string[];
          codeChallenge: string;
          state?: string;
          nonce?: string;
      };

/** Build a redirect URL, merging params into the (possibly already query-bearing) base. */
function buildRedirect(base: string, params: Record<string, string | undefined>): string {
    const url = new URL(base);
    for (const [k, v] of Object.entries(params)) {
        if (v !== undefined) url.searchParams.set(k, v);
    }
    return url.toString();
}

/**
 * Validate an authorization request. Order is security-significant: client and redirect_uri
 * are checked first (their failures cannot redirect), then everything else.
 */
async function validateAuthorizeRequest(p: RawParams): Promise<Validation> {
    if (!p.clientId) {
        return { kind: 'page_error', status: 400, error: 'invalid_request', description: 'client_id is required' };
    }
    const client = await getClientByClientId(p.clientId);
    if (!client) {
        return { kind: 'page_error', status: 400, error: 'invalid_client', description: 'Unknown client' };
    }
    if (!p.redirectUri) {
        return { kind: 'page_error', status: 400, error: 'invalid_request', description: 'redirect_uri is required' };
    }
    if (!redirectUriMatches(client.redirect_uris, p.redirectUri)) {
        return {
            kind: 'page_error',
            status: 400,
            error: 'invalid_request',
            description: 'redirect_uri does not match a registered URI',
        };
    }

    // From here, redirect_uri is trusted — errors redirect back with state.
    const redirectError = (error: string, description: string): Validation => ({
        kind: 'redirect_error',
        redirectUri: p.redirectUri!,
        error,
        description,
        state: p.state,
    });

    if (p.responseType !== 'code') {
        return redirectError('unsupported_response_type', 'response_type must be "code"');
    }

    const scopes = parseScopes(p.scope);
    const notAllowed = scopesNotAllowed(scopes, client.allowed_scopes);
    if (notAllowed.length) {
        return redirectError('invalid_scope', `Scope(s) not permitted for this client: ${notAllowed.join(' ')}`);
    }

    // PKCE is mandatory for every client (SECURITY_DECISIONS #5) and must use S256.
    if (!p.codeChallenge) {
        return redirectError('invalid_request', 'code_challenge is required (PKCE)');
    }
    if (p.codeChallengeMethod !== 'S256') {
        return redirectError('invalid_request', 'code_challenge_method must be S256');
    }

    return {
        kind: 'ok',
        client,
        redirectUri: p.redirectUri,
        scopes,
        codeChallenge: p.codeChallenge,
        state: p.state,
        nonce: p.nonce,
    };
}

function paramsFromQuery(req: Request): RawParams {
    const q = req.query as Record<string, string | undefined>;
    return {
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        responseType: q.response_type,
        scope: q.scope,
        state: q.state,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
        nonce: q.nonce,
    };
}

function paramsFromBody(req: Request): RawParams {
    const b = req.body as Record<string, string | undefined>;
    return {
        clientId: b.client_id,
        redirectUri: b.redirect_uri,
        responseType: b.response_type,
        scope: b.scope,
        state: b.state,
        codeChallenge: b.code_challenge,
        codeChallengeMethod: b.code_challenge_method,
        nonce: b.nonce,
    };
}

/** Emit the response for a non-ok validation outcome. Returns true if it handled the response. */
function handleInvalid(res: Response, v: Validation): boolean {
    if (v.kind === 'page_error') {
        res.status(v.status).json({ error: v.error, error_description: v.description });
        return true;
    }
    if (v.kind === 'redirect_error') {
        res.redirect(
            buildRedirect(v.redirectUri, { error: v.error, error_description: v.description, state: v.state }),
        );
        return true;
    }
    return false;
}

// GET /authorize — validate, then: not-logged-in -> login; already-consented -> code;
// otherwise -> a consent prompt (JSON, since the consent UI is Phase 7).
router.get(
    '/authorize',
    loadUser,
    h(async (req, res) => {
        const v = await validateAuthorizeRequest(paramsFromQuery(req));
        if (handleInvalid(res, v)) return;
        if (v.kind !== 'ok') return;

        if (!req.user) {
            // Send the user to log in, then back to this exact authorize URL.
            const returnTo = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
            res.redirect(buildRedirect(oauthFlowConfig.loginUrl, { return_to: returnTo }));
            return;
        }

        if (await hasConsentFor(req.user.id, v.client.id, v.scopes)) {
            const code = await issueCode({
                clientDbId: v.client.id,
                userId: req.user.id,
                redirectUri: v.redirectUri,
                scopes: v.scopes,
                codeChallenge: v.codeChallenge,
                nonce: v.nonce,
            });
            res.redirect(buildRedirect(v.redirectUri, { code, state: v.state }));
            return;
        }

        // Consent required — describe the request so the UI (Phase 7) can render it and POST back.
        res.status(200).json({
            consent_required: true,
            client: { client_id: v.client.client_id, name: v.client.name },
            scopes: v.scopes,
            authorization_request: {
                client_id: v.client.client_id,
                redirect_uri: v.redirectUri,
                response_type: 'code',
                scope: v.scopes.join(' '),
                state: v.state,
                code_challenge: v.codeChallenge,
                code_challenge_method: 'S256',
                nonce: v.nonce,
            },
        });
    }),
);

// POST /authorize — the consent decision. Re-validates everything (never trust the GET).
router.post(
    '/authorize',
    requireAuth,
    h(async (req, res) => {
        const v = await validateAuthorizeRequest(paramsFromBody(req));
        if (handleInvalid(res, v)) return;
        if (v.kind !== 'ok') return;

        const approved = req.body.approved === true || req.body.approved === 'true';
        if (!approved) {
            res.redirect(
                buildRedirect(v.redirectUri, {
                    error: 'access_denied',
                    error_description: 'The user denied the authorization request',
                    state: v.state,
                }),
            );
            return;
        }

        await recordConsent(req.user!.id, v.client.id, v.scopes);
        const code = await issueCode({
            clientDbId: v.client.id,
            userId: req.user!.id,
            redirectUri: v.redirectUri,
            scopes: v.scopes,
            codeChallenge: v.codeChallenge,
            nonce: v.nonce,
        });
        res.redirect(buildRedirect(v.redirectUri, { code, state: v.state }));
    }),
);

// ---------------------------------------------------------------------------
// Token endpoint (Phase 4 + Phase 5) — back-channel. JSON error responses (RFC 6749 §5.2),
// NOT redirects. Supports the authorization_code and refresh_token grants. Successful
// responses include a rotating, single-use refresh_token (Phase 5).
// ---------------------------------------------------------------------------

function tokenError(res: Response, status: number, error: string, description: string): void {
    res.status(status)
        .set('Cache-Control', 'no-store')
        .set('Pragma', 'no-cache')
        .json({ error, error_description: description });
}

/**
 * Authenticate the client for a back-channel request. Confidential clients must present a
 * valid secret. On failure this writes the error response and returns null.
 */
async function authenticateClient(
    res: Response,
    clientId: string | undefined,
    clientSecret: string | undefined,
): Promise<ClientRecord | null> {
    if (!clientId) {
        tokenError(res, 400, 'invalid_request', 'client_id is required');
        return null;
    }
    const client = await getClientByClientId(clientId);
    if (!client) {
        tokenError(res, 401, 'invalid_client', 'Unknown client');
        return null;
    }
    if (client.client_type === 'confidential') {
        if (!clientSecret || !(await verifyClientSecret(clientId, clientSecret))) {
            tokenError(res, 401, 'invalid_client', 'Client authentication failed');
            return null;
        }
    }
    return client;
}

/**
 * Mint an access token and write the RFC 6749 §5.1 success response. A refresh token is
 * included only when `refresh` is provided: at code exchange that means the client is allowed
 * the refresh_token grant (a new family begins); on rotation `refresh.family` continues the
 * existing family within its absolute deadline.
 */
async function issueTokenResponse(
    res: Response,
    client: ClientRecord,
    userId: string,
    scopes: string[],
    refresh: { family: { familyId: string; parentTokenHash: string; familyExpiresAt: Date } | null } | null,
    nonce: string | null = null,
): Promise<void> {
    const access = await signAccessToken({ userId, clientId: client.client_id, scopes });

    const body: Record<string, unknown> = {
        access_token: access.accessToken,
        token_type: access.tokenType,
        expires_in: access.expiresIn,
        scope: access.scope,
    };

    // OIDC: an `openid` scope yields an ID token signed with the same key as the access token.
    if (scopes.includes('openid')) {
        const user = await getUserById(userId);
        if (user) {
            body.id_token = await signIdToken({
                userId,
                clientId: client.client_id,
                nonce,
                claims: buildIdentityClaims(user, scopes),
            });
        }
    }

    if (refresh) {
        const issued = await issueRefreshToken({
            userId,
            clientDbId: client.id,
            scopes,
            familyId: refresh.family?.familyId,
            parentTokenHash: refresh.family?.parentTokenHash,
            familyExpiresAt: refresh.family?.familyExpiresAt,
        });
        body.refresh_token = issued.refreshToken;
    }

    res.status(200).set('Cache-Control', 'no-store').set('Pragma', 'no-cache').json(body);
}

async function handleAuthorizationCodeGrant(
    res: Response,
    client: ClientRecord,
    b: Record<string, string | undefined>,
): Promise<void> {
    const { code, redirect_uri: redirectUri, code_verifier: codeVerifier } = b;

    if (!code || !redirectUri || !codeVerifier) {
        return tokenError(res, 400, 'invalid_request', 'code, redirect_uri and code_verifier are required');
    }

    // Single-use consumption: the code is burned here, even if a later check fails.
    const consumed = await consumeCode(code);
    if (!consumed.ok || !consumed.record) {
        if (consumed.reason === 'already_used') {
            logger.warn({ event: 'authz_code_reuse', clientId: client.client_id });
        }
        return tokenError(res, 400, 'invalid_grant', 'Authorization code is invalid, expired, or already used');
    }
    const record = consumed.record;

    // The code must have been issued to THIS client and THIS redirect_uri.
    if (record.client_id !== client.id) {
        return tokenError(res, 400, 'invalid_grant', 'Authorization code was issued to a different client');
    }
    if (record.redirect_uri !== redirectUri) {
        return tokenError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request');
    }

    // PKCE: the verifier must hash to the stored challenge.
    if (!verifyPkceS256(codeVerifier, record.code_challenge)) {
        return tokenError(res, 400, 'invalid_grant', 'PKCE verification failed');
    }

    // Only mint a refresh token (a new family) if this client is allowed the refresh_token grant.
    const wantsRefresh = client.allowed_grant_types.includes('refresh_token');
    await issueTokenResponse(
        res,
        client,
        record.user_id,
        record.scopes,
        wantsRefresh ? { family: null } : null,
        record.nonce, // OIDC nonce -> ID token
    );
}

async function handleRefreshTokenGrant(
    res: Response,
    client: ClientRecord,
    b: Record<string, string | undefined>,
): Promise<void> {
    const presented = b.refresh_token;
    if (!presented) {
        return tokenError(res, 400, 'invalid_request', 'refresh_token is required');
    }

    const result = await rotateRefreshToken(presented, client.id);
    if (!result.ok || !result.record) {
        if (result.reason === 'reused' || result.reason === 'revoked') {
            // Replay of a rotated/revoked token: the whole family was just revoked.
            logger.warn({ event: 'refresh_token_reuse', clientId: client.client_id });
        }
        return tokenError(res, 400, 'invalid_grant', 'Refresh token is invalid, expired, or has been revoked');
    }
    const old = result.record;

    // Rotate: mint a new access token + a child refresh token in the SAME family, inheriting
    // the family's absolute deadline (rotation never extends it).
    await issueTokenResponse(res, client, old.user_id, old.scopes, {
        family: {
            familyId: old.token_family_id,
            parentTokenHash: old.token_hash,
            familyExpiresAt: old.family_expires_at,
        },
    });
}

router.post(
    '/token',
    tokenRateLimit,
    h(async (req, res) => {
        const b = req.body as Record<string, string | undefined>;

        // Validate the grant type before authenticating, so an unsupported grant is reported
        // as such regardless of client credentials.
        if (b.grant_type !== 'authorization_code' && b.grant_type !== 'refresh_token') {
            return tokenError(
                res,
                400,
                'unsupported_grant_type',
                'Only authorization_code and refresh_token are supported',
            );
        }

        const client = await authenticateClient(res, b.client_id, b.client_secret);
        if (!client) return; // error already written

        // Enforce per-client grant restrictions (RFC 6749 §5.2 unauthorized_client).
        if (!client.allowed_grant_types.includes(b.grant_type)) {
            return tokenError(res, 400, 'unauthorized_client', 'This client may not use the requested grant type');
        }

        if (b.grant_type === 'authorization_code') {
            return handleAuthorizationCodeGrant(res, client, b);
        }
        return handleRefreshTokenGrant(res, client, b);
    }),
);

// ---------------------------------------------------------------------------
// Revocation endpoint (Phase 5) — RFC 7009. Back-channel, client-authenticated. Revokes a
// refresh token and its whole family. Per the RFC, an invalid/unknown token is NOT an error:
// the endpoint responds 200 regardless, so clients can't probe token validity here.
// ---------------------------------------------------------------------------

router.post(
    '/revoke',
    tokenRateLimit,
    h(async (req, res) => {
        const b = req.body as Record<string, string | undefined>;

        const client = await authenticateClient(res, b.client_id, b.client_secret);
        if (!client) return; // error already written

        const token = b.token;
        if (token) {
            // token_type_hint is advisory; we only manage refresh tokens (access tokens are
            // stateless JWTs). Unknown/foreign tokens are silently ignored per RFC 7009 §2.2.
            await revokeRefreshToken(token, client.id);
        }

        res.status(200).set('Cache-Control', 'no-store').set('Pragma', 'no-cache').json({});
    }),
);

// ---------------------------------------------------------------------------
// UserInfo endpoint (Phase 6, OIDC) — requires a valid Bearer access token. Returns the
// subject plus the identity claims permitted by the token's scopes. RFC 6750 errors are
// signalled via the WWW-Authenticate header.
// ---------------------------------------------------------------------------

function bearerToken(req: Request): string | null {
    const header = req.get('authorization');
    if (!header) return null;
    const [scheme, value] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !value) return null;
    return value.trim();
}

router.get(
    '/userinfo',
    h(async (req, res) => {
        const token = bearerToken(req);
        if (!token) {
            res.status(401)
                .set('WWW-Authenticate', 'Bearer error="invalid_request"')
                .json({ error: 'invalid_request', error_description: 'Missing Bearer access token' });
            return;
        }

        let payload;
        try {
            payload = await verifyAccessToken(token);
        } catch {
            res.status(401)
                .set('WWW-Authenticate', 'Bearer error="invalid_token"')
                .json({ error: 'invalid_token', error_description: 'The access token is invalid or expired' });
            return;
        }

        const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
        const user = payload.sub ? await getUserById(payload.sub) : null;
        if (!user) {
            res.status(401)
                .set('WWW-Authenticate', 'Bearer error="invalid_token"')
                .json({ error: 'invalid_token', error_description: 'Unknown subject' });
            return;
        }

        // `sub` is always returned; everything else is scope-gated (same map as the ID token).
        res.status(200)
            .set('Cache-Control', 'no-store')
            .json({ sub: user.id, ...buildIdentityClaims(user, scopes) });
    }),
);

export default router;
