/**
 * OpenID Connect discovery endpoints (Phase 6). Mounted at the ISSUER ROOT (not under the
 * /api/v1 prefix) because RFC 8414 / OIDC Discovery require:
 *
 *   GET /.well-known/openid-configuration   provider metadata
 *   GET /.well-known/jwks.json              public signing keys (JWK Set)
 *
 * Both are PUBLIC (no authentication) and safe to cache. The `issuer` here must exactly equal
 * the `iss` claim minted by token.service, or clients will reject the tokens.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { serverConfig } from '../config';
import { oauthFlowConfig, oauthConfig } from '../config';
import { query } from '../db/pool';
import { getPublicJwks } from '../services/key.service';

const router = Router();

const h =
    (fn: (req: Request, res: Response) => Promise<void>) =>
    (req: Request, res: Response, next: NextFunction) =>
        fn(req, res).catch(next);

const ISSUER = oauthFlowConfig.issuer;
const OAUTH_BASE = `${ISSUER}/api/${serverConfig.apiVersion}/oauth`;

router.get(
    '/.well-known/openid-configuration',
    h(async (_req, res) => {
        // Advertise the seeded scope catalogue (openid is part of it).
        const { rows } = await query<{ name: string }>('SELECT name FROM oauth_scopes ORDER BY name');
        const scopes = rows.map((r) => r.name);

        res.status(200).json({
            issuer: ISSUER,
            authorization_endpoint: `${OAUTH_BASE}/authorize`,
            token_endpoint: `${OAUTH_BASE}/token`,
            userinfo_endpoint: `${OAUTH_BASE}/userinfo`,
            revocation_endpoint: `${OAUTH_BASE}/revoke`,
            jwks_uri: `${ISSUER}/.well-known/jwks.json`,
            scopes_supported: scopes,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'refresh_token'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: [oauthConfig.tokens.algorithm],
            token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
            code_challenge_methods_supported: ['S256'],
            claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'email', 'email_verified'],
        });
    }),
);

router.get(
    '/.well-known/jwks.json',
    h(async (_req, res) => {
        const jwks = await getPublicJwks();
        // Public keys are cacheable; allow a short cache to ease verifier load.
        res.status(200).set('Cache-Control', 'public, max-age=300').json(jwks);
    }),
);

export default router;
