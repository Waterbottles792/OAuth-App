/**
 * OAuth helper primitives shared across phases.
 *
 * Redirect-URI rules enforce SECURITY_DECISIONS #7 (exact match, no wildcards). These are
 * validated here at registration time (Phase 2); Phase 3 will additionally enforce an
 * exact match between a request's redirect_uri and the client's registered set.
 */

import crypto from 'crypto';
import { ValidationError } from './errors';
import { safeEqual } from './crypto';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Validate a single redirect URI for registration. Throws ValidationError if it violates
 * any rule. Rules:
 *   - must be an absolute http/https URL
 *   - no wildcards anywhere (no '*')
 *   - no URL fragment (#...)  — forbidden for OAuth redirect URIs
 *   - http is allowed ONLY for loopback hosts (dev); everything else must be https
 */
export function validateRedirectUri(uri: string): void {
    if (typeof uri !== 'string' || uri.trim() === '') {
        throw new ValidationError('redirect_uri must be a non-empty string');
    }
    if (uri.includes('*')) {
        throw new ValidationError(`redirect_uri must not contain wildcards: ${uri}`);
    }

    let url: URL;
    try {
        url = new URL(uri);
    } catch {
        throw new ValidationError(`redirect_uri is not a valid absolute URL: ${uri}`);
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new ValidationError(`redirect_uri must use http or https: ${uri}`);
    }
    if (url.hash !== '') {
        throw new ValidationError(`redirect_uri must not contain a fragment: ${uri}`);
    }
    if (url.protocol === 'http:' && !LOCAL_HOSTS.has(url.hostname)) {
        throw new ValidationError(`redirect_uri must use https (http allowed only for localhost): ${uri}`);
    }
}

/** Exact-match check used when a request presents a redirect_uri (Phase 3). */
export function redirectUriMatches(registered: string[], provided: string): boolean {
    return registered.includes(provided);
}

/** Return the requested scopes that are NOT in `allowed` (empty array = all allowed). */
export function scopesNotAllowed(requested: string[], allowed: string[]): string[] {
    const allowedSet = new Set(allowed);
    return requested.filter((s) => !allowedSet.has(s));
}

/** Parse an OAuth `scope` parameter (space-delimited) into a de-duplicated array. */
export function parseScopes(scope: string | undefined): string[] {
    if (!scope) return [];
    return [...new Set(scope.trim().split(/\s+/).filter(Boolean))];
}

/**
 * PKCE S256 verification: the code_verifier hashes (SHA-256, base64url) to the stored
 * code_challenge. Constant-time comparison. (RFC 7636 §4.6.)
 */
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
    if (!codeVerifier || !codeChallenge) return false;
    const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return safeEqual(computed, codeChallenge);
}
