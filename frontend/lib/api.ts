/**
 * Backend API client (Phase 7).
 *
 * SECURITY: every request is credentialed (`credentials: 'include'`) so the backend's
 * HttpOnly `sid` session cookie travels with it — and we NEVER read or store any token in
 * JS (SECURITY_DECISIONS #8/#9). The browser holds auth state entirely in the HttpOnly
 * cookie; this module only ever sees JSON bodies, never the session value.
 */

export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const API_VERSION = process.env.NEXT_PUBLIC_API_VERSION || 'v1';

export const API_BASE = `${API_URL}/api/${API_VERSION}`;

export class ApiError extends Error {
    status: number;
    code?: string;
    constructor(status: number, message: string, code?: string) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

type Json = Record<string, unknown>;

async function request<T = Json>(method: string, path: string, body?: Json): Promise<T> {
    let res: Response;
    try {
        res = await fetch(`${API_BASE}${path}`, {
            method,
            credentials: 'include',
            headers: body ? { 'Content-Type': 'application/json' } : undefined,
            body: body ? JSON.stringify(body) : undefined,
        });
    } catch {
        throw new ApiError(0, 'Could not reach the server. Is the backend running?');
    }

    const text = await res.text();
    const data = text ? (JSON.parse(text) as Json) : {};
    if (!res.ok) {
        const message =
            (data.message as string) || (data.error_description as string) || (data.error as string) || res.statusText;
        throw new ApiError(res.status, message, (data.error as string) || (data.code as string));
    }
    return data as T;
}

export const api = {
    get: <T = Json>(path: string) => request<T>('GET', path),
    post: <T = Json>(path: string, body?: Json) => request<T>('POST', path, body),
    delete: <T = Json>(path: string) => request<T>('DELETE', path),
};

/**
 * Validate a `return_to` value before navigating to it (open-redirect guard). Only allow the
 * backend's own authorize endpoint or a relative path on this site — never an arbitrary URL.
 */
export function safeReturnTo(raw: string | null): string | null {
    if (!raw) return null;
    // Relative path on this origin.
    if (raw.startsWith('/') && !raw.startsWith('//')) return raw;
    try {
        const url = new URL(raw);
        const apiOrigin = new URL(API_URL).origin;
        if (url.origin === apiOrigin && url.pathname.endsWith('/oauth/authorize')) {
            return url.toString();
        }
    } catch {
        /* not a valid absolute URL */
    }
    return null;
}
