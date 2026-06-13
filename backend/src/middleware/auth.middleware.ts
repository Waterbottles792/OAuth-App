/**
 * Session authentication middleware.
 *
 * Reads the session cookie, validates it against the session store, and attaches the user
 * to `req.user`. `requireAuth` rejects unauthenticated requests; `requireAdmin` additionally
 * enforces the admin flag.
 */

import { Request, Response, NextFunction } from 'express';
import { securityConfig } from '../config';
import { UnauthorizedError, ForbiddenError } from '../lib/errors';
import { getSession } from '../services/session.service';
import { getUserById, User } from '../services/auth.service';

declare global {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace Express {
        interface Request {
            user?: User;
            sessionToken?: string;
        }
    }
}

function readSessionToken(req: Request): string | undefined {
    const name = securityConfig.session.cookieName;
    // cookie-parser populates signedCookies when the cookie was signed.
    return req.signedCookies?.[name] ?? req.cookies?.[name];
}

/** Resolve the session if present, but never reject. Useful for optional-auth routes. */
export async function loadUser(req: Request, _res: Response, next: NextFunction): Promise<void> {
    try {
        const token = readSessionToken(req);
        if (token) {
            const session = await getSession(token);
            if (session) {
                const user = await getUserById(session.userId);
                if (user) {
                    req.user = user;
                    req.sessionToken = token;
                }
            }
        }
        next();
    } catch (err) {
        next(err);
    }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
    await loadUser(req, res, (err?: unknown) => {
        if (err) return next(err);
        if (!req.user) return next(new UnauthorizedError());
        next();
    });
}

export function requireAdmin(req: Request, _res: Response, next: NextFunction): void {
    if (!req.user) return next(new UnauthorizedError());
    if (!req.user.is_admin) return next(new ForbiddenError('Admin privileges required'));
    next();
}
