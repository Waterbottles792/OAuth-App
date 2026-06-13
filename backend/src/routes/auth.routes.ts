/**
 * Identity Core routes (Phase 1).
 *
 *   POST /register          create account (email + password)
 *   POST /login             password step; returns a session or an MFA challenge
 *   POST /mfa/login         complete the MFA challenge from /login
 *   POST /logout            destroy current session            (auth)
 *   GET  /me                current user                        (auth)
 *   POST /mfa/enable        begin TOTP enrollment               (auth)
 *   POST /mfa/verify        confirm TOTP enrollment             (auth)
 *
 * Thin layer: validate input, call services, manage cookies. No business logic here.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { securityConfig, authConfig } from '../config';
import { validate, registerSchema, loginSchema, totpCodeSchema } from '../lib/validation';
import { UnauthorizedError } from '../lib/errors';
import { loginRateLimit } from '../middleware/rateLimit.middleware';
import { requireAuth } from '../middleware/auth.middleware';
import * as authService from '../services/auth.service';
import { destroySession } from '../services/session.service';
import { beginEnrollment, verifyEnrollment } from '../services/mfa.service';

const router = Router();

const sessionCookieBase = {
    ...securityConfig.session.cookieOptions,
    signed: true,
};

function setSessionCookie(res: Response, token: string): void {
    res.cookie(securityConfig.session.cookieName, token, {
        ...sessionCookieBase,
        maxAge: authConfig.session.ttlSeconds * 1000,
    });
}

function setMfaCookie(res: Response, token: string): void {
    res.cookie(securityConfig.session.mfaCookieName, token, {
        ...sessionCookieBase,
        maxAge: authConfig.mfa.pendingChallengeTtlSeconds * 1000,
    });
}

function clearCookie(res: Response, name: string): void {
    res.clearCookie(name, { ...sessionCookieBase });
}

function reqContext(req: Request) {
    return { ip: req.ip, userAgent: req.get('user-agent') ?? undefined };
}

// Wrap async handlers so thrown errors reach the global error handler.
const h =
    (fn: (req: Request, res: Response) => Promise<void>) =>
    (req: Request, res: Response, next: NextFunction) =>
        fn(req, res).catch(next);

router.post(
    '/register',
    h(async (req, res) => {
        const { email, password } = validate(registerSchema, req.body);
        const { userId } = await authService.register(email, password);
        res.status(201).json({ userId, message: 'Account created. Check your email to verify.' });
    }),
);

router.post(
    '/login',
    loginRateLimit,
    h(async (req, res) => {
        const { email, password } = validate(loginSchema, req.body);
        const result = await authService.login(email, password, reqContext(req));

        if (result.status === 'mfa_required') {
            setMfaCookie(res, result.challengeToken);
            res.status(200).json({ mfaRequired: true });
            return;
        }

        setSessionCookie(res, result.sessionToken);
        res.status(200).json({ user: result.user });
    }),
);

router.post(
    '/mfa/login',
    h(async (req, res) => {
        const challengeToken = req.signedCookies?.[securityConfig.session.mfaCookieName];
        if (!challengeToken) throw new UnauthorizedError('No pending MFA challenge');
        const { code } = validate(totpCodeSchema, req.body);

        const { sessionToken, user } = await authService.completeMfaLogin(
            challengeToken,
            code,
            reqContext(req),
        );

        clearCookie(res, securityConfig.session.mfaCookieName);
        setSessionCookie(res, sessionToken);
        res.status(200).json({ user });
    }),
);

router.post(
    '/logout',
    requireAuth,
    h(async (req, res) => {
        if (req.sessionToken) await destroySession(req.sessionToken);
        clearCookie(res, securityConfig.session.cookieName);
        res.status(200).json({ message: 'Logged out' });
    }),
);

router.get(
    '/me',
    requireAuth,
    h(async (req, res) => {
        res.status(200).json({ user: req.user });
    }),
);

router.post(
    '/mfa/enable',
    requireAuth,
    h(async (req, res) => {
        const user = req.user!;
        const enrollment = await beginEnrollment(user.id, user.email);
        res.status(200).json({
            qrCode: enrollment.qrCodeDataUrl,
            otpauthUrl: enrollment.otpauthUrl,
            backupCodes: enrollment.backupCodes,
            message: 'Scan the QR code, then confirm with POST /mfa/verify to activate.',
        });
    }),
);

router.post(
    '/mfa/verify',
    requireAuth,
    h(async (req, res) => {
        const { code } = validate(totpCodeSchema, req.body);
        const ok = await verifyEnrollment(req.user!.id, code);
        if (!ok) throw new UnauthorizedError('Invalid MFA code');
        res.status(200).json({ success: true, message: 'MFA enabled' });
    }),
);

export default router;
