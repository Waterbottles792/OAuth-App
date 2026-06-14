/**
 * OAuth 2.1 + OIDC Authorization Server
 *
 * PHASE 1: Identity Core — user registration, login, server-side sessions, MFA.
 *
 * SECURITY BOUNDARIES (still not implemented — later phases):
 * - NO OAuth endpoints (/authorize, /token)        (Phase 3+)
 * - NO token issuance / JWTs                        (Phase 4+)
 * - NO OAuth clients / consent                      (Phase 2+)
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { serverConfig, securityConfig, validateConfig } from './config';
import { logger } from './lib/logger';
import { isAppError } from './lib/errors';
import { requireAuth, requireAdmin } from './middleware/auth.middleware';
import authRoutes from './routes/auth.routes';
import clientRoutes from './routes/clients.routes';
import oauthRoutes from './routes/oauth.routes';
import wellKnownRoutes from './routes/wellknown.routes';

// Validate configuration before doing anything else.
validateConfig();

// Re-exported for backwards compatibility; the logger now lives in lib/logger.
export { logger };

// ============================================
// APP FACTORY
// ============================================
export function createApp() {
    const app = express();

    // Derive req.ip from X-Forwarded-For only as far as the configured proxy topology allows.
    // Must match the real deployment or IP-keyed rate limits become spoofable (see config).
    app.set('trust proxy', securityConfig.trustProxy);

    app.use(
        helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", 'data:', 'https:'],
                },
            },
            hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        }),
    );

    app.use(
        cors({
            origin: (origin, callback) => {
                if (!origin) return callback(null, true);
                if (securityConfig.corsOrigins.includes(origin)) return callback(null, true);
                logger.warn(`CORS blocked origin: ${origin}`);
                callback(new Error('CORS policy violation'));
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
        }),
    );

    app.use(express.json({ limit: '10kb' }));
    app.use(express.urlencoded({ extended: true, limit: '10kb' }));
    app.use(cookieParser(securityConfig.session.secret));

    // Request logging
    app.use((req: Request, res: Response, next: NextFunction) => {
        const startTime = Date.now();
        res.on('finish', () => {
            logger.info({
                method: req.method,
                path: req.path,
                status: res.statusCode,
                duration: `${Date.now() - startTime}ms`,
                ip: req.ip,
            });
        });
        next();
    });

    // ---- Health / status ----
    app.get('/health', (_req: Request, res: Response) => {
        res.status(200).json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            environment: serverConfig.env,
            phase: 'PHASE_6_OPENID_CONNECT',
        });
    });

    app.get(`/api/${serverConfig.apiVersion}/status`, (_req: Request, res: Response) => {
        res.status(200).json({
            service: 'OAuth 2.1 + OIDC Authorization Server',
            version: serverConfig.apiVersion,
            phase: 'Phase 6: OpenID Connect',
            features: {
                authentication: true, // Phase 1 ✅
                mfa: true, // Phase 1 ✅
                client_registry: true, // Phase 2 ✅
                authorization_endpoint: true, // Phase 3 ✅
                token_issuance: true, // Phase 4 ✅ (access tokens, RS256)
                refresh_tokens: true, // Phase 5 ✅ (rotating, reuse detection)
                openid_connect: true, // Phase 6 ✅ (ID token, userinfo, discovery, JWKS)
            },
        });
    });

    // ---- OIDC discovery (root, public, no /api prefix) ----
    app.use('/', wellKnownRoutes);

    // ---- Feature routes ----
    app.use(`/api/${serverConfig.apiVersion}/auth`, authRoutes);
    // Client registry is admin-only; guards applied before the router.
    app.use(`/api/${serverConfig.apiVersion}/clients`, requireAuth, requireAdmin, clientRoutes);
    // OAuth authorization endpoint (authorize). Auth/consent handled inside the router.
    app.use(`/api/${serverConfig.apiVersion}/oauth`, oauthRoutes);

    // ---- 404 ----
    app.use((req: Request, res: Response) => {
        logger.warn(`404 Not Found: ${req.method} ${req.path}`);
        res.status(404).json({ error: 'not_found', message: 'Endpoint not found' });
    });

    // ---- Global error handler ----
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
        if (isAppError(err)) {
            if (err.statusCode >= 500) {
                logger.error({ code: err.code, message: err.message, detail: err.logDetail });
            } else {
                logger.warn({ code: err.code, message: err.message, path: req.path });
            }
            res.status(err.statusCode).json({ error: err.code, message: err.message });
            return;
        }

        logger.error({ error: err.message, stack: err.stack, path: req.path, method: req.method });
        res.status(500).json({
            error: 'internal_server_error',
            message: serverConfig.isDevelopment ? err.message : 'An error occurred',
        });
    });

    return app;
}

const app = createApp();

// ============================================
// SERVER STARTUP (only when run directly)
// ============================================
if (require.main === module) {
    const server = app.listen(serverConfig.port, () => {
        logger.info(`
╔══════════════════════════════════════════════════════════════════════╗
║  OAuth 2.1 + OIDC Authorization Server — Phase 6: OpenID Connect      ║
╚══════════════════════════════════════════════════════════════════════╝

🚀 Server running on port ${serverConfig.port}
🌍 Environment: ${serverConfig.env}
🔒 CORS origins: ${securityConfig.corsOrigins.join(', ')}

📍 Auth endpoints (/api/${serverConfig.apiVersion}/auth):
   POST /register   POST /login   POST /mfa/login
   POST /logout     GET  /me      POST /mfa/enable   POST /mfa/verify

📍 Client registry (/api/${serverConfig.apiVersion}/clients, admin only):
   POST /   GET /   GET /:clientId   DELETE /:clientId

📍 OAuth (/api/${serverConfig.apiVersion}/oauth):
   GET /authorize   POST /authorize   POST /token   POST /revoke   GET /userinfo

📍 OIDC discovery (public, root):
   GET /.well-known/openid-configuration   GET /.well-known/jwks.json

✅ Configuration validated   ✅ Security middleware active
    `);
    });

    process.on('SIGTERM', () => {
        logger.info('SIGTERM received, shutting down gracefully');
        server.close(() => {
            logger.info('Server closed');
            process.exit(0);
        });
    });
}

export default app;
