/**
 * OAuth 2.1 + OIDC Authorization Server
 * 
 * PHASE 0: Foundation - Minimal server setup with security middleware
 * 
 * SECURITY BOUNDARIES:
 * - NO OAuth endpoints (Phase 3+)
 * - NO authentication logic (Phase 1+)
 * - NO token generation (Phase 4+)
 * - NO user management (Phase 1+)
 * 
 * This server currently provides:
 * - Basic Express setup with security headers
 * - CORS configuration
 * - Health check endpoint
 * - Request logging
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { serverConfig, securityConfig, validateConfig } from './config';
import winston from 'winston';

// Validate configuration before starting server
validateConfig();

// Initialize Express application
const app = express();

// ============================================
// LOGGING SETUP
// ============================================
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
        }),
    ],
});

// ============================================
// SECURITY MIDDLEWARE
// ============================================

/**
 * Helmet: Sets security-related HTTP headers
 * - X-Content-Type-Options: nosniff
 * - X-Frame-Options: DENY
 * - X-XSS-Protection: 1; mode=block
 * - Strict-Transport-Security (in production)
 */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:'],
        },
    },
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
    },
}));

/**
 * CORS: Explicit origin allowlist
 * NO wildcards allowed - exact origin matching only
 */
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);

        if (securityConfig.corsOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked origin: ${origin}`);
            callback(new Error('CORS policy violation'));
        }
    },
    credentials: true, // Allow cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

/**
 * Body parsing middleware
 * Rate limiting will be added in Phase 1
 */
app.use(express.json({ limit: '10kb' })); // Prevent large payloads
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

/**
 * Request logging middleware
 */
app.use((req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info({
            method: req.method,
            path: req.path,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
        });
    });

    next();
});

// ============================================
// HEALTH CHECK ENDPOINT
// ============================================

/**
 * Health check endpoint for load balancers and monitoring
 */
app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: serverConfig.env,
        phase: 'PHASE_0_FOUNDATION',
    });
});

/**
 * API version endpoint
 */
app.get(`/api/${serverConfig.apiVersion}/status`, (req: Request, res: Response) => {
    res.status(200).json({
        service: 'OAuth 2.1 + OIDC Authorization Server',
        version: serverConfig.apiVersion,
        phase: 'Phase 0: Foundation',
        features: {
            authentication: false,      // Phase 1+
            oauth_endpoints: false,      // Phase 3+
            token_issuance: false,       // Phase 4+
            refresh_tokens: false,       // Phase 5+
            openid_connect: false,       // Phase 6+
        },
    });
});

// ============================================
// INTENTIONALLY NOT IMPLEMENTED (YET)
// ============================================

// ❌ NO /authorize endpoint (Phase 3+)
// ❌ NO /token endpoint (Phase 4+)
// ❌ NO /userinfo endpoint (Phase 6+)
// ❌ NO /register endpoint (Phase 1+)
// ❌ NO /login endpoint (Phase 1+)
// ❌ NO authentication middleware (Phase 1+)
// ❌ NO session management (Phase 1+)
// ❌ NO rate limiting (Phase 1+)

// ============================================
// ERROR HANDLING
// ============================================

/**
 * 404 handler
 */
app.use((req: Request, res: Response) => {
    logger.warn(`404 Not Found: ${req.method} ${req.path}`);
    res.status(404).json({
        error: 'not_found',
        message: 'Endpoint not found',
        phase: 'Phase 0: Foundation',
        note: 'OAuth and authentication endpoints will be available in future phases',
    });
});

/**
 * Global error handler
 */
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error({
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
    });

    res.status(500).json({
        error: 'internal_server_error',
        message: serverConfig.isDevelopment ? err.message : 'An error occurred',
    });
});

// ============================================
// SERVER STARTUP
// ============================================

const server = app.listen(serverConfig.port, () => {
    logger.info(`
╔════════════════════════════════════════════════════════════════╗
║  OAuth 2.1 + OIDC Authorization Server                        ║
║  Phase 0: Foundation                                           ║
╚════════════════════════════════════════════════════════════════╝

🚀 Server running on port ${serverConfig.port}
🌍 Environment: ${serverConfig.env}
🔒 CORS origins: ${securityConfig.corsOrigins.join(', ')}

📍 Endpoints:
   GET  /health                      - Health check
   GET  /api/${serverConfig.apiVersion}/status    - Service status

⚠️  Phase 0 Status:
   ❌ Authentication not implemented (Phase 1)
   ❌ OAuth endpoints not implemented (Phase 3+)
   ❌ Token issuance not implemented (Phase 4+)

✅ Configuration validated
✅ Security middleware active
✅ Ready for Phase 1 implementation
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});

export default app;
