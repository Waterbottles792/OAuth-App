/**
 * Configuration Management Module
 * 
 * Centralized configuration with environment variable validation.
 * Phase 0: Basic server and security configuration only.
 * 
 * SECURITY NOTES:
 * - All secrets must be loaded from environment variables, never hardcoded
 * - Configuration validation prevents server startup with invalid/missing values
 * - Database and Redis configs are defined but not used until Phase 1
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

/**
 * Server Configuration
 */
export const serverConfig = {
    env: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT || '3001', 10),
    apiVersion: process.env.API_VERSION || 'v1',

    // Security: Force HTTPS in production
    isProduction: process.env.NODE_ENV === 'production',
    isDevelopment: process.env.NODE_ENV === 'development',
} as const;

/**
 * Database Configuration (PostgreSQL)
 * 
 * NOT USED IN PHASE 0
 * Will be activated in Phase 1 for user accounts and sessions
 */
export const databaseConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'oauth_platform',
    user: process.env.DB_USER || 'oauth_user',
    password: process.env.DB_PASSWORD || '',
    ssl: process.env.DB_SSL === 'true',

    // Connection pool settings for production
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
} as const;

/**
 * Redis Configuration
 * 
 * NOT USED IN PHASE 0
 * Will be activated in Phase 1 for session storage and rate limiting
 */
export const redisConfig = {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || '',
} as const;

/**
 * Security Configuration
 */
export const securityConfig = {
    // CORS: Explicit origin allowlist (no wildcards allowed)
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],

    // Rate limiting configuration (enforced in Phase 1+)
    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    },

    // Session configuration (used in Phase 1+)
    session: {
        // Dev fallback only; production startup validation (below) requires a real value.
        secret:
            process.env.SESSION_SECRET ||
            (process.env.NODE_ENV === 'production'
                ? ''
                : 'dev-only-insecure-session-secret-change-me-32+'),
        cookieMaxAge: parseInt(process.env.SESSION_COOKIE_MAX_AGE || '86400000', 10), // 24 hours
        cookieName: 'sid',
        mfaCookieName: 'mfa_pending',

        // Security flags for session cookies
        cookieOptions: {
            httpOnly: true, // Prevent JavaScript access (XSS protection)
            secure: process.env.NODE_ENV === 'production', // HTTPS only in production
            sameSite: 'lax' as const, // CSRF protection
            path: '/',
        },
    },
} as const;

/**
 * Identity Core (Phase 1) tunables. Centralized so security-relevant numbers live in
 * one place and are referenced by name (never hardcoded in services).
 */
export const authConfig = {
    // Argon2id parameters (decision: m=64MB, t=3, p=4)
    argon2: {
        memoryCost: 64 * 1024, // KiB => 64 MB
        timeCost: 3,
        parallelism: 4,
    },
    session: {
        ttlSeconds: 24 * 60 * 60, // 24h, refreshed on use (sliding window)
    },
    lockout: {
        maxFailedAttempts: 5, // lock the account after this many consecutive failures
        lockDurationSeconds: 60 * 60, // 1 hour
    },
    loginRateLimit: {
        windowSeconds: 15 * 60, // 15 minutes
        maxAttempts: 5, // per IP+email within the window
    },
    mfa: {
        issuer: 'OAuthPlatform',
        totpWindow: 1, // accept codes +/- 1 step (30s) to tolerate clock drift
        backupCodeCount: 10,
        pendingChallengeTtlSeconds: 5 * 60, // time to complete the MFA step after password
    },
} as const;

/**
 * OAuth flow configuration (Phase 3+). Lifetimes and the issuer identity.
 */
export const oauthFlowConfig = {
    // Authorization code: short-lived and single-use (decision: 10 minutes max).
    authorizationCodeTtlSeconds: 10 * 60,
    // Where the authorization endpoint sends an unauthenticated user to log in. The frontend
    // is expected to send the user back to the original /authorize URL afterwards.
    loginUrl: process.env.LOGIN_URL || 'http://localhost:3000/login',
    // JWT issuer identity (the `iss` claim) — must be stable; resource servers verify it.
    issuer: process.env.ISSUER_URL || `http://localhost:${serverConfig.port}`,
    // Default audience (`aud`) for access tokens until resource indicators exist.
    accessTokenAudience: process.env.ACCESS_TOKEN_AUDIENCE || 'oauth-platform-api',
} as const;

/**
 * Signing-key configuration (Phase 4). The encryption secret protects private keys at rest.
 */
export const keyConfig = {
    // LOCKED to asymmetric (SECURITY_DECISIONS #2). RS256 with RSA-2048.
    signingAlgorithm: 'RS256' as const,
    rsaModulusLength: 2048,
    // Used to derive the AES-256-GCM key that encrypts JWT private keys at rest.
    // Dev fallback only; production startup validation requires a real value.
    encryptionSecret:
        process.env.JWT_KEY_ENCRYPTION_SECRET ||
        (process.env.NODE_ENV === 'production'
            ? ''
            : 'dev-only-insecure-key-encryption-secret-change-me'),
} as const;

/**
 * Logging Configuration
 */
export const loggingConfig = {
    level: process.env.LOG_LEVEL || 'info',
} as const;

/**
 * OAuth 2.1 & OIDC Non-Negotiable Configuration
 * 
 * These settings are LOCKED and must never be changed.
 * They represent security-critical decisions for the platform.
 * 
 * NOT IMPLEMENTED IN PHASE 0 - Documentation only
 */
export const oauthConfig = {
    // Token configuration (Phase 4+)
    tokens: {
        format: 'JWT' as const, // LOCKED: JWT format only
        algorithm: 'RS256' as const, // LOCKED: Asymmetric signing (RS256 or ES256)
        accessTokenLifetime: 900, // LOCKED: 15 minutes maximum (in seconds)
    },

    // Flow configuration (Phase 3+)
    flows: {
        allowedGrants: ['authorization_code'] as const, // LOCKED: Only auth code flow
        requirePkce: true, // LOCKED: PKCE required for all clients
        allowImplicit: false, // LOCKED: Implicit flow forbidden
        allowWildcardRedirects: false, // LOCKED: Exact redirect URI match only
    },

    // Refresh token configuration (Phase 5+)
    refreshTokens: {
        rotating: true, // LOCKED: Single-use rotating refresh tokens
        reuseDetection: true, // LOCKED: Detect and revoke on reuse
    },
} as const;

/**
 * Configuration Validation
 * 
 * Validates critical configuration on server startup.
 * Prevents running with insecure or missing configuration.
 */
export function validateConfig(): void {
    const errors: string[] = [];

    // Validate port
    if (isNaN(serverConfig.port) || serverConfig.port < 1 || serverConfig.port > 65535) {
        errors.push('Invalid PORT: must be between 1 and 65535');
    }

    // Validate CORS origins (no wildcards)
    securityConfig.corsOrigins.forEach(origin => {
        if (origin.includes('*')) {
            errors.push(`Invalid CORS origin "${origin}": wildcards not allowed`);
        }
    });

    // Production-specific validations
    if (serverConfig.isProduction) {
        if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
            errors.push('SESSION_SECRET must be at least 32 characters in production');
        }

        if (!process.env.DB_PASSWORD) {
            errors.push('DB_PASSWORD is required in production');
        }

        if (!process.env.REDIS_PASSWORD) {
            errors.push('REDIS_PASSWORD is required in production');
        }

        if (!process.env.JWT_KEY_ENCRYPTION_SECRET || process.env.JWT_KEY_ENCRYPTION_SECRET.length < 32) {
            errors.push('JWT_KEY_ENCRYPTION_SECRET must be at least 32 characters in production');
        }
    }

    if (errors.length > 0) {
        console.error('❌ Configuration validation failed:');
        errors.forEach(error => console.error(`  - ${error}`));
        process.exit(1);
    }

    console.log('✅ Configuration validated successfully');
}
