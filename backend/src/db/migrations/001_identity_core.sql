-- Phase 1: Identity Core schema
-- Users, server-side sessions, and MFA secrets. No OAuth tables here (Phase 2+).

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

CREATE TABLE IF NOT EXISTS users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 VARCHAR(255) UNIQUE NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    is_admin              BOOLEAN NOT NULL DEFAULT FALSE,
    locked_at             TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sessions are primarily held in Redis (hashed token -> session). This table is a
-- persistent audit/fallback record of active sessions. token_hash is SHA-256 hex.
CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_secrets (
    user_id      UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret  VARCHAR(255) NOT NULL,
    backup_codes TEXT[] NOT NULL DEFAULT '{}', -- array of hashed (SHA-256) single-use codes
    enabled_at   TIMESTAMPTZ                   -- NULL until enrollment is confirmed
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
