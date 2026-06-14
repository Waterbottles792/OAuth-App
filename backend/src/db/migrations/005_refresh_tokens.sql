-- Phase 5: Refresh Tokens & Revocation
-- Rotating, single-use refresh tokens with reuse detection and token-family revocation.
-- Like authorization codes, the token itself is never stored — only its SHA-256 hash.
--
-- Each issuance at code-exchange time starts a new FAMILY (token_family_id). Every rotation
-- mints a child token in the same family and records its parent (parent_token_hash). If a
-- token that was already `used` (or `revoked`) is presented again, that is reuse: the whole
-- family is revoked, defeating a stolen-token replay.

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash        VARCHAR(64) PRIMARY KEY,                  -- sha256 hex of the raw token
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id         UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes            TEXT[] NOT NULL DEFAULT '{}',
    token_family_id   UUID NOT NULL,                            -- shared across a rotation chain
    parent_token_hash VARCHAR(64),                              -- previous token in the family (NULL = root)
    used              BOOLEAN NOT NULL DEFAULT FALSE,           -- flipped on rotation (single-use)
    revoked           BOOLEAN NOT NULL DEFAULT FALSE,           -- set by /revoke or family revocation
    expires_at        TIMESTAMPTZ NOT NULL,                     -- 30-day max lifetime
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(token_family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
