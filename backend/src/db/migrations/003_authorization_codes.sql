-- Phase 3: Authorization Code Flow (PKCE)
-- Short-lived, single-use authorization codes. The code itself is never stored — only its
-- SHA-256 hash — and it is bound to the client, user, redirect_uri, and PKCE challenge so
-- it cannot be replayed against a different context. No tokens here (Phase 4+).

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash             VARCHAR(64) PRIMARY KEY,                  -- sha256 hex of the raw code
    client_id             UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}',
    code_challenge        VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL CHECK (code_challenge_method = 'S256'),
    used                  BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_authz_codes_expires ON authorization_codes(expires_at);
