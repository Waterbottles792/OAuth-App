-- Phase 4: Token Service
-- Asymmetric signing keys for JWT access tokens. The public key is stored in the clear
-- (it is public — published via JWKS in Phase 6). The private key is stored ENCRYPTED at
-- rest (AES-256-GCM); it never appears in plaintext on disk or in version control.

CREATE TABLE IF NOT EXISTS jwt_keys (
    kid                  VARCHAR(64) PRIMARY KEY,
    algorithm            VARCHAR(10) NOT NULL,          -- e.g. RS256
    public_key           TEXT NOT NULL,                 -- SPKI PEM (public)
    private_key_enc      TEXT NOT NULL,                 -- base64(iv).base64(tag).base64(ciphertext)
    active               BOOLEAN NOT NULL DEFAULT TRUE, -- the current signing key
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ                    -- for rotation (Phase 8)
);

-- Only one active signing key at a time (rotation in Phase 8 toggles this).
CREATE UNIQUE INDEX IF NOT EXISTS idx_jwt_keys_one_active ON jwt_keys(active) WHERE active;
