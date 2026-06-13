-- Phase 2: Client & Trust Modeling
-- OAuth client registry, the catalogue of valid scopes, and per-user consent records.
-- No authorization codes or tokens here (Phase 3+).

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(255) UNIQUE NOT NULL,
    name                VARCHAR(255) NOT NULL,
    client_secret_hash  VARCHAR(255),                 -- NULL for public clients
    client_type         VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris       TEXT[] NOT NULL,              -- exact-match URIs, validated in app
    allowed_scopes      TEXT[] NOT NULL DEFAULT '{}',
    allowed_grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'],
    require_pkce        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A confidential client must carry a secret hash; a public client must not.
    CONSTRAINT client_secret_matches_type CHECK (
        (client_type = 'confidential' AND client_secret_hash IS NOT NULL) OR
        (client_type = 'public'       AND client_secret_hash IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS oauth_scopes (
    name        VARCHAR(100) PRIMARY KEY,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_consents (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents(user_id);

-- Default scope catalogue. openid/profile/email are the standard OIDC scopes used in
-- Phase 6; read:profile/write:profile are example resource scopes.
INSERT INTO oauth_scopes (name, description) VALUES
    ('openid',        'Subject identifier — required for OpenID Connect'),
    ('profile',       'Basic profile information'),
    ('email',         'Email address and verification status'),
    ('read:profile',  'Read the user profile'),
    ('write:profile', 'Modify the user profile')
ON CONFLICT (name) DO NOTHING;
