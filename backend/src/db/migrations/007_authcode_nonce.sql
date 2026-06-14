-- Phase 6: OpenID Connect — carry the OIDC `nonce` through the authorization code.
--
-- The nonce is a client-supplied value from the /authorize request that must be embedded,
-- unchanged, into the ID token minted at /token. Binding it via the (hashed, single-use)
-- authorization code is what gives the client replay protection on the ID token. Optional
-- (only meaningful for the openid scope), so the column is nullable.

ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS nonce TEXT;
