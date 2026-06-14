-- Phase 8: Immutable audit log.
--
-- Append-only record of security-relevant auth/OAuth decisions. Rows are write-once: an
-- AFTER-the-fact UPDATE or DELETE raises an exception (a BEFORE trigger), so the log can't be
-- tampered with through the app's own DB role. TRUNCATE is intentionally still allowed (used
-- only by the test suite's reset; revoke TRUNCATE from the app role in production).
--
-- NEVER store secrets here: no passwords, tokens, client secrets, raw codes, or PKCE verifiers.
-- Identifiers only (user UUID, public client_id), an outcome, and non-sensitive JSON context.

CREATE TABLE IF NOT EXISTS audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    event         VARCHAR(64) NOT NULL,          -- e.g. login, consent, access_token_issued
    actor_user_id UUID,                          -- nullable: some events are pre-auth (no FK: log outlives the user)
    client_id     VARCHAR(255),                  -- public client_id string, nullable
    ip            INET,
    result        VARCHAR(16) NOT NULL,          -- success | failure | detected
    detail        JSONB,                         -- non-sensitive structured context
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id, created_at);

-- Enforce append-only: block UPDATE and DELETE at the row level.
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only (% denied)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_modify ON audit_logs;
CREATE TRIGGER audit_logs_no_modify
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
