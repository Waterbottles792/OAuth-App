-- Phase 5 hardening: absolute refresh-token FAMILY lifetime cap.
--
-- Previously each rotation reset a token's 30-day TTL, so a continuously-rotated family could
-- live forever — contradicting the "30-day maximum lifetime" rule. `family_expires_at` is an
-- ABSOLUTE deadline stamped when the family is created and carried unchanged through every
-- rotation. A child's own expires_at is capped to it, and rotation is refused once it passes.

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_expires_at TIMESTAMPTZ;

-- Backfill any pre-existing rows (none in a fresh DB): 30 days from issuance.
UPDATE refresh_tokens
   SET family_expires_at = created_at + interval '30 days'
 WHERE family_expires_at IS NULL;

ALTER TABLE refresh_tokens ALTER COLUMN family_expires_at SET NOT NULL;
