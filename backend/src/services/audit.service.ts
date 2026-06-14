/**
 * Immutable audit logging (Phase 8).
 *
 * Records security-relevant decisions to the append-only `audit_logs` table. Writing is
 * best-effort and never throws into the request path: if the audit write fails we log the
 * failure and carry on (the alternative — failing the user's request because logging broke —
 * is worse). The table's trigger guarantees rows can't later be altered.
 *
 * Callers MUST pass only non-sensitive context: identifiers and outcomes, never passwords,
 * tokens, secrets, raw authorization codes, or PKCE verifiers.
 */

import { query } from '../db/pool';
import { logger } from '../lib/logger';

export type AuditResult = 'success' | 'failure' | 'detected';

export interface AuditEntry {
    event: string;
    result: AuditResult;
    actorUserId?: string | null;
    clientId?: string | null;
    ip?: string | null;
    detail?: Record<string, unknown>;
}

export async function recordAudit(entry: AuditEntry): Promise<void> {
    try {
        await query(
            `INSERT INTO audit_logs (event, actor_user_id, client_id, ip, result, detail)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                entry.event,
                entry.actorUserId ?? null,
                entry.clientId ?? null,
                entry.ip ?? null,
                entry.result,
                entry.detail ? JSON.stringify(entry.detail) : null,
            ],
        );
    } catch (err) {
        // Audit must never break the request it's describing.
        logger.error({ event: 'audit_write_failed', error: (err as Error).message, audited: entry.event });
    }
}
