/**
 * Security alerting hooks (Phase 8).
 *
 * Two shapes:
 *   - triggerAlert(kind): fire immediately — for events alarming on a single occurrence
 *     (refresh-token reuse, authorization-code reuse).
 *   - bump-and-maybe-alert helpers: count an event in a Redis window and fire only when it
 *     crosses a threshold (login-failure spikes, token-signature-failure spikes).
 *
 * The handler is pluggable (`setAlertHandler`) so tests can assert alerts fire and a real
 * deployment can wire it to PagerDuty/Slack/etc. The default handler logs at error level.
 * Alerting is best-effort: it must never throw into the request path.
 */

import { getRedis } from '../db/redis';
import { logger } from './logger';

export interface SecurityAlert {
    kind: string;
    context?: Record<string, unknown>;
}

export type AlertHandler = (alert: SecurityAlert) => void;

const defaultHandler: AlertHandler = (alert) =>
    logger.error({ event: 'SECURITY_ALERT', kind: alert.kind, ...alert.context });

let handler: AlertHandler = defaultHandler;

export function setAlertHandler(h: AlertHandler): void {
    handler = h;
}

export function resetAlertHandler(): void {
    handler = defaultHandler;
}

/** Fire an alert now (single-occurrence events). */
export function triggerAlert(kind: string, context?: Record<string, unknown>): void {
    try {
        handler({ kind, context });
    } catch (err) {
        logger.error({ event: 'alert_handler_failed', error: (err as Error).message });
    }
}

/** Count an event in a fixed Redis window; alert when the count reaches `threshold`. */
async function bumpAndMaybeAlert(
    kind: string,
    key: string,
    threshold: number,
    windowSeconds: number,
    context?: Record<string, unknown>,
): Promise<void> {
    try {
        const redis = await getRedis();
        const redisKey = `alert:${kind}:${key}`;
        const count = await redis.incr(redisKey);
        if (count === 1) await redis.expire(redisKey, windowSeconds);
        if (count === threshold) {
            triggerAlert(kind, { ...context, count, window_seconds: windowSeconds });
        }
    } catch {
        /* alerting must never break the request */
    }
}

const LOGIN_FAILURE_THRESHOLD = 10; // per key per window
const SIGNATURE_FAILURE_THRESHOLD = 5;
const WINDOW_SECONDS = 5 * 60;

/** Per-IP login-failure spike detector. */
export function recordLoginFailure(key: string): Promise<void> {
    return bumpAndMaybeAlert('login_failure_spike', key, LOGIN_FAILURE_THRESHOLD, WINDOW_SECONDS, { key });
}

/** Access-token signature/verification failure spike detector (e.g. forgery attempts). */
export function recordSignatureFailure(): Promise<void> {
    return bumpAndMaybeAlert('token_signature_failure_spike', 'global', SIGNATURE_FAILURE_THRESHOLD, WINDOW_SECONDS);
}
