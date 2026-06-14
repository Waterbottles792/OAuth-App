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
import { alertConfig } from '../config';
import { logger } from './logger';

export interface SecurityAlert {
    kind: string;
    context?: Record<string, unknown>;
}

/** Rough severity for routing/colour in the sink. */
const SEVERITY: Record<string, 'critical' | 'high'> = {
    refresh_token_reuse: 'critical',
    authz_code_reuse: 'critical',
    login_failure_spike: 'high',
    token_signature_failure_spike: 'high',
};

export type AlertHandler = (alert: SecurityAlert) => void;

const logAlert: AlertHandler = (alert) =>
    logger.error({ event: 'SECURITY_ALERT', kind: alert.kind, severity: SEVERITY[alert.kind] ?? 'high', ...alert.context });

const defaultHandler: AlertHandler = logAlert;

let handler: AlertHandler = defaultHandler;

export function setAlertHandler(h: AlertHandler): void {
    handler = h;
}

export function resetAlertHandler(): void {
    handler = defaultHandler;
}

/** Build the JSON body POSTed to the alert webhook. `text` is what Slack/Discord render. */
export function buildAlertPayload(alert: SecurityAlert): Record<string, unknown> {
    const severity = SEVERITY[alert.kind] ?? 'high';
    return {
        text: `🚨 [${alertConfig.environment}] security alert: ${alert.kind} (${severity})`,
        kind: alert.kind,
        severity,
        environment: alertConfig.environment,
        context: alert.context ?? {},
        timestamp: new Date().toISOString(),
    };
}

/** POST an alert to `url`. Best-effort: bounded by a timeout and never throws. */
export async function postAlert(url: string, alert: SecurityAlert): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), alertConfig.timeoutMs);
    try {
        await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(buildAlertPayload(alert)),
            signal: controller.signal,
        });
    } catch (err) {
        logger.error({ event: 'alert_webhook_failed', kind: alert.kind, error: (err as Error).message });
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Install the production alert sink: always log, and additionally POST to the configured
 * webhook when ALERT_WEBHOOK_URL is set. Called once at app startup. Tests that override the
 * handler via setAlertHandler are unaffected.
 */
export function installAlertSink(): void {
    setAlertHandler((alert) => {
        logAlert(alert);
        if (alertConfig.webhookUrl) void postAlert(alertConfig.webhookUrl, alert);
    });
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
