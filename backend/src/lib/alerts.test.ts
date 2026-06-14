import { describe, it, expect, afterEach, vi } from 'vitest';
import {
    triggerAlert,
    recordLoginFailure,
    recordSignatureFailure,
    setAlertHandler,
    resetAlertHandler,
    buildAlertPayload,
    postAlert,
    SecurityAlert,
} from './alerts';

describe('Phase 8 — alert hooks', () => {
    afterEach(() => resetAlertHandler());

    it('triggerAlert invokes the handler immediately', () => {
        const seen: SecurityAlert[] = [];
        setAlertHandler((a) => seen.push(a));
        triggerAlert('refresh_token_reuse', { client_id: 'c1' });
        expect(seen).toHaveLength(1);
        expect(seen[0].kind).toBe('refresh_token_reuse');
        expect(seen[0].context?.client_id).toBe('c1');
    });

    it('login-failure spike fires once when the threshold (10) is crossed', async () => {
        const seen: SecurityAlert[] = [];
        setAlertHandler((a) => seen.push(a));
        const key = `ip-${Date.now()}`;
        for (let i = 0; i < 9; i++) await recordLoginFailure(key);
        expect(seen).toHaveLength(0); // below threshold
        await recordLoginFailure(key); // 10th
        expect(seen.filter((a) => a.kind === 'login_failure_spike')).toHaveLength(1);
        await recordLoginFailure(key); // 11th — no second alert in the same window
        expect(seen.filter((a) => a.kind === 'login_failure_spike')).toHaveLength(1);
    });

    it('signature-failure spike fires when the threshold (5) is crossed', async () => {
        const seen: SecurityAlert[] = [];
        setAlertHandler((a) => seen.push(a));
        for (let i = 0; i < 5; i++) await recordSignatureFailure();
        expect(seen.filter((a) => a.kind === 'token_signature_failure_spike')).toHaveLength(1);
    });
});

describe('Phase 8 — alert webhook sink', () => {
    afterEach(() => vi.restoreAllMocks());

    it('builds a Slack/generic-compatible payload', () => {
        const p = buildAlertPayload({ kind: 'refresh_token_reuse', context: { client_id: 'c1' } });
        expect(p.kind).toBe('refresh_token_reuse');
        expect(p.severity).toBe('critical');
        expect(typeof p.text).toBe('string');
        expect((p.context as Record<string, unknown>).client_id).toBe('c1');
        expect(p.timestamp).toBeTruthy();
    });

    it('POSTs the alert to the webhook URL', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true });
        vi.stubGlobal('fetch', fetchMock);

        await postAlert('https://hooks.example.com/x', { kind: 'authz_code_reuse', context: { client_id: 'c2' } });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, opts] = fetchMock.mock.calls[0];
        expect(url).toBe('https://hooks.example.com/x');
        expect(opts.method).toBe('POST');
        expect(JSON.parse(opts.body).kind).toBe('authz_code_reuse');
    });

    it('swallows webhook delivery errors (never throws)', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));
        await expect(postAlert('https://hooks.example.com/x', { kind: 'login_failure_spike' })).resolves.toBeUndefined();
    });
});
