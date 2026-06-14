'use client';

/**
 * Consent page (Phase 7). The backend's /authorize redirects the browser here when consent is
 * required. We fetch read-only details (client name + scope descriptions) from /consent-info,
 * then let the user Allow/Deny.
 *
 * The decision is submitted as a real top-level HTML form POST to the backend's /authorize
 * (NOT a fetch): that lets the browser follow the backend's 302 to the client's redirect_uri
 * with the authorization code, completing the OAuth flow. The form carries the request params
 * verbatim; the backend re-validates everything and the HttpOnly session cookie authenticates
 * the user (same-site, so it rides along).
 */

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { API_BASE, api, ApiError } from '../../lib/api';
import * as ui from '../../lib/ui';

const PARAM_KEYS = [
    'client_id',
    'redirect_uri',
    'response_type',
    'scope',
    'state',
    'code_challenge',
    'code_challenge_method',
    'nonce',
] as const;

interface ConsentInfo {
    client: { client_id: string; name: string };
    scopes: { name: string; description: string | null }[];
}

function Consent() {
    const search = useSearchParams();
    const [info, setInfo] = useState<ConsentInfo | null>(null);
    const [error, setError] = useState('');

    // Collect the authorize params present in the URL.
    const params: Record<string, string> = {};
    for (const k of PARAM_KEYS) {
        const v = search.get(k);
        if (v !== null) params[k] = v;
    }

    useEffect(() => {
        const qs = new URLSearchParams(params).toString();
        api.get<ConsentInfo>(`/oauth/consent-info?${qs}`)
            .then(setInfo)
            .catch((err: ApiError) => {
                if (err.status === 401) {
                    // Not logged in — bounce to login, returning to the original authorize URL.
                    const authorizeUrl = `${API_BASE}/oauth/authorize?${qs}`;
                    window.location.href = `/login?return_to=${encodeURIComponent(authorizeUrl)}`;
                    return;
                }
                setError(err.message || 'Could not load the authorization request');
            });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if (error) {
        return (
            <div style={ui.page}>
                <div style={ui.card}>
                    <h1 style={ui.h1}>Authorization error</h1>
                    <div style={ui.alertError}>{error}</div>
                </div>
            </div>
        );
    }

    if (!info) {
        return <div style={ui.page}><div style={ui.card}>Loading…</div></div>;
    }

    return (
        <div style={ui.page}>
            <div style={ui.card}>
                <h1 style={ui.h1}>Authorize access</h1>
                <p style={{ color: '#444', marginTop: 0 }}>
                    <strong>{info.client.name}</strong> wants to access your account with these permissions:
                </p>

                <ul style={{ listStyle: 'none', padding: 0, margin: '1rem 0 1.5rem' }}>
                    {info.scopes.map((s) => (
                        <li
                            key={s.name}
                            style={{ padding: '0.6rem 0.8rem', background: '#f5f6f8', borderRadius: 6, marginBottom: 8 }}
                        >
                            <code style={{ color: '#4338ca' }}>{s.name}</code>
                            {s.description && <div style={{ fontSize: '0.85rem', color: '#666' }}>{s.description}</div>}
                        </li>
                    ))}
                </ul>

                {/* Top-level form POST so the browser follows the backend 302 to the client. */}
                <form method="POST" action={`${API_BASE}/oauth/authorize`}>
                    {PARAM_KEYS.map((k) =>
                        params[k] !== undefined ? <input key={k} type="hidden" name={k} value={params[k]} /> : null,
                    )}
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                        <button style={ui.button} type="submit" name="approved" value="true">
                            Allow
                        </button>
                        <button style={ui.buttonSecondary} type="submit" name="approved" value="false">
                            Deny
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export default function ConsentPage() {
    return (
        <Suspense fallback={<div style={ui.page} />}>
            <Consent />
        </Suspense>
    );
}
