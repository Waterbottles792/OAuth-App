'use client';

/**
 * Developer dashboard (Phase 7) — admin-only OAuth client management. Lists clients, registers
 * new ones, and deletes them via the admin /clients API. A newly created confidential client's
 * secret is shown exactly once (the backend never returns it again).
 */

import { useEffect, useState } from 'react';
import { api, ApiError, API_URL } from '../../lib/api';
import * as ui from '../../lib/ui';

interface Client {
    client_id: string;
    name: string;
    client_type: string;
    redirect_uris: string[];
    allowed_scopes: string[];
}

export default function DashboardPage() {
    const [me, setMe] = useState<{ email: string; is_admin: boolean } | null>(null);
    const [clients, setClients] = useState<Client[]>([]);
    const [scopeCatalogue, setScopeCatalogue] = useState<string[]>([]);
    const [error, setError] = useState('');
    const [createdSecret, setCreatedSecret] = useState<{ clientId: string; secret?: string } | null>(null);

    // form state
    const [name, setName] = useState('');
    const [clientType, setClientType] = useState('confidential');
    const [redirectUris, setRedirectUris] = useState('');
    const [scopes, setScopes] = useState<string[]>(['openid']);

    async function loadClients() {
        const res = await api.get<{ clients: Client[] }>('/clients');
        setClients(res.clients);
    }

    useEffect(() => {
        api.get<{ user: { email: string; is_admin: boolean } }>('/auth/me')
            .then((res) => {
                setMe(res.user);
                if (res.user.is_admin) {
                    loadClients().catch((e: ApiError) => setError(e.message));
                    fetch(`${API_URL}/.well-known/openid-configuration`)
                        .then((r) => r.json())
                        .then((d) => setScopeCatalogue(d.scopes_supported || []))
                        .catch(() => undefined);
                }
            })
            .catch((err: ApiError) => {
                if (err.status === 401) window.location.href = '/login?return_to=/dashboard';
                else setError(err.message);
            });
    }, []);

    async function createClient(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        setCreatedSecret(null);
        try {
            const res = await api.post<{ clientId: string; clientSecret?: string }>('/clients', {
                name,
                clientType,
                redirectUris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
                allowedScopes: scopes,
            });
            setCreatedSecret({ clientId: res.clientId, secret: res.clientSecret });
            setName('');
            setRedirectUris('');
            await loadClients();
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Failed to create client');
        }
    }

    async function remove(clientId: string) {
        if (!confirm(`Delete client ${clientId}?`)) return;
        try {
            await api.delete(`/clients/${clientId}`);
            await loadClients();
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Failed to delete');
        }
    }

    function toggleScope(s: string) {
        setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
    }

    if (me && !me.is_admin) {
        return (
            <div style={ui.page}>
                <div style={ui.card}>
                    <h1 style={ui.h1}>Dashboard</h1>
                    <div style={ui.alertInfo}>Client management requires an admin account.</div>
                    <a style={ui.link} href="/profile">Go to your profile →</a>
                </div>
            </div>
        );
    }

    return (
        <div style={{ ...ui.page, alignItems: 'flex-start' }}>
            <div style={ui.wideCard}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h1 style={{ ...ui.h1, marginBottom: 0 }}>Client Dashboard</h1>
                    <a style={ui.link} href="/profile">Profile</a>
                </div>
                {error && <div style={{ ...ui.alertError, marginTop: '1rem' }}>{error}</div>}

                {createdSecret && (
                    <div style={{ ...ui.alertInfo, marginTop: '1rem' }}>
                        <strong>Client created.</strong> client_id: <code>{createdSecret.clientId}</code>
                        {createdSecret.secret && (
                            <div style={{ marginTop: 6 }}>
                                client_secret (shown once): <code>{createdSecret.secret}</code>
                            </div>
                        )}
                    </div>
                )}

                <h2 style={{ fontSize: '1.1rem', marginTop: '1.5rem' }}>Register a client</h2>
                <form onSubmit={createClient}>
                    <label style={ui.label} htmlFor="cname">Name</label>
                    <input id="cname" style={ui.input} value={name} onChange={(e) => setName(e.target.value)} required />

                    <label style={ui.label} htmlFor="ctype">Type</label>
                    <select id="ctype" style={ui.input} value={clientType} onChange={(e) => setClientType(e.target.value)}>
                        <option value="confidential">confidential (server-side, gets a secret)</option>
                        <option value="public">public (SPA/mobile, PKCE only)</option>
                    </select>

                    <label style={ui.label} htmlFor="curis">Redirect URIs (one per line, exact match)</label>
                    <textarea
                        id="curis"
                        style={{ ...ui.input, minHeight: 70, fontFamily: 'monospace' }}
                        value={redirectUris}
                        onChange={(e) => setRedirectUris(e.target.value)}
                        placeholder="https://app.example.com/callback"
                        required
                    />

                    <label style={ui.label}>Scopes</label>
                    <div style={{ marginBottom: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
                        {(scopeCatalogue.length ? scopeCatalogue : ['openid', 'email', 'profile']).map((s) => (
                            <label key={s} style={{ fontSize: '0.9rem' }}>
                                <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} /> {s}
                            </label>
                        ))}
                    </div>

                    <button style={{ ...ui.button, width: 'auto', padding: '0.6rem 1.2rem' }} type="submit">
                        Create client
                    </button>
                </form>

                <h2 style={{ fontSize: '1.1rem', marginTop: '2rem' }}>Registered clients</h2>
                {clients.length === 0 ? (
                    <p style={{ color: '#666' }}>No clients yet.</p>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                        <thead>
                            <tr style={{ textAlign: 'left', borderBottom: '2px solid #eee' }}>
                                <th style={{ padding: '0.5rem' }}>Name</th>
                                <th style={{ padding: '0.5rem' }}>client_id</th>
                                <th style={{ padding: '0.5rem' }}>Type</th>
                                <th style={{ padding: '0.5rem' }}>Scopes</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {clients.map((c) => (
                                <tr key={c.client_id} style={{ borderBottom: '1px solid #f0f0f0' }}>
                                    <td style={{ padding: '0.5rem' }}>{c.name}</td>
                                    <td style={{ padding: '0.5rem', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                                        {c.client_id}
                                    </td>
                                    <td style={{ padding: '0.5rem' }}>{c.client_type}</td>
                                    <td style={{ padding: '0.5rem' }}>{c.allowed_scopes.join(', ')}</td>
                                    <td style={{ padding: '0.5rem' }}>
                                        <button style={ui.buttonDanger} onClick={() => remove(c.client_id)}>
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}
