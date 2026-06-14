'use client';

/**
 * Registration page (Phase 7). Calls the enumeration-resistant backend /auth/register, which
 * always returns the same 202 response whether or not the email was already taken.
 */

import { useState } from 'react';
import { api, ApiError } from '../../lib/api';
import * as ui from '../../lib/ui';

export default function RegisterPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [done, setDone] = useState(false);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    async function submit(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        setBusy(true);
        try {
            await api.post('/auth/register', { email, password });
            setDone(true);
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Registration failed');
        } finally {
            setBusy(false);
        }
    }

    return (
        <div style={ui.page}>
            <div style={ui.card}>
                <h1 style={ui.h1}>Create your account</h1>
                {done ? (
                    <>
                        <div style={ui.alertInfo}>
                            If the email can be registered, a verification link has been sent. You can now sign in.
                        </div>
                        <a style={ui.link} href="/login">Go to sign in →</a>
                    </>
                ) : (
                    <form onSubmit={submit}>
                        {error && <div style={ui.alertError}>{error}</div>}
                        <label style={ui.label} htmlFor="email">Email</label>
                        <input
                            id="email"
                            style={ui.input}
                            type="email"
                            autoComplete="username"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <label style={ui.label} htmlFor="password">Password</label>
                        <input
                            id="password"
                            style={ui.input}
                            type="password"
                            autoComplete="new-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            minLength={12}
                            required
                        />
                        <button style={ui.button} type="submit" disabled={busy}>
                            {busy ? 'Creating…' : 'Create account'}
                        </button>
                        <p style={{ marginTop: '1.25rem', fontSize: '0.9rem', color: '#666' }}>
                            Already have an account? <a style={ui.link} href="/login">Sign in</a>
                        </p>
                    </form>
                )}
            </div>
        </div>
    );
}
