'use client';

/**
 * Login page (Phase 7). Two steps: password, then (if the account has MFA) a TOTP code.
 * On success the backend has set the HttpOnly `sid` cookie; we then navigate to a validated
 * `return_to` (the OAuth /authorize URL when arriving from a client) or the profile page.
 *
 * No token or session value is ever read or stored in JS — auth lives in the cookie.
 */

import { useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { api, ApiError, safeReturnTo } from '../../lib/api';
import * as ui from '../../lib/ui';

function LoginForm() {
    const params = useSearchParams();
    const returnTo = safeReturnTo(params.get('return_to'));

    const [step, setStep] = useState<'password' | 'mfa'>('password');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [code, setCode] = useState('');
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    function done() {
        window.location.href = returnTo || '/profile';
    }

    async function submitPassword(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        setBusy(true);
        try {
            const res = await api.post<{ mfaRequired?: boolean }>('/auth/login', { email, password });
            if (res.mfaRequired) setStep('mfa');
            else done();
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Login failed');
        } finally {
            setBusy(false);
        }
    }

    async function submitMfa(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        setBusy(true);
        try {
            await api.post('/auth/mfa/login', { code });
            done();
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Invalid code');
        } finally {
            setBusy(false);
        }
    }

    return (
        <div style={ui.page}>
            <div style={ui.card}>
                <h1 style={ui.h1}>🔐 Sign in</h1>
                {returnTo && <div style={ui.alertInfo}>An application is requesting access to your account.</div>}
                {error && <div style={ui.alertError}>{error}</div>}

                {step === 'password' ? (
                    <form onSubmit={submitPassword}>
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
                            autoComplete="current-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                        <button style={ui.button} type="submit" disabled={busy}>
                            {busy ? 'Signing in…' : 'Sign in'}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={submitMfa}>
                        <div style={ui.alertInfo}>Enter the 6-digit code from your authenticator app.</div>
                        <label style={ui.label} htmlFor="code">Authentication code</label>
                        <input
                            id="code"
                            style={ui.input}
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            value={code}
                            onChange={(e) => setCode(e.target.value)}
                            required
                        />
                        <button style={ui.button} type="submit" disabled={busy}>
                            {busy ? 'Verifying…' : 'Verify'}
                        </button>
                    </form>
                )}

                <p style={{ marginTop: '1.25rem', fontSize: '0.9rem', color: '#666' }}>
                    No account? <a style={ui.link} href="/register">Create one</a>
                </p>
            </div>
        </div>
    );
}

export default function LoginPage() {
    // useSearchParams requires a Suspense boundary in the app router.
    return (
        <Suspense fallback={<div style={ui.page} />}>
            <LoginForm />
        </Suspense>
    );
}
