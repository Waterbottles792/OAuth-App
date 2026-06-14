'use client';

/**
 * Profile page (Phase 7). Shows the signed-in user, drives TOTP MFA enrollment (QR + one-time
 * backup codes, then a verification code), and logs out. All via credentialed calls to the
 * backend; the session lives only in the HttpOnly cookie.
 */

import { useEffect, useState } from 'react';
import { api, ApiError } from '../../lib/api';
import * as ui from '../../lib/ui';

interface Me {
    id: string;
    email: string;
    email_verified: boolean;
    is_admin: boolean;
}

export default function ProfilePage() {
    const [me, setMe] = useState<Me | null>(null);
    const [error, setError] = useState('');
    const [enroll, setEnroll] = useState<{ qrCode: string; backupCodes: string[] } | null>(null);
    const [code, setCode] = useState('');
    const [mfaDone, setMfaDone] = useState(false);

    useEffect(() => {
        api.get<{ user: Me }>('/auth/me')
            .then((res) => setMe(res.user))
            .catch((err: ApiError) => {
                if (err.status === 401) window.location.href = '/login?return_to=/profile';
                else setError(err.message);
            });
    }, []);

    async function startEnroll() {
        setError('');
        try {
            const res = await api.post<{ qrCode: string; backupCodes: string[] }>('/auth/mfa/enable');
            setEnroll({ qrCode: res.qrCode, backupCodes: res.backupCodes });
            setMfaDone(false);
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Could not start MFA setup');
        }
    }

    async function verifyEnroll(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        try {
            await api.post('/auth/mfa/verify', { code });
            setMfaDone(true);
            setEnroll(null);
            setCode('');
        } catch (err) {
            setError(err instanceof ApiError ? err.message : 'Invalid code');
        }
    }

    async function logout() {
        try {
            await api.post('/auth/logout');
        } finally {
            window.location.href = '/login';
        }
    }

    if (!me) {
        return <div style={ui.page}><div style={ui.card}>{error ? <div style={ui.alertError}>{error}</div> : 'Loading…'}</div></div>;
    }

    return (
        <div style={{ ...ui.page, alignItems: 'flex-start' }}>
            <div style={ui.card}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h1 style={{ ...ui.h1, marginBottom: 0 }}>Your profile</h1>
                    {me.is_admin && <a style={ui.link} href="/dashboard">Dashboard</a>}
                </div>

                {error && <div style={{ ...ui.alertError, marginTop: '1rem' }}>{error}</div>}

                <dl style={{ margin: '1.25rem 0' }}>
                    <dt style={ui.label}>Email</dt>
                    <dd style={{ margin: '0 0 0.75rem' }}>{me.email}</dd>
                    <dt style={ui.label}>Email verified</dt>
                    <dd style={{ margin: '0 0 0.75rem' }}>{me.email_verified ? 'Yes' : 'No'}</dd>
                    <dt style={ui.label}>Role</dt>
                    <dd style={{ margin: 0 }}>{me.is_admin ? 'Admin' : 'User'}</dd>
                </dl>

                <hr style={{ border: 0, borderTop: '1px solid #eee', margin: '1.5rem 0' }} />

                <h2 style={{ fontSize: '1.1rem' }}>Two-factor authentication</h2>
                {mfaDone && <div style={ui.alertInfo}>MFA is now enabled on your account.</div>}

                {!enroll ? (
                    <button style={{ ...ui.buttonSecondary, width: 'auto', padding: '0.5rem 1rem' }} onClick={startEnroll}>
                        Set up authenticator app
                    </button>
                ) : (
                    <div>
                        <p style={{ color: '#444' }}>Scan this QR code with your authenticator app:</p>
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img src={enroll.qrCode} alt="MFA QR code" style={{ width: 180, height: 180 }} />
                        <div style={{ ...ui.alertInfo, marginTop: '1rem' }}>
                            <strong>Backup codes</strong> (store these safely — shown once):
                            <div style={{ fontFamily: 'monospace', marginTop: 6, columns: 2 }}>
                                {enroll.backupCodes.map((c) => <div key={c}>{c}</div>)}
                            </div>
                        </div>
                        <form onSubmit={verifyEnroll}>
                            <label style={ui.label} htmlFor="mfacode">Enter a code to confirm</label>
                            <input
                                id="mfacode"
                                style={ui.input}
                                inputMode="numeric"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                required
                            />
                            <button style={{ ...ui.button, width: 'auto', padding: '0.6rem 1.2rem' }} type="submit">
                                Confirm & enable
                            </button>
                        </form>
                    </div>
                )}

                <hr style={{ border: 0, borderTop: '1px solid #eee', margin: '1.5rem 0' }} />
                <button style={{ ...ui.buttonSecondary, width: 'auto', padding: '0.5rem 1rem' }} onClick={logout}>
                    Sign out
                </button>
            </div>
        </div>
    );
}
