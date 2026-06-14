/**
 * Home page (Phase 7). Entry point with links into the user-facing flows. The OAuth flow
 * itself is initiated by client applications hitting the backend's authorization_endpoint
 * (see /.well-known/openid-configuration) — this page is just the platform's own UI.
 */

import * as ui from '../lib/ui';

export default function HomePage() {
    return (
        <div style={ui.page}>
            <div style={{ ...ui.card, textAlign: 'center' }}>
                <h1 style={{ fontSize: '2rem', color: '#1a1a2e' }}>🔐 OAuth 2.1 + OIDC Platform</h1>
                <p style={{ color: '#666', marginBottom: '2rem' }}>
                    Authorization &amp; Identity Provider
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <a href="/login" style={{ ...ui.button, textDecoration: 'none', display: 'block' }}>Sign in</a>
                    <a href="/register" style={{ ...ui.buttonSecondary, textDecoration: 'none', display: 'block' }}>
                        Create an account
                    </a>
                    <a href="/profile" style={ui.link}>Your profile</a>
                    <a href="/dashboard" style={ui.link}>Developer dashboard (admin)</a>
                </div>
            </div>
        </div>
    );
}
