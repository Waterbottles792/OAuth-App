/**
 * Home Page (Placeholder)
 * 
 * Phase 0: Basic placeholder page
 * Phase 7: Will implement:
 * - Login UI
 * - Consent UI
 * - Developer dashboard
 * - Admin panel
 * 
 * SECURITY NOTES:
 * - NO OAuth flow implementation yet
 * - NO login forms yet
 * - NO token handling yet
 */

export default function HomePage() {
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            padding: '2rem',
            backgroundColor: '#f5f5f5',
        }}>
            <div style={{
                backgroundColor: 'white',
                padding: '3rem',
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                maxWidth: '600px',
                textAlign: 'center',
            }}>
                <h1 style={{
                    fontSize: '2.5rem',
                    marginBottom: '1rem',
                    color: '#333',
                }}>
                    🔐 OAuth 2.1 + OIDC Platform
                </h1>

                <p style={{
                    fontSize: '1.25rem',
                    color: '#666',
                    marginBottom: '2rem',
                }}>
                    Production-Grade Authorization & Identity Platform
                </p>

                <div style={{
                    backgroundColor: '#fff3cd',
                    border: '1px solid #ffc107',
                    borderRadius: '4px',
                    padding: '1.5rem',
                    marginBottom: '2rem',
                    textAlign: 'left',
                }}>
                    <h2 style={{
                        fontSize: '1.25rem',
                        marginTop: 0,
                        marginBottom: '1rem',
                        color: '#856404',
                    }}>
                        ⚠️ Phase 0: Foundation
                    </h2>

                    <p style={{ margin: '0.5rem 0', color: '#856404' }}>
                        <strong>Status:</strong> Infrastructure setup only
                    </p>

                    <p style={{ margin: '0.5rem 0', color: '#856404' }}>
                        <strong>Not Yet Implemented:</strong>
                    </p>
                    <ul style={{ margin: '0.5rem 0', paddingLeft: '1.5rem', color: '#856404' }}>
                        <li>User authentication (Phase 1)</li>
                        <li>OAuth endpoints (Phase 3+)</li>
                        <li>Token issuance (Phase 4+)</li>
                        <li>Login/Consent UI (Phase 7)</li>
                    </ul>
                </div>

                <div style={{
                    backgroundColor: '#d1ecf1',
                    border: '1px solid #17a2b8',
                    borderRadius: '4px',
                    padding: '1.5rem',
                    textAlign: 'left',
                }}>
                    <h2 style={{
                        fontSize: '1.25rem',
                        marginTop: 0,
                        marginBottom: '1rem',
                        color: '#0c5460',
                    }}>
                        ✅ Completed
                    </h2>

                    <ul style={{ margin: 0, paddingLeft: '1.5rem', color: '#0c5460' }}>
                        <li>Project structure created</li>
                        <li>Backend server configured</li>
                        <li>Security middleware active</li>
                        <li>Database infrastructure ready</li>
                        <li>Configuration validated</li>
                    </ul>
                </div>

                <div style={{ marginTop: '2rem', fontSize: '0.875rem', color: '#999' }}>
                    <p>
                        Backend API: <code>http://localhost:3001</code>
                    </p>
                    <p>
                        Health Check: <code>GET /health</code>
                    </p>
                </div>
            </div>
        </div>
    );
}
