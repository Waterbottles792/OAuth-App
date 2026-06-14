/**
 * Root Layout Component
 * 
 * Phase 0: Minimal layout structure
 * Phase 7: Will include navigation, authentication state, etc.
 */

import type { Metadata, Viewport } from 'next';

export const metadata: Metadata = {
    title: 'OAuth 2.1 + OIDC Platform',
    description: 'Production-grade Authorization and Identity Platform',
    robots: 'noindex, nofollow', // Don't index during development
};

export const viewport: Viewport = {
    width: 'device-width',
    initialScale: 1,
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body style={{ margin: 0, fontFamily: 'system-ui, sans-serif' }}>
                {children}
            </body>
        </html>
    );
}
