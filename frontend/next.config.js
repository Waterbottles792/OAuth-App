/** @type {import('next').NextConfig} */

// Backend API origin (where credentialed fetches and the consent form POST go). Read from the
// same public env the client uses so CSP stays in sync with the actual API target.
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

const isDev = process.env.NODE_ENV !== 'production';

// Content-Security-Policy. Notes:
//  - connect-src must allow the backend API origin (fetch from the SPA); in dev the Next HMR
//    websocket also needs ws:.
//  - form-action must allow the API origin: the consent page POSTs its decision form to the
//    backend /authorize as a top-level navigation, which form-action governs.
//  - img-src allows data: for the MFA enrollment QR code (a data URL).
//  - script-src/style-src use 'unsafe-inline' because Next's hydration injects inline flight
//    data and React uses inline style attributes. 'unsafe-eval' is required ONLY in dev mode
//    (Next's HMR / React Refresh evaluate code via eval); it is omitted in production.
//    Tightening to nonces is a Phase 8 item.
const csp = [
    "default-src 'self'",
    `connect-src 'self' ${API_URL}${isDev ? ' ws: wss:' : ''}`,
    "img-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
    "base-uri 'self'",
    "frame-ancestors 'none'",
    `form-action 'self' ${API_URL}`,
].join('; ');

const nextConfig = {
    reactStrictMode: true,

    async headers() {
        return [
            {
                source: '/:path*',
                headers: [
                    { key: 'Content-Security-Policy', value: csp },
                    { key: 'X-Frame-Options', value: 'DENY' },
                    { key: 'X-Content-Type-Options', value: 'nosniff' },
                    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
                ],
            },
        ];
    },
};

module.exports = nextConfig;
