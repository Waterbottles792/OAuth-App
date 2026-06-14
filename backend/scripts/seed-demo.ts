/**
 * Demo seeder (dev only) — makes the platform easy to try end-to-end.
 *
 *   npx ts-node scripts/seed-demo.ts
 *
 * Creates (idempotently):
 *   - a demo user, promoted to admin            (demo@example.com / DemoPassword123)
 *   - a confidential OAuth client with openid/email/profile scopes
 *
 * Then prints the client credentials and a ready-to-use PKCE authorize URL: paste it into a
 * browser while signed in as the demo user to walk login → consent → redirect-with-code.
 *
 * Refuses to run with NODE_ENV=production.
 */

import crypto from 'crypto';
import { query, closePool } from '../src/db/pool';
import { register } from '../src/services/auth.service';
import { createClient } from '../src/services/client.service';
import { oauthFlowConfig, serverConfig } from '../src/config';

const DEMO_EMAIL = 'demo@example.com';
const DEMO_PASSWORD = 'DemoPassword123';
const REDIRECT_URI = 'https://client.example.com/cb';

async function main() {
    if (serverConfig.isProduction) {
        throw new Error('seed-demo refuses to run in production');
    }

    // 1. Demo user (register is enumeration-resistant; ignore "already exists") + promote.
    await register(DEMO_EMAIL, DEMO_PASSWORD);
    await query('UPDATE users SET is_admin = TRUE, email_verified = TRUE WHERE email = $1', [DEMO_EMAIL]);
    const { rows } = await query<{ id: string }>('SELECT id FROM users WHERE email = $1', [DEMO_EMAIL]);
    const userId = rows[0]?.id;

    // 2. Confidential client (reuse if one with this name already exists).
    let clientId: string;
    let clientSecret: string | undefined;
    const existing = await query<{ client_id: string }>(
        "SELECT client_id FROM oauth_clients WHERE name = 'Demo Client' LIMIT 1",
    );
    if (existing.rows[0]) {
        clientId = existing.rows[0].client_id;
        clientSecret = undefined; // secret only shown at creation; recreate to get a new one
    } else {
        const created = await createClient({
            name: 'Demo Client',
            clientType: 'confidential',
            redirectUris: [REDIRECT_URI],
            allowedScopes: ['openid', 'email', 'profile'],
        });
        clientId = created.client.client_id;
        clientSecret = created.clientSecret;
    }

    // 3. PKCE pair + authorize URL.
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const authorizeUrl =
        `${oauthFlowConfig.issuer}/api/${serverConfig.apiVersion}/oauth/authorize?` +
        new URLSearchParams({
            response_type: 'code',
            client_id: clientId,
            redirect_uri: REDIRECT_URI,
            scope: 'openid email',
            state: 'demo-state',
            code_challenge: challenge,
            code_challenge_method: 'S256',
            nonce: 'demo-nonce',
        }).toString();

    console.log('\n=== Demo seed complete ===');
    console.log(`User:           ${DEMO_EMAIL} / ${DEMO_PASSWORD} (admin)`);
    console.log(`User ID:        ${userId}`);
    console.log(`Client ID:      ${clientId}`);
    console.log(`Client secret:  ${clientSecret ?? '(unchanged — delete "Demo Client" in the dashboard to mint a new one)'}`);
    console.log(`PKCE verifier:  ${verifier}`);
    console.log('\nAuthorize URL (sign in as the demo user first at http://localhost:3000/login):');
    console.log(authorizeUrl);
    console.log('\nAfter approving consent you get ...?code=XXX. Exchange it:');
    console.log(
        `curl -s -X POST ${oauthFlowConfig.issuer}/api/${serverConfig.apiVersion}/oauth/token -H 'content-type: application/json' \\\n` +
            `  -d '{"grant_type":"authorization_code","code":"XXX","redirect_uri":"${REDIRECT_URI}","client_id":"${clientId}","client_secret":"${clientSecret ?? '<SECRET>'}","code_verifier":"${verifier}"}'`,
    );
    console.log('');
}

main()
    .catch((err) => {
        console.error('seed-demo failed:', err);
        process.exitCode = 1;
    })
    .finally(() => closePool());
