/**
 * JWT signing key management (Phase 4).
 *
 * - On first use, generates an RSA-2048 keypair (RS256). The public key (SPKI PEM) is stored
 *   in the clear; the private key (PKCS8 PEM) is encrypted at rest with AES-256-GCM before
 *   being written to `jwt_keys`. No key material is ever written to the filesystem or VCS.
 * - The active signing key is cached in memory (decrypted once) so signing doesn't decrypt
 *   on every request.
 * - The AES key is derived from `keyConfig.encryptionSecret` via scrypt.
 *
 * SECURITY_DECISIONS #2: asymmetric only (RS256). HS256/none are never produced.
 */

import crypto from 'crypto';
import { importSPKI, exportJWK, JWK } from 'jose';
import { query } from '../db/pool';
import { keyConfig } from '../config';
import { randomToken } from '../lib/crypto';

export interface SigningKey {
    kid: string;
    algorithm: string;
    publicKeyPem: string;
    privateKeyPem: string; // decrypted; kept only in memory
}

let cachedActiveKey: SigningKey | null = null;

// ---- AES-256-GCM encryption of the private key at rest --------------------------------

const AES_KEY = crypto.scryptSync(keyConfig.encryptionSecret, 'jwt-key-salt', 32);

function encryptPrivateKey(pem: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64')}.${tag.toString('base64')}.${ciphertext.toString('base64')}`;
}

function decryptPrivateKey(stored: string): string {
    const [ivB64, tagB64, dataB64] = stored.split('.');
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

// ---- Key generation & retrieval -------------------------------------------------------

function generateRsaKeypair(): { publicKeyPem: string; privateKeyPem: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: keyConfig.rsaModulusLength,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKeyPem: publicKey as string, privateKeyPem: privateKey as string };
}

interface KeyRow {
    kid: string;
    algorithm: string;
    public_key: string;
    private_key_enc: string;
}

async function loadActiveRow(): Promise<KeyRow | null> {
    const { rows } = await query<KeyRow>(
        'SELECT kid, algorithm, public_key, private_key_enc FROM jwt_keys WHERE active = TRUE LIMIT 1',
    );
    return rows[0] ?? null;
}

/**
 * Return the active signing key, generating and persisting one if none exists yet.
 * The decrypted key is cached in memory for the process lifetime.
 */
export async function getActiveSigningKey(): Promise<SigningKey> {
    if (cachedActiveKey) return cachedActiveKey;

    let row = await loadActiveRow();
    if (!row) {
        const kid = `key_${randomToken(8)}`;
        const { publicKeyPem, privateKeyPem } = generateRsaKeypair();
        const privateKeyEnc = encryptPrivateKey(privateKeyPem);
        try {
            await query(
                `INSERT INTO jwt_keys (kid, algorithm, public_key, private_key_enc, active)
                 VALUES ($1, $2, $3, $4, TRUE)`,
                [kid, keyConfig.signingAlgorithm, publicKeyPem, privateKeyEnc],
            );
            row = { kid, algorithm: keyConfig.signingAlgorithm, public_key: publicKeyPem, private_key_enc: privateKeyEnc };
        } catch (err) {
            // Another process won the race to create the single active key; load theirs.
            if ((err as { code?: string }).code === '23505') {
                row = await loadActiveRow();
            } else {
                throw err;
            }
        }
    }

    if (!row) throw new Error('Failed to obtain an active signing key');

    cachedActiveKey = {
        kid: row.kid,
        algorithm: row.algorithm,
        publicKeyPem: row.public_key,
        privateKeyPem: decryptPrivateKey(row.private_key_enc),
    };
    return cachedActiveKey;
}

/** Public key PEM for a given kid (used to verify tokens; JWKS in Phase 6). */
export async function getPublicKeyPem(kid: string): Promise<string | null> {
    const { rows } = await query<{ public_key: string }>(
        'SELECT public_key FROM jwt_keys WHERE kid = $1',
        [kid],
    );
    return rows[0]?.public_key ?? null;
}

/**
 * Public JWK Set for the JWKS endpoint (Phase 6). Exports the public half of every key in
 * `jwt_keys` (not just the active one, so tokens signed by a key being rotated out still
 * verify). Ensures at least one key exists first. Only public parameters (kty/n/e) plus
 * kid/use/alg are exposed — never any private material.
 */
export async function getPublicJwks(): Promise<{ keys: JWK[] }> {
    await getActiveSigningKey(); // generate the first key on demand if none exists yet

    const { rows } = await query<{ kid: string; algorithm: string; public_key: string }>(
        'SELECT kid, algorithm, public_key FROM jwt_keys ORDER BY active DESC, created_at DESC',
    );

    const keys = await Promise.all(
        rows.map(async (r) => {
            const key = await importSPKI(r.public_key, r.algorithm);
            const jwk = await exportJWK(key); // public params only (kty, n, e)
            return { ...jwk, kid: r.kid, use: 'sig', alg: r.algorithm };
        }),
    );

    return { keys };
}

/** Test/rotation helper: drop the in-memory cache so the next call reloads from the DB. */
export function clearKeyCache(): void {
    cachedActiveKey = null;
}
