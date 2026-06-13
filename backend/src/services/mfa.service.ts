/**
 * Multi-factor authentication (TOTP + single-use backup codes).
 *
 * - TOTP via speakeasy (6-digit, 30s step), validated with a small drift window.
 * - Backup codes are random, shown to the user once, and stored only as SHA-256 hashes.
 * - The TOTP secret row is created on enrollment with enabled_at = NULL, and only marked
 *   enabled once the user proves possession by submitting a valid code (verifyEnrollment).
 */

import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { query } from '../db/pool';
import { authConfig } from '../config';
import { randomToken, sha256 } from '../lib/crypto';

export interface MfaEnrollment {
    otpauthUrl: string;
    qrCodeDataUrl: string;
    backupCodes: string[]; // plaintext, returned ONCE
}

interface MfaRow {
    totp_secret: string;
    backup_codes: string[];
    enabled_at: Date | null;
}

async function getMfaRow(userId: string): Promise<MfaRow | null> {
    const { rows } = await query<MfaRow>(
        'SELECT totp_secret, backup_codes, enabled_at FROM mfa_secrets WHERE user_id = $1',
        [userId],
    );
    return rows[0] ?? null;
}

export async function isMfaEnabled(userId: string): Promise<boolean> {
    const row = await getMfaRow(userId);
    return !!row?.enabled_at;
}

function generateBackupCodes(): { plain: string[]; hashed: string[] } {
    const plain: string[] = [];
    for (let i = 0; i < authConfig.mfa.backupCodeCount; i++) {
        // 8 hex-ish chars, easy to type, ~40 bits each
        plain.push(randomToken(5).replace(/[-_]/g, '').slice(0, 8).toUpperCase());
    }
    return { plain, hashed: plain.map(sha256) };
}

/**
 * Begin enrollment: generate (or replace any unconfirmed) TOTP secret + backup codes.
 * Returns provisioning data. MFA is NOT active until verifyEnrollment succeeds.
 */
export async function beginEnrollment(userId: string, email: string): Promise<MfaEnrollment> {
    const secret = speakeasy.generateSecret({
        name: `${authConfig.mfa.issuer} (${email})`,
        issuer: authConfig.mfa.issuer,
    });
    const { plain, hashed } = generateBackupCodes();

    await query(
        `INSERT INTO mfa_secrets (user_id, totp_secret, backup_codes, enabled_at)
         VALUES ($1, $2, $3, NULL)
         ON CONFLICT (user_id) DO UPDATE
           SET totp_secret = EXCLUDED.totp_secret,
               backup_codes = EXCLUDED.backup_codes,
               enabled_at = NULL`,
        [userId, secret.base32, hashed],
    );

    const otpauthUrl = secret.otpauth_url ?? '';
    const qrCodeDataUrl = otpauthUrl ? await qrcode.toDataURL(otpauthUrl) : '';
    return { otpauthUrl, qrCodeDataUrl, backupCodes: plain };
}

function verifyTotp(secret: string, code: string): boolean {
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: code,
        window: authConfig.mfa.totpWindow,
    });
}

/** Confirm enrollment: a valid TOTP flips enabled_at to NOW(). */
export async function verifyEnrollment(userId: string, code: string): Promise<boolean> {
    const row = await getMfaRow(userId);
    if (!row) return false;
    if (!verifyTotp(row.totp_secret, code)) return false;
    await query('UPDATE mfa_secrets SET enabled_at = NOW() WHERE user_id = $1', [userId]);
    return true;
}

/**
 * Verify a login-time challenge. Accepts a valid TOTP code OR an unused backup code.
 * A used backup code is consumed (removed) so it can't be replayed.
 */
export async function verifyChallenge(userId: string, code: string): Promise<boolean> {
    const row = await getMfaRow(userId);
    if (!row?.enabled_at) return false;

    if (verifyTotp(row.totp_secret, code)) return true;

    const codeHash = sha256(code.trim().toUpperCase());
    if (row.backup_codes.includes(codeHash)) {
        const remaining = row.backup_codes.filter((c) => c !== codeHash);
        await query('UPDATE mfa_secrets SET backup_codes = $1 WHERE user_id = $2', [
            remaining,
            userId,
        ]);
        return true;
    }
    return false;
}
