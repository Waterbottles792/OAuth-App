/**
 * JWT signing-key rotation (Phase 8).
 *
 *   npm run rotate:keys
 *
 * Generates a new active signing key and retires the current one for an overlap window
 * (keyConfig.rotationOverlapSeconds) during which it is still published via JWKS so tokens it
 * already signed keep verifying. Intended to be run on a schedule (e.g. monthly) by ops.
 */

import { rotateSigningKey } from '../src/services/key.service';
import { closePool } from '../src/db/pool';

rotateSigningKey()
    .then((key) => {
        console.log(`✅ rotated. New active signing kid: ${key.kid}`);
    })
    .catch((err) => {
        console.error('key rotation failed:', err);
        process.exitCode = 1;
    })
    .finally(() => closePool());
