/**
 * Request validation schemas (zod) and a helper to run them.
 *
 * House rule: every external input goes through a schema. No raw req.body in services.
 */

import { z } from 'zod';
import { ValidationError } from './errors';

/**
 * Password policy: 12+ chars, with upper, lower, and a digit. Argon2id handles the
 * cryptographic strength; this just blocks trivially weak inputs.
 */
const password = z
    .string()
    .min(12, 'Password must be at least 12 characters')
    .max(128, 'Password must be at most 128 characters')
    .regex(/[a-z]/, 'Password must contain a lowercase letter')
    .regex(/[A-Z]/, 'Password must contain an uppercase letter')
    .regex(/[0-9]/, 'Password must contain a digit');

const email = z.string().trim().toLowerCase().email('Invalid email address').max(255);

export const registerSchema = z.object({
    email,
    password,
});

export const loginSchema = z.object({
    email,
    password: z.string().min(1, 'Password is required').max(128),
});

export const totpCodeSchema = z.object({
    code: z.string().trim().regex(/^[0-9A-Za-z]{6,10}$/, 'Invalid code format'),
});

/** Parse `data` against `schema`, throwing a ValidationError with a friendly message. */
export function validate<T>(schema: z.ZodType<T>, data: unknown): T {
    const result = schema.safeParse(data);
    if (!result.success) {
        const first = result.error.issues[0];
        throw new ValidationError(first?.message ?? 'Invalid request', result.error.flatten());
    }
    return result.data;
}
