/**
 * Typed application errors.
 *
 * Services throw these; the global error handler in server.ts maps them to safe
 * HTTP responses. Error `code` values follow an OAuth-style snake_case convention so
 * later phases (OAuth/OIDC) can reuse the same vocabulary.
 *
 * NEVER put sensitive detail (password, token, stack) in `message` — it may be returned
 * to the client. Use `logDetail` for anything that should only reach the logs.
 */

export class AppError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly logDetail?: unknown;

    constructor(statusCode: number, code: string, message: string, logDetail?: unknown) {
        super(message);
        this.name = 'AppError';
        this.statusCode = statusCode;
        this.code = code;
        this.logDetail = logDetail;
        // Use new.target so subclasses (ConflictError, etc.) keep their own prototype and
        // `instanceof` works correctly after TS-to-ES5 downleveling.
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class ValidationError extends AppError {
    constructor(message: string, logDetail?: unknown) {
        super(400, 'invalid_request', message, logDetail);
        this.name = 'ValidationError';
    }
}

export class UnauthorizedError extends AppError {
    constructor(message = 'Authentication required') {
        super(401, 'unauthorized', message);
        this.name = 'UnauthorizedError';
    }
}

export class ForbiddenError extends AppError {
    constructor(message = 'Access denied') {
        super(403, 'forbidden', message);
        this.name = 'ForbiddenError';
    }
}

export class ConflictError extends AppError {
    constructor(message: string) {
        super(409, 'conflict', message);
        this.name = 'ConflictError';
    }
}

export class RateLimitError extends AppError {
    constructor(message = 'Too many requests', public readonly retryAfterSeconds?: number) {
        super(429, 'rate_limited', message);
        this.name = 'RateLimitError';
    }
}

/** Type guard for the global error handler. */
export function isAppError(err: unknown): err is AppError {
    return err instanceof AppError;
}
