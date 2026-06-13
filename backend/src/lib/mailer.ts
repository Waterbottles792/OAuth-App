/**
 * Mailer abstraction.
 *
 * Phase 1 ships a dev mailer that just logs the message (so email verification links are
 * visible in the console without an SMTP server). Production can drop in a real transport
 * behind the same `Mailer` interface without touching callers.
 */

export interface Mailer {
    send(to: string, subject: string, body: string): Promise<void>;
}

const devMailer: Mailer = {
    async send(to, subject, body) {
        // eslint-disable-next-line no-console
        console.log(`\n📧 [dev-mailer] to=${to} subject="${subject}"\n${body}\n`);
    },
};

// Swap this out in Phase 8 / production wiring.
export const mailer: Mailer = devMailer;
