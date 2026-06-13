/**
 * Minimal migration runner.
 *
 * Applies every `*.sql` file in `db/migrations/` in filename order, exactly once.
 * Applied filenames are recorded in `schema_migrations`. Each migration runs inside a
 * transaction, so a failing migration leaves the DB unchanged.
 *
 * Usage:
 *   npm run migrate          # apply pending migrations
 *   npm run migrate:status   # list applied vs pending
 *
 * Decision (Phase 1): plain SQL files + this runner, instead of an external migration
 * library. Zero extra dependencies, fully transparent, good enough for this project's
 * forward-only schema evolution.
 */

import fs from 'fs';
import path from 'path';
import { getPool, closePool, withTransaction } from './pool';

const MIGRATIONS_DIR = path.resolve(__dirname, 'migrations');

async function ensureMigrationsTable(): Promise<void> {
    await getPool().query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename   VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
}

function listMigrationFiles(): string[] {
    if (!fs.existsSync(MIGRATIONS_DIR)) return [];
    return fs
        .readdirSync(MIGRATIONS_DIR)
        .filter((f) => f.endsWith('.sql'))
        .sort();
}

async function appliedMigrations(): Promise<Set<string>> {
    const { rows } = await getPool().query<{ filename: string }>(
        'SELECT filename FROM schema_migrations',
    );
    return new Set(rows.map((r: { filename: string }) => r.filename));
}

export async function runMigrations(): Promise<string[]> {
    await ensureMigrationsTable();
    const applied = await appliedMigrations();
    const pending = listMigrationFiles().filter((f) => !applied.has(f));

    for (const filename of pending) {
        const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, filename), 'utf8');
        await withTransaction(async (client) => {
            await client.query(sql);
            await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [filename]);
        });
        console.log(`✅ applied ${filename}`);
    }
    return pending;
}

async function status(): Promise<void> {
    await ensureMigrationsTable();
    const applied = await appliedMigrations();
    for (const f of listMigrationFiles()) {
        console.log(`${applied.has(f) ? '✅ applied' : '⏳ pending'}  ${f}`);
    }
}

// CLI entrypoint
if (require.main === module) {
    const mode = process.argv[2] === 'status' ? 'status' : 'migrate';
    (async () => {
        try {
            if (mode === 'status') {
                await status();
            } else {
                const pending = await runMigrations();
                console.log(pending.length ? `\nApplied ${pending.length} migration(s).` : 'Up to date.');
            }
        } catch (err) {
            console.error('Migration failed:', err);
            process.exitCode = 1;
        } finally {
            await closePool();
        }
    })();
}
