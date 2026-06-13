/**
 * PostgreSQL connection pool.
 *
 * Single shared pool for the process, built from `databaseConfig`. Import `query`
 * for one-off statements or `getPool()` when you need a client (transactions).
 */

import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';
import { databaseConfig } from '../config';

let pool: Pool | null = null;

export function getPool(): Pool {
    if (!pool) {
        pool = new Pool({
            host: databaseConfig.host,
            port: databaseConfig.port,
            database: databaseConfig.database,
            user: databaseConfig.user,
            password: databaseConfig.password,
            ssl: databaseConfig.ssl ? { rejectUnauthorized: false } : undefined,
            max: databaseConfig.max,
            idleTimeoutMillis: databaseConfig.idleTimeoutMillis,
            connectionTimeoutMillis: databaseConfig.connectionTimeoutMillis,
        });

        pool.on('error', (err) => {
            // Errors on idle clients shouldn't crash the process.
            console.error('Unexpected PostgreSQL pool error:', err.message);
        });
    }
    return pool;
}

export function query<T extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: unknown[],
): Promise<QueryResult<T>> {
    return getPool().query<T>(text, params as never[]);
}

/**
 * Run a function inside a transaction. Commits on success, rolls back on throw.
 */
export async function withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await getPool().connect();
    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

export async function closePool(): Promise<void> {
    if (pool) {
        await pool.end();
        pool = null;
    }
}
