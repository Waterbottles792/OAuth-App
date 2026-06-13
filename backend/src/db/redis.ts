/**
 * Redis client.
 *
 * Shared client for session storage and rate-limit counters. Connects lazily on first
 * use so importing this module doesn't open a socket (keeps tests/CLI tools cheap).
 */

import { createClient, RedisClientType } from 'redis';
import { redisConfig } from '../config';

let client: RedisClientType | null = null;
let connecting: Promise<RedisClientType> | null = null;

export async function getRedis(): Promise<RedisClientType> {
    if (client && client.isOpen) return client;
    if (connecting) return connecting;

    const c: RedisClientType = createClient({
        socket: { host: redisConfig.host, port: redisConfig.port },
        password: redisConfig.password || undefined,
    });

    c.on('error', (err) => {
        console.error('Redis client error:', err.message);
    });

    connecting = c.connect().then(() => {
        client = c;
        connecting = null;
        return c;
    });

    return connecting;
}

export async function closeRedis(): Promise<void> {
    if (client && client.isOpen) {
        await client.quit();
    }
    client = null;
    connecting = null;
}
