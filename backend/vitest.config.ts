import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        globals: true,
        // Identity Core tests share one Postgres + Redis; run serially to avoid races
        // from the per-test truncate/flush in setup.
        fileParallelism: false,
        pool: 'forks',
        maxWorkers: 1,
        setupFiles: ['./src/test/setup.ts'],
        hookTimeout: 30000,
        testTimeout: 30000,
    },
});
