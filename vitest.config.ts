import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { __APP_VERSION__: '"test"', __APP_COMMIT__: '"test"' },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Core unit tests run with the pass-through hook; production defaults to fail closed.
    setupFiles: ['test/setup.ts'],
    // Low-memory machine: one worker, one file at a time.
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 30000,
  },
});
