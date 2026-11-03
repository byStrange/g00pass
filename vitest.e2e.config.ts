import { defineConfig } from 'vitest/config';

// Browser e2e (Playwright, preinstalled Chromium). Run `npm run e2e` (builds dist/ first).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['e2e/**/*.e2e.ts'],
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 600_000,
    hookTimeout: 120_000,
  },
});
