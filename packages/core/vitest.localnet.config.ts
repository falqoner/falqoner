import { defineConfig } from 'vitest/config';

/**
 * Integration suite: end-to-end migration against a real Algorand node.
 *
 * Discovery is the mirror image of `vitest.config.ts` — only `*.localnet.test.ts`
 * runs here. `test/localnet.globalSetup.ts` probes algod, indexer, KMD and the
 * Falcon-1024 consensus capability first and throws when any of them is
 * missing, so an absent node fails the run instead of skipping it.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.localnet.test.ts'],
    exclude: ['**/node_modules/**', '**/.git/**'],
    globalSetup: ['test/localnet.globalSetup.ts'],
    // Never let an empty match report success: a required suite that collected
    // no files is a harness failure, which is exactly what this ticket fixes.
    passWithNoTests: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
