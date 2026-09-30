import { defineConfig } from 'vitest/config';

/**
 * Offline suite: unit, regression and cryptographic tests only.
 *
 * It has to pass with Docker and the LocalNet services absent, so the LocalNet
 * suite is removed at discovery rather than skipped at runtime. Excluding it
 * means the file is never imported, which is the only way to guarantee no
 * offline run can reach a node: skipping still executes module scope, and that
 * is exactly how the old harness came to probe algod on every offline run.
 *
 * The LocalNet suite runs from `vitest.localnet.config.ts`.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: [
      '**/node_modules/**',
      '**/.git/**',
      // Requires a live node; see vitest.localnet.config.ts.
      '**/*.localnet.test.ts',
    ],
    // An offline run that collected nothing is a broken checkout, not a pass.
    passWithNoTests: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
