import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * CLI suite: offline, like the core offline suite, and run after it by
 * `npm test` from the repository root.
 *
 * Two kinds of test run here. Dispatch tests call the CLI in-process against
 * a deterministic fake ledger, with traps on recovery-phrase access, signing
 * and submission. Executable tests run the built `falconer` binary as a
 * subprocess with network and environment traps preloaded. Neither contacts a
 * node, so the suite passes with Docker and LocalNet absent.
 */
export default defineConfig({
  resolve: {
    alias: {
      // In-process tests run against core's source, so a stale core build can
      // never stand in for the code under test.
      '@falconer/core': fileURLToPath(
        new URL('../core/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/.git/**'],
    // Builds core and the CLI first, so the executable tests run the current
    // source and never whatever `dist` happened to hold.
    globalSetup: ['test/build.globalSetup.ts'],
    // An offline run that collected nothing is a broken checkout, not a pass.
    passWithNoTests: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
