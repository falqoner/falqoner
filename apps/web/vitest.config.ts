import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Web suite: offline, run by `npm test` from the root after the core and CLI
 * suites.
 *
 * Two kinds of test run here. Rendering checks render components to static
 * markup in Node, from exposures the real core model produces against a
 * scripted provider. Migration tests mount the whole app in a jsdom document
 * (each file opts in with `@vitest-environment jsdom`), with the core helpers
 * that sign and send replaced by promises the test settles, and with network
 * access trapped. No browser, no network and no node are involved.
 */
export default defineConfig({
  esbuild: { jsx: 'automatic' },
  resolve: {
    alias: {
      // The same core source the app itself builds against (vite.config.ts).
      '@falconer/core': fileURLToPath(
        new URL('../../packages/core/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    exclude: ['**/node_modules/**', '**/.git/**'],
    // One realm for typed arrays under jsdom; see test/realm.ts.
    setupFiles: ['test/realm.ts'],
    // An offline run that collected nothing is a broken checkout, not a pass.
    passWithNoTests: false,
    // The mounted tests wait, in real time, for bounded timeouts to pass.
    testTimeout: 30_000,
  },
});
