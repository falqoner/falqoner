import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

/**
 * Gate the LocalNet suite on a real node being present.
 *
 * The suite used to probe algod itself and turn an unreachable node into
 * `describe.skip`, which reported a green run that had asserted nothing about
 * the chain. LocalNet tests are required, so a missing prerequisite has to
 * fail: throwing here aborts the run before any test file is imported and
 * leaves a nonzero exit code.
 *
 * The probe runs as a child process so `scripts/localnet-preflight.mjs` stays
 * the only implementation, shared with `npm run localnet:status`. It is
 * read-only; nothing here starts, resets or deletes LocalNet state.
 */
const PREFLIGHT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../scripts/localnet-preflight.mjs',
);

export async function setup(): Promise<void> {
  const res = spawnSync(process.execPath, [PREFLIGHT], { stdio: 'inherit' });

  if (res.error) {
    throw new Error(
      `LocalNet preflight could not be executed (${res.error.message}). ` +
        `Expected the probe at ${PREFLIGHT}.`,
    );
  }
  if (res.signal) {
    throw new Error(`LocalNet preflight was killed by ${res.signal}.`);
  }
  if (res.status !== 0) {
    throw new Error(
      `LocalNet preflight failed (exit ${res.status}); the diagnostic above ` +
        'names each missing prerequisite. The LocalNet suite is required and ' +
        'is never skipped, so this run fails.',
    );
  }
}
