#!/usr/bin/env node
/**
 * Portable sequential test runner: `node scripts/run-tests.mjs <unit|localnet|all>`.
 *
 * The root entry points and `@falconer/core`'s `test:all` route through this
 * file so they describe the same behavior, and it stays runnable on Windows,
 * macOS and Linux: no POSIX-only `VAR=value cmd` prefixes, no shell, and vitest
 * is invoked through the current Node binary rather than a platform-specific
 * shim.
 *
 * `unit` runs every offline suite: core's, the CLI's, then the web app's
 * rendering and migration checks. None contacts a node, so all pass with Docker and
 * LocalNet absent. `localnet` runs the integration suite alone, and `all`
 * runs the offline suites and then it.
 *
 * Failures propagate. A stage that exits nonzero ends the run with that exact
 * code, so no later stage runs: `all` never reaches LocalNet if an offline
 * suite failed.
 *
 * Skips are failures too. Vitest exits 0 with skipped or todo tests, and a
 * test that did not run asserted nothing, so each stage's JSON report must
 * show every collected test passed. The counts it shows are printed.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORE = path.join(ROOT, 'packages', 'core');
const CLI = path.join(ROOT, 'packages', 'cli');
const WEB = path.join(ROOT, 'apps', 'web');

/** @type {Record<string, { label: string, cwd: string, config: string }>} */
const STAGES = {
  core: { label: 'core offline', cwd: CORE, config: 'vitest.config.ts' },
  cli: { label: 'CLI offline', cwd: CLI, config: 'vitest.config.ts' },
  web: { label: 'web offline', cwd: WEB, config: 'vitest.config.ts' },
  localnet: { label: 'LocalNet', cwd: CORE, config: 'vitest.localnet.config.ts' },
};

/** @type {Record<string, string[]>} */
const MODES = {
  unit: ['core', 'cli', 'web'],
  localnet: ['localnet'],
  all: ['core', 'cli', 'web', 'localnet'],
};

const mode = process.argv[2];
if (mode === undefined || MODES[mode] === undefined) {
  process.stderr.write(
    `usage: node scripts/run-tests.mjs <${Object.keys(MODES).join('|')}>\n`,
  );
  process.exit(2);
}

const require = createRequire(import.meta.url);
/** The published bin, resolved through the exports map the package allows. */
const VITEST = path.join(
  path.dirname(require.resolve('vitest/package.json')),
  'vitest.mjs',
);

const REPORTS = mkdtempSync(path.join(os.tmpdir(), 'falconer-tests-'));
process.on('exit', () => rmSync(REPORTS, { recursive: true, force: true }));

for (const stage of /** @type {string[]} */ (MODES[mode])) {
  const { label, cwd, config } =
    /** @type {{ label: string, cwd: string, config: string }} */ (STAGES[stage]);
  const where = path.relative(ROOT, path.join(cwd, config)).split(path.sep).join('/');
  process.stdout.write(`\n> ${label} suite (${where})\n`);

  const report = path.join(REPORTS, `${stage}.json`);
  const res = spawnSync(
    process.execPath,
    [
      VITEST, 'run', '--config', config,
      '--reporter=default', '--reporter=json', `--outputFile.json=${report}`,
    ],
    { cwd, stdio: 'inherit' },
  );

  if (res.error) {
    process.stderr.write(`\n${label} suite could not start: ${res.error.message}\n`);
    process.exit(1);
  }
  if (res.signal) {
    process.stderr.write(`\n${label} suite was killed by ${res.signal}\n`);
    process.exit(1);
  }
  if (res.status !== 0) {
    process.stderr.write(`\n${label} suite failed (exit ${res.status})\n`);
    process.exit(res.status ?? 1);
  }

  /** @type {{ numTotalTests: number, numPassedTests: number }} */
  const { numTotalTests: total, numPassedTests: passed } = JSON.parse(
    readFileSync(report, 'utf8'),
  );
  if (total === 0 || passed !== total) {
    process.stderr.write(
      `\n${label} suite passed ${passed} of ${total} tests; ` +
        'a skipped or todo test is a failure, not a pass\n',
    );
    process.exit(1);
  }
  process.stdout.write(`\n${label} suite: ${passed} of ${total} tests passed, none skipped\n`);
}
