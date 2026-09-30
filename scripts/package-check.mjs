#!/usr/bin/env node
/**
 * Packed-artifact check: `npm run test:package`.
 *
 * Builds core and the CLI, packs both into a scratch directory and installs
 * the two tarballs into a fresh consumer outside the workspace, so nothing can
 * resolve through a workspace link. The public npm registry has an unrelated
 * `@falconer/cli`, and any `@falconer` name could resolve there, so the
 * consumer's lockfile must show
 * that each package came from its own tarball and that `falcon-1024` is the
 * locked release whose provenance was checked.
 *
 * In the consumer it then checks that each package ships its README and the
 * project's LICENSE, and nothing outside `dist`; that core imports and signs
 * and verifies with Falcon-1024 in memory, which runs the embedded
 * WebAssembly and prints no key; that the `falconer` bin prints help; and
 * that `verify` passes against the CLI's fixed ledger with its offline traps
 * loaded, which refuse any other request.
 *
 * It prints each tarball's files and SHA-256 and exits 1 on the first
 * failure. Core's dependencies come from the npm cache or registry. The
 * scratch directory is removed on exit.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI_TEST = path.join(ROOT, 'packages', 'cli', 'test');
/** Where each package lives in the workspace. */
const PACKAGES = { '@falconer/core': 'packages/core', '@falconer/cli': 'packages/cli' };
/** Every packed path must be one of these or under `dist/`. */
const ALWAYS = ['package.json', 'README.md', 'LICENSE'];

/** @param {string} message @returns {never} */
function fail(message) {
  process.stderr.write(`\npackage check failed: ${message}\n`);
  process.exit(1);
}

// npm sets this for `npm run`; it is the npm CLI script, run through this Node.
const NPM = process.env.npm_execpath;
if (!NPM) fail('run it through npm: npm run test:package');

const scratch = mkdtempSync(path.join(os.tmpdir(), 'falconer-package-'));
process.on('exit', () => rmSync(scratch, { recursive: true, force: true }));

/**
 * Run a Node script, failing the check if it does not exit 0.
 * @param {string} label @param {string[]} args @param {import('node:child_process').SpawnSyncOptions} [options]
 */
function node(label, args, options = {}) {
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 300_000, ...options });
  if (res.error || res.status !== 0) {
    const tail = `${res.stdout ?? ''}${res.stderr ?? ''}`.trim().split('\n').slice(-15).join('\n');
    fail(`${label} (${res.error?.message ?? res.signal ?? `exit ${res.status}`})\n${tail}`);
  }
  return String(res.stdout);
}
/** @param {string} label @param {string[]} args @param {string} cwd */
const npm = (label, args, cwd) => node(label, [/** @type {string} */ (NPM), ...args], { cwd });

const sha256 = (/** @type {string} */ file) =>
  createHash('sha256').update(readFileSync(file)).digest('hex');
const text = (/** @type {string} */ file) => readFileSync(file, 'utf8').replace(/\r\n/g, '\n');

// 1. Build and pack the current source.
npm('build', ['run', 'build', '-w', '@falconer/core', '-w', '@falconer/cli'], ROOT);
/** @type {Array<{ name: string, filename: string, integrity: string, files: Array<{ path: string }> }>} */
const packed = JSON.parse(
  npm('pack', ['pack', '--json', '--pack-destination', scratch,
    ...Object.keys(PACKAGES).flatMap((name) => ['-w', name])], ROOT),
);

// 2. What each tarball contains.
for (const { name, filename, integrity, files } of packed) {
  const dir = path.join(ROOT, /** @type {string} */ (PACKAGES[/** @type {keyof PACKAGES} */ (name)]));
  const manifest = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const paths = files.map((f) => f.path);
  const entries = [manifest.main, manifest.types, ...Object.values(manifest.bin ?? {})]
    .filter(Boolean)
    .map((p) => path.posix.normalize(p));
  for (const required of [...ALWAYS, ...entries]) {
    if (!paths.includes(required)) fail(`${name} tarball is missing ${required}`);
  }
  for (const p of paths) {
    if (!ALWAYS.includes(p) && !p.startsWith('dist/')) fail(`${name} tarball includes ${p}`);
    // tsc never deletes output, so a build left from a removed source would ship.
    if (p.endsWith('.js') && !existsSync(path.join(dir, 'src', p.slice(5, -3) + '.ts'))) {
      fail(`${name} tarball includes ${p}, which no source file builds`);
    }
  }
  console.log(`${filename}: ${paths.length} files, sha256 ${sha256(path.join(scratch, filename))}`);
  console.log(`  ${integrity}`);
  console.log(`  ${paths.sort().join(' ')}`);
}

// 3. A fresh consumer outside the workspace installs both tarballs.
const consumer = path.join(scratch, 'consumer');
mkdirSync(consumer);
writeFileSync(
  path.join(consumer, 'package.json'),
  JSON.stringify({ name: 'falconer-package-check', private: true, type: 'module' }),
);
npm('consumer install', ['install', '--no-audit', '--no-fund', '--prefer-offline',
  ...packed.map((p) => path.join(scratch, p.filename))], consumer);

/** @type {{ packages: Record<string, { resolved?: string, integrity?: string, link?: boolean, version?: string }> }} */
const lock = JSON.parse(readFileSync(path.join(consumer, 'package-lock.json'), 'utf8'));
const copies = (/** @type {string} */ name) =>
  Object.keys(lock.packages).filter((k) => k === `node_modules/${name}` || k.endsWith(`/node_modules/${name}`));

for (const { name, filename, integrity } of packed) {
  const entry = lock.packages[`node_modules/${name}`];
  if (!entry || entry.link || entry.integrity !== integrity || !entry.resolved?.startsWith('file:')
    || !entry.resolved.endsWith(filename)) {
    fail(`${name} was not installed from ${filename}: ${JSON.stringify(entry)}`);
  }
  if (copies(name).length !== 1) fail(`${name} is installed more than once: ${copies(name).join(', ')}`);
  const installed = path.join(consumer, 'node_modules', ...name.split('/'));
  if (lstatSync(installed).isSymbolicLink()) fail(`${name} is a link, not an installed copy`);
  for (const doc of ['README.md', 'LICENSE']) {
    if (!existsSync(path.join(installed, doc))) fail(`installed ${name} has no ${doc}`);
  }
  if (text(path.join(installed, 'LICENSE')) !== text(path.join(ROOT, 'LICENSE'))) {
    fail(`installed ${name} LICENSE differs from the project LICENSE`);
  }
}

/** @type {{ packages: Record<string, { integrity?: string }> }} */
const workspaceLock = JSON.parse(readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
const falcon = lock.packages['node_modules/falcon-1024'];
const lockedFalcon = workspaceLock.packages['node_modules/falcon-1024'];
if (copies('falcon-1024').length !== 1 || !falcon || falcon.integrity !== lockedFalcon?.integrity) {
  fail(`falcon-1024 in the consumer is not the workspace's locked release: ${JSON.stringify(falcon)}`);
}
console.log(`consumer: both packages from their tarballs; falcon-1024 ${falcon.version} ${falcon.integrity}`);

// 4. Core runs from the consumer: Falcon-1024 through the embedded WebAssembly.
const probe = `
import { classifyAddressShape, generatePqIdentity, selfTestIdentity } from '@falconer/core';
const a = generatePqIdentity();
const b = generatePqIdentity();
console.log(JSON.stringify({
  core: import.meta.resolve('@falconer/core'),
  falcon: import.meta.resolve('falcon-1024'),
  shape: classifyAddressShape(a.address),
  signs: selfTestIdentity(a),
  rejectsOtherKey: !selfTestIdentity({ ...a, publicKey: b.publicKey }),
}));`;
const core = JSON.parse(node('core import', ['--input-type=module', '-e', probe], { cwd: consumer }));
const within = (/** @type {string} */ url, /** @type {string} */ name) =>
  realpathSync(fileURLToPath(url)).startsWith(
    realpathSync(path.join(consumer, 'node_modules', ...name.split('/'))) + path.sep,
  );
if (!within(core.core, '@falconer/core') || !within(core.falcon, 'falcon-1024')) {
  fail(`core or falcon-1024 did not load from the consumer: ${core.core} ${core.falcon}`);
}
if (core.shape !== 'off-curve' || core.signs !== true || core.rejectsOtherKey !== true) {
  fail(`Falcon round trip: ${JSON.stringify({ ...core, core: undefined, falcon: undefined })}`);
}
console.log('core: imported; a Falcon-1024 key signs and verifies, and another key is rejected');

// 5. The CLI's bin, and a fixed-ledger command with the offline traps loaded.
const cliDir = path.join(consumer, 'node_modules', '@falconer', 'cli');
const bin = path.join(cliDir, JSON.parse(readFileSync(path.join(cliDir, 'package.json'), 'utf8')).bin.falconer);
if (!existsSync(path.join(consumer, 'node_modules', '.bin', 'falconer'))) fail('npm linked no falconer bin');
if (!readFileSync(bin, 'utf8').startsWith('#!/usr/bin/env node\n')) fail('the falconer bin has no node shebang');
if (!node('falconer help', [bin, 'help'], { cwd: consumer }).includes('falconer - post-quantum readiness')) {
  fail('falconer help did not print the command reference');
}

for (const file of ['offline-trap.mjs', 'fixture-ledger.mjs']) {
  copyFileSync(path.join(CLI_TEST, file), path.join(consumer, file));
}
// The consumer's copy, so the ledger itself imports the installed core.
const { FIXTURE } = await import(pathToFileURL(path.join(consumer, 'fixture-ledger.mjs')).href);
const trapLog = path.join(consumer, 'trap.log');
/** @type {NodeJS.ProcessEnv} */
const env = { ...process.env, NO_COLOR: '1', FALCONER_FIXTURE: '1', FALCONER_TRAP_LOG: trapLog };
delete env.NODE_OPTIONS;
const verdict = JSON.parse(node('falconer verify on the fixed ledger', [
  '--import', pathToFileURL(path.join(consumer, 'offline-trap.mjs')).href,
  bin, 'verify', FIXTURE.postQuantum, '--network', 'localnet', '--json',
], { cwd: consumer, env }));
const trapped = existsSync(trapLog) ? text(trapLog).split('\n').filter(Boolean) : [];
if (verdict.quantumSafe !== true || verdict.proven !== true) {
  fail(`verify did not establish the fixture's post-quantum authority: ${JSON.stringify(verdict)}`);
}
if (trapped.length === 0 || !trapped.every((line) => line.startsWith('fixture GET '))) {
  fail(`the traps recorded more than fixture reads: ${trapped.join('; ')}`);
}
console.log(`cli: help printed; verify exit 0 on the fixed ledger, ${trapped.length} fixture reads, nothing else`);
console.log('\npackage check passed');
