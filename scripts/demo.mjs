#!/usr/bin/env node
/**
 * Falconer in two minutes.
 *
 *   npm install && npm run build && npm run demo
 *
 * By default every command runs against a fixed ledger
 * (`packages/cli/test/fixture-ledger.mjs`) with the CLI's offline traps
 * loaded: nothing leaves the machine, and the output is the same on every
 * run, which is what the recording (`npm run record`) is made from. The
 * narration states what that ledger holds, and says it is a fixture.
 *
 * `--live` runs the same commands, read-only, against public MainNet
 * endpoints. The chain can change, so the narration then says only what each
 * command does, never what it will find, and every result is the one
 * observed. `--short` keeps the two beats the recording uses.
 *
 * Each command's exit code is printed with its meaning. A command that fails
 * (exit 1) is reported as a failure, and the demo then exits 1 too.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { devNull } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const short = process.argv.includes('--short');
const live = process.argv.includes('--live');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(root, 'packages', 'cli', 'dist', 'index.js');
const CLI_TEST = path.join(root, 'packages', 'cli', 'test');
const TRAP = pathToFileURL(path.join(CLI_TEST, 'offline-trap.mjs')).href;

const useColor =
  !process.env.NO_COLOR && (!!process.env.FORCE_COLOR || process.stdout.isTTY);
const c = (/** @type {string} */ code) => (/** @type {string} */ s) =>
  useColor ? `\u001b[${code}m${s}\u001b[0m` : s;
const bold = c('1');
const dim = c('2');
const cyan = c('36');
const yellow = c('33');

if (!existsSync(CLI) || !existsSync(path.join(root, 'packages', 'core', 'dist', 'index.js'))) {
  console.error('The CLI is not built yet. Run: npm run build');
  process.exit(1);
}

/**
 * What each mode runs against, and what may be said about it. Only the
 * fixture's contents are known in advance.
 */
const MODE = live
  ? {
      network: 'mainnet',
      banner: ['Live MainNet, read-only. Nothing below needs a key.',
        'Every result is what the chain said just now.'],
      // Public MainNet addresses. What they hold is whatever the chain says.
      manager: '37XL3M57AXBUJARWMT5R7M35OERXMH3Q22JMMEFLBYNDXXADGFN625HAL4',
      asset: '31566704',
      hashed: '2UEQTE5QDNXPI7M3TU44G6SYKLFWLPQO7EBZM7K7MHMQQMFI4QJPLHQFHM',
      scanNote: 'A MainNet account, with USDC (asset 31566704) checked exactly.',
      hashedNote: 'A hash-derived MainNet address.',
    }
  : await (async () => {
      const { FIXTURE, ASSET } = await import(pathToFileURL(path.join(CLI_TEST, 'fixture-ledger.mjs')).href);
      return {
        network: 'localnet',
        banner: ['Fixture ledger: fixed records answering for LocalNet. No node, no',
          'network, not live data. npm run demo -- --live reads MainNet instead.'],
        manager: FIXTURE.manager,
        asset: String(ASSET),
        hashed: FIXTURE.multisig,
        scanNote: `In the fixture this account holds 0.3 ALGO and manages asset ${ASSET}.`,
        hashedNote: 'In the fixture: a 2-of-3 multisig address, with one confirmed record.',
      };
    })();

/** What each exit code of each command means, as `falconer help` states. */
const MEANING = {
  scan: ['report printed', '', 'the --fail-on threshold was met, or could not be evaluated'],
  verify: ['post-quantum authority on a confirmed Falcon-1024 record', '', 'not established as post-quantum'],
  inspect: ['printed'],
};
let failed = false;

/** Wrap a long command the way a shell would, rather than off the edge. */
function commandLines(/** @type {string[]} */ args, /** @type {boolean} */ quiet) {
  const parts = ['falconer', ...args];
  if (quiet) parts.push('>', '/dev/null');
  const width = 84;
  const lines = [];
  let line = '  $ ';
  for (const part of parts) {
    const candidate = line.endsWith('$ ') ? line + part : `${line} ${part}`;
    if (candidate.length > width && !line.trimEnd().endsWith('$')) {
      lines.push(`${line} \\`);
      line = `      ${part}`;
    } else {
      line = candidate;
    }
  }
  lines.push(line);
  return lines;
}

/**
 * Run the real CLI, show its real output, and report its exit code.
 * `quiet` drops stdout and keeps stderr, where the point is the exit code
 * and the gate's notice rather than the report itself.
 */
async function run(/** @type {string[]} */ command, { quiet = false } = {}) {
  // inspect reads no provider, so it is given no network.
  const args = command[0] === 'inspect' ? command : [...command, '--network', MODE.network];
  console.log('');
  for (const line of commandLines(args, quiet)) console.log(cyan(line));
  const code = await new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      live ? [CLI, ...args] : ['--import', TRAP, CLI, ...args],
      {
        stdio: quiet ? ['inherit', 'ignore', 'inherit'] : 'inherit',
        cwd: root,
        env: live
          ? process.env
          : { ...process.env, FALCONER_FIXTURE: '1', FALCONER_TRAP_LOG: devNull },
      },
    );
    child.on('close', (/** @type {number | null} */ status) => resolve(status));
  });
  const meaning =
    code === 1 || code === null
      ? 'the command failed; its error is above'
      : /** @type {Record<string, string[]>} */ (MEANING)[command[0] ?? '']?.[code] ?? 'unexpected';
  if (code !== 0 && code !== 2) failed = true;
  console.log(code === 0 || code === 2 ? dim(`  exit ${code}: ${meaning}`) : yellow(`  exit ${code}: ${meaning}`));
  return code;
}

function beat(/** @type {number} */ n, /** @type {string} */ title, /** @type {string[]} */ why) {
  console.log('');
  console.log(bold('─'.repeat(72)));
  console.log(bold(`  ${n}. ${title}`));
  for (const line of why) console.log(dim(`     ${line}`));
  console.log(bold('─'.repeat(72)));
}

console.log('');
for (const line of MODE.banner) console.log(dim(`  # ${line}`));

if (short) {
  console.log('');
  console.log(dim('  # 1. Authority, not balance: scan reports roles beyond the balance.'));
  console.log(dim(`  # ${MODE.scanNote}`));
  await run(['scan', MODE.manager, '--assets', MODE.asset, '--compact']);
  console.log('');
  console.log(dim('  # 2. Record, not shape: verify names an authority only from a confirmed record.'));
  console.log(dim(`  # ${MODE.hashedNote}`));
  await run(['verify', MODE.hashed, '--compact']);
  console.log('');
  process.exit(failed ? 1 : 0);
}

console.log('');
console.log(bold('  Falconer'));
console.log(dim('  What one Algorand key really controls, and whether it is quantum-safe.'));

beat(1, 'A balance tells you almost nothing', [
  'scan reads the roles an account holds on the assets it is asked',
  'about, whatever its balance.',
  MODE.scanNote,
]);
await run(['scan', MODE.manager, '--assets', MODE.asset]);

beat(2, 'Off-curve is not the same as post-quantum', [
  'An address off the Ed25519 curve is hash-derived, so no bare classical',
  'key can produce it. Multisig and logic-signature addresses are too.',
  MODE.hashedNote,
]);
await run(['inspect', MODE.hashed]);

beat(3, 'The verdict comes from a record, not a shape', [
  'verify reads the confirmed transactions the indexer reports for the',
  'account and names its authority only from one of them, stating the',
  'record and what Falconer checked itself.',
]);
await run(['verify', MODE.hashed]);

beat(4, 'And exposure is gateable too', [
  'scan exits 2 when exposure meets a threshold, or when an incomplete',
  'check means it cannot be evaluated, so a pipeline can fail on it.',
  'Report suppressed here; the point is the exit code.',
]);
await run(['scan', MODE.hashed, '--json', '--fail-on', 'elevated'], { quiet: true });

console.log('');
console.log(bold('─'.repeat(72)));
console.log(bold('  What that showed'));
console.log(dim('   - Authority, not balance: a scan reports what a key can do beyond'));
console.log(dim('     its balance, and states what it searched and what it did not.'));
console.log(dim('   - Evidence, not inference: off-curve rules out a bare key and nothing'));
console.log(dim('     more; an authority is named only from a confirmed record.'));
console.log(dim('   - Exit codes are the contract, per command: see falconer help.'));
console.log('');
console.log(dim('  Migration itself runs against LocalNet and TestNet in the web app'));
console.log(dim('  (npm run dev). MainNet signing belongs in your wallet.'));
console.log(bold('─'.repeat(72)));
console.log('');
process.exit(failed ? 1 : 0);
