/**
 * The built `falconer` executable, run as a real subprocess (SAFE-01).
 *
 * The suite's global setup builds core and the CLI first, so this runs the
 * current source. Every process starts with `offline-trap.mjs` preloaded,
 * which records and refuses any network request, any socket connection and
 * any read of the environment variables a test names. The records outlive the
 * process, so these checks show that nothing was attempted, not merely that
 * nothing succeeded.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { ACCOUNTS, TARGET } from './fake-ledger.js';
import { CONFIRMED_ROUND, FIXTURE, TXIDS, WHALE_BALANCE } from './fixture-ledger.mjs';

const CLI = fileURLToPath(new URL('../dist/index.js', import.meta.url));
const TRAP = pathToFileURL(fileURLToPath(new URL('./offline-trap.mjs', import.meta.url))).href;

/** The variable a caller would have named with `--mnemonic-env`. */
const PHRASE_VAR = 'FALCONER_SAFE01_PHRASE';
/** Stands in for a recovery phrase. It is not one: no word is in any wordlist. */
const SENTINEL = Array.from({ length: 25 }, (_, i) => `sentinel${i + 1}`).join(' ');
/** Any valid address. Nothing here reads it from a provider. */
const ADDRESS = ACCOUNTS.classical;

const scratch = mkdtempSync(path.join(tmpdir(), 'falconer-cli-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const ANSI = /\u001b\[[0-9;]*m/g;
let runs = 0;

/** Output with wrapping and indentation collapsed, for wrapped statements. */
const flat = (s: string) => s.replace(/\s+/g, ' ');

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  /** Whether any colour escape reached each stream, before stripping. */
  ansi: { stdout: boolean; stderr: boolean };
  /** What the trap recorded: requests, connections, and reads of trapped names. */
  trapped: string[];
}

async function falconer(
  args: string[],
  {
    env = {},
    trapEnv = [],
    fixture = false,
  }: {
    /** Set, or with `undefined` remove, a variable in the child's environment. */
    env?: Record<string, string | undefined>;
    trapEnv?: string[];
    /** Answer provider reads from `fixture-ledger.mjs` (PQ-04). */
    fixture?: boolean;
  } = {},
): Promise<Run> {
  const log = path.join(scratch, `trap-${++runs}.log`);
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NO_COLOR: '1',
    FALCONER_TRAP_LOG: log,
    FALCONER_TRAP_ENV: trapEnv.join(','),
    ...(fixture ? { FALCONER_FIXTURE: '1' } : {}),
  };
  // Nothing the test runner set up may change how Node starts the CLI, or
  // whether it colours its output.
  delete childEnv.NODE_OPTIONS;
  delete childEnv.FORCE_COLOR;
  delete childEnv.TERM;
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) delete childEnv[name];
    else childEnv[name] = value;
  }
  // Asynchronous, so a test can start several at once: each start costs
  // about a second, most of it loading core.
  const res = await new Promise<{ status: number | null; stdout: string; stderr: string }>(
    (resolve, reject) => {
      const child = spawn(process.execPath, ['--import', TRAP, CLI, ...args], {
        env: childEnv,
        timeout: 30_000,
      });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (d: string) => (stdout += d));
      child.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
      child.on('error', reject);
      child.on('close', (status) => resolve({ status, stdout, stderr }));
    },
  );
  return {
    status: res.status,
    stdout: res.stdout.replace(ANSI, ''),
    stderr: res.stderr.replace(ANSI, ''),
    ansi: { stdout: res.stdout.includes('\u001b['), stderr: res.stderr.includes('\u001b[') },
    trapped: existsSync(log)
      ? readFileSync(log, 'utf8').split('\n').filter(Boolean)
      : [],
  };
}

it('runs a build of the current source', () => {
  expect(existsSync(CLI)).toBe(true);
});

describe('the traps are armed', () => {
  it('records the environment reads the CLI does make', async () => {
    // The CLI reads NO_COLOR at startup to choose its output style.
    const r = await falconer(['help'], { trapEnv: ['NO_COLOR'] });
    expect(r.status).toBe(0);
    expect(r.trapped).toContain('env get NO_COLOR');
  });

  const ROUTES: Array<[string, string[], string]> = [
    ['verify on default MainNet', ['verify', ADDRESS], 'https://mainnet-api.algonode.cloud'],
    ['verify on MainNet', ['verify', ADDRESS, '--network', 'mainnet'], 'https://mainnet-api.algonode.cloud'],
    ['verify on TestNet', ['verify', ADDRESS, '-n', 'testnet'], 'https://testnet-api.algonode.cloud'],
    ['verify on LocalNet', ['verify', ADDRESS, '--network', 'localnet'], 'http://localhost:4001'],
    ['scan on default MainNet', ['scan', ADDRESS], 'https://mainnet-api.algonode.cloud'],
    ['plan on TestNet', ['plan', ADDRESS, '--to', TARGET, '-n', 'testnet'], 'https://testnet-api.algonode.cloud'],
  ];

  it.each(ROUTES)('refuses the first read %s makes, a GET to %s', async (_name, args, origin) => {
    const r = await falconer(args);
    // The refused read ends the command, as an unreachable provider would.
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('offline trap: network request refused');
    expect(r.trapped).toEqual([`fetch GET ${origin}/v2/accounts/${ADDRESS}`]);
  });
});

describe('the removed --mnemonic-env option', () => {
  const FORMS: Array<[string, string[]]> = [
    ['--mnemonic-env VAR', ['verify', ADDRESS, '--mnemonic-env', PHRASE_VAR]],
    ['--mnemonic-env=VAR', ['verify', ADDRESS, `--mnemonic-env=${PHRASE_VAR}`]],
    ['before the address', ['verify', '--mnemonic-env', PHRASE_VAR, ADDRESS]],
    ['with its value missing', ['verify', ADDRESS, '--mnemonic-env']],
    ['with --json', ['verify', ADDRESS, '--json', '--mnemonic-env', PHRASE_VAR]],
    ['on explicit MainNet', ['verify', ADDRESS, '--network', 'mainnet', '--mnemonic-env', PHRASE_VAR]],
    ['on TestNet', ['verify', ADDRESS, '-n', 'testnet', '--mnemonic-env', PHRASE_VAR]],
    ['on LocalNet', ['verify', ADDRESS, '--network', 'localnet', '--mnemonic-env', PHRASE_VAR]],
    ['with a phrase passed as its value by mistake', ['verify', ADDRESS, '--mnemonic-env', SENTINEL]],
  ];

  it.each(FORMS)(
    'is refused %s: exit 1, no environment read, no request, nothing echoed',
    async (_name, args) => {
      const r = await falconer(args, {
        env: { [PHRASE_VAR]: SENTINEL },
        trapEnv: [PHRASE_VAR],
      });
      expect(r.status).toBe(1);
      // First what matters: the variable was never read and nothing was sent.
      expect(r.trapped).toEqual([]);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain('verify no longer accepts --mnemonic-env');
      expect(r.stderr).not.toContain(PHRASE_VAR);
      expect(r.stderr).not.toContain('sentinel');
    },
  );
});

describe('help and usage', () => {
  it.each([{ args: ['help'] }, { args: ['--help'] }, { args: ['-h'] }, { args: [] }])(
    'falconer $args prints the usage and exits 0',
    async ({ args }) => {
      const r = await falconer(args);
      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      expect(r.trapped).toEqual([]);
      for (const command of ['scan', 'plan', 'verify', 'inspect', 'keygen']) {
        expect(r.stdout).toMatch(new RegExp(`^\\s+${command}\\s`, 'm'));
      }
      expect(r.stdout).toContain(
        'Read-only on every network, MainNet included: these commands never load',
      );
      expect(r.stdout).toContain('Secret output:');
      expect(r.stdout).toContain('Anyone who reads the output controls the');
      expect(r.stdout).toContain('There is no migrate command.');
      expect(r.stdout).toContain('No Falconer command can check a written-down phrase.');
      expect(r.stdout).toContain('--json prints JSON alone on stdout and overrides --compact');
      // One row per command, each naming what 0 and 2 mean for it.
      for (const row of [
        /^\s+scan\s+0 {2}printed; without --fail-on, whatever it found$/m,
        /^\s+2 {2}--fail-on met, or not evaluable on an incomplete verdict$/m,
        /^\s+verify\s+0 {2}post-quantum authority on a confirmed Falcon-1024 record$/m,
        /^\s+plan\s+0 {2}no blockers, and a budget priced from the network$/m,
        /^\s+2 {2}blocked, or no budget could be priced$/m,
        /^\s+inspect, keygen, help\n\s+0 {2}printed$/m,
        /^\s+any\s+1 {2}usage error, or a failure it could not get past/m,
      ]) {
        expect(r.stdout).toMatch(row);
      }
      expect(r.stdout).not.toContain('--mnemonic-env');
      expect(r.stdout).not.toMatch(/^\s+migrate\s/m);
    },
  );

  const USAGE_ERRORS: Array<[string, string[], string]> = [
    ['migrate, which is not a command', ['migrate', ADDRESS], 'Unknown command "migrate". Run: falconer help'],
    ['verify without an address', ['verify'], 'Usage: falconer verify <address> [-n network] [--compact] [--json]'],
    ['an unknown network', ['verify', ADDRESS, '--network', 'betanet'], 'Unknown network "betanet"'],
    ['an option scan never had', ['scan', ADDRESS, '--mnemonic-env', PHRASE_VAR], "Unknown option '--mnemonic-env'"],
    ['a plan without --to', ['plan', ADDRESS], 'Missing --to <pq-address>'],
    ['a plan whose --to is not an address', ['plan', ADDRESS, '--to', 'nope'], '--to is not a valid Algorand address'],
    ['inspect of an invalid address', ['inspect', 'not-an-address'], 'Not a valid Algorand address'],
    ['verify of an invalid address', ['verify', 'not-an-address'], 'Not a valid Algorand address'],
    ['scan with an unknown threshold', ['scan', ADDRESS, '--fail-on', 'severe'], '--fail-on must be one of'],
    ['scan with a malformed asset list', ['scan', ADDRESS, '--assets', 'seven'], '--assets takes a comma-separated'],
  ];

  // The fixture ledger stands ready to answer, so an empty record shows the
  // input was refused before anything was asked, not that nothing could be.
  it.each(USAGE_ERRORS)('%s exits 1 before any request', async (_name, args, message) => {
    const r = await falconer(args, { fixture: true });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain(`error  ${message}`);
    expect(r.trapped).toEqual([]);
  });

  it('inspect runs offline, exits 0 for either shape, and calls neither a verdict', async () => {
    const [on, off] = await Promise.all([
      falconer(['inspect', ADDRESS]),
      falconer(['inspect', FIXTURE.multisig]),
    ]);
    for (const r of [on, off]) {
      expect(r.status).toBe(0);
      expect(r.trapped).toEqual([]);
    }
    expect(on.stdout).toContain('on-curve');
    // Off the curve rules out a bare key, not a multisig.
    expect(flat(off.stdout)).toContain(
      'off-curve hash-derived: a post-quantum, multisig, logic-signature or application address',
    );
  });
});

/**
 * The built executable against the fixed ledger in `fixture-ledger.mjs`
 * (PQ-04): the exits, labels and output a pipeline sees, through algosdk's
 * own decoding of the provider's JSON. Each read it answers is recorded as
 * `fixture GET`; anything else is still recorded and refused.
 */
describe.concurrent('against a fixed ledger', () => {
  const fx = (args: string[], options: Parameters<typeof falconer>[1] = {}) =>
    falconer([...args, '-n', 'localnet'], { ...options, fixture: true });
  /** Everything the run asked for, the fixture answered, and all of it was a read. */
  const onlyServedReads = (r: Run) => {
    expect(r.trapped.length).toBeGreaterThan(0);
    expect(r.trapped.filter((t) => !t.startsWith('fixture GET '))).toEqual([]);
  };

  // [case, account, verify exit, authorityClass, the one label every view prints]
  const CLASSES: Array<[string, string, 0 | 2, string, string]> = [
    ['post-quantum', FIXTURE.postQuantum, 0, 'post-quantum', 'post-quantum, on a provider-confirmed record'],
    ['classical by shape', FIXTURE.classical, 2, 'classical-key', 'classical, by address shape: on the Ed25519 curve'],
    ['a multisig record', FIXTURE.multisig, 2, 'classical-multisig', 'classical multisignature, on a provider-confirmed record'],
    ['a logic-signature record', FIXTURE.logicsig, 2, 'logicsig', 'logic signature, safety unproven'],
    ['no record', FIXTURE.unconfirmed, 2, 'unknown-hash-derived', 'hash-derived, type unconfirmed'],
    ['only a rejected record', FIXTURE.rejected, 2, 'unknown-hash-derived', 'hash-derived, a record rejected'],
    ['an unavailable history', FIXTURE.unavailable, 2, 'unknown-hash-derived', 'could not be checked'],
    // Through a real client an unusable list fails to decode: still never an empty history.
    ['a malformed history', FIXTURE.malformed, 2, 'unknown-hash-derived', 'could not be checked'],
  ];

  it.each(CLASSES)('%s: one verdict and one label in every mode', async (_name, account, exit, authorityClass, label) => {
    const [full, compact, json, scan, scanCompact] = await Promise.all([
      fx(['verify', account]),
      fx(['verify', account, '--compact']),
      fx(['verify', account, '--json']),
      fx(['scan', account]),
      fx(['scan', account, '--compact']),
    ]);
    for (const r of [full, compact, json]) {
      expect(r.status).toBe(exit);
      expect(r.stderr).toBe('');
      onlyServedReads(r);
    }
    expect(flat(full.stdout)).toContain(`${account} ${label}`);
    expect(flat(compact.stdout)).toContain(`authority ${label}`);
    expect(compact.stdout).toContain(
      exit === 0 ? '✔ post-quantum, on a provider-confirmed record' : '✖ not established as post-quantum',
    );
    expect(JSON.parse(json.stdout)).toMatchObject({
      address: account,
      authorityClass,
      quantumSafe: exit === 0,
      evidenceUnavailable: label === 'could not be checked',
    });
    // scan states the same label, and without --fail-on exits 0 whatever it found.
    for (const r of [scan, scanCompact]) {
      expect(r.status).toBe(0);
      expect(flat(r.stdout)).toContain(`authority ${label}`);
    }
  });

  // CORE-04: an account read that fails, or answers with a record the ledger
  // could not hold, used to be read as an empty account and judged clean.
  it.each([
    ['answered 404', FIXTURE.accountMissing, 'no accounts found for address'],
    ['answered with holdings short of their total', FIXTURE.accountUnusable, 'unusable account record (malformed account asset holdings)'],
  ])('refuses an account read %s in every command that reads it', async (_name, account, reason) => {
    const runs = await Promise.all([
      fx(['scan', account]),
      fx(['scan', account, '--json']),
      fx(['scan', account, '--compact', '--fail-on', 'critical']),
      fx(['plan', account, '--to', FIXTURE.target]),
      fx(['plan', account, '--to', FIXTURE.target, '--json']),
      fx(['verify', account, '--json']),
    ]);
    for (const r of runs) {
      expect(r.status).toBe(1);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain(reason);
      onlyServedReads(r);
    }
  });

  it('names a refused record as rejected, never as evidence', async () => {
    const [compact, full] = await Promise.all([
      fx(['verify', FIXTURE.rejected, '--compact']),
      fx(['verify', FIXTURE.rejected]),
    ]);
    expect(compact.stdout).toContain(`rejected   tx/${TXIDS.rejected.slice(0, 36)}...`);
    expect(compact.stdout).not.toMatch(/^\s+evidence\s/m);
    expect(full.stdout).toContain(`rejected  ${TXIDS.rejected}`);
  });

  it('compact keeps every qualification, however many lines they take', async () => {
    const [r, verify] = await Promise.all([
      fx(['scan', FIXTURE.brokenSearch, '--compact']),
      fx(['verify', FIXTURE.brokenSearch, '--compact']),
    ]);
    expect(r.status).toBe(0);
    for (const notice of [
      'signs for at least 1 (1 not post-quantum), search incomplete',
      'risk 40+/100 Elevated exposure, at least',
      'coverage incomplete: rekeyed to it partial',
      'At least 1 account rekeyed to this address is signed for by the key behind it',
      'Not established: the search for accounts rekeyed to this address failed after 1 were found. This is not a safe verdict.',
    ]) {
      expect(flat(r.stdout)).toContain(notice);
    }
    // verify's verdict is this account's own; the floor is stated beside it.
    expect(verify.status).toBe(2);
    expect(flat(verify.stdout)).toContain('At least 1 account rekeyed to this address');
  });

  // [case, account, threshold, exit, what stderr says]
  const GATE: Array<[string, string, string, 0 | 2, string]> = [
    ['complete and under it', FIXTURE.classical, 'critical', 0, ''],
    ['complete and at it', FIXTURE.classical, 'elevated', 2, 'Exposure elevated meets or exceeds elevated.'],
    ['incomplete and under it', FIXTURE.brokenSearch, 'critical', 2, 'Exposure could not be evaluated against critical'],
    ['at it as a lower bound', FIXTURE.brokenSearch, 'elevated', 2, 'Exposure elevated (at least) meets or exceeds elevated.'],
    ['an authority not checked', FIXTURE.unavailable, 'critical', 2, 'Exposure could not be evaluated against critical'],
  ];

  it.each(GATE)('--fail-on, %s: the same exit in every mode', async (_name, account, threshold, exit, message) => {
    const modes = [[], ['--compact'], ['--json']];
    const results = await Promise.all(modes.map((mode) => fx(['scan', account, ...mode, '--fail-on', threshold])));
    for (const [i, r] of results.entries()) {
      expect(r.status).toBe(exit);
      if (message) expect(flat(r.stderr)).toContain(message);
      else expect(r.stderr).toBe('');
      // The gate notice stays on stderr, so JSON stays parseable.
      if (modes[i]![0] === '--json') expect(JSON.parse(r.stdout).address).toBe(account);
    }
  });

  it('writes every big integer as an exact decimal string', async () => {
    const [scanRun, verifyRun] = await Promise.all([
      fx(['scan', FIXTURE.whale, '--json']),
      fx(['verify', FIXTURE.postQuantum, '--json']),
    ]);
    // 2^53 + 1: a JSON number would already have rounded it.
    expect(JSON.parse(scanRun.stdout).microAlgos).toBe(String(WHALE_BALANCE));
    expect(JSON.parse(verifyRun.stdout).evidence).toMatchObject({
      txId: TXIDS.postQuantum,
      confirmedRound: String(CONFIRMED_ROUND),
      guarantees: { independentSignatureVerification: false },
    });
  });

  it.each([['scan'], ['verify']])('%s --json overrides --compact, in either order', async (command) => {
    const orders = [['--json', '--compact'], ['--compact', '--json']];
    for (const r of await Promise.all(orders.map((flags) => fx([command, FIXTURE.postQuantum, ...flags])))) {
      expect(r.status).toBe(0);
      expect(r.stdout.trimStart()[0]).toBe('{');
      expect(JSON.parse(r.stdout).address).toBe(FIXTURE.postQuantum);
    }
  });

  // [case, environment, whether colour is written]
  const COLOUR: Array<[string, Record<string, string | undefined>, boolean]> = [
    ['nothing set, piped', { NO_COLOR: undefined }, false],
    ['NO_COLOR', { NO_COLOR: '1' }, false],
    ['FORCE_COLOR', { NO_COLOR: undefined, FORCE_COLOR: '1' }, true],
    ['NO_COLOR over FORCE_COLOR', { NO_COLOR: '1', FORCE_COLOR: '1' }, false],
    ['FORCE_COLOR=0', { NO_COLOR: undefined, FORCE_COLOR: '0' }, false],
    ['TERM=dumb over FORCE_COLOR', { NO_COLOR: undefined, FORCE_COLOR: '1', TERM: 'dumb' }, false],
  ];

  it.each(COLOUR)('colour, %s', async (_name, env, coloured) => {
    const [r, json] = await Promise.all([
      fx(['scan', FIXTURE.classical, '--compact', '--fail-on', 'elevated'], { env }),
      fx(['scan', FIXTURE.classical, '--json', '--fail-on', 'elevated'], { env }),
    ]);
    expect(r.status).toBe(2);
    expect(r.ansi).toEqual({ stdout: coloured, stderr: coloured });
    // JSON is never coloured, and its notice follows stderr's setting.
    expect(json.ansi).toEqual({ stdout: false, stderr: coloured });
    expect(JSON.parse(json.stdout).address).toBe(FIXTURE.classical);
  });

  it('plan exits 2 when no budget can be priced, having only read', async () => {
    const [human, json] = await Promise.all([
      fx(['plan', FIXTURE.classical, '--to', FIXTURE.target]),
      fx(['plan', FIXTURE.classical, '--to', FIXTURE.target, '--json']),
    ]);
    expect(JSON.parse(json.stdout).budget.status).toBe('unavailable');
    expect(flat(human.stdout)).toContain("no budget The budget's inputs could not be read");
    for (const r of [human, json]) {
      expect(r.status).toBe(2);
      // The fixture serves no network parameters, so those reads were
      // refused; nothing else was asked for, and nothing was sent.
      expect(r.trapped.filter((t) => !t.startsWith('fixture GET ')).sort()).toEqual([
        'fetch GET http://localhost:4001/v2/status',
        'fetch GET http://localhost:4001/v2/transactions/params',
      ]);
    }
  });
});

/**
 * The README's recording is made from the demo's fixture mode, so it is
 * reproducible byte for byte. This fails whenever the CLI's output moves on
 * and the recording has not been made again with `npm run record` (PQ-04).
 */
it('the committed recording is what the fixture demo prints now', async () => {
  const RECORD = fileURLToPath(new URL('../../../scripts/record-demo.mjs', import.meta.url));
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const r = await new Promise<{ status: number | null; output: string }>((resolve, reject) => {
    const child = spawn(process.execPath, [RECORD, '--check'], { env, timeout: 60_000 });
    let output = '';
    child.stdout.on('data', (d) => (output += d));
    child.stderr.on('data', (d) => (output += d));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, output }));
  });
  expect(r.output).toContain('match what the demo prints');
  expect(r.status).toBe(0);
});

/**
 * keygen prints a real, if throwaway and unfunded, recovery phrase. These
 * checks assert on it without ever echoing it: a failing assertion reports a
 * label, never the output.
 */
describe('keygen, the one command that prints a secret', () => {
  const expectIn = (text: string, needle: string, label: string) =>
    expect(text.includes(needle), `${label} should include "${needle}"`).toBe(true);

  it('prints the phrase with secret-output guidance, and nothing leaves the process', async () => {
    const r = await falconer(['keygen']);
    expect(r.status, 'keygen exit status').toBe(0);
    expect(r.trapped, 'network and environment traps').toEqual([]);
    expectIn(r.stdout, 'Recovery phrase (25 words, secret)', 'stdout');
    expectIn(r.stdout, 'Anyone who reads it controls the account.', 'stdout');
    expectIn(r.stdout, 'logs, CI output, screenshots and shared terminals.', 'stdout');
    // Only a workflow that exists: no command reads a phrase back (PQ-04).
    expectIn(flat(r.stdout), 'Nothing has checked what you wrote down, and Falconer cannot:', 'stdout');
    expectIn(flat(r.stdout), 'the CLI has no command that reads a phrase back', 'stdout');
    expectIn(flat(r.stdout), 'falconer plan --to reads only', 'stdout');
    expect(flat(r.stdout).includes('type the phrase back'), 'advises a check that does not exist').toBe(false);
  });

  it('--json keeps stdout parseable and warns on stderr, which never carries the phrase', async () => {
    const r = await falconer(['keygen', '--json']);
    expect(r.status, 'keygen --json exit status').toBe(0);
    expect(r.trapped, 'network and environment traps').toEqual([]);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      throw new Error('keygen --json did not print valid JSON (output withheld: it holds a phrase)');
    }
    expect(Object.keys(parsed), 'JSON keys').toEqual(['address', 'salt', 'mnemonic', 'scheme']);
    const phrase = String(parsed.mnemonic);
    expect(phrase.split(' ').length, 'phrase word count').toBe(25);
    expectIn(r.stderr, 'The JSON on stdout contains the recovery phrase', 'stderr');
    expect(r.stderr.includes(phrase), 'stderr carries the phrase').toBe(false);
    expect(
      r.stderr.includes(phrase.split(' ').slice(0, 3).join(' ')),
      'stderr carries part of the phrase',
    ).toBe(false);
  });
});
