/**
 * The CLI's command dispatch and option parsing, run in-process (SAFE-01).
 *
 * `verify --mnemonic-env` used to load a Falcon recovery phrase and submit a
 * signed transaction through `verifyMigration`, on default MainNet included.
 * These tests drive `run()` exactly as the executable does, against a
 * deterministic offline ledger, with every path the CLI must never take
 * replaced by a trap:
 *
 * - recovery-phrase access: reads of an environment variable holding a
 *   stand-in phrase, recorded through a proxy on `process.env`;
 * - identity recovery, creation and signing: core's entry points for them;
 * - submission: every provider method the ledger does not answer, and any
 *   network request at all.
 *
 * Public inspection has to succeed with all of those forbidden.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SCORE_SCOPE } from '../../core/src/coverage.js';
import { formatAlgos } from '../../core/src/exposure.js';
import { NETWORKS } from '../../core/src/networks.js';
import {
  ACCOUNTS,
  APP_REF,
  BROKEN_ASSET,
  MALFORMED_APP,
  MALFORMED_ASSET,
  MISSING_ASSET,
  CONFIRMED_ROUND,
  MANAGED_ASSET,
  WRONG_ID_ASSET,
  LOGICSIG_TXID,
  MULTISIG_TXID,
  PQ_EVIDENCE_TXID,
  PROVIDER_ROUND,
  REJECTED_TXID,
  TARGET,
  fakeClientsFor,
  forbidden,
  reads,
  requested,
  resetRecords,
  trapped,
  type NetworkName,
} from './fake-ledger.js';

vi.mock('@falqoner/core', async (importOriginal) => {
  const real = await importOriginal<Record<string, unknown>>();
  const ledger = await import('./fake-ledger.js');
  const traps: Record<string, unknown> = {};
  for (const name of ledger.FORBIDDEN_CORE) {
    // A trap for a name core no longer exports would guard nothing.
    if (typeof real[name] !== 'function') {
      throw new Error(`@falqoner/core no longer exports ${name}; update FORBIDDEN_CORE`);
    }
    traps[name] = ledger.forbidden(`core.${name}`);
  }
  return { ...real, ...traps, clientsFor: ledger.fakeClientsFor };
});

import { run } from '../src/cli.js';

/** The variable a caller would have named with `--mnemonic-env`. */
const PHRASE_VAR = 'FALCONER_SAFE01_PHRASE';
/** Stands in for a recovery phrase. It is not one: no word is in any wordlist. */
const SENTINEL = Array.from({ length: 25 }, (_, i) => `sentinel${i + 1}`).join(' ');

const realEnv = process.env;
/** Reads of PHRASE_VAR made while the CLI was running. */
let envReads: string[] = [];
let armed = false;
/** Set by the tests that fire a trap on purpose, to show it is armed. */
let firesTraps = false;

beforeEach(() => {
  resetRecords();
  envReads = [];
  firesTraps = false;
  const note = (kind: string, prop: string | symbol) => {
    if (armed && prop === PHRASE_VAR) envReads.push(kind);
  };
  process.env = new Proxy(
    { ...realEnv, [PHRASE_VAR]: SENTINEL },
    {
      get(target, prop, receiver) {
        note('get', prop);
        return Reflect.get(target, prop, receiver);
      },
      has(target, prop) {
        note('has', prop);
        return Reflect.has(target, prop);
      },
      getOwnPropertyDescriptor(target, prop) {
        note('descriptor', prop);
        return Reflect.getOwnPropertyDescriptor(target, prop);
      },
    },
  );
  // The fake ledger replaces the transport, so any real request is a bug.
  vi.stubGlobal('fetch', forbidden('fetch'));
});

afterEach(() => {
  process.env = realEnv;
  vi.unstubAllGlobals();
  // Whatever else a test checks, no trap may have fired during it.
  if (!firesTraps) {
    expect(trapped, 'forbidden calls').toEqual([]);
    expect(envReads, 'reads of the phrase variable').toEqual([]);
  }
});

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

const ANSI = /\u001b\[[0-9;]*m/g;

/** Run one command line through `run()`, capturing everything it prints. */
async function cli(...argv: string[]): Promise<CliResult> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const text = (parts: unknown[]) => parts.map(String).join(' ');
  const log = vi
    .spyOn(console, 'log')
    .mockImplementation((...parts: unknown[]) => void stdout.push(text(parts)));
  const error = vi
    .spyOn(console, 'error')
    .mockImplementation((...parts: unknown[]) => void stderr.push(text(parts)));
  const write = vi
    .spyOn(process.stderr, 'write')
    .mockImplementation((chunk: unknown) => (stderr.push(String(chunk)), true));
  armed = true;
  try {
    const code = await run(argv);
    return {
      code,
      stdout: stdout.join('\n').replace(ANSI, ''),
      stderr: stderr.join('\n').replace(ANSI, ''),
    };
  } finally {
    armed = false;
    log.mockRestore();
    error.mockRestore();
    write.mockRestore();
  }
}

/** Output with wrapping and indentation collapsed, for wrapped statements. */
const flat = (s: string) => s.replace(/\s+/g, ' ');

/**
 * Nothing forbidden ran: no trap fired, the phrase variable was never read,
 * and no output carries the phrase.
 */
function expectNothingForbidden(r: CliResult): void {
  expect(trapped).toEqual([]);
  expect(envReads).toEqual([]);
  expect(`${r.stdout}\n${r.stderr}`).not.toContain('sentinel');
}

/* ---------------------------------------------------------------- */

describe('the traps are armed', () => {
  // Without these, a passing read-only test could mean a trap was never wired.
  beforeEach(() => {
    firesTraps = true;
  });

  it('records a read of the phrase variable', () => {
    armed = true;
    try {
      void process.env[PHRASE_VAR];
    } finally {
      armed = false;
    }
    expect(envReads).toEqual(['get']);
  });

  it('refuses the identity creation keygen needs, in-process', async () => {
    const r = await cli('keygen');
    expect(r.code).toBe(1);
    expect(trapped).toEqual(['core.generatePqIdentity']);
    expect(r.stdout).toBe('');
  });

  it('refuses a submission to the fake provider', () => {
    const clients = fakeClientsFor('mainnet');
    const algod = clients.algod as unknown as Record<string, (...a: unknown[]) => unknown>;
    expect(() => algod.sendRawTransaction!(new Uint8Array(1))).toThrow('read-only trap');
    expect(() => algod.simulateTransactions!(new Uint8Array(1))).toThrow('read-only trap');
    expect(trapped).toEqual([
      'mainnet algod.sendRawTransaction',
      'mainnet algod.simulateTransactions',
    ]);
  });

  it('refuses any network request', () => {
    expect(() => fetch('https://mainnet-api.algonode.cloud/v2/status')).toThrow(
      'read-only trap',
    );
    expect(trapped).toEqual(['fetch']);
  });
});

describe('public inspection is read-only on every supported network', () => {
  const NETWORK_FLAGS: Array<[string, string[], NetworkName]> = [
    ['default MainNet', [], 'mainnet'],
    ['--network mainnet', ['--network', 'mainnet'], 'mainnet'],
    ['-n MainNet', ['-n', 'MainNet'], 'mainnet'],
    ['--network testnet', ['--network', 'testnet'], 'testnet'],
    ['-n localnet', ['-n', 'localnet'], 'localnet'],
  ];

  describe.each(NETWORK_FLAGS)('%s', (_name, flags, network) => {
    /** The CLI asked for this network once, and read only from it. */
    function expectReadsOn(): void {
      expect(requested).toEqual([network]);
      expect(reads.length).toBeGreaterThan(0);
      for (const read of reads) expect(read.startsWith(`${network} `)).toBe(true);
    }

    it('verify establishes post-quantum authority from the record and exits 0', async () => {
      const r = await cli('verify', ACCOUNTS.postQuantum, ...flags);
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(r.stdout).toContain(
        `  ${ACCOUNTS.postQuantum}
  post-quantum, on a provider-confirmed record via`,
      );
      expect(flat(r.stdout)).toContain(
        `The ${network} indexer reported confirmed transaction ${PQ_EVIDENCE_TXID}`,
      );
    });

    it('verify --compact states the provider basis', async () => {
      const r = await cli('verify', ACCOUNTS.postQuantum, '--compact', ...flags);
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(r.stdout).toContain('✔ post-quantum, on a provider-confirmed record');
      expect(flat(r.stdout)).toContain(
        `basis confirmed record ${PQ_EVIDENCE_TXID} in round ${CONFIRMED_ROUND}, ` +
          `reported by the ${network} indexer; address binding checked locally; ` +
          'signature bytes not verified by Falconer',
      );
    });

    it('verify --json names the provider it read', async () => {
      const r = await cli('verify', ACCOUNTS.postQuantum, '--json', ...flags);
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(JSON.parse(r.stdout).evidence.provider).toEqual({
        network,
        indexer: NETWORKS[network].indexerUrl,
      });
    });

    it('verify exits 2 for a classical account', async () => {
      const r = await cli('verify', ACCOUNTS.classical, ...flags);
      expect(r.code).toBe(2);
      expectReadsOn();
      expectNothingForbidden(r);
    });

    it('scan maps the account and exits 0', async () => {
      const r = await cli(
        'scan',
        ACCOUNTS.classical,
        '--assets',
        String(MANAGED_ASSET),
        ...flags,
      );
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(reads).toContain(`${network} getAssetByID ${MANAGED_ASSET}`);
      expect(r.stdout).toContain(ACCOUNTS.classical);
    });

    it('scan --compact states the basis of a record-based verdict', async () => {
      const r = await cli('scan', ACCOUNTS.postQuantum, '--compact', ...flags);
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(flat(r.stdout)).toContain(
        `basis ${network} indexer record, round ${CONFIRMED_ROUND}; address ` +
          'binding checked locally; signature not verified by Falconer',
      );
    });

    it('plan reads the account, sends nothing and exits 0', async () => {
      const r = await cli('plan', ACCOUNTS.classical, '--to', TARGET, ...flags);
      expect(r.code).toBe(0);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(r.stdout).toContain('Migration plan');
    });

    it('plan --json exits 2 on a blocked plan', async () => {
      // A target on the curve is not a post-quantum address.
      const r = await cli('plan', ACCOUNTS.classical, '--to', ACCOUNTS.postQuantum, '--json', ...flags);
      expect(r.code).toBe(2);
      expectReadsOn();
      expectNothingForbidden(r);
      expect(JSON.parse(r.stdout).blockers.length).toBeGreaterThan(0);
    });

    it('verify refuses --mnemonic-env before reading the phrase or contacting a provider', async () => {
      const r = await cli('verify', ACCOUNTS.postQuantum, ...flags, '--mnemonic-env', PHRASE_VAR);
      expect(r.code).toBe(1);
      expectNothingForbidden(r);
      expect(requested).toEqual([]);
      expect(reads).toEqual([]);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain('verify no longer accepts --mnemonic-env');
      expect(r.stderr).not.toContain(PHRASE_VAR);
    });
  });

  it('inspect answers from the address alone and creates no provider clients', async () => {
    const r = await cli('inspect', ACCOUNTS.classical);
    expect(r.code).toBe(0);
    expect(requested).toEqual([]);
    expect(reads).toEqual([]);
    expectNothingForbidden(r);
    expect(r.stdout).toContain('on-curve');
  });
});

describe('verify exits on the evidence, in every output mode', () => {
  const CASES: Array<{
    name: string;
    account: string;
    exit: 0 | 2;
    authorityClass: string;
    /** The shared label every view prints for it (PQ-04). */
    label: string;
    evidence: Record<string, unknown>;
    basis: string;
  }> = [
    {
      name: 'post-quantum authority on a confirmed record',
      account: ACCOUNTS.postQuantum,
      exit: 0,
      authorityClass: 'post-quantum',
      label: 'post-quantum, on a provider-confirmed record',
      evidence: { basis: 'provider-record', lookup: 'found', txId: PQ_EVIDENCE_TXID },
      basis:
        `confirmed record ${PQ_EVIDENCE_TXID} in round ${CONFIRMED_ROUND}, reported ` +
        'by the mainnet indexer; address binding checked locally; signature ' +
        'bytes not verified by Falconer',
    },
    {
      name: 'a classical authority, by address shape',
      account: ACCOUNTS.classical,
      exit: 2,
      authorityClass: 'classical-key',
      // The shape establishes exposure, never a single Ed25519 key.
      label: 'classical, by address shape: on the Ed25519 curve',
      evidence: { basis: 'address-shape', lookup: 'not-needed' },
      basis:
        'address shape: on the Ed25519 curve, so a classical key can authorise ' +
        'it; the account type was not observed',
    },
    {
      name: 'a classical multisig, on a confirmed record',
      account: ACCOUNTS.multisig,
      exit: 2,
      authorityClass: 'classical-multisig',
      label: 'classical multisignature, on a provider-confirmed record',
      evidence: { basis: 'provider-record', lookup: 'found', txId: MULTISIG_TXID },
      basis:
        `confirmed record ${MULTISIG_TXID} in round ${CONFIRMED_ROUND}, reported ` +
        'by the mainnet indexer; signature bytes not verified by Falconer',
    },
    {
      name: 'a logic signature, on a confirmed record',
      account: ACCOUNTS.logicsig,
      exit: 2,
      authorityClass: 'logicsig',
      label: 'logic signature, safety unproven',
      evidence: { basis: 'provider-record', lookup: 'found', txId: LOGICSIG_TXID },
      basis:
        `confirmed record ${LOGICSIG_TXID} in round ${CONFIRMED_ROUND}, reported ` +
        'by the mainnet indexer; signature bytes not verified by Falconer',
    },
    {
      name: 'a hash-derived authority with no record',
      account: ACCOUNTS.unconfirmed,
      exit: 2,
      authorityClass: 'unknown-hash-derived',
      label: 'hash-derived, type unconfirmed',
      evidence: { basis: 'none', lookup: 'none-found', rejected: [] },
      basis: 'no acceptable record found',
    },
    {
      name: 'only a record in a scheme Falconer does not support',
      account: ACCOUNTS.rejected,
      exit: 2,
      authorityClass: 'unknown-hash-derived',
      label: 'hash-derived, a record rejected',
      evidence: {
        basis: 'none',
        lookup: 'none-found',
        rejected: [{ txId: REJECTED_TXID, reason: 'unsupported-scheme' }],
      },
      basis: 'no acceptable record found; 1 record rejected (unsupported-scheme)',
    },
    {
      name: 'a malformed provider response',
      account: ACCOUNTS.malformed,
      exit: 2,
      authorityClass: 'unknown-hash-derived',
      label: 'could not be checked',
      evidence: {
        basis: 'none',
        lookup: 'invalid-response',
        responseFault: 'malformed-transaction-list',
      },
      basis:
        'no evidence: the provider returned a malformed response ' +
        '(malformed-transaction-list)',
    },
    {
      name: 'an unavailable provider',
      account: ACCOUNTS.unavailable,
      exit: 2,
      authorityClass: 'unknown-hash-derived',
      label: 'could not be checked',
      evidence: { basis: 'none', lookup: 'unavailable' },
      basis: 'no evidence: transaction history could not be read',
    },
  ];

  describe.each(CASES)('$name', ({ account, exit, authorityClass, label, evidence, basis }) => {
    it(`exits ${exit} in the full view, with the shared label`, async () => {
      const r = await cli('verify', account);
      expect(r.code).toBe(exit);
      expectNothingForbidden(r);
      expect(r.stdout).toContain(`  ${account}\n  ${label}`);
    });

    it(`exits ${exit} in compact output, stating the label and basis`, async () => {
      const r = await cli('verify', account, '--compact');
      expect(r.code).toBe(exit);
      expectNothingForbidden(r);
      expect(flat(r.stdout)).toContain(`authority ${label}`);
      expect(flat(r.stdout)).toContain(`basis ${basis}`);
      // A record the verdict refused is never presented as its evidence.
      if (evidence.basis !== 'provider-record') expect(r.stdout).not.toMatch(/^\s+evidence\s/m);
      expect(r.stdout).toContain(
        exit === 0
          ? '✔ post-quantum, on a provider-confirmed record'
          : '✖ not established as post-quantum',
      );
    });

    it('prints the same label in scan, full and compact', async () => {
      for (const mode of [[], ['--compact']]) {
        const r = await cli('scan', account, ...mode);
        expect(r.code).toBe(0);
        expect(flat(r.stdout)).toContain(`authority ${label}`);
      }
    });

    it(`exits ${exit} in JSON, with the evidence behind the verdict`, async () => {
      const r = await cli('verify', account, '--json');
      expect(r.code).toBe(exit);
      expectNothingForbidden(r);
      const json = JSON.parse(r.stdout);
      expect(json.authorityClass).toBe(authorityClass);
      expect(json.quantumSafe).toBe(exit === 0);
      expect(json.evidence).toMatchObject(evidence);
      expect(json.evidence.guarantees.independentSignatureVerification).toBe(false);
    });
  });

  it('names no Ed25519 private key for a hash-derived address that signs for itself', async () => {
    for (const account of [ACCOUNTS.multisig, ACCOUNTS.logicsig]) {
      const r = await cli('scan', account);
      expect(r.stdout).toContain('Balance held under an authority not established as post-quantum');
      expect(r.stdout).not.toContain('Ed25519 private key');
    }
    // An on-curve address signing for itself does have one.
    expect(flat((await cli('scan', ACCOUNTS.classical)).stdout)).toContain(
      "Balance held under a classical key 5 ALGO is spendable by whoever holds this account's Ed25519 private key",
    );
  });

  it('keeps the JSON shape, with bigints as strings', async () => {
    const r = await cli('verify', ACCOUNTS.postQuantum, '--json');
    const json = JSON.parse(r.stdout);
    expect(Object.keys(json)).toEqual([
      'address',
      'authAddr',
      'authorityClass',
      'quantumSafe',
      'proven',
      'basis',
      'evidence',
      'evidenceUnavailable',
      'evidenceTxId',
      'note',
    ]);
    expect(json).toMatchObject({
      address: ACCOUNTS.postQuantum,
      proven: true,
      basis: 'provider-record',
      evidenceUnavailable: false,
      evidenceTxId: PQ_EVIDENCE_TXID,
    });
    expect(json.evidence).toMatchObject({
      confirmedRound: String(CONFIRMED_ROUND),
      providerRound: String(PROVIDER_ROUND),
      guarantees: {
        providerConfirmedRecord: true,
        localAddressBinding: true,
        independentSignatureVerification: false,
      },
    });
  });

  it('reports unavailable and malformed evidence as unavailable, never as an empty history', async () => {
    for (const account of [ACCOUNTS.malformed, ACCOUNTS.unavailable]) {
      const json = JSON.parse((await cli('verify', account, '--json')).stdout);
      expect(json.evidenceUnavailable).toBe(true);
    }
    expect(trapped).toEqual([]);
  });
});

describe('the removed --mnemonic-env option', () => {
  const FORMS: Array<[string, string[]]> = [
    ['as --mnemonic-env VAR', ['--mnemonic-env', PHRASE_VAR]],
    ['as --mnemonic-env=VAR', [`--mnemonic-env=${PHRASE_VAR}`]],
    ['before the address', ['--mnemonic-env', PHRASE_VAR, 'ADDRESS']],
    ['with its value missing', ['--mnemonic-env']],
    ['with --json', ['--json', '--mnemonic-env', PHRASE_VAR]],
    ['with --compact on TestNet', ['--compact', '-n', 'testnet', '--mnemonic-env', PHRASE_VAR]],
    ['with a phrase passed as its value by mistake', ['--mnemonic-env', SENTINEL]],
  ];

  it.each(FORMS)('is refused %s, without reading anything', async (_name, form) => {
    // 'ADDRESS' marks where the address goes; otherwise it leads.
    const argv = form.includes('ADDRESS')
      ? form.map((a) => (a === 'ADDRESS' ? ACCOUNTS.postQuantum : a))
      : [ACCOUNTS.postQuantum, ...form];
    const r = await cli('verify', ...argv);
    expect(r.code).toBe(1);
    // First what matters: the variable was never read and nothing was sent.
    expectNothingForbidden(r);
    expect(requested).toEqual([]);
    expect(reads).toEqual([]);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('verify no longer accepts --mnemonic-env');
    expect(r.stderr).not.toContain(PHRASE_VAR);
  });

  it('is refused with no address at all', async () => {
    const r = await cli('verify', '--mnemonic-env', PHRASE_VAR);
    expect(r.code).toBe(1);
    expectNothingForbidden(r);
    expect(requested).toEqual([]);
    expect(r.stderr).toContain('verify no longer accepts --mnemonic-env');
  });

  it('after --, is a positional and verify stays read-only', async () => {
    const r = await cli('verify', ACCOUNTS.postQuantum, '--', '--mnemonic-env', PHRASE_VAR);
    expect(r.code).toBe(0);
    expect(requested).toEqual(['mainnet']);
    expectNothingForbidden(r);
  });
});

describe('usage errors exit 1 before any provider is read', () => {
  const USAGE_ERRORS: Array<[string, string[], string]> = [
    ['verify without an address', ['verify'], 'Usage: falqoner verify <address>'],
    [
      'an unknown network',
      ['verify', ACCOUNTS.classical, '--network', 'betanet'],
      'Unknown network "betanet"',
    ],
    ['an invalid address', ['verify', 'not-an-address'], 'Not a valid Algorand address'],
    [
      '--mnemonic-env on scan, which never had it',
      ['scan', ACCOUNTS.classical, '--mnemonic-env', PHRASE_VAR],
      "Unknown option '--mnemonic-env'",
    ],
    [
      'a malformed --assets list',
      ['scan', ACCOUNTS.classical, '--assets', 'seven'],
      '--assets takes a comma-separated list of positive numeric ids',
    ],
    ['a plan without --to', ['plan', ACCOUNTS.classical], 'Missing --to <pq-address>'],
    [
      'a plan whose --to is not an address',
      ['plan', ACCOUNTS.classical, '--to', 'not-an-address'],
      '--to is not a valid Algorand address',
    ],
    ['migrate, which is not a command', ['migrate', ACCOUNTS.classical], 'Unknown command "migrate"'],
    ['an unknown command', ['frobnicate'], 'Unknown command "frobnicate"'],
    ['inspect without an address', ['inspect'], 'Usage: falqoner inspect <address>'],
    ['inspect of an invalid address', ['inspect', 'not-an-address'], 'Not a valid Algorand address'],
  ];

  it.each(USAGE_ERRORS)('%s', async (_name, argv, message) => {
    const r = await cli(...argv);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain(message);
    expect(reads).toEqual([]);
    expectNothingForbidden(r);
  });
});

describe('help', () => {
  it.each([['help'], ['--help'], ['-h'], []])('%j prints the usage and exits 0', async (...argv) => {
    const r = await cli(...argv);
    expect(r.code).toBe(0);
    expect(r.stderr).toBe('');
    expect(requested).toEqual([]);
    expectNothingForbidden(r);
    expect(r.stdout).toContain('Read-only on every network, MainNet included');
    expect(r.stdout).not.toContain('--mnemonic-env');
  });
});

/**
 * Coverage, reach and the CI gate (CORE-03), as the CLI renders them. Every
 * view reads the same core model, so these check the rendering and exits,
 * not the model itself.
 */
describe('coverage, reach and --fail-on', () => {
  it('states every check, and the scope of the score, in the full view', async () => {
    const r = await cli('scan', ACCOUNTS.classical);
    expect(r.code).toBe(0);
    for (const label of ['signing history', 'rekeyed to it', 'asset roles', 'app state']) {
      expect(r.stdout).toMatch(new RegExp(`^\\s+${label}\\s+complete\\s*$`, 'm'));
    }
    expect(r.stdout).not.toContain('app permissions');
    expect(flat(r.stdout)).toContain(SCORE_SCOPE);
    expect(r.stdout).toContain('29/100  Elevated exposure');
  });

  it('leads a clean, complete verdict with "No exposure found", never a certification', async () => {
    const r = await cli('scan', ACCOUNTS.protectedSigner, '--compact');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('0/100  No exposure found');
    expect(r.stdout).not.toMatch(/SAFE|Not exposed/);
    expect(flat(r.stdout)).toContain('coverage complete for the checks run');
  });

  it('describes a post-quantum address signing only for protected accounts as exactly that', async () => {
    for (const mode of [[], ['--compact']]) {
      const r = await cli('scan', ACCOUNTS.protectedSigner, ...mode);
      expect(r.code).toBe(0);
      expect(flat(r.stdout)).toContain(
        'It signs for 1 account rekeyed to it with a post-quantum key, on a ' +
          'provider-confirmed record.',
      );
      expect(r.stdout).not.toMatch(
        /freeze|seize|Breaking the exposed key|Controls external assets/,
      );
    }
  });

  it('names an exposed asset power, and the authority it rests on', async () => {
    const r = await cli('scan', ACCOUNTS.classical, '--assets', String(MANAGED_ASSET));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('59/100  High exposure');
    expect(flat(r.stdout)).toContain(
      '! This address can seize 1 asset from any holder. Those roles are ' +
        "exercised under this account's own authority, which is not " +
        'established as post-quantum.',
    );
    expect(flat(r.stdout)).toContain(
      'Breaking the exposed key would reach beyond this account.',
    );
  });

  it('shows an application reference as unverified, and the verdict as a lower bound', async () => {
    const full = await cli('scan', ACCOUNTS.appCreator);
    expect(full.code).toBe(0);
    expect(reads).toContain(`mainnet getApplicationByID ${APP_REF}`);
    expect(full.stdout).toContain('29+/100  Elevated exposure, at least');
    expect(full.stdout).toMatch(/app references\s+1 \(permissions unverified\)/);
    expect(full.stdout).toMatch(/^\s+app permissions\s+unverified\s*$/m);
    expect(full.stdout).toContain('Created 1 application; permissions unverified');
    expect(full.stdout).not.toMatch(/can (delete|update)/);

    const compact = await cli('scan', ACCOUNTS.appCreator, '--compact');
    expect(flat(compact.stdout)).toContain(
      'coverage incomplete: app permissions unverified',
    );
    expect(flat(compact.stdout)).toContain(
      'Not established: 1 application reference with unverified ' +
        'permissions. This is not a safe verdict.',
    );
  });

  it('takes nothing from an unusable record, and keeps the verdict incomplete', async () => {
    // The record for another asset would make this account a seizing
    // manager. Read for the id asked for, it establishes nothing at all.
    const wrong = await cli('scan', ACCOUNTS.classical, '--assets', String(WRONG_ID_ASSET));
    expect(wrong.code).toBe(0);
    expect(reads).toContain(`mainnet getAssetByID ${WRONG_ID_ASSET}`);
    expect(wrong.stdout).toContain('29+/100  Elevated exposure, at least');
    expect(wrong.stdout).not.toMatch(/seize|Manager of/);
    expect(wrong.stdout).toMatch(/^\s+asset roles\s+invalid response\s*$/m);
    expect(flat(wrong.stdout)).toContain(
      '1 named asset record was unusable (asset record for a different id)',
    );

    const app = await cli('scan', ACCOUNTS.classical, '--apps', String(MALFORMED_APP), '--compact');
    expect(app.code).toBe(0);
    expect(flat(app.stdout)).toContain('coverage incomplete: app state invalid response');
    expect(app.stdout).toContain('29+/100');

    const json = JSON.parse(
      (await cli('scan', ACCOUNTS.classical, '--assets', String(MALFORMED_ASSET), '--json')).stdout,
    );
    expect(json.coverage.assets).toMatchObject({
      status: 'invalid-response',
      errors: ['malformed asset parameters'],
      named: { requested: 1, attempted: 1, read: 0, invalid: 1 },
    });
    expect(json.risk).toMatchObject({ complete: false, band: 'elevated' });
    expect(json.risk.uncertainties).toEqual(['1 named asset record was unusable']);
  });

  it('keeps what an unfinished incoming search found, and says it is a floor', async () => {
    const r = await cli('scan', ACCOUNTS.brokenSearch, '--compact');
    expect(r.code).toBe(0);
    expect(flat(r.stdout)).toContain(
      'signs for at least 1 (1 not post-quantum), search incomplete',
    );
    expect(flat(r.stdout)).toContain('coverage incomplete: rekeyed to it partial');
    expect(r.stdout).toContain('40+/100  Elevated exposure, at least');
    const full = await cli('scan', ACCOUNTS.brokenSearch);
    expect(flat(full.stdout)).toContain('before a later request failed (HTTP 503)');
  });

  // [case, exit code, scan arguments, what stderr must say]
  const GATE: Array<[string, number, string[], string]> = [
    ['complete and under the threshold', 0, [ACCOUNTS.classical, '--fail-on', 'critical'], ''],
    [
      'complete and at the threshold',
      2,
      [ACCOUNTS.classical, '--fail-on', 'elevated'],
      'Exposure elevated meets or exceeds elevated.',
    ],
    ['clean and complete', 0, [ACCOUNTS.protectedSigner, '--fail-on', 'low'], ''],
    [
      'under the threshold, with an unverified reference',
      2,
      [ACCOUNTS.appCreator, '--fail-on', 'critical'],
      'Exposure could not be evaluated against critical: 1 application ' +
        'reference with unverified permissions.',
    ],
    [
      'at the threshold even as a lower bound',
      2,
      [ACCOUNTS.appCreator, '--fail-on', 'low'],
      'Exposure elevated (at least) meets or exceeds low.',
    ],
    [
      'under the threshold, with an unfinished incoming search',
      2,
      [ACCOUNTS.brokenSearch, '--fail-on', 'critical'],
      'the search for accounts rekeyed to this address failed after 1 were found',
    ],
    [
      'a named asset that does not exist',
      0,
      [ACCOUNTS.classical, '--assets', String(MISSING_ASSET), '--fail-on', 'critical'],
      '',
    ],
    [
      'a named asset whose read failed',
      2,
      [ACCOUNTS.classical, '--assets', String(BROKEN_ASSET), '--fail-on', 'critical'],
      '1 named asset read failed',
    ],
    [
      'a named asset whose record is unusable',
      2,
      [ACCOUNTS.classical, '--assets', String(MALFORMED_ASSET), '--fail-on', 'critical'],
      '1 named asset record was unusable',
    ],
    [
      "a named asset answered with another asset's record",
      2,
      [ACCOUNTS.classical, '--assets', String(WRONG_ID_ASSET), '--fail-on', 'critical'],
      '1 named asset record was unusable',
    ],
    [
      'a named application whose state is unreadable',
      2,
      [ACCOUNTS.classical, '--apps', String(MALFORMED_APP), '--fail-on', 'critical'],
      '1 application record was unusable',
    ],
    ['a finished ledger sample', 0, [ACCOUNTS.classical, '--deep', '--fail-on', 'critical'], ''],
  ];

  it.each(GATE)('--fail-on: %s exits %i', async (_name, exit, argv, message) => {
    const r = await cli('scan', ...argv, '--compact');
    expect(r.code).toBe(exit);
    if (message) expect(flat(r.stderr)).toContain(message);
    else expect(r.stderr).toBe('');
  });

  it.each([
    ['an unknown threshold', ['--fail-on', 'severe'], '--fail-on must be one of'],
    [
      'a zero sample limit',
      ['--deep', '--scan-limit', '0'],
      '--scan-limit takes a positive whole number',
    ],
    [
      'an unreadable sample limit',
      ['--scan-limit', 'lots'],
      '--scan-limit takes a positive whole number',
    ],
    [
      'a zero application id',
      ['--apps', '0'],
      '--apps takes a comma-separated list of positive numeric ids',
    ],
  ])('refuses %s before reading anything', async (_name, flags, message) => {
    const r = await cli('scan', ACCOUNTS.classical, ...flags);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(message);
    expect(requested).toEqual([]);
    expect(reads).toEqual([]);
  });

  it('carries coverage, reach and completeness in scan --json', async () => {
    const clean = JSON.parse((await cli('scan', ACCOUNTS.classical, '--json')).stdout);
    expect(clean.risk).toMatchObject({ complete: true, uncertainties: [], band: 'elevated' });
    expect(clean.coverage.incoming).toMatchObject({
      status: 'complete',
      found: 0,
      exhausted: true,
    });
    expect(clean.coverage.assets.sample.status).toBe('not-requested');
    expect(clean.coverage.appPermissions).toBe('no-references');
    expect(clean.reach).toMatchObject({ seize: [], freeze: [], appReferences: 0 });

    const refs = JSON.parse((await cli('scan', ACCOUNTS.appCreator, '--json')).stdout);
    expect(refs.risk.complete).toBe(false);
    expect(refs.risk.uncertainties).toEqual([
      '1 application reference with unverified permissions',
    ]);
    expect(refs.coverage.appPermissions).toBe('unverified');
    expect(refs.coverage.apps.reads).toMatchObject({ requested: 1, read: 1 });
    const f = refs.findings.find((x: { kind: string }) => x.kind === 'app-creator');
    expect(f).toMatchObject({
      thirdParty: false,
      fixedByRekey: false,
      appIds: [String(APP_REF)],
    });
    expect(
      refs.edges.find((x: { relation: string }) => x.relation === 'app-creator'),
    ).toMatchObject({ basis: 'reference' });
  });
});

describe('plan prices its budget from the network, read-only (SAFE-03a)', () => {
  const algos = (m: string) => `${formatAlgos(BigInt(m))} ALGO`;

  it('carries the budget in JSON, from parameter, status and account reads only', async () => {
    const r = await cli('plan', ACCOUNTS.classical, '--to', TARGET, '--json', '-n', 'localnet');
    expect(r.code).toBe(0);
    expectNothingForbidden(r);
    const plan = JSON.parse(r.stdout);
    expect(plan.budget.status).toBe('available');
    expect(plan.budget.stages.map((s: { stage: string; sender: string; amount: string; fee: string }) => [s.stage, s.sender, s.amount, s.fee])).toEqual([
      ['funding', ACCOUNTS.classical, '103000', '1000'],
      ['proof', TARGET, '0', '3000'],
      ['rekey', ACCOUNTS.classical, '0', '1000'],
      ['verification', ACCOUNTS.classical, '0', '3000'],
    ]);
    expect(plan.budget.totals).toMatchObject({ feeExpense: '8000', transfer: '103000', sourceDebit: '108000', targetRetained: '100000' });
    expect(plan.estimatedFeeMicroAlgos).toBe('8000');
    expect(plan.steps.map((s: { feeMicroAlgos: string }) => s.feeMicroAlgos)).toEqual(['1000', '3000', '1000', '3000']);
    expect(reads).toEqual(expect.arrayContaining([
      'localnet getTransactionParams',
      'localnet status',
      `localnet accountInformation ${TARGET}`,
    ]));
  });

  it('prints in human output exactly the figures the JSON carries', async () => {
    const json = JSON.parse((await cli('plan', ACCOUNTS.classical, '--to', TARGET, '--json', '-n', 'localnet')).stdout);
    resetRecords();
    const r = await cli('plan', ACCOUNTS.classical, '--to', TARGET, '-n', 'localnet');
    expect(r.code).toBe(0);
    expectNothingForbidden(r);
    const lines = r.stdout.split('\n');
    const names = ['fund the new address', 'prove its key', 'rekey', 'verify'];
    for (const [i, s] of json.budget.stages.entries()) {
      const line = lines.find((l) => l.trim().startsWith(names[i]!))!;
      expect(line, s.stage).toContain(`sends ${algos(s.amount)}`);
      expect(line, s.stage).toContain(`fee ${algos(s.fee)}`);
    }
    const t = json.budget.totals;
    expect(r.stdout).toContain(`fees            ${algos(t.feeExpense)}`);
    expect(r.stdout).toContain(`account pays    ${algos(t.sourceDebit)} (sends ${algos(t.transfer)}, fees ${algos(t.sourceFees)})`);
    expect(r.stdout).toContain(`keeps ${algos(t.targetRetained)}, minimum ${algos(json.budget.target.minBalance)}`);
    expect(r.stdout).toContain(`round ${json.budget.observed.round} on dockernet-v1, consensus v42`);
    expect(r.stdout).not.toContain('one-off cost');
  });

  it('refuses an account whose signer it cannot price, and exits 2', async () => {
    // Rekeyed to a hash-derived authority nothing identifies.
    const r = await cli('plan', ACCOUNTS.unconfirmed, '--to', TARGET, '--json', '-n', 'localnet');
    expect(r.code).toBe(2);
    expectNothingForbidden(r);
    const plan = JSON.parse(r.stdout);
    expect(plan.budget.status).toBe('blocked');
    expect(plan.blockers.join(' ')).toContain('Nothing establishes what signs for');
  });

  it('prices a Falcon current signer as Falcon', async () => {
    const r = await cli('plan', ACCOUNTS.postQuantum, '--to', TARGET, '--json', '-n', 'localnet');
    expect(r.code).toBe(0);
    const fees = JSON.parse(r.stdout).budget.stages.map((s: { stage: string; fee: string }) => [s.stage, s.fee]);
    expect(fees).toEqual([['funding', '3000'], ['proof', '3000'], ['rekey', '3000'], ['verification', '3000']]);
  });
});
