/**
 * Evidence trust and classification (CORE-02).
 *
 * RC01 trusts the configured indexer as a source of confirmed ledger records.
 * Falconer checks that a reported Falcon record is well formed and binds, by
 * local re-derivation, to the account's authority. It does not verify the
 * signature bytes or the transaction payload, so a provider that fabricates a
 * fully coherent record is outside the boundary - and no test here implies
 * otherwise.
 *
 * Each negative case below starts from the well-formed record and breaks one
 * thing, so a failure names exactly which check stopped it.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  assessAuthority,
  checkPqAddressBinding,
  describeEvidence,
  verifyPqSignatureAuthorises,
} from '../src/authority.js';
import type { AuthorityAssessment } from '../src/authority.js';
import { derivePqAddressAtSalt, generatePqIdentity, isHashDerivedAddress } from '../src/falcon.js';
import type { FalconerClients } from '../src/networks.js';
import type { PqIdentity } from '../src/types.js';
import { txid } from './fixtures.js';

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

/** Real-length signature bytes. Their content is never examined. */
const SIG = new Uint8Array(1230).fill(9);

/** An indexer returning exactly `transactions`, or failing outright. */
function indexer(
  transactions: any[],
  opts: { fails?: boolean; currentRound?: number } = {},
): FalconerClients {
  return {
    algod: {} as any,
    indexer: {
      searchForTransactions: () => ({
        address: () => ({
          addressRole: () => ({
            limit: () => ({
              do: async () => {
                if (opts.fails) throw new Error('indexer down');
                return {
                  'current-round': opts.currentRound ?? 100,
                  transactions,
                };
              },
            }),
          }),
        }),
      }),
    } as any,
    network: {
      name: 'localnet',
      algodUrl: 'http://localhost:4001',
      algodToken: '',
      indexerUrl: 'http://localhost:8980',
    },
  };
}

const classical = () => algosdk.generateAccount().addr.toString();

/** Find an identity whose canonical salt is exactly `want`. */
function identityWithSalt(want: number): PqIdentity {
  for (let i = 0; i < 400; i++) {
    const id = generatePqIdentity();
    if (id.salt === want) return id;
  }
  throw new Error(`no identity with salt ${want}`);
}

/**
 * The well-formed record, in the REST shape observed on LocalNet: sender
 * rekeyed to `pq`, confirmed, one Falcon signature, base64 bytes.
 */
function record(
  sender: string,
  pq: PqIdentity,
  over: { tx?: Record<string, unknown>; pqsig?: Record<string, unknown> } = {},
) {
  return {
    id: txid('PQTX'),
    sender,
    'auth-addr': pq.address,
    'confirmed-round': 42,
    signature: {
      pqsig: {
        scheme: 'f1',
        'public-key': b64(pq.publicKey),
        salt: pq.salt,
        signature: b64(SIG),
        ...over.pqsig,
      },
    },
    ...over.tx,
  };
}

async function assess(
  sender: string,
  pq: PqIdentity,
  txns: any[],
  opts?: Parameters<typeof indexer>[1],
): Promise<AuthorityAssessment> {
  return assessAuthority(indexer(txns, opts), sender, pq.address);
}

function expectNotEstablished(a: AuthorityAssessment) {
  expect(a.authorityClass).toBe('unknown-hash-derived');
  expect(a.quantumSafe).toBe(false);
  expect(a.proven).toBe(false);
  expect(a.evidence.basis).toBe('none');
  expect(a.evidence.guarantees.providerConfirmedRecord).toBe(false);
  expect(a.evidence.guarantees.localAddressBinding).toBe(false);
}

describe('a positive verdict states exactly what it rests on', () => {
  it('establishes post-quantum from a well-formed confirmed record', async () => {
    const sender = classical();
    const pq = generatePqIdentity();
    const a = await assess(sender, pq, [record(sender, pq)], { currentRound: 77 });

    expect(a.authorityClass).toBe('post-quantum');
    expect(a.quantumSafe).toBe(true);
    expect(a.proven).toBe(true);
    expect(a.evidence).toMatchObject({
      basis: 'provider-record',
      lookup: 'found',
      provider: { network: 'localnet', indexer: 'http://localhost:8980' },
      txId: txid('PQTX'),
      confirmedRound: 42n,
      providerRound: 77n,
      guarantees: {
        providerConfirmedRecord: true,
        localAddressBinding: true,
        independentSignatureVerification: false,
      },
    });
    // The verdict says whose record it is and what Falconer did not check.
    expect(a.detail).toContain(`indexer reported confirmed transaction ${txid('PQTX')}`);
    expect(a.detail).toContain('re-derived the authority address');
    expect(a.detail).toContain('did not verify the signature bytes');
    expect(a.detail).not.toMatch(/verifiably|cryptographically proven/);
  });

  it('accepts the algosdk model shape as well as the REST shape', async () => {
    // What analyzeAccount really receives: an Address object for auth-addr,
    // a bigint round, raw bytes, and every signature kind present as a key.
    const sender = classical();
    const pq = generatePqIdentity();
    const model = {
      id: txid('MODEL'),
      sender,
      authAddr: algosdk.Address.fromString(pq.address),
      confirmedRound: 42n,
      signature: {
        logicsig: undefined,
        multisig: undefined,
        sig: undefined,
        pqsig: {
          publicKey: pq.publicKey,
          scheme: 'f1',
          signature: SIG,
          salt: pq.salt,
        },
      },
    };
    const a = await assess(sender, pq, [model]);
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.evidence.confirmedRound).toBe(42n);
  });

  it('accepts a coherent record without checking its signature bytes (RC01 boundary)', async () => {
    // Not a security property - a stated limitation. The signature bytes are
    // never verified, so arbitrary bytes on an otherwise coherent record are
    // accepted, and the evidence says so.
    const sender = classical();
    const pq = generatePqIdentity();
    const a = await assess(sender, pq, [
      record(sender, pq, { pqsig: { signature: b64(new Uint8Array(7).fill(1)) } }),
    ]);
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.evidence.guarantees.independentSignatureVerification).toBe(false);
    expect(describeEvidence(a)).toContain('signature bytes not verified by Falconer');
  });
});

describe('records that must not establish post-quantum', () => {
  const sender = classical();
  const pq = generatePqIdentity();

  const cases: Array<[string, any, string]> = [
    ['sent by another account', record(classical(), pq), 'wrong-sender'],
    ['not confirmed', record(sender, pq, { tx: { 'confirmed-round': undefined } }), 'unconfirmed'],
    ['confirmed in round 0', record(sender, pq, { tx: { 'confirmed-round': 0 } }), 'unconfirmed'],
    ['without any signature', record(sender, pq, { tx: { signature: {} } }), 'missing-signature'],
    ['without signature bytes', record(sender, pq, { pqsig: { signature: undefined } }), 'missing-signature'],
    ['with empty signature bytes', record(sender, pq, { pqsig: { signature: new Uint8Array(0) } }), 'missing-signature'],
    ['with signature bytes that are not base64', record(sender, pq, { pqsig: { signature: 'not base64!' } }), 'missing-signature'],
    [
      'with both an Ed25519 and a Falcon signature',
      record(sender, pq, {
        tx: {
          signature: {
            sig: b64(new Uint8Array(64)),
            pqsig: { scheme: 'f1', 'public-key': b64(pq.publicKey), salt: pq.salt, signature: b64(SIG) },
          },
        },
      }),
      'contradictory-record',
    ],
    [
      // The case the "more than one kind" check exists for: a well-formed
      // multisig beside a Falcon signature would otherwise be read as a
      // proven multisig. (Ed25519 + Falcon is caught twice over, because an
      // Ed25519 signature from a hash-derived authority is contradictory by
      // itself, so it cannot isolate this check.)
      'with both a multisig and a Falcon signature',
      record(sender, pq, {
        tx: {
          signature: {
            multisig: { threshold: 1, subsignature: [{}] },
            pqsig: { scheme: 'f1', 'public-key': b64(pq.publicKey), salt: pq.salt, signature: b64(SIG) },
          },
        },
      }),
      'contradictory-record',
    ],
    [
      'claiming an Ed25519 signature from a hash-derived authority',
      record(sender, pq, { tx: { signature: { sig: b64(new Uint8Array(64)) } } }),
      'contradictory-record',
    ],
    ['with an unsupported scheme', record(sender, pq, { pqsig: { scheme: 'f5' } }), 'unsupported-scheme'],
    ['with a base64-looking scheme', record(sender, pq, { pqsig: { scheme: 'ZjE=' } }), 'unsupported-scheme'],
    ['without a scheme', record(sender, pq, { pqsig: { scheme: undefined } }), 'malformed-scheme'],
    ['with a numeric scheme', record(sender, pq, { pqsig: { scheme: 1 } }), 'malformed-scheme'],
    [
      'with a truncated public key',
      record(sender, pq, { pqsig: { 'public-key': b64(pq.publicKey.slice(0, 1792)) } }),
      'malformed-public-key',
    ],
    ['with a public key of the wrong type', record(sender, pq, { pqsig: { 'public-key': 12345 } }), 'malformed-public-key'],
    ['without a public key', record(sender, pq, { pqsig: { 'public-key': undefined } }), 'malformed-public-key'],
    ['with a null salt', record(sender, pq, { pqsig: { salt: null } }), 'malformed-salt'],
    ['with a text salt', record(sender, pq, { pqsig: { salt: String(pq.salt) } }), 'malformed-salt'],
    ['with a fractional salt', record(sender, pq, { pqsig: { salt: 1.5 } }), 'malformed-salt'],
    ['with a negative salt', record(sender, pq, { pqsig: { salt: -1 } }), 'malformed-salt'],
    ['with a salt beyond the maximum', record(sender, pq, { pqsig: { salt: 256 } }), 'malformed-salt'],
    [
      'whose key binds to another address',
      record(sender, pq, { pqsig: { 'public-key': b64(generatePqIdentity().publicKey) } }),
      'address-mismatch',
    ],
  ];

  for (const [name, txn, reason] of cases) {
    it(`rejects a record ${name}`, async () => {
      const a = await assess(sender, pq, [txn]);
      expectNotEstablished(a);
      expect(a.evidence.rejected.map((r) => r.reason)).toEqual([reason]);
      // Named, so the suspicious record can be looked at.
      expect(a.evidenceTxId).toBe(txid('PQTX'));
      expect(describeEvidence(a)).toContain(reason);
    });
  }

  it('rejects a Falcon record that binds to an on-curve address', async () => {
    // Find a salt at which this key lands on the curve, and claim that
    // address as the authority: a classical key could claim it too.
    const id = generatePqIdentity();
    let onCurveSalt = -1;
    let onCurveAddress = '';
    for (let salt = 0; salt <= 255; salt++) {
      const addr = derivePqAddressAtSalt(id.publicKey, salt);
      if (!isHashDerivedAddress(addr)) {
        onCurveSalt = salt;
        onCurveAddress = addr;
        break;
      }
    }
    if (onCurveSalt < 0) return; // vanishingly unlikely; nothing to assert
    const s = classical();
    const txn = {
      id: txid('ONCURVE'),
      sender: s,
      'auth-addr': onCurveAddress,
      'confirmed-round': 42,
      signature: {
        pqsig: { scheme: 'f1', 'public-key': b64(id.publicKey), salt: onCurveSalt, signature: b64(SIG) },
      },
    };
    expect(checkPqAddressBinding(txn.signature.pqsig, onCurveAddress)).toEqual({
      bound: false,
      reason: 'on-curve-binding',
    });
    // assessAuthority never gets that far: an on-curve authority is
    // classified by shape before any record is read.
    const a = await assessAuthority(indexer([txn]), s, onCurveAddress);
    expect(a.authorityClass).toBe('classical-key');
    expect(a.quantumSafe).toBe(false);
  });

  it('passes over a record authorised by a previous authority, without rejecting it', async () => {
    // Genuine history about another key: not evidence about the current
    // authority, and not a provider fault either.
    const previous = generatePqIdentity();
    const txn = record(sender, previous, { tx: { id: txid('OLD') } });
    const a = await assess(sender, pq, [txn]);
    expectNotEstablished(a);
    expect(a.evidence.rejected).toEqual([]);
    expect(a.evidence.lookup).toBe('none-found');
    expect(a.evidence.examined).toBe(1);
  });

  it('does not accept a malformed multisig as proof of a multisig', async () => {
    const txn = record(sender, pq, {
      tx: { signature: { multisig: { threshold: 3, subsignature: [{}, {}] } } },
    });
    const a = await assess(sender, pq, [txn]);
    expectNotEstablished(a);
    expect(a.evidence.rejected.map((r) => r.reason)).toEqual(['malformed-multisig']);
  });

  it('does not accept a logic signature without a program', async () => {
    const txn = record(sender, pq, { tx: { signature: { logicsig: { args: [] } } } });
    const a = await assess(sender, pq, [txn]);
    expectNotEstablished(a);
    expect(a.evidence.rejected.map((r) => r.reason)).toEqual(['malformed-logicsig']);
  });

  it('keeps rejected records as provenance when a later one is accepted', async () => {
    const bad = record(sender, pq, { tx: { id: txid('BAD') }, pqsig: { signature: undefined } });
    const good = record(sender, pq, { tx: { id: txid('GOOD') } });
    const a = await assess(sender, pq, [bad, good]);
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.evidence.txId).toBe(txid('GOOD'));
    expect(a.evidence.rejected).toEqual([{ txId: txid('BAD'), reason: 'missing-signature' }]);
  });
});

describe('absent and limited evidence stay distinct', () => {
  const sender = classical();
  const pq = generatePqIdentity();

  it('reports an unreadable history as unavailable, not as nothing found', async () => {
    const a = await assess(sender, pq, [], { fails: true });
    expectNotEstablished(a);
    expect(a.evidenceUnavailable).toBe(true);
    expect(a.evidence.lookup).toBe('unavailable');
    expect(describeEvidence(a)).toContain('could not be read');
  });

  it('reports a history with nothing in it as none found', async () => {
    const a = await assess(sender, pq, []);
    expectNotEstablished(a);
    expect(a.evidenceUnavailable).toBe(false);
    expect(a.evidence.lookup).toBe('none-found');
    expect(a.detail).toContain('No transaction signed by this authority was found');
  });

  it('says when the history limit was reached without an answer', async () => {
    // A full page of irrelevant history: older evidence may exist unread.
    const previous = generatePqIdentity();
    const page = Array.from({ length: 50 }, (_, i) =>
      record(sender, previous, { tx: { id: txid(`OLD${i}`) } }),
    );
    const a = await assess(sender, pq, page);
    expectNotEstablished(a);
    expect(a.evidence.lookup).toBe('history-limited');
    expect(a.evidence.examined).toBe(50);
    expect(a.evidence.lookback).toBe(50);
    expect(a.detail).toContain('older ones were not read');
    expect(describeEvidence(a)).toContain('older ones were not read');
  });
});

describe('proven means an observed account type, never a shape', () => {
  it('reports an on-curve authority as exposed by shape, not proven', async () => {
    const acct = classical();
    const a = await assessAuthority(indexer([]), acct, undefined);
    expect(a.authorityClass).toBe('classical-key');
    expect(a.quantumSafe).toBe(false);
    expect(a.proven).toBe(false);
    expect(a.evidence).toMatchObject({
      basis: 'address-shape',
      lookup: 'not-needed',
      examined: 0,
    });
    expect(a.detail).toContain('establishes the exposure, not which kind of account');
    expect(describeEvidence(a)).toContain('account type was not observed');
  });

  it('proves a multisig only from a well-formed confirmed record', async () => {
    const msig = (() => {
      for (let i = 0; i < 64; i++) {
        const a = algosdk
          .multisigAddress({
            version: 1,
            threshold: 2,
            addrs: [classical(), classical()],
          })
          .toString();
        if (isHashDerivedAddress(a)) return a;
      }
      throw new Error('no off-curve multisig address');
    })();
    const txn = {
      id: txid('MSIG'),
      sender: msig,
      'confirmed-round': 5,
      signature: { multisig: { threshold: 2, subsignature: [{}, {}] } },
    };
    const a = await assessAuthority(indexer([txn]), msig, undefined);
    expect(a.authorityClass).toBe('classical-multisig');
    expect(a.proven).toBe(true);
    expect(a.evidence.basis).toBe('provider-record');
    // A multisig record is confirmed, but there is no address binding to
    // claim for it here.
    expect(a.evidence.guarantees).toEqual({
      providerConfirmedRecord: true,
      localAddressBinding: false,
      independentSignatureVerification: false,
    });
  });
});

describe('the binding check is named for what it does', () => {
  it('reports each binding failure with its reason', () => {
    const id = generatePqIdentity();
    const ok = { scheme: 'f1', publicKey: id.publicKey, salt: id.salt };
    expect(checkPqAddressBinding(ok, id.address)).toEqual({ bound: true });
    expect(checkPqAddressBinding({ ...ok, scheme: 'f9' }, id.address).reason).toBe('unsupported-scheme');
    expect(checkPqAddressBinding({ ...ok, publicKey: new Uint8Array(10) }, id.address).reason).toBe(
      'malformed-public-key',
    );
    expect(checkPqAddressBinding({ ...ok, salt: null }, id.address).reason).toBe('malformed-salt');
    expect(checkPqAddressBinding(ok, generatePqIdentity().address).reason).toBe('address-mismatch');
  });

  it('accepts a scheme sent as raw bytes', () => {
    const id = generatePqIdentity();
    const scheme = new TextEncoder().encode('f1');
    expect(
      checkPqAddressBinding({ scheme, publicKey: id.publicKey, salt: id.salt }, id.address).bound,
    ).toBe(true);
  });

  it('keeps the omitted-salt and non-canonical-salt cases working', () => {
    // Salt 0 is omitted by canonical encoding; the absent field means zero.
    const zero = identityWithSalt(0);
    expect(
      checkPqAddressBinding({ scheme: 'f1', publicKey: zero.publicKey }, zero.address).bound,
    ).toBe(true);
    // One key controls every off-curve address it can derive, not only the
    // canonical one.
    const id = generatePqIdentity();
    let alt = -1;
    for (let salt = 0; salt <= 255; salt++) {
      if (salt !== id.salt && isHashDerivedAddress(derivePqAddressAtSalt(id.publicKey, salt))) {
        alt = salt;
        break;
      }
    }
    expect(alt).toBeGreaterThanOrEqual(0);
    const altAddress = derivePqAddressAtSalt(id.publicKey, alt);
    expect(
      checkPqAddressBinding({ scheme: 'f1', publicKey: id.publicKey, salt: alt }, altAddress).bound,
    ).toBe(true);
  });

  it('keeps the deprecated name as the binding check, and nothing more', () => {
    const id = generatePqIdentity();
    const pqsig = { scheme: 'f1', publicKey: id.publicKey, salt: id.salt };
    // No signature bytes at all, and it still "passes": it never looked at
    // them, which is why the name is deprecated.
    expect(verifyPqSignatureAuthorises(pqsig, id.address)).toBe(true);
    expect(verifyPqSignatureAuthorises(pqsig, id.address)).toBe(
      checkPqAddressBinding(pqsig, id.address).bound,
    );
  });
});

describe('a report states the basis where users read it', () => {
  it('names the basis in the post-quantum finding and summary', async () => {
    const { analyzeAccount } = await import('../src/exposure.js');
    const sender = classical();
    const pq = generatePqIdentity();
    const clients = indexer([record(sender, pq)]);
    (clients as any).algod = {
      accountInformation: () => ({
        do: async () => ({
          amount: 1_000_000n,
          minBalance: 100_000n,
          authAddr: pq.address,
          assets: [],
          createdAssets: [],
          createdApps: [],
          appsLocalState: [],
        }),
      }),
    };
    (clients as any).indexer.searchAccounts = () => ({
      authAddr: () => ({ limit: () => ({ do: async () => ({ accounts: [] }) }) }),
    });

    const e = await analyzeAccount(clients, sender);
    expect(e.isPostQuantum).toBe(true);
    const f = e.findings.find((x) => x.kind === 'already-pq');
    expect(f!.title).toBe('Post-quantum authority, on a provider-confirmed record');
    expect(f!.title).not.toContain('verified');
    expect(f!.detail).toContain('did not verify the signature bytes');
    expect(e.risk.summary).toContain('confirmed Falcon-signed transaction');
    expect(e.risk.summary).toContain('address binding');
    expect(e.risk.summary).not.toContain('verified on chain');
  });
});

/**
 * Malformed provider responses (A-02-01 / A-02-02).
 *
 * A record must be nameable and confirmed no later than the provider's own
 * current round before it can establish anything, and a response that is not
 * a usable search result must not read as an empty one. Each case changes
 * exactly one thing relative to the well-formed control.
 */
describe('malformed provider responses', () => {
  const sender = classical();
  const pq = generatePqIdentity();

  /** A provider whose search answers with exactly `response`. */
  const respond = (response: unknown): FalconerClients => {
    const c = indexer([]);
    (c as any).indexer.searchForTransactions = () => ({
      address: () => ({
        addressRole: () => ({
          limit: () => ({ do: async () => response }),
        }),
      }),
    });
    return c;
  };
  const assessRaw = (response: unknown) =>
    assessAuthority(respond(response), sender, pq.address);

  it('control: a well-formed record in a well-formed response is accepted', async () => {
    const a = await assessRaw({ 'current-round': 100, transactions: [record(sender, pq)] });
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.evidence.txId).toBe(txid('PQTX'));
    expect(a.evidence.providerRound).toBe(100n);
  });

  it('accepts the algosdk response shape, with a bigint current round', async () => {
    const a = await assessRaw({ currentRound: 100n, transactions: [record(sender, pq)] });
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.evidence.providerRound).toBe(100n);
  });

  describe('a record that cannot be named', () => {
    const idCases: Array<[string, unknown, string]> = [
      ['no id', undefined, 'missing-id'],
      ['a null id', null, 'missing-id'],
      ['an empty id', '', 'missing-id'],
      ['a blank id', '   ', 'missing-id'],
      ['an id too short to be one', 'TX1', 'malformed-id'],
      ['a lower-case id', txid('PQTX').toLowerCase(), 'malformed-id'],
      ['an id one character short', txid('PQTX').slice(1), 'malformed-id'],
      ['an id with a character base32 lacks', `${txid('PQTX').slice(1)}1`, 'malformed-id'],
      ['a numeric id', 12345, 'malformed-id'],
    ];
    for (const [name, id, reason] of idCases) {
      it(`is rejected with ${name}`, async () => {
        const a = await assessRaw({
          'current-round': 100,
          transactions: [record(sender, pq, { tx: { id } })],
        });
        expectNotEstablished(a);
        expect(a.evidence.rejected.map((r) => r.reason)).toEqual([reason]);
        expect(a.detail).not.toContain('(no id)');
      });
    }

    it('keeps a malformed id, truncated, so the record can be traced', async () => {
      const a = await assessRaw({
        'current-round': 100,
        transactions: [record(sender, pq, { tx: { id: 'TX1' } })],
      });
      expect(a.evidence.rejected).toEqual([{ txId: 'TX1', reason: 'malformed-id' }]);
      expect(a.evidenceTxId).toBe('TX1');
    });
  });

  describe('confirmation against the provider round', () => {
    it('rejects a record confirmed after the provider’s current round', async () => {
      // Confirmed in 42 by a provider that says it is at round 10.
      const a = await assessRaw({ 'current-round': 10, transactions: [record(sender, pq)] });
      expectNotEstablished(a);
      expect(a.evidence.rejected).toEqual([
        { txId: txid('PQTX'), reason: 'confirmed-after-current-round' },
      ]);
      expect(a.evidence.providerRound).toBe(10n);
    });

    it('accepts a record confirmed in the provider’s current round itself', async () => {
      const a = await assessRaw({ 'current-round': 42, transactions: [record(sender, pq)] });
      expect(a.authorityClass).toBe('post-quantum');
    });

    it('rejects a malformed record even from a previous authority', async () => {
      // Irrelevant history is passed over, but a record that is not a
      // confirmed ledger record is a provider fault wherever it appears.
      const previous = generatePqIdentity();
      const a = await assessRaw({
        'current-round': 10,
        transactions: [record(sender, previous, { tx: { id: txid('OLD') } })],
      });
      expectNotEstablished(a);
      expect(a.evidence.rejected).toEqual([
        { txId: txid('OLD'), reason: 'confirmed-after-current-round' },
      ]);
    });
  });

  describe('a response that is not a usable search result', () => {
    const faults: Array<[string, unknown, string]> = [
      ['no response at all', null, 'malformed-response'],
      ['a response that is not an object', 'transactions', 'malformed-response'],
      ['no transaction list', { 'current-round': 100 }, 'missing-transaction-list'],
      ['a null transaction list', { 'current-round': 100, transactions: null }, 'malformed-transaction-list'],
      ['a transaction list that is an object', { 'current-round': 100, transactions: { 0: {} } }, 'malformed-transaction-list'],
      ['a transaction list that is text', { 'current-round': 100, transactions: '[]' }, 'malformed-transaction-list'],
      ['no current round', { transactions: [] }, 'missing-provider-round'],
      ['a current round that is text', { 'current-round': 'soon', transactions: [] }, 'malformed-provider-round'],
      ['a negative current round', { 'current-round': -1, transactions: [] }, 'malformed-provider-round'],
      ['a fractional current round', { 'current-round': 1.5, transactions: [] }, 'malformed-provider-round'],
      ['a null current round', { 'current-round': null, transactions: [] }, 'malformed-provider-round'],
    ];
    for (const [name, response, fault] of faults) {
      it(`is invalid, not empty, with ${name}`, async () => {
        const a = await assessRaw(response);
        expectNotEstablished(a);
        expect(a.evidenceUnavailable).toBe(true);
        expect(a.evidence.lookup).toBe('invalid-response');
        expect(a.evidence.responseFault).toBe(fault);
        expect(a.evidence.examined).toBe(0);
        expect(a.detail).toContain('response could not be used');
        expect(describeEvidence(a)).toContain(fault);
      });
    }

    it('does not let a malformed response hide a valid record in it', async () => {
      // A good record is no use when the response around it has no round
      // to check its confirmation against.
      const a = await assessRaw({ transactions: [record(sender, pq)] });
      expectNotEstablished(a);
      expect(a.evidence.responseFault).toBe('missing-provider-round');
    });

    it('rejects a list entry that is not a record', async () => {
      const a = await assessRaw({ 'current-round': 100, transactions: [null, 7] });
      expectNotEstablished(a);
      expect(a.evidence.lookup).toBe('none-found');
      expect(a.evidence.rejected.map((r) => r.reason)).toEqual([
        'malformed-record',
        'malformed-record',
      ]);
    });
  });

  describe('a valid empty search stays distinct', () => {
    it('reads an empty list with a current round as a completed search', async () => {
      const a = await assessRaw({ 'current-round': 100, transactions: [] });
      expectNotEstablished(a);
      expect(a.evidenceUnavailable).toBe(false);
      expect(a.evidence.lookup).toBe('none-found');
      expect(a.evidence.responseFault).toBeUndefined();
      expect(a.evidence.providerRound).toBe(100n);
    });

    it('accepts a chain at round 0 as a valid, empty answer', async () => {
      const a = await assessRaw({ 'current-round': 0, transactions: [] });
      expect(a.evidence.lookup).toBe('none-found');
      expect(a.evidence.providerRound).toBe(0n);
    });

    it('keeps both non-post-quantum, and tells them apart', async () => {
      const empty = await assessRaw({ 'current-round': 100, transactions: [] });
      const broken = await assessRaw({ 'current-round': 100 });
      for (const a of [empty, broken]) expect(a.quantumSafe).toBe(false);
      expect(empty.evidence.lookup).not.toBe(broken.evidence.lookup);
      expect(empty.evidenceUnavailable).toBe(false);
      expect(broken.evidenceUnavailable).toBe(true);
    });
  });
});
