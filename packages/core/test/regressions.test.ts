/**
 * Regressions for classification and safety-gate bugs.
 *
 * Each test here corresponds to a case where Falconer previously stated
 * something it had not established. They run offline against stubbed indexer
 * responses, because the property under test is what the tool *says*, not
 * whether the network agrees.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import { assessAuthority } from '../src/authority.js';
import {
  classifyAddressShape,
  derivePqAddressAtSalt,
  generatePqIdentity,
  isHashDerivedAddress,
} from '../src/falcon.js';
import { verifyPqSignatureAuthorises } from '../src/authority.js';
import { assessRisk, formatAlgos } from '../src/exposure.js';
import { planMigration, preflight } from '../src/migrate.js';
import { ED25519_BY_PHRASE, V42_PROTOCOL, computeBudget } from '../src/budget.js';
import type { FalconerClients } from '../src/networks.js';
import { txid } from './fixtures.js';

/**
 * Stand-in Falcon signature bytes. Falconer checks that a record carries a
 * signature but does not verify the bytes (the RC01 trust boundary), so any
 * non-empty value of the real length is a faithful fixture.
 */
const SIGNATURE_BYTES = new Uint8Array(1230).fill(7);

/** An indexer that returns exactly the transactions a test hands it. */
function stub(transactions: any[] = []): FalconerClients {
  return {
    algod: {} as any,
    indexer: {
      searchForTransactions: () => ({
        address: () => ({
          addressRole: () => ({
            // A real response always carries the provider's current round.
            limit: () => ({
              do: async () => ({ 'current-round': 100, transactions }),
            }),
          }),
        }),
      }),
    } as any,
    network: { name: 'custom', algodUrl: '', algodToken: '' },
  };
}

function exposureStub(over: Record<string, unknown> = {}): any {
  return {
    address: algosdk.generateAccount().addr.toString(),
    authAddr: undefined,
    isPostQuantum: false,
    microAlgos: 10_000_000n,
    minBalance: 100_000n,
    createdAssets: [],
    foreignRoles: [],
    controlsAccounts: [],
    ...over,
  };
}

function multisigAddress(): string {
  return algosdk
    .multisigAddress({
      version: 1,
      threshold: 2,
      addrs: [
        algosdk.generateAccount().addr.toString(),
        algosdk.generateAccount().addr.toString(),
      ],
    })
    .toString();
}

/**
 * A multisig address is a plain hash, so unlike a post-quantum address -
 * whose salt is chosen precisely to force it off the curve - it lands *on*
 * the curve about half the time. Tests that need the off-curve case have to
 * ask for it rather than assume it.
 */
function offCurveMultisigAddress(): string {
  for (let i = 0; i < 64; i++) {
    const a = multisigAddress();
    if (isHashDerivedAddress(a)) return a;
  }
  throw new Error('no off-curve multisig address in 64 tries');
}

describe('authority is never read off the shape of the address', () => {
  it('does not call a self-authorised post-quantum address a classical key', async () => {
    const pq = generatePqIdentity();
    expect(isHashDerivedAddress(pq.address)).toBe(true);

    const a = await assessAuthority(stub(), pq.address, undefined);

    // The old behaviour returned classical-key with proven: true, and said
    // the address *was* the Ed25519 public key. It is off-curve, so it isn't.
    expect(a.authorityClass).toBe('unknown-hash-derived');
    expect(a.quantumSafe).toBe(false);
    expect(a.proven).toBe(false);
    expect(a.detail).not.toContain('the address is the public key');
  });

  it('does not call a self-authorised application address a classical key', async () => {
    const app = algosdk.getApplicationAddress(1234).toString();
    const a = await assessAuthority(stub(), app, undefined);
    expect(a.authorityClass).toBe('unknown-hash-derived');
    expect(a.proven).toBe(false);
  });

  it('does not call an off-curve self-authorised multisig a classical key', async () => {
    const a = await assessAuthority(stub(), offCurveMultisigAddress(), undefined);
    expect(a.authorityClass).toBe('unknown-hash-derived');
    expect(a.proven).toBe(false);
  });

  it('still reports an on-curve multisig as classical and exposed', async () => {
    // Half of all multisig addresses hash onto the curve and are then
    // indistinguishable from a bare key without evidence. The verdict that
    // matters - classical, not quantum safe - is the same either way, and
    // the detail must not name the address as *the* public key.
    let onCurve = '';
    for (let i = 0; i < 64 && !onCurve; i++) {
      const a = multisigAddress();
      if (!isHashDerivedAddress(a)) onCurve = a;
    }
    expect(onCurve).not.toBe('');

    const a = await assessAuthority(stub(), onCurve, undefined);
    expect(a.authorityClass).toBe('classical-key');
    expect(a.quantumSafe).toBe(false);
    expect(a.detail).not.toContain('the address is the public key');
  });

  it('still calls an on-curve self-authorised address a classical key', async () => {
    const acct = algosdk.generateAccount();
    const a = await assessAuthority(stub(), acct.addr.toString(), undefined);
    expect(a.authorityClass).toBe('classical-key');
    // CORE-02: this used to assert proven: true, which read the account
    // *type* off the address. Shape establishes the classical exposure only,
    // so it is stated as the basis instead and `proven` stays false.
    expect(a.proven).toBe(false);
    expect(a.evidence.basis).toBe('address-shape');
    expect(a.quantumSafe).toBe(false);
  });

  it('proves a self-authorised account from its own Falcon signature', async () => {
    const pq = generatePqIdentity();
    const a = await assessAuthority(
      stub([
        {
          id: txid('SELFPQ'),
          sender: pq.address,
          'confirmed-round': 10,
          // No auth-addr: the account signs for itself.
          signature: {
            pqsig: {
              scheme: 'f1',
              'public-key': pq.publicKey,
              salt: pq.salt,
              signature: SIGNATURE_BYTES,
            },
          },
        },
      ]),
      pq.address,
      undefined,
    );
    expect(a.authorityClass).toBe('post-quantum');
    expect(a.quantumSafe).toBe(true);
    expect(a.evidenceTxId).toBe(txid('SELFPQ'));
  });

  it('identifies a self-authorised multisig from its signature', async () => {
    // Off-curve, so the evidence path runs at all: an on-curve multisig is
    // classified as classical without ever reaching the indexer.
    const msig = offCurveMultisigAddress();
    const a = await assessAuthority(
      stub([
        {
          id: txid('MSIG'),
          sender: msig,
          'confirmed-round': 10,
          signature: { multisig: { threshold: 2, subsignature: [{}, {}] } },
        },
      ]),
      msig,
      undefined,
    );
    expect(a.authorityClass).toBe('classical-multisig');
    expect(a.quantumSafe).toBe(false);
  });
});

describe('a post-quantum signature that does not verify', () => {
  it('is reported as unverified, not as nothing found', async () => {
    const real = generatePqIdentity();
    const other = generatePqIdentity();
    const a = await assessAuthority(
      stub([
        {
          id: txid('SPOOF'),
          sender: 'ACCT',
          'auth-addr': real.address,
          'confirmed-round': 10,
          signature: {
            pqsig: {
              scheme: 'f1',
              'public-key': other.publicKey,
              salt: other.salt,
              signature: SIGNATURE_BYTES,
            },
          },
        },
      ]),
      'ACCT',
      real.address,
    );

    expect(a.quantumSafe).toBe(false);
    expect(a.proven).toBe(false);
    expect(a.detail).not.toContain('No transaction signed by this authority');
    expect(a.detail).toContain('does not re-derive');
    // The suspicious transaction has to be nameable, so it can be looked at.
    expect(a.evidenceTxId).toBe(txid('SPOOF'));
  });
});

describe('pre-flight transcription check', () => {
  it('reports "not checked" when no transcription is supplied', () => {
    const id = generatePqIdentity();
    const r = preflight(id);
    const phrase = r.checks.find((c) => c.name.includes('phrase'))!;
    expect(r.transcriptionConfirmed).toBe(false);
    expect(phrase.passed).toBe(false);
    expect(phrase.detail).toContain('Not checked');
    // The offline key checks still pass, so keygen can assert on them.
    expect(r.ok).toBe(true);
  });

  it('passes when the typed phrase re-derives the identity', () => {
    const id = generatePqIdentity();
    const r = preflight(id, id.mnemonic!);
    expect(r.ok).toBe(true);
    expect(r.transcriptionConfirmed).toBe(true);
  });

  it('fails on a mis-transcribed phrase', () => {
    const id = generatePqIdentity();
    const words = id.mnemonic!.split(' ');
    [words[0], words[1]] = [words[1]!, words[0]!];
    const r = preflight(id, words.join(' '));
    expect(r.ok).toBe(false);
    expect(r.transcriptionConfirmed).toBe(false);
  });
});

describe('formatAlgos', () => {
  it('carries the sign rather than leaving it in the digits', () => {
    // spendable = balance - minBalance goes negative below min balance, and
    // formatting each part separately rendered -900000 as "0.-9".
    expect(formatAlgos(-900_000n)).toBe('-0.9');
    expect(formatAlgos(-1_500_000n)).toBe('-1.5');
    expect(formatAlgos(-1n)).toBe('-0.000001');
    expect(formatAlgos(-1_000_000n)).toBe('-1');
  });

  it('is unchanged for zero and positive amounts', () => {
    expect(formatAlgos(0n)).toBe('0');
    expect(formatAlgos(1_500_000n)).toBe('1.5');
    expect(formatAlgos(1_000_001n)).toBe('1.000001');
  });
});

describe('planMigration', () => {
  it('blocks a rekey to the address that is already the authority', () => {
    const pq = generatePqIdentity();
    const plan = planMigration(
      exposureStub({ authAddr: pq.address, isPostQuantum: true }),
      pq.address,
    );
    expect(plan.blockers.join(' ')).toContain('already this account');
  });

  it('warns rather than blocks when replacing a different authority', () => {
    const current = generatePqIdentity();
    const next = generatePqIdentity();
    const plan = planMigration(
      exposureStub({ authAddr: current.address, isPostQuantum: true }),
      next.address,
    );
    expect(plan.blockers).toHaveLength(0);
    // CORE-02: stated with its basis rather than as "verified".
    expect(plan.warnings.join(' ')).toContain('already under post-quantum authority');
  });

  it('warns when replacing an authority that was never proven', () => {
    const current = generatePqIdentity();
    const next = generatePqIdentity();
    const plan = planMigration(
      exposureStub({ authAddr: current.address, isPostQuantum: false }),
      next.address,
    );
    // The unproven case is where a silent replacement would be worst, and it
    // previously produced no warning at all.
    expect(plan.warnings.join(' ')).toContain('already rekeyed to');
  });

  it('reports a readable shortfall below the minimum balance', () => {
    const exposure = exposureStub({ microAlgos: 100_000n, minBalance: 1_000_000n });
    const target = generatePqIdentity().address;
    const reading = (address: string, balance: bigint, minBalance: bigint) => ({
      address, exists: balance > 0n, balance, minBalance, authAddr: null, round: 10n,
    });
    const budget = computeBudget(
      {
        params: { genesis: { id: 'testnet-v1.0', hash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=' }, protocol: V42_PROTOCOL, minFee: 1000n, feePerByte: 0n, round: 10n, upgrade: null },
        source: reading(exposure.address, 100_000n, 1_000_000n),
        target: reading(target, 0n, 100_000n),
      },
      { sender: exposure.address, authorizer: exposure.address, target, signer: ED25519_BY_PHRASE },
    );
    const plan = planMigration(exposure, target, { budget });
    expect(plan.blockers.join(' ')).toContain('-0.9 ALGO above its minimum');
  });
});

describe('assessRisk value scaling', () => {
  it('counts balances in accounts rekeyed to this key', () => {
    // 0 ALGO of its own, signing authority over 100M ALGO. Scoring only the
    // account's own balance made this read as a low-value key.
    const controller = assessRisk({
      alreadyPq: false,
      microAlgos: 0n,
      controlledValue: 100_000_000_000_000n,
      assetsHeld: 0,
      appCount: 0,
      seizable: 0,
      freezable: 0,
      controlsCount: 1,
    });
    const empty = assessRisk({
      alreadyPq: false,
      microAlgos: 0n,
      controlledValue: 0n,
      assetsHeld: 0,
      appCount: 0,
      seizable: 0,
      freezable: 0,
      controlsCount: 1,
    });
    expect(controller.score).toBeGreaterThan(empty.score);
    expect(controller.band).toBe('high');
    expect(controller.directMicroAlgos).toBe(100_000_000_000_000n);
  });
});

describe('classifyAddressShape', () => {
  it('separates invalid input from an on-curve address', () => {
    // isHashDerivedAddress has to answer false for undecodable input, which
    // a caller reading only the boolean presents as "a valid Ed25519 point".
    expect(classifyAddressShape('not-an-address')).toBe('invalid');
    expect(classifyAddressShape('')).toBe('invalid');
    expect(classifyAddressShape('AAAA')).toBe('invalid');
    expect(isHashDerivedAddress('not-an-address')).toBe(false);
  });

  it('classifies real addresses by their shape', () => {
    expect(classifyAddressShape(algosdk.generateAccount().addr.toString()))
      .toBe('on-curve');
    expect(classifyAddressShape(generatePqIdentity().address)).toBe('off-curve');
  });
});

describe('non-canonical salts', () => {
  it('derives the same address as algosdk at the canonical salt', () => {
    // The salt-aware derivation has to reproduce the SDK exactly where the
    // SDK has an opinion, or it is not deriving Algorand addresses at all.
    for (let i = 0; i < 4; i++) {
      const id = generatePqIdentity();
      const ref = algosdk.addressFromPQKey(
        algosdk.FALCON_1024_SCHEME,
        id.publicKey,
      );
      expect(derivePqAddressAtSalt(id.publicKey, ref.salt)).toBe(
        ref.address.toString(),
      );
      expect(derivePqAddressAtSalt(id.publicKey, ref.salt)).toBe(id.address);
    }
  });

  it('verifies a signature whose salt is not the canonical one', () => {
    // The protocol verifies a pqsig at any salt, so one Falcon key controls
    // up to 256 addresses. Re-deriving the canonical salt and demanding a
    // match reported those accounts as unconfirmed.
    const id = generatePqIdentity();

    // The next salt that still yields an off-curve address - a legitimate
    // address this key controls, and not the one algosdk would produce.
    let altSalt = -1;
    let altAddress = '';
    for (let s2 = id.salt + 1; s2 <= 255; s2++) {
      const a = derivePqAddressAtSalt(id.publicKey, s2);
      if (isHashDerivedAddress(a)) { altSalt = s2; altAddress = a; break; }
    }
    expect(altSalt).toBeGreaterThan(id.salt);
    expect(altAddress).not.toBe(id.address);

    expect(
      verifyPqSignatureAuthorises(
        { scheme: 'f1', 'public-key': id.publicKey, salt: altSalt },
        altAddress,
      ),
    ).toBe(true);

    // algosdk's own helper cannot express this account at all.
    expect(() =>
      algosdk.addressFromPQSig({
        sch: algosdk.FALCON_1024_SCHEME,
        pk: id.publicKey,
        slt: altSalt,
      } as any),
    ).toThrow();
  });

  it('still rejects a salt that does not produce the claimed address', () => {
    const id = generatePqIdentity();
    const wrong = id.salt === 255 ? 254 : id.salt + 1;
    expect(
      verifyPqSignatureAuthorises(
        { scheme: 'f1', 'public-key': id.publicKey, salt: wrong },
        id.address,
      ),
    ).toBe(false);
  });

  it('refuses a Falcon signature over an on-curve address', () => {
    // An on-curve address can be claimed by an Ed25519 key pair too, so a
    // valid Falcon signature over one is not post-quantum authority.
    const id = generatePqIdentity();
    let onCurveSalt = -1;
    let onCurveAddress = '';
    for (let s2 = 0; s2 <= 255; s2++) {
      const a = derivePqAddressAtSalt(id.publicKey, s2);
      if (!isHashDerivedAddress(a)) { onCurveSalt = s2; onCurveAddress = a; break; }
    }
    if (onCurveSalt < 0) return; // vanishingly unlikely; nothing to assert
    expect(
      verifyPqSignatureAuthorises(
        { scheme: 'f1', 'public-key': id.publicKey, salt: onCurveSalt },
        onCurveAddress,
      ),
    ).toBe(false);
  });

  it('rejects an out-of-range salt instead of hashing garbage', () => {
    const id = generatePqIdentity();
    expect(() => derivePqAddressAtSalt(id.publicKey, 256)).toThrow();
    expect(() => derivePqAddressAtSalt(id.publicKey, -1)).toThrow();
    expect(
      verifyPqSignatureAuthorises(
        { scheme: 'f1', 'public-key': id.publicKey, salt: 999 },
        id.address,
      ),
    ).toBe(false);
  });
});
