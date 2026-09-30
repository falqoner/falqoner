/**
 * Regressions for non-recursive rekey semantics (CORE-01).
 *
 * Algorand checks a transaction's signature against its sender's auth-addr
 * and never follows that address's own auth-addr. So with A rekeyed to B and
 * B then rekeyed to a post-quantum C, B's *original* key still signs for A,
 * and C cannot. Falconer used to report the opposite: accounts rekeyed to a
 * migrated address were said to follow it, their exposure was marked fixed by
 * that rekey, and the migrated account's post-quantum status zeroed their
 * risk.
 *
 * These drive `analyzeAccount` end to end against a fake ledger. Post-quantum
 * evidence is built from real Falcon keys, so the signature re-derivation the
 * tool relies on runs for real; only the network is replaced.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  analyzeAccount,
  assessRisk,
  riskVerdict,
  INCOMING_LOOKUP_LIMIT,
} from '../src/exposure.js';
import { generatePqIdentity } from '../src/falcon.js';
import { planMigration } from '../src/migrate.js';
import type { FalconerClients } from '../src/networks.js';
import type { PqIdentity } from '../src/types.js';
import { txid } from './fixtures.js';

interface FakeAccount {
  amount: bigint;
  authAddr?: string;
  createdAssets?: Array<{ index: bigint; params: Record<string, unknown> }>;
}

interface FakeLedger {
  clients: FalconerClients;
  /** Evidence lookups the indexer answered, per sender address. */
  lookups: string[];
}

/**
 * A ledger that answers exactly the queries `analyzeAccount` makes, from the
 * accounts and transactions a test hands it.
 */
function ledger(
  accounts: Record<string, FakeAccount>,
  transactions: any[] = [],
  opts: { incomingSearchFails?: boolean } = {},
): FakeLedger {
  const lookups: string[] = [];
  const clients: FalconerClients = {
    algod: {
      accountInformation: (address: string) => ({
        do: async () => {
          // As algod answers an address it has no record for: an empty account.
          const a = accounts[address] ?? { amount: 0n };
          return {
            amount: a.amount,
            minBalance: 100_000n,
            authAddr: a.authAddr,
            assets: [],
            createdAssets: a.createdAssets ?? [],
            createdApps: [],
            appsLocalState: [],
          };
        },
      }),
    } as any,
    indexer: {
      searchAccounts: () => ({
        authAddr: (auth: string) => ({
          limit: () => ({
            do: async () => {
              if (opts.incomingSearchFails) throw new Error('indexer down');
              return {
                accounts: Object.entries(accounts)
                  .filter(([, a]) => a.authAddr === auth)
                  .map(([address, a]) => ({ address, amount: a.amount })),
              };
            },
          }),
        }),
      }),
      searchForTransactions: () => ({
        address: (sender: string) => ({
          addressRole: () => ({
            limit: () => ({
              do: async () => {
                lookups.push(sender);
                return {
                  // A real response always carries the provider's current round.
                  'current-round': 100,
                  transactions: transactions.filter((t) => t.sender === sender),
                };
              },
            }),
          }),
        }),
      }),
    } as any,
    network: { name: 'custom', algodUrl: '', algodToken: '' },
  };
  return { clients, lookups };
}

const classical = () => algosdk.generateAccount().addr.toString();

/**
 * A transaction `sender` sent, signed by the Falcon key behind `signer`.
 * `label` names it; the id is a real-format one derived from it.
 */
function falconSigned(
  label: string,
  sender: string,
  signer: PqIdentity,
): Record<string, unknown> {
  return {
    id: txid(label),
    sender,
    'confirmed-round': 10,
    // A transaction authorised by its own sender carries no auth-addr.
    ...(sender === signer.address ? {} : { 'auth-addr': signer.address }),
    signature: {
      pqsig: {
        scheme: 'f1',
        'public-key': signer.publicKey,
        salt: signer.salt,
        // Not verified by Falconer (RC01 trust boundary): any real-length
        // bytes are a faithful fixture.
        signature: new Uint8Array(1230).fill(7),
      },
    },
  };
}

function rolesAsset(index: bigint, holder: string) {
  return {
    index,
    params: {
      creator: holder,
      manager: holder,
      reserve: holder,
      freeze: holder,
      clawback: holder,
      unitName: 'ROLE',
      total: 1_000n,
      decimals: 0,
    },
  };
}

describe('direct authority: A -> B, then B -> C', () => {
  // The ceremony the LocalNet suite runs for real, reduced to ledger state.
  const A = classical();
  const B = classical();
  const C = generatePqIdentity();
  const accounts: Record<string, FakeAccount> = {
    [A]: { amount: 7_000_000n, authAddr: B },
    [B]: {
      amount: 3_000_000n,
      authAddr: C.address,
      createdAssets: [rolesAsset(42n, B)],
    },
    [C.address]: { amount: 200_000n },
  };
  const txns = [
    // B moved under C after its rekey, which is what proves B is migrated.
    falconSigned('B-UNDER-C', B, C),
    // C's own proof-of-control drill.
    falconSigned('C-DRILL', C.address, C),
  ];

  it('reports B itself as post-quantum', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    expect(b.authAddr).toBe(C.address);
    expect(b.authority.authorityClass).toBe('post-quantum');
    expect(b.isPostQuantum).toBe(true);
  });

  it('keeps A authorised by B directly, never by C', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    expect(b.controlsAccounts).toEqual([A]);
    expect(b.incoming).toHaveLength(1);
    const a = b.incoming[0]!;
    expect(a.address).toBe(A);
    // Authorised by B's address - not by C, which only authorises B.
    expect(a.authority.authAddr).toBe(B);
    expect(a.authority.authorityClass).toBe('classical-key');
    expect(a.authority.quantumSafe).toBe(false);
    expect(a.authority.detail).toContain(`${B} itself`);
  });

  it('does not let B’s migration clear A’s exposure', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    expect(b.risk.band).not.toBe('safe');
    expect(b.risk.score).toBeGreaterThan(0);
    expect(b.risk.residualAccounts).toBe(1);
    expect(b.risk.residualMicroAlgos).toBe(7_000_000n);
    // Own safety and residual exposure are stated separately, not blended.
    expect(b.risk.summary).toContain('confirmed Falcon-signed transaction');
    expect(b.risk.summary).toContain('does not cover');
  });

  it('reports A’s exposure as not fixed by any rekey of B', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    const controls = b.findings.filter((f) => f.kind === 'controls-account');
    expect(controls).toHaveLength(1);
    expect(controls[0]!.severity).toBe('critical');
    expect(controls[0]!.fixedByRekey).toBe(false);
    expect(controls[0]!.accounts).toEqual([A]);
    expect(controls[0]!.detail).toContain('migrating this account does not move it');
    // Naming B's own authority keeps the two keys apart for the reader.
    expect(controls[0]!.detail).toContain(`not by ${C.address}`);
  });

  it('keeps B’s address-bound asset roles following B’s own rekey', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    for (const kind of ['asa-clawback', 'asa-manager', 'asa-freeze'] as const) {
      const f = b.findings.find((x) => x.kind === kind);
      expect(f, kind).toBeDefined();
      // Exercised by transactions B sends, so C now signs for them.
      expect(f!.fixedByRekey, kind).toBe(true);
    }
    // Roles do not add to the residual: only A does.
    expect(b.risk.residualAccounts).toBe(1);
  });

  it('never tells B’s operator that A follows the migration', async () => {
    const { clients } = ledger(accounts, txns);
    const b = await analyzeAccount(clients, B);
    const plan = planMigration(b, generatePqIdentity().address);
    const text = [...plan.warnings, ...plan.steps.map((s) => s.detail)].join(' ');
    expect(text).not.toMatch(/follow this migration automatically/);
    expect(text).toContain('will not follow this migration');
    expect(text).toContain(`key behind ${B}`);
    expect(text).toContain('1 of them remains exposed');
  });

  it('reports A as classical and not migrated, although B is', async () => {
    const { clients } = ledger(accounts, txns);
    const a = await analyzeAccount(clients, A);
    expect(a.authAddr).toBe(B);
    // B's new Falcon authority is not inherited.
    expect(a.authority.authorityClass).toBe('classical-key');
    expect(a.isPostQuantum).toBe(false);
    expect(a.risk.band).not.toBe('safe');

    const away = a.findings.find((f) => f.kind === 'rekeyed-away');
    expect(away).toBeDefined();
    // Fixed by a rekey of A itself...
    expect(away!.fixedByRekey).toBe(true);
    // ...and only that: the old copy said migrating B would do it.
    expect(away!.detail).not.toContain('means migrating that key');
    expect(away!.detail).toContain('needs its own rekey');
  });

  it('plans A’s own rekey as signed by B’s key, not as done', async () => {
    const { clients } = ledger(accounts, txns);
    const a = await analyzeAccount(clients, A);
    const plan = planMigration(a, C.address);
    expect(plan.blockers).toHaveLength(0);
    expect(plan.warnings.join(' ')).toContain(`already rekeyed to ${B}`);
    expect(plan.steps.some((s) => s.kind === 'rekey')).toBe(true);
  });
});

describe('own post-quantum status and incoming exposure stay distinct', () => {
  it('keeps unconfirmed incoming authority unconfirmed, without borrowing the own proof', async () => {
    // X is a hash-derived address rekeyed to C, and C is proven. Y is
    // rekeyed to X. What signs for Y is the key behind X - which has never
    // been seen signing - so C's proof must not be carried over to Y.
    const X = generatePqIdentity();
    const C = generatePqIdentity();
    const Y = classical();
    const { clients } = ledger(
      {
        [X.address]: { amount: 2_000_000n, authAddr: C.address },
        [Y]: { amount: 5_000_000n, authAddr: X.address },
      },
      [falconSigned('X-UNDER-C', X.address, C)],
    );

    const x = await analyzeAccount(clients, X.address);
    expect(x.isPostQuantum).toBe(true);
    const y = x.incoming[0]!;
    expect(y.authority.authAddr).toBe(X.address);
    expect(y.authority.authorityClass).toBe('unknown-hash-derived');
    expect(y.authority.quantumSafe).toBe(false);
    expect(y.authority.evidenceTxId).toBeUndefined();

    expect(x.risk.band).not.toBe('safe');
    expect(x.risk.residualAccounts).toBe(1);
    expect(x.risk.summary).toContain('unconfirmed');
    const f = x.findings.find((g) => g.kind === 'controls-account');
    expect(f!.severity).toBe('medium');
    expect(f!.fixedByRekey).toBe(false);
  });

  it('lets a directly proven post-quantum authoriser protect incoming accounts', async () => {
    // C signs for itself and is proven, so the key behind C's address is
    // known to be Falcon. B rekeyed to C is authorised by exactly that key.
    const C = generatePqIdentity();
    const B = classical();
    const { clients, lookups } = ledger(
      {
        [C.address]: { amount: 1_000_000n },
        [B]: { amount: 4_000_000n, authAddr: C.address },
      },
      [falconSigned('C-DRILL', C.address, C)],
    );

    const c = await analyzeAccount(clients, C.address);
    expect(c.isPostQuantum).toBe(true);
    const b = c.incoming[0]!;
    expect(b.authority.authorityClass).toBe('post-quantum');
    expect(b.authority.quantumSafe).toBe(true);
    expect(b.authority.authAddr).toBe(C.address);
    expect(b.authority.evidenceTxId).toBe(txid('C-DRILL'));
    // C's own evidence answered for B: no second lookup was needed.
    expect(lookups).toEqual([C.address]);

    expect(c.risk.band).toBe('safe');
    expect(c.risk.score).toBe(0);
    expect(c.risk.residualAccounts).toBe(0);
    expect(c.risk.residualMicroAlgos).toBe(0n);
    const f = c.findings.find((g) => g.kind === 'controls-account');
    expect(f!.severity).toBe('info');
    expect(f!.fixedByRekey).toBe(false);
  });

  it('reports safe with no incoming accounts, as before', async () => {
    const C = generatePqIdentity();
    const B = classical();
    const { clients } = ledger(
      {
        [B]: { amount: 9_000_000n, authAddr: C.address },
        [C.address]: { amount: 200_000n },
      },
      [falconSigned('B-UNDER-C', B, C)],
    );

    const b = await analyzeAccount(clients, B);
    expect(b.isPostQuantum).toBe(true);
    expect(b.incoming).toEqual([]);
    expect(b.incomingScan).toBe('complete');
    expect(b.risk.band).toBe('safe');
    expect(b.risk.score).toBe(0);
    expect(b.risk.residualAccounts).toBe(0);
    expect(b.findings.some((f) => f.kind === 'controls-account')).toBe(false);
  });

  it('proves an unobserved authoriser from an incoming account’s own signature', async () => {
    // X signs for itself but has never transacted, so its own authority is
    // unconfirmed. Y2 has moved under X's Falcon key, which proves the key
    // behind X - for Y2, and for Y1, which X authorises the same way.
    const X = generatePqIdentity();
    const Y1 = classical();
    const Y2 = classical();
    const { clients } = ledger(
      {
        [X.address]: { amount: 1_000_000n },
        [Y1]: { amount: 1_000_000n, authAddr: X.address },
        [Y2]: { amount: 1_000_000n, authAddr: X.address },
      },
      [falconSigned('Y2-UNDER-X', Y2, X)],
    );

    const x = await analyzeAccount(clients, X.address);
    // The own-account model is unchanged: X's own evidence is still absent.
    expect(x.authority.authorityClass).toBe('unknown-hash-derived');
    expect(x.isPostQuantum).toBe(false);
    for (const y of x.incoming) {
      expect(y.authority.authorityClass, y.address).toBe('post-quantum');
      expect(y.authority.evidenceTxId, y.address).toBe(txid('Y2-UNDER-X'));
    }
    expect(x.risk.residualAccounts).toBe(0);
  });

  it('stops looking after the lookup limit and leaves the rest unchecked', async () => {
    const X = generatePqIdentity();
    const C = generatePqIdentity();
    const accounts: Record<string, FakeAccount> = {
      [X.address]: { amount: 1_000_000n, authAddr: C.address },
    };
    const count = INCOMING_LOOKUP_LIMIT + 5;
    for (let i = 0; i < count; i++) {
      accounts[classical()] = { amount: 1_000_000n, authAddr: X.address };
    }
    const { clients, lookups } = ledger(accounts);

    const x = await analyzeAccount(clients, X.address);
    expect(x.incoming).toHaveLength(count);
    // One lookup for X's own authority, then the bounded incoming ones.
    expect(lookups.length).toBe(1 + INCOMING_LOOKUP_LIMIT);
    const unchecked = x.incoming.filter((i) => i.authority.evidenceUnavailable);
    expect(unchecked).toHaveLength(5);
    for (const i of x.incoming) expect(i.authority.quantumSafe).toBe(false);
    expect(x.risk.residualAccounts).toBe(count);
  });

  it('never reads an unavailable incoming search as "none"', async () => {
    const C = generatePqIdentity();
    const B = classical();
    const { clients } = ledger(
      { [B]: { amount: 1_000_000n, authAddr: C.address } },
      [falconSigned('B-UNDER-C', B, C)],
      { incomingSearchFails: true },
    );

    const b = await analyzeAccount(clients, B);
    expect(b.isPostQuantum).toBe(true);
    expect(b.incomingScan).toBe('unavailable');
    const f = b.findings.find((g) => g.kind === 'controls-account');
    expect(f).toBeDefined();
    expect(f!.title).toContain('could not be checked');
    expect(f!.fixedByRekey).toBe(false);

    // A-01-01: the aggregate verdict used to be 0 / "safe" here, which the
    // web showed as "Not exposed" and compact CLI as SAFE.
    expect(b.risk.band).not.toBe('safe');
    expect(b.risk.band).toBe('unverified');
    expect(b.risk.incomingUnverified).toBe(true);
    expect(b.risk.summary).toContain('could not be checked');
    expect(b.risk.summary).toContain('not a safe verdict');

    // Own authority is still reported as proven, separately.
    expect(b.authority.authorityClass).toBe('post-quantum');
    expect(b.risk.summary).toContain('confirmed Falcon-signed transaction');

    // Nothing is invented for what could not be looked at.
    expect(b.incoming).toEqual([]);
    expect(b.controlsAccounts).toEqual([]);
    expect(b.risk.residualAccounts).toBe(0);
    expect(b.risk.residualMicroAlgos).toBe(0n);
    expect(b.risk.score).toBe(0);

    // And no presentation can lead with a clean verdict.
    const v = riskVerdict(b.risk);
    expect(v.safe).toBe(false);
    expect(v.headline).not.toBe('Not exposed');
    expect(v.headline).toBe('Exposure not verified');
    expect(v.score).toBe('?');
  });

  it('never reads an unavailable search as safe when nothing else is held', async () => {
    // A key with no balance of its own is exactly the controller that signs
    // for others. With the search down, "nothing held" is all that is known.
    const K = classical();
    const { clients } = ledger({}, [], { incomingSearchFails: true });

    const k = await analyzeAccount(clients, K);
    expect(k.microAlgos).toBe(0n);
    expect(k.authority.authorityClass).toBe('classical-key');
    expect(k.risk.score).toBe(0);
    expect(k.risk.band).toBe('unverified');
    expect(k.risk.summary).toContain('Nothing checked is exposed');
    expect(k.risk.summary).not.toContain('Nothing of value is held');
    expect(riskVerdict(k.risk).safe).toBe(false);
  });

  it('keeps an established band as a lower bound when the search is down', async () => {
    const B = classical();
    const { clients } = ledger(
      { [B]: { amount: 50_000_000n } },
      [],
      { incomingSearchFails: true },
    );

    const b = await analyzeAccount(clients, B);
    // Own exposure is real and known, so it is reported, not replaced.
    expect(['low', 'elevated', 'high', 'critical']).toContain(b.risk.band);
    expect(b.risk.incomingUnverified).toBe(true);
    expect(b.risk.summary).toContain('not a safe verdict');
    const v = riskVerdict(b.risk);
    expect(v.score).toBe(`${b.risk.score}+`);
    expect(v.headline).toContain('at least');
  });

  it('accounts for each incoming balance exactly once', async () => {
    // Every account rekeyed to one address shares that address as its
    // authoriser, so a scan sees them all residual or all protected. Both
    // cases must report each balance once, and never add residual on top
    // of the reach it is part of.
    const C = generatePqIdentity();
    const B = classical();
    const in1 = classical();
    const in2 = classical();
    const residualLedger = ledger(
      {
        [B]: { amount: 1_000_000n, authAddr: C.address },
        [in1]: { amount: 6_000_000n, authAddr: B },
        [in2]: { amount: 4_000_000n, authAddr: B },
      },
      [falconSigned('B-UNDER-C', B, C)],
    );
    const exposed = await analyzeAccount(residualLedger.clients, B);

    const X = generatePqIdentity();
    const in3 = classical();
    const in4 = classical();
    const protectedLedger = ledger(
      {
        [X.address]: { amount: 1_000_000n },
        [in3]: { amount: 6_000_000n, authAddr: X.address },
        [in4]: { amount: 4_000_000n, authAddr: X.address },
      },
      [falconSigned('X-DRILL', X.address, X)],
    );
    const covered = await analyzeAccount(protectedLedger.clients, X.address);

    for (const [e, residual] of [
      [exposed, 10_000_000n],
      [covered, 0n],
    ] as const) {
      const reported = e.findings
        .filter((f) => f.kind === 'controls-account')
        .reduce((total, f) => total + (f.microAlgos ?? 0n), 0n);
      expect(reported).toBe(10_000_000n);
      expect(e.risk.directMicroAlgos).toBe(1_000_000n + 10_000_000n);
      expect(e.risk.residualMicroAlgos).toBe(residual);
    }
  });
});

describe('assessRisk residual incoming exposure', () => {
  const base = {
    microAlgos: 5_000_000n,
    controlledValue: 50_000_000n,
    assetsHeld: 0,
    appCount: 0,
    seizable: 0,
    freezable: 0,
    controlsCount: 1,
  };

  it('does not let own post-quantum status clear classical incoming exposure', () => {
    const r = assessRisk({
      ...base,
      alreadyPq: true,
      residualCount: 1,
      residualValue: 50_000_000n,
      residualUnconfirmed: 0,
    });
    expect(r.band).not.toBe('safe');
    expect(r.score).toBeGreaterThan(0);
    expect(r.residualAccounts).toBe(1);
    expect(r.residualMicroAlgos).toBe(50_000_000n);
  });

  it('treats unresolved incoming authority as exposed by default', () => {
    // A caller that has not resolved incoming authority gets the
    // conservative answer, never a silent "safe".
    const r = assessRisk({ ...base, alreadyPq: true });
    expect(r.band).not.toBe('safe');
    expect(r.residualAccounts).toBe(1);
  });

  it('is safe when every incoming account is directly protected', () => {
    const r = assessRisk({
      ...base,
      alreadyPq: true,
      residualCount: 0,
      residualValue: 0n,
    });
    expect(r.band).toBe('safe');
    expect(r.score).toBe(0);
    expect(r.summary).toContain('authorised directly by a post-quantum key');
  });

  it('scores only the exposed part once the account itself is migrated', () => {
    // Own balance and roles move with the account's own authority; the
    // residual does not, so the migrated score is the residual alone.
    const migrated = assessRisk({
      ...base,
      alreadyPq: true,
      seizable: 3,
      residualCount: 1,
      residualValue: 50_000_000n,
    });
    const residualOnly = assessRisk({
      ...base,
      alreadyPq: false,
      microAlgos: 0n,
      residualCount: 1,
      residualValue: 50_000_000n,
    });
    expect(migrated.score).toBe(residualOnly.score);
  });

  it('discounts unconfirmed incoming authority but never classical', () => {
    const unconfirmed = assessRisk({
      ...base,
      alreadyPq: true,
      residualCount: 1,
      residualValue: 50_000_000n,
      residualUnconfirmed: 1,
    });
    const classicalResidual = assessRisk({
      ...base,
      alreadyPq: true,
      residualCount: 1,
      residualValue: 50_000_000n,
      residualUnconfirmed: 0,
    });
    expect(unconfirmed.score).toBeLessThan(classicalResidual.score);

    // An unproven own authority must not discount a classical incoming
    // account: its exposure does not depend on this account's authority.
    const ownUnprovenClassicalIn = assessRisk({
      ...base,
      alreadyPq: false,
      authorityUnproven: true,
      residualCount: 1,
      residualValue: 50_000_000n,
      residualUnconfirmed: 0,
    });
    const ownClassicalClassicalIn = assessRisk({
      ...base,
      alreadyPq: false,
      authorityUnproven: false,
      residualCount: 1,
      residualValue: 50_000_000n,
      residualUnconfirmed: 0,
    });
    expect(ownUnprovenClassicalIn.score).toBe(ownClassicalClassicalIn.score);
  });

  it('withholds "safe" only when incoming coverage is actually missing', () => {
    const covered = { ...base, controlsCount: 0, controlledValue: 0n, alreadyPq: true };
    // Complete coverage: unchanged, still safe.
    const complete = assessRisk(covered);
    expect(complete.band).toBe('safe');
    expect(complete.incomingUnverified).toBe(false);
    // Missing coverage: not safe, and no residual invented for it.
    const missing = assessRisk({ ...covered, incomingUnverified: true });
    expect(missing.band).toBe('unverified');
    expect(missing.score).toBe(0);
    expect(missing.residualAccounts).toBe(0);
    expect(missing.residualMicroAlgos).toBe(0n);
  });

  it('leaves the score unchanged when every controlled account is residual', () => {
    // The pre-existing inputs, with residual left to its default, must score
    // exactly as they did: a classical key signing for classical accounts.
    const implicit = assessRisk({ ...base, alreadyPq: false });
    const explicit = assessRisk({
      ...base,
      alreadyPq: false,
      residualCount: 1,
      residualValue: base.controlledValue,
      residualUnconfirmed: 0,
    });
    expect(explicit.score).toBe(implicit.score);
    expect(explicit.band).toBe(implicit.band);
  });
});

/**
 * The verdict every presentation leads with. The CLI risk line and the web
 * gauge and headline both render `riskVerdict` verbatim, so these are the
 * presentation checks: a report can only lead with a clean verdict when the
 * verdict is complete, and even then it claims only that nothing exposed was
 * found (CORE-03), never a certification.
 */
describe('riskVerdict presentation', () => {
  const complete = {
    alreadyPq: false,
    microAlgos: 0n,
    controlledValue: 0n,
    assetsHeld: 0,
    appCount: 0,
    seizable: 0,
    freezable: 0,
    controlsCount: 0,
  };

  it('says "No exposure found" only for a complete clean verdict', () => {
    const v = riskVerdict(assessRisk(complete));
    expect(v).toEqual({ headline: 'No exposure found', score: '0', safe: true });
  });

  it('shows an incomplete clean-looking verdict as unverified, not zero', () => {
    const v = riskVerdict(assessRisk({ ...complete, incomingUnverified: true }));
    expect(v).toEqual({
      headline: 'Exposure not verified',
      score: '?',
      safe: false,
    });
  });

  it('marks a known band as a lower bound only when coverage is missing', () => {
    const known = { ...complete, microAlgos: 50_000_000n };
    const full = riskVerdict(assessRisk(known));
    const partial = riskVerdict(
      assessRisk({ ...known, incomingUnverified: true }),
    );
    expect(full.score).not.toContain('+');
    expect(full.headline).not.toContain('at least');
    expect(partial.score).toBe(`${full.score}+`);
    expect(partial.headline).toBe(`${full.headline}, at least`);
    expect(full.safe).toBe(false);
    expect(partial.safe).toBe(false);
  });
});
