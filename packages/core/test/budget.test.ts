/**
 * The migration budget (SAFE-03a): fees from the network's parameters and
 * each signer's envelope, balances against minimums after every step, and
 * refusal of anything the model does not know how to price.
 *
 * The real Falcon-1024 keys here come from fixed public seeds.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  BudgetInputError,
  ED25519_BY_PHRASE,
  FALCON_MAX_SIGNATURE_BYTES,
  MAX_STAGE_FEE_MICROALGOS,
  V42_PROTOCOL,
  attemptTransaction,
  computeBudget,
  exceedsApproved,
  makeFalconSigner,
  planMigration,
  planProblem,
  pqIdentityFromMnemonic,
  preparedMismatch,
  quoteMigration,
  quoteStage,
  readAccountForBudget,
  signedMismatch,
  signedSizeBound,
  signerFromAuthority,
  stageOf,
  PROTOCOL_RULES,
  type AccountReading,
  type BudgetInputs,
  type BudgetSpec,
  type FeeParams,
  type MigrationBudget,
  type StageShape,
} from '../src/index.js';
import { scriptedLedger, BASE_MIN_BALANCE } from './scripted-ledger.js';

const seeded = (fill: number) => {
  const account = algosdk.mnemonicToSecretKey(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill)));
  return { address: account.addr.toString(), account, signer: algosdk.makeBasicAccountTransactionSigner(account) };
};
const OWNER = seeded(21);
const AUTHORITY = seeded(22);
const TARGET = pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(23)));
const OTHER_PQ = pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(24)));
const GENESIS = { id: 'testnet-v1.0', hash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=' };
const RULES = PROTOCOL_RULES[V42_PROTOCOL]!;

const params = (over: Partial<FeeParams> = {}): FeeParams => ({
  genesis: GENESIS,
  protocol: V42_PROTOCOL,
  minFee: 1000n,
  feePerByte: 0n,
  round: 1000n,
  upgrade: null,
  ...over,
});
const account = (address: string, over: Partial<AccountReading> = {}): AccountReading => ({
  address,
  exists: true,
  balance: 10_000_000n,
  minBalance: 100_000n,
  authAddr: null,
  round: 1000n,
  ...over,
});
const absent = (address: string): AccountReading =>
  account(address, { exists: false, balance: 0n, minBalance: BASE_MIN_BALANCE });

const inputs = (over: { params?: Partial<FeeParams>; source?: Partial<AccountReading>; target?: AccountReading } = {}): BudgetInputs => ({
  params: params(over.params),
  source: account(OWNER.address, over.source),
  target: over.target ?? absent(TARGET.address),
});
const SPEC: BudgetSpec = { sender: OWNER.address, authorizer: OWNER.address, target: TARGET.address, signer: ED25519_BY_PHRASE };
const fee = (b: MigrationBudget, stage: string) => b.stages.find((s) => s.stage === stage)!.fee;

/* ------------------------------------------------------------------ */

describe('fees follow the network and the signer', () => {
  it('charges the minimum fee for Ed25519 and three times it for Falcon-1024, with no congestion', () => {
    const b = computeBudget(inputs(), SPEC);
    expect(b.status).toBe('available');
    expect(b.stages.map((s) => [s.stage, s.sender, s.scheme, s.fee])).toEqual([
      ['funding', OWNER.address, 'ed25519', 1000n],
      ['proof', TARGET.address, 'falcon-1024', 3000n],
      ['rekey', OWNER.address, 'ed25519', 1000n],
      ['verification', OWNER.address, 'falcon-1024', 3000n],
    ]);
    expect(b.postMigrationFee).toBe(3000n);
  });

  it('follows a changed minimum fee', () => {
    const b = computeBudget(inputs({ params: { minFee: 2500n } }), SPEC);
    expect(b.stages.map((s) => s.fee)).toEqual([2500n, 7500n, 2500n, 7500n]);
  });

  it('charges a nonzero per-byte fee on the signed length, envelope included', () => {
    const b = computeBudget(inputs({ params: { feePerByte: 10n } }), SPEC);
    for (const s of b.stages) {
      expect(s.feeQuote.congestionCharge).toBe(10n * BigInt(s.feeQuote.maxSignedBytes));
      expect(s.fee).toBe(s.feeQuote.congestionCharge > s.feeQuote.consensusMinimum ? s.feeQuote.congestionCharge : s.feeQuote.consensusMinimum);
    }
    // A Falcon envelope is over 3 kB, so its per-byte charge dwarfs an Ed25519 one.
    expect(fee(b, 'proof')).toBeGreaterThan(30_000n);
    expect(fee(b, 'funding')).toBeLessThan(3_000n);
  });

  it('prices the Falcon signer as Falcon when the account is already under a Falcon key', () => {
    const b = computeBudget(
      inputs({ source: { authAddr: OTHER_PQ.address } }),
      { ...SPEC, authorizer: OTHER_PQ.address, signer: signerFromAuthority({ authorityClass: 'post-quantum' }, OTHER_PQ.address) },
    );
    expect(b.status).toBe('available');
    expect(fee(b, 'funding')).toBe(3000n);
    expect(fee(b, 'rekey')).toBe(3000n);
  });

  it('prices a delegated signer with the authorizer named in its envelope', () => {
    const self: StageShape = { stage: 'rekey', sender: OWNER.address, authorizer: OWNER.address, receiver: OWNER.address, rekeyTo: TARGET.address, scheme: 'ed25519', transfers: false };
    const delegated = { ...self, authorizer: AUTHORITY.address };
    // `sgnr`: a 4-character key, and 32 bytes behind a two-byte header.
    expect(signedSizeBound(delegated, GENESIS) - signedSizeBound(self, GENESIS)).toBe(39);
    const pqSelf: StageShape = { stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, rekeyTo: null, scheme: 'falcon-1024', transfers: false };
    const pqDelegated: StageShape = { ...pqSelf, stage: 'verification', sender: OWNER.address, receiver: OWNER.address, authorizer: TARGET.address };
    expect(signedSizeBound(pqDelegated, GENESIS) - signedSizeBound(pqSelf, GENESIS)).toBe(39);
  });

  it('is not an Ed25519 size estimate: a Falcon envelope adds over 3 kB', () => {
    const shape: StageShape = { stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, rekeyTo: null, scheme: 'falcon-1024', transfers: false };
    const txn = attemptTransaction({ stage: 'proof', genesisId: GENESIS.id, genesisHash: GENESIS.hash, sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, amount: 0n, fee: 3000n, firstValid: 1000n, lastValid: 1050n, rekeyTo: null });
    // algosdk's estimate: the unsigned bytes plus 75 for an Ed25519 signature.
    const sdkEstimate = txn.toByte().length + 75;
    expect(signedSizeBound(shape, GENESIS) - sdkEstimate).toBeGreaterThan(3000);
  });

  it('refuses a fee above the ceiling this tool will pay', () => {
    const b = computeBudget(inputs({ params: { feePerByte: 1000n } }), SPEC);
    expect(b.status).toBe('blocked');
    expect(b.problems.join(' ')).toContain(`above the ${Number(MAX_STAGE_FEE_MICROALGOS) / 1e6} ALGO`);
  });
});

describe('the size bound holds against real encodings', () => {
  it('never falls below a real Falcon-1024 signing, whatever the signature length', async () => {
    const pqSelf: StageShape = { stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, rekeyTo: null, scheme: 'falcon-1024', transfers: false };
    const pqDelegated: StageShape = { stage: 'verification', sender: OWNER.address, authorizer: TARGET.address, receiver: OWNER.address, rekeyTo: null, scheme: 'falcon-1024', transfers: false };
    const self = makeFalconSigner(TARGET);
    const delegated = makeFalconSigner(TARGET, OWNER.address);
    let shortest = Infinity;
    let longest = 0;
    let longestSigned = { self: 0, delegated: 0 };
    // Fees and rounds across every msgpack width, so the fee field's own
    // encoding is covered too.
    const values = [1n, 127n, 128n, 255n, 256n, 65_535n, 65_536n, 4_294_967_295n, 4_294_967_296n, (1n << 64n) - 1n];
    for (let i = 0; i < 120; i++) {
      const v = values[i % values.length]!;
      const fv = values[(i * 7) % values.length]!;
      for (const [shape, signer, key] of [[pqSelf, self, 'self'], [pqDelegated, delegated, 'delegated']] as const) {
        const txn = attemptTransaction({
          stage: shape.stage, genesisId: GENESIS.id, genesisHash: GENESIS.hash,
          sender: shape.sender, authorizer: shape.authorizer, receiver: shape.receiver,
          amount: 0n, fee: v, firstValid: fv, lastValid: fv, rekeyTo: null,
        });
        const [signed] = await signer([txn], [0]);
        const sig = algosdk.decodeSignedTransaction(signed!).pqsig!.sig.length;
        shortest = Math.min(shortest, sig);
        longest = Math.max(longest, sig);
        longestSigned = { ...longestSigned, [key]: Math.max(longestSigned[key], signed!.length) };
        expect(signed!.length).toBeLessThanOrEqual(signedSizeBound(shape, GENESIS));
      }
    }
    // The signature length really does vary, and stays inside the bound's maximum.
    expect(longest).toBeGreaterThan(shortest);
    expect(longest).toBeLessThanOrEqual(FALCON_MAX_SIGNATURE_BYTES);
    expect(signedSizeBound(pqSelf, GENESIS) - longestSigned.self).toBeLessThan(FALCON_MAX_SIGNATURE_BYTES - shortest + 40);
  });

  it('never falls below a real Ed25519 signing, own or delegated, with any amount', async () => {
    const funding: StageShape = { stage: 'funding', sender: OWNER.address, authorizer: AUTHORITY.address, receiver: TARGET.address, rekeyTo: null, scheme: 'ed25519', transfers: true };
    for (const amount of [1n, 200_000n, (1n << 64n) - 1n]) {
      for (const f of [1000n, 65_536n, (1n << 64n) - 1n]) {
        const txn = attemptTransaction({ stage: 'funding', genesisId: GENESIS.id, genesisHash: GENESIS.hash, sender: OWNER.address, authorizer: AUTHORITY.address, receiver: TARGET.address, amount, fee: f, firstValid: (1n << 64n) - 1n, lastValid: (1n << 64n) - 1n, rekeyTo: null });
        const stxn = new algosdk.SignedTransaction({ txn, sig: txn.rawSignTxn(AUTHORITY.account.sk), sgnr: algosdk.Address.fromString(AUTHORITY.address) });
        expect(algosdk.encodeMsgpack(stxn).length).toBeLessThanOrEqual(signedSizeBound(funding, GENESIS));
      }
    }
  });
});

describe('balances and minimums', () => {
  it('charges the source the transfer and its own fees, never the proof fee paid from the transfer', () => {
    const b = computeBudget(inputs(), SPEC);
    expect(b.totals).toEqual({
      feeExpense: 8000n,
      sourceFees: 5000n,
      targetProofExpense: 3000n,
      // The new address's minimum balance, and its proof fee.
      transfer: 103_000n,
      reserve: 0n,
      sourceDebit: 108_000n,
      sourceRequired: 208_000n,
      sourceRetained: 10_000_000n - 108_000n,
      targetRetained: 100_000n,
    });
    expect(b.stages.map((s) => s.after)).toEqual([
      { source: 10_000_000n - 104_000n, target: 103_000n },
      { source: 10_000_000n - 104_000n, target: 100_000n },
      { source: 10_000_000n - 105_000n, target: 100_000n },
      { source: 10_000_000n - 108_000n, target: 100_000n },
    ]);
  });

  it('is affordable at exactly the required balance, and blocked one microAlgo short', () => {
    const exact = computeBudget(inputs({ source: { balance: 208_000n } }), SPEC);
    expect(exact.status).toBe('available');
    expect(exact.totals!.sourceRetained).toBe(100_000n);
    const short = computeBudget(inputs({ source: { balance: 207_999n } }), SPEC);
    expect(short.status).toBe('blocked');
    expect(short.problems[0]).toContain('short by 0.000001 ALGO');
    // It is the final step, the verification after the rekey, that crosses the minimum.
    expect(short.problems[0]).toContain('at "verification"');
    expect(planProblem(planMigration(stub(), TARGET.address, { budget: short }))).toContain('short by');
  });

  it('funds only the target’s shortfall when it already holds some', () => {
    const b = computeBudget(inputs({ target: account(TARGET.address, { balance: 150_000n }) }), SPEC);
    expect(b.stages[0]!.amount).toBe(0n);
    const partial = computeBudget(inputs({ target: account(TARGET.address, { balance: 50_000n, exists: true }) }), SPEC);
    expect(partial.stages[0]!.amount).toBe(53_000n);
    expect(partial.totals!.targetRetained).toBe(100_000n);
  });

  it('sends a zero-value funding, fee shown, when the target already holds enough', () => {
    const b = computeBudget(inputs({ target: account(TARGET.address, { balance: 1_000_000n }) }), SPEC);
    expect(b.status).toBe('available');
    expect(b.stages[0]).toMatchObject({ stage: 'funding', amount: 0n, fee: 1000n });
    expect(b.totals).toMatchObject({ transfer: 0n, sourceDebit: 5000n, targetRetained: 997_000n });
    expect(b.assumptions.join(' ')).toContain('sends nothing');
  });

  it('uses the target’s actual minimum when it exists, and the creation rule when it does not', () => {
    const holding = computeBudget(inputs({ target: account(TARGET.address, { balance: 250_000n, minBalance: 300_000n }) }), SPEC);
    expect(holding.stages[0]!.amount).toBe(53_000n);
    const fresh = computeBudget(inputs(), SPEC);
    expect(fresh.target).toMatchObject({ exists: false, minBalance: RULES.baseMinBalance });
    expect(fresh.assumptions.join(' ')).toContain('does not exist yet');
  });

  it('follows a changed minimum balance on the source', () => {
    const before = computeBudget(inputs({ source: { balance: 1_300_000n } }), SPEC);
    expect(before.status).toBe('available');
    // Opting into assets raises the minimum between two readings.
    const after = computeBudget(inputs({ source: { balance: 1_300_000n, minBalance: 1_200_000n } }), SPEC);
    expect(after.status).toBe('blocked');
    expect(after.totals!.sourceRequired).toBe(1_308_000n);
  });

  it('adds only an explicitly labelled reserve', () => {
    const b = computeBudget(inputs(), { ...SPEC, reserve: 50_000n });
    expect(b.totals).toMatchObject({ transfer: 153_000n, reserve: 50_000n, targetRetained: 150_000n });
    expect(b.assumptions.join(' ')).toContain('reserve of 0.05 ALGO');
  });

  it('prices only the remaining steps, from current balances, so a confirmed transfer is not counted again', () => {
    // After the funding confirmed: the target holds it, the source paid it.
    const b = computeBudget(
      inputs({ source: { balance: 10_000_000n - 104_000n }, target: account(TARGET.address, { balance: 103_000n }) }),
      { ...SPEC, from: 'proof' },
    );
    expect(b.stages.map((s) => s.stage)).toEqual(['proof', 'rekey', 'verification']);
    expect(b.totals).toMatchObject({ transfer: 0n, sourceDebit: 4000n, targetProofExpense: 3000n });
  });

  it('blocks rather than tops up a target that can no longer pay its proof', () => {
    const b = computeBudget(inputs({ target: account(TARGET.address, { balance: 101_000n }) }), { ...SPEC, from: 'proof' });
    expect(b.status).toBe('blocked');
    expect(b.stages.map((s) => s.stage)).not.toContain('funding');
    expect(b.problems.join(' ')).toContain('Nothing tops it up automatically');
  });

  it('expects the new key as the authority once only the verification remains', () => {
    const ok = computeBudget(inputs({ source: { authAddr: TARGET.address } }), { ...SPEC, from: 'verification' });
    expect(ok.status).toBe('available');
    expect(ok.stages.map((s) => [s.stage, s.authorizer])).toEqual([['verification', TARGET.address]]);
    const stale = computeBudget(inputs(), { ...SPEC, from: 'verification' });
    expect(stale.status).toBe('blocked');
  });

  it('blocks when the account answers to someone else, or the target is rekeyed away', () => {
    const moved = computeBudget(inputs({ source: { authAddr: AUTHORITY.address } }), SPEC);
    expect(moved.problems.join(' ')).toContain(`answers to ${AUTHORITY.address}`);
    const rekeyedTarget = computeBudget(inputs({ target: account(TARGET.address, { authAddr: OTHER_PQ.address }) }), SPEC);
    expect(rekeyedTarget.problems.join(' ')).toContain('cannot sign the proof');
  });

  it('prices a plan without the drill as the rekey and its verification only', () => {
    const b = computeBudget(inputs(), { ...SPEC, drill: false });
    expect(b.stages.map((s) => s.stage)).toEqual(['rekey', 'verification']);
    expect(b.totals).toMatchObject({ transfer: 0n, sourceDebit: 4000n, targetRetained: 0n });
  });
});

describe('unsupported assumptions are refused, never priced', () => {
  it('names each unsupported signer', () => {
    for (const authorityClass of ['classical-multisig', 'logicsig', 'unknown-hash-derived'] as const) {
      const signer = signerFromAuthority({ authorityClass }, AUTHORITY.address);
      expect(signer.supported).toBe(false);
      const b = computeBudget(inputs(), { ...SPEC, signer });
      expect(b.status).toBe('blocked');
      expect(b.stages).toEqual([]);
    }
    expect(signerFromAuthority(undefined, TARGET.address).supported).toBe(false);
    expect(signerFromAuthority({ authorityClass: 'classical-key' }, OWNER.address)).toMatchObject({ supported: true, scheme: 'ed25519' });
  });

  it('does not need the source signer once only Falcon-signed steps remain', () => {
    const signer = signerFromAuthority({ authorityClass: 'logicsig' }, AUTHORITY.address);
    const b = computeBudget(inputs({ source: { authAddr: TARGET.address } }), { ...SPEC, signer, from: 'verification' });
    expect(b.status).toBe('available');
  });

  it('leaves the budget unavailable on another protocol, a scheduled upgrade, or no inputs', () => {
    expect(computeBudget(inputs({ params: { protocol: 'future' } }), SPEC).status).toBe('unavailable');
    expect(computeBudget(inputs({ params: { upgrade: { protocol: 'future', round: 1050n } } }), SPEC).status).toBe('unavailable');
    expect(computeBudget(inputs({ params: { upgrade: { protocol: 'future', round: 5000n } } }), SPEC).status).toBe('available');
    const none = computeBudget(null, SPEC);
    expect(none).toMatchObject({ status: 'unavailable', totals: null, stages: [] });
    expect(computeBudget(inputs({ params: { minFee: 0n } }), SPEC).status).toBe('unavailable');
    expect(computeBudget(inputs({ source: { round: 1200n } }), SPEC).problems[0]).toContain('too many rounds apart');
  });

  it('refuses unsafe integers from the node rather than rounding them', async () => {
    const l = scriptedLedger({ accounts: { [OWNER.address]: {} } });
    const base = l.clients.algod;
    const answering = (amount: unknown) => ({
      ...l.clients,
      algod: Object.assign(Object.create(base), {
        accountInformation: () => ({ do: async () => ({ address: OWNER.address, amount, minBalance: 100_000n, round: 1000n }) }),
      }),
    });
    for (const amount of [2 ** 53 + 2, -1, 1.5, '100', 1n << 64n]) {
      await expect(readAccountForBudget(answering(amount), OWNER.address)).rejects.toBeInstanceOf(BudgetInputError);
    }
    const b = await quoteMigration(answering(2 ** 60), SPEC);
    expect(b.status).toBe('unavailable');
  });
});

describe('reading the inputs', () => {
  it('reads parameters, status and both accounts, and tells an absent target from a failed lookup', async () => {
    const l = scriptedLedger({ accounts: { [OWNER.address]: {} } });
    const b = await quoteMigration(l.clients, SPEC);
    expect(b.status).toBe('available');
    expect(b.target!.exists).toBe(false);
    expect([...l.requests].sort()).toEqual(['account ' + OWNER.address, 'account ' + TARGET.address, 'params', 'status'].sort());
    expect(l.landed).toHaveLength(0);

    l.fail('account', 'server-error', (who) => who === TARGET.address);
    const failed = await quoteMigration(l.clients, SPEC);
    expect(failed.status).toBe('unavailable');
    expect(failed.problems[0]).toContain('could not be read');
  });

  it('is unavailable while the node catches up, or answers malformed parameters', async () => {
    const l = scriptedLedger({ accounts: { [OWNER.address]: {} } });
    l.setCatchingUp(true);
    expect((await quoteMigration(l.clients, SPEC)).problems[0]).toContain('catching up');
    l.setCatchingUp(false);
    l.fail('params', 'malformed');
    expect((await quoteMigration(l.clients, SPEC)).status).toBe('unavailable');
  });

  it('refuses parameters and status read too many rounds apart, and dates a quote by the older', async () => {
    const step = { stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, rekeyTo: null, scheme: 'falcon-1024', amount: 0n } as const;
    for (const method of ['params', 'status'] as const) {
      const l = scriptedLedger({ accounts: { [OWNER.address]: {} } });
      const answer = method === 'params'
        ? { ...await l.clients.algod.getTransactionParams().do(), firstValid: l.round - 11n }
        : { ...await l.clients.algod.status().do(), lastRound: l.round - 11n };
      l.failTimes(method, { answer }, 2);
      const b = await quoteMigration(l.clients, SPEC);
      expect(b).toMatchObject({ status: 'unavailable', stages: [] });
      expect(b.problems[0]).toContain('too many rounds apart');
      await expect(quoteStage(l.clients, step)).rejects.toBeInstanceOf(BudgetInputError);

      const lagging = method === 'params' ? { ...answer, firstValid: l.round - 10n } : { ...answer, lastRound: l.round - 10n };
      l.failTimes(method, { answer: lagging }, 2);
      expect((await quoteMigration(l.clients, SPEC)).observed!.round).toBe(l.round - 10n);
      expect((await quoteStage(l.clients, step)).validThroughRound).toBe(l.round - 10n + 50n);
      expect(l.landed).toHaveLength(0);
    }
  });

  it('follows the simulated congestion and minimum fee the node reports', async () => {
    const l = scriptedLedger({ accounts: { [OWNER.address]: {} } });
    l.setMinFee(2000n);
    l.setFeePerByte(2n);
    const b = await quoteMigration(l.clients, SPEC);
    expect(b.observed).toMatchObject({ minFee: 2000n, feePerByte: 2n });
    expect(fee(b, 'funding')).toBe(2000n);
    expect(fee(b, 'proof')).toBe(6000n + 0n > 2n * BigInt(b.stages[1]!.feeQuote.maxSignedBytes) ? 6000n : 2n * BigInt(b.stages[1]!.feeQuote.maxSignedBytes));
  });
});

describe('holding a run to what was approved', () => {
  const approved = computeBudget(inputs(), SPEC);

  it('accepts the same or lower figures', () => {
    expect(exceedsApproved(approved, approved)).toBeNull();
    const lower = computeBudget(inputs({ target: account(TARGET.address, { balance: 50_000n }) }), SPEC);
    expect(exceedsApproved(approved, lower)).toBeNull();
  });

  it('refuses a higher fee, a larger transfer, a blocked reading or another network', () => {
    expect(exceedsApproved(approved, computeBudget(inputs({ params: { minFee: 1001n } }), SPEC))).toContain('now needs a fee');
    const moreFunding = computeBudget(inputs({ target: account(TARGET.address, { balance: 10_000n, minBalance: 200_000n }) }), SPEC);
    expect(exceedsApproved(approved, moreFunding)).toContain('now needs to send');
    expect(exceedsApproved(approved, computeBudget(inputs({ source: { balance: 1000n } }), SPEC))).toContain('blocked');
    expect(exceedsApproved(approved, computeBudget(inputs({ params: { genesis: { id: 'other', hash: GENESIS.hash } } }), SPEC))).toContain('not testnet');
  });

  it('refuses a prepared transaction that is not the budgeted one, and a stale quote', () => {
    const stage = stageOf(approved, 'funding');
    const attempt = {
      txId: 'X', stage: 'funding' as const, genesisId: GENESIS.id, genesisHash: GENESIS.hash,
      sender: OWNER.address, authorizer: OWNER.address, receiver: TARGET.address,
      amount: stage.amount, fee: stage.fee, firstValid: 1000n, lastValid: 1050n, rekeyTo: null,
    };
    expect(preparedMismatch(attempt, stage)).toBeNull();
    expect(preparedMismatch({ ...attempt, fee: stage.fee + 1n }, stage)).toContain('fee');
    expect(preparedMismatch({ ...attempt, amount: stage.amount + 1n }, stage)).toContain('amount');
    expect(preparedMismatch({ ...attempt, firstValid: stage.validThroughRound + 1n }, stage)).toContain('too long ago');
  });

  it('refuses a signature of another scheme, another fee, or a length its fee does not cover', async () => {
    const stage = stageOf(approved, 'funding');
    const txn = attemptTransaction({ stage: 'funding', genesisId: GENESIS.id, genesisHash: GENESIS.hash, sender: OWNER.address, authorizer: OWNER.address, receiver: TARGET.address, amount: stage.amount, fee: stage.fee, firstValid: 1000n, lastValid: 1050n, rekeyTo: null });
    const [ed] = await OWNER.signer([txn], [0]);
    expect(signedMismatch(ed!, stage)).toBeNull();
    const [pq] = await makeFalconSigner(TARGET, OWNER.address)([txn], [0]);
    expect(signedMismatch(pq!, stage)).toContain('falcon-1024, not the ed25519');
    expect(signedMismatch(ed!, { ...stage, fee: stage.fee + 1n })).toContain('not the budgeted');
    expect(signedMismatch(ed!, { ...stage, feeQuote: { ...stage.feeQuote, maxSignedBytes: 100 } })).toContain('longer than');
    expect(signedMismatch(ed!, { ...stage, feeQuote: { ...stage.feeQuote, consensusMinimum: stage.fee + 1n } })).toContain('below the');
    expect(signedMismatch(new Uint8Array([1, 2, 3]), stage)).toContain('do not decode');
  });
});

describe('the plan states the budget it was given, and no other', () => {
  it('states no costs without live inputs, and does not call that a blocker', () => {
    const plan = planMigration(stub(), TARGET.address);
    expect(plan.budget.status).toBe('unavailable');
    expect(plan.estimatedFeeMicroAlgos).toBeNull();
    expect(plan.postMigrationFeeMicroAlgos).toBeNull();
    expect(plan.steps.every((s) => s.feeMicroAlgos === null)).toBe(true);
    expect(plan.blockers).toEqual([]);
    expect(planProblem(plan)).toContain('unavailable');
  });

  it('takes its step fees and transfer from the budget', () => {
    const budget = computeBudget(inputs(), SPEC);
    const plan = planMigration(stub(), TARGET.address, { budget });
    expect(plan.steps.map((s) => s.feeMicroAlgos)).toEqual([1000n, 3000n, 1000n, 3000n]);
    expect(plan.estimatedFeeMicroAlgos).toBe(8000n);
    expect(plan.steps[0]!.detail).toContain('Send 0.103 ALGO');
    expect(planProblem(plan)).toBeNull();
    expect(plan.warnings.join(' ')).toContain('needs 0.003 ALGO, where an Ed25519-signed one needs 0.001 ALGO');
  });

  it('refuses a budget made for another migration', () => {
    const budget = computeBudget(inputs(), { ...SPEC, drill: false });
    expect(planMigration(stub(), TARGET.address, { budget }).budget.problems[0]).toContain('different migration');
  });
});

function stub(): any {
  return {
    address: OWNER.address,
    authAddr: undefined,
    authority: { authorityClass: 'classical-key' },
    isPostQuantum: false,
    microAlgos: 10_000_000n,
    minBalance: 100_000n,
    createdAssets: [],
    foreignRoles: [],
    controlsAccounts: [],
  };
}
