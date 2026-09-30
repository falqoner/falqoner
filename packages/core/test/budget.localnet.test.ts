/**
 * The migration budget against a real LocalNet node (SAFE-03a).
 *
 * The node's consensus, fee checks and minimum balances are real: every
 * boundary here is decided by algod 5.0.2, not by the model. What LocalNet
 * cannot show is congestion - its pool reports no per-byte fee - so the
 * per-byte charge is covered by the offline tests against simulated values,
 * and nothing here claims to have met it.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  ED25519_BY_PHRASE,
  V42_PROTOCOL,
  fundPqAddress,
  generatePqIdentity,
  makeFalconSigner,
  prepareAttempt,
  prepareFunding,
  prepareStage,
  proveControl,
  quoteMigration,
  rekeyToPq,
  sendAttempt,
  signAttempt,
  signStage,
  stageOf,
  submitAndConfirm,
  verifyMigration,
  type AttemptSpec,
  type MigrationBudget,
  type PqIdentity,
  type StageBudget,
} from '../src/index.js';
import { dispenser, fundedAccount, localnet, type LocalAccount } from './helpers.js';

const clients = localnet();
let funder: LocalAccount;

beforeAll(async () => {
  funder = await dispenser(clients);
});

const balance = async (address: string) => BigInt((await clients.algod.accountInformation(address).do()).amount);

const quote = (account: LocalAccount, target: PqIdentity, from?: StageBudget['stage']) =>
  quoteMigration(clients, { sender: account.address, authorizer: account.address, target: target.address, signer: ED25519_BY_PHRASE, from });

/** Send `stage` with its fee lowered by one microAlgo; the node must refuse it. */
async function refusedOneShort(stage: StageBudget, signer: algosdk.TransactionSigner) {
  const spec: AttemptSpec = { ...stage, fee: stage.fee - 1n };
  const prepared = await prepareAttempt(clients, spec);
  const sent = await sendAttempt(clients, prepared, await signAttempt(prepared, signer));
  expect(sent.status).toBe('rejected');
  expect((sent as { reason: string }).reason).toMatch(/fee/i);
}

/** Send `stage` exactly as budgeted; return its signed length. */
async function landed(stage: StageBudget, signer: algosdk.TransactionSigner): Promise<number> {
  const prepared = await prepareStage(clients, stage);
  const signed = await signStage(prepared, signer, stage);
  await submitAndConfirm(clients, prepared, () => Promise.resolve([signed]));
  return signed.length;
}

describe('the budget against real consensus', () => {
  it('reads the node’s protocol, fees and minimum balances', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const b = await quote(account, generatePqIdentity());
    expect(b.status).toBe('available');
    expect(b.observed).toMatchObject({ protocol: V42_PROTOCOL, rules: 'v42', minFee: 1000n, feePerByte: 0n });
    expect(b.source).toMatchObject({ balance: 5_000_000n, minBalance: 100_000n });
    expect(b.target).toMatchObject({ exists: false, balance: 0n, minBalance: 100_000n });
  });

  it('prices every step at exactly what the node accepts, and the node refuses one microAlgo less', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const approved: MigrationBudget = await quote(account, target);
    expect(approved.stages.map((s) => [s.stage, s.amount, s.fee])).toEqual([
      ['funding', 103_000n, 1000n],
      ['proof', 0n, 3000n],
      ['rekey', 0n, 1000n],
      ['verification', 0n, 3000n],
    ]);
    const before = await balance(account.address);
    const signers = {
      funding: account.signer,
      proof: makeFalconSigner(target),
      rekey: account.signer,
      verification: makeFalconSigner(target, account.address),
    };
    const lengths: number[] = [];
    for (const name of ['funding', 'proof', 'rekey', 'verification'] as const) {
      // Each step from a fresh reading, as the page does, never above the approval.
      const stage = stageOf(await quote(account, target, name), name);
      expect(stage.fee).toBeLessThanOrEqual(stageOf(approved, name).fee);
      await refusedOneShort(stage, signers[name]);
      const length = await landed(stage, signers[name]);
      // The size bound holds against encodings the node accepted.
      expect(length).toBeLessThanOrEqual(stage.feeQuote.maxSignedBytes);
      lengths.push(length);
    }
    // Falcon envelopes, own and delegated: the delegated one names its signer.
    expect(lengths[1]).toBeGreaterThan(3000);
    expect(lengths[3]).toBeGreaterThan(lengths[1]!);

    // The ledger's accounting matches the budget's to the microAlgo: the
    // account paid the transfer and its three fees, the new address paid its
    // proof from the transfer and keeps exactly its minimum.
    const t = approved.totals!;
    expect(before - (await balance(account.address))).toBe(t.sourceDebit);
    expect(t.sourceDebit).toBe(108_000n);
    expect(await balance(target.address)).toBe(t.targetRetained);
    expect(t.targetRetained).toBe(100_000n);
    expect((await clients.algod.accountInformation(account.address).do()).authAddr?.toString()).toBe(target.address);
  });

  it('creates the new address only at its minimum balance, and leaves it exactly there', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const funding = stageOf(await quote(account, target), 'funding');
    // One microAlgo short of what creating it takes: the node refuses it.
    const short = await prepareAttempt(clients, { ...funding, amount: 99_999n });
    const refused = await sendAttempt(clients, short, await signAttempt(short, account.signer));
    expect(refused.status).toBe('rejected');
    expect((refused as { reason: string }).reason).toMatch(/min/i);
    await landed(funding, account.signer);
    await proveControl(clients, target);
    expect(await balance(target.address)).toBe(100_000n);
    // It can pay for nothing more: a second proof would take it below its minimum.
    const b = await quote(account, target, 'proof');
    expect(b.status).toBe('blocked');
    expect(b.problems.join(' ')).toContain('below its minimum balance');
  });

  it('runs the whole ceremony from exactly the required balance, and refuses one microAlgo less before sending', async () => {
    const exact = await fundedAccount(clients, funder, 208_000n);
    const target = generatePqIdentity();
    const b = await quote(exact, target);
    expect(b).toMatchObject({ status: 'available' });
    expect(b.totals!.sourceRequired).toBe(208_000n);
    await fundPqAddress(clients, exact, target.address);
    await proveControl(clients, target);
    await rekeyToPq(clients, exact, target.address);
    expect(await verifyMigration(clients, exact.address, target)).toMatchObject({ controlProven: true });
    // The account ends at exactly its minimum balance.
    expect(await balance(exact.address)).toBe(100_000n);

    const short = await fundedAccount(clients, funder, 207_999n);
    const other = generatePqIdentity();
    const blocked = await quote(short, other);
    expect(blocked.status).toBe('blocked');
    expect(blocked.problems[0]).toContain('short by 0.000001 ALGO');
    await expect(prepareFunding(clients, { address: short.address }, other.address)).rejects.toThrow(/budget is blocked/);
    expect(await balance(short.address)).toBe(207_999n);
    expect(await balance(other.address)).toBe(0n);
  });

  it('sends a zero-value funding, fee only, to a target that already holds enough', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    await submitAndConfirm(
      clients,
      await prepareAttempt(clients, { stage: 'funding', sender: funder.address, authorizer: funder.address, receiver: target.address, amount: 500_000n, fee: 1000n }),
      funder.signer,
    );
    const b = await quote(account, target);
    expect(b.stages[0]).toMatchObject({ stage: 'funding', amount: 0n, fee: 1000n });
    expect(b.totals).toMatchObject({ transfer: 0n, sourceDebit: 5000n, targetRetained: 497_000n });
    const before = await balance(account.address);
    await landed(b.stages[0]!, account.signer);
    await proveControl(clients, target);
    expect(before - (await balance(account.address))).toBe(1000n);
    expect(await balance(target.address)).toBe(497_000n);
  });
});
