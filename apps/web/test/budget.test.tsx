/**
 * @vitest-environment jsdom
 */
/**
 * The budget, mounted (SAFE-03a).
 *
 * Migrating or continuing approves the budget on screen. Before each step the
 * page reads it again, and a step that would cost more than was approved, or
 * that the account can no longer afford, is not sent: the run stops with the
 * new reading on screen, and only continuing approves it. After a reload
 * nothing is approved until the operator continues again.
 *
 * Every figure here comes from the scripted ledger, which enforces algod's
 * fee and minimum-balance checks on each send. A nonzero fee per byte is
 * simulated congestion, not a node condition.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as Core from '@falconer/core';
import type { AccountExposure, PqIdentity } from '@falconer/core';

const mocks = vi.hoisted(() => ({
  analyzeAccount: vi.fn(),
  clientsFor: vi.fn(),
  generatePqIdentity: vi.fn(),
  preflight: vi.fn(),
}));

vi.mock('@falconer/core', async (importOriginal) => ({
  ...(await importOriginal<typeof Core>()),
  ...mocks,
}));

import algosdk from 'algosdk';
import { prepareFunding, sendAttempt, signAttempt } from '@falconer/core';
import type { Stage } from '../src/operation';
import { JOURNAL_KEY, newRecord, serializeRecord, type MigrationRecord } from '../src/journal';
import {
  A,
  SIGNER,
  STAGE_LIST,
  T1,
  TIMING,
  click,
  expectNoSecrets,
  exposureOf,
  installCore,
  landedStages,
  mount,
  queries,
  reload,
  setValue,
  settle,
  stageOfSigned,
  stored,
  unmount,
  until,
  type Page,
  type World,
} from './harness';
import { LOCAL_GENESIS } from './fixtures';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let EXPOSURE_A: AccountExposure;
let world: World;
let page: Page;
const $ = queries(() => page);
const local = () => world.ledgers.localnet;
const fetchTrap = vi.fn(() => Promise.reject(new Error('offline test: network access refused')));

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchTrap);
  vi.spyOn(XMLHttpRequest.prototype, 'open').mockImplementation(() => {
    throw new Error('offline test: network access refused');
  });
  EXPOSURE_A = await exposureOf(A);
});

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  world = installCore(mocks);
  page = mount({ timing: TIMING });
});

afterEach(() => {
  unmount(page);
  expect(fetchTrap).not.toHaveBeenCalled();
  expect(XMLHttpRequest.prototype.open).not.toHaveBeenCalled();
  const text = stored();
  if (text) expectNoSecrets(text);
});

const at = (stage: Stage | '', s: string) => () => $.status() === s && ($.panel()?.dataset.stage ?? '') === stage;
const verified = at('verification', 'confirmed');
const fees = () => local().landed.map((s) => s.txn.fee);
/** The budget on screen, one row per step: [step, amount, fee]. */
const shown = () =>
  Array.from(document.querySelectorAll('[data-budget-stage]'), (row) => [
    row.getAttribute('data-budget-stage'),
    BigInt(row.getAttribute('data-amount')!),
    BigInt(row.getAttribute('data-fee')!),
  ]);
const budgetFrom = (from: Stage) =>
  until(() => $.q('[data-budget]')?.getAttribute('data-budget-from') === from && !$.q('[data-budget-reading]'), `the budget from ${from}`);

/** Scan, generate, and type both phrases. The budget is on screen. */
async function readyToMigrate(): Promise<PqIdentity> {
  await settle(() => setValue($.networkSelect(), 'localnet'));
  await settle(() => setValue($.addressInput(), A));
  await settle(() => click($.button('Scan')!));
  await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
  await settle(() => click($.button('Generate a post-quantum key')!));
  const target = mocks.generatePqIdentity.mock.results.at(-1)!.value as PqIdentity;
  await settle(() => setValue($.transcription()!, target.mnemonic!));
  await settle(() => setValue($.signing()!, SIGNER.phrase));
  await budgetFrom('funding');
  return target;
}

async function continueWith(signingPhrase?: string) {
  if (signingPhrase && $.signing()) await settle(() => setValue($.signing()!, signingPhrase));
  await settle(() => click($.continueButton()!));
}

describe('the budget binds the run', () => {
  it('runs within the budget on screen, with the ledger’s own accounting', async () => {
    const target = await readyToMigrate();
    expect(shown()).toEqual([['funding', 103_000n, 1000n], ['proof', 0n, 3000n], ['rekey', 0n, 1000n], ['verification', 0n, 3000n]]);
    expect($.q('[data-budget-source]')!.textContent).toContain('0.108 ALGO in all');
    expect($.q('[data-budget-target]')!.textContent).toContain('keeps 0.1 ALGO');
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration');
    expect(fees()).toEqual([1000n, 3000n, 1000n, 3000n]);
    expect(local().balance(A)).toBe(10_000_000n - 108_000n);
    expect(local().balance(target.address)).toBe(100_000n);
    // Afterwards the page shows the budget the run was approved on, and the
    // plan priced by it; it never claims that nothing was read.
    expect($.q('[data-budget-settled]')).not.toBeNull();
    expect(shown()).toEqual([['funding', 103_000n, 1000n], ['proof', 0n, 3000n], ['rekey', 0n, 1000n], ['verification', 0n, 3000n]]);
    expect($.text()).toContain('Send 0.103 ALGO to');
    expect($.text()).not.toContain('none were read');
    expect($.text()).not.toContain('No live parameters were read');
  });

  it('stops before sending when the fee rises after approval, and goes on only once the new budget is approved', async () => {
    await readyToMigrate();
    // As soon as the proof is in, the network's minimum fee rises.
    local().onSend((s) => {
      if (stageOfSigned(s) === 'proof') local().setMinFee(1001n);
    });
    await settle(() => click($.button('Migrate')!));
    await until(at('rekey', 'failed'), 'the run to stop');
    // Nothing was sent for the rekey, or recorded for it.
    expect(landedStages(local())).toEqual(['funding', 'proof']);
    expect(JSON.parse(stored()!).attempts.map((a: { stage: string }) => a.stage)).toEqual(['funding', 'proof']);
    expect(local().authority(A)).toBe(A);
    expect($.q('[data-error]')!.textContent).toContain('Nothing was sent for this step. The budget changed since it was approved.');
    expect($.q('[data-error]')!.textContent).toContain('Review the budget below: going on approves it.');
    expect($.q('[data-budget-changed]')!.textContent).toContain('"rekey" now needs a fee of 0.001001 ALGO; 0.001 ALGO was approved');
    expect(shown()).toEqual([['rekey', 0n, 1001n], ['verification', 0n, 3003n]]);
    // Continuing approves the reading on screen, and the run finishes within it.
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration');
    expect(fees()).toEqual([1000n, 3000n, 1001n, 3003n]);
  });

  it('never tops up a new address that can no longer pay its proof: it waits for funds from elsewhere', async () => {
    const target = await readyToMigrate();
    // The funding was exactly enough for a 0.003 ALGO proof; the fee then rises.
    local().onSend((s) => {
      if (stageOfSigned(s) === 'funding') local().setMinFee(1001n);
    });
    await settle(() => click($.button('Migrate')!));
    await until(at('proof', 'failed'), 'the run to stop');
    expect(landedStages(local())).toEqual(['funding']);
    expect($.q('[data-budget]')!.getAttribute('data-budget-status')).toBe('blocked');
    expect($.q('[data-budget-problems]')!.textContent).toContain('Nothing tops it up automatically');
    expect($.continueButton()!.disabled).toBe(true);
    // Topped up from outside this page, and the budget read again.
    local().setBalance(target.address, local().balance(target.address) + 3n);
    await settle(() => click($.button('Read the budget again')!));
    await budgetFrom('proof');
    expect($.q('[data-budget]')!.getAttribute('data-budget-status')).toBe('available');
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration');
    // Still exactly one funding: the page sent no second one.
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(fees()).toEqual([1000n, 3003n, 1001n, 3003n]);
    expect(local().balance(target.address)).toBe(100_000n);
  });

  it('refuses a reading older than the fee on the network, and Migrate then approves the fresh one', async () => {
    await readyToMigrate();
    // Between the reading on screen and the click.
    local().setMinFee(1500n);
    await settle(() => click($.button('Migrate')!));
    await until(at('', 'failed'), 'the refusal');
    expect(local().count('send')).toBe(0);
    expect(stored()).toBeNull();
    expect($.q('[data-budget-changed]')).not.toBeNull();
    // The new reading is on screen: the minimum balance and a dearer proof.
    expect(shown()[0]).toEqual(['funding', 104_500n, 1500n]);
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration');
    expect(fees()).toEqual([1500n, 4500n, 1500n, 4500n]);
    // The new address was sent its minimum and its proof fee at the new rate.
    expect(local().landed[0]!.txn.payment!.amount).toBe(104_500n);
  });

  it('stops, sending nothing more, when the account can no longer afford the rest, and never tops anything up', async () => {
    await readyToMigrate();
    // Drained from elsewhere as the funding lands.
    local().onSend((s) => {
      if (stageOfSigned(s) === 'funding') local().setBalance(A, 150_000n);
    });
    await settle(() => click($.button('Migrate')!));
    await until(at('proof', 'failed'), 'the run to stop');
    expect(landedStages(local())).toEqual(['funding']);
    expect($.q('[data-budget]')!.getAttribute('data-budget-status')).toBe('blocked');
    expect($.q('[data-budget-problems]')!.textContent).toContain('the migration needs');
    // A blocked reading cannot be approved, and the page does not suggest it can.
    expect($.q('[data-error]')!.textContent).toContain('Nothing can go on until the budget below can be approved.');
    expect($.q('[data-budget-changed]')!.textContent).toContain('Nothing can go ahead until a reading can be approved.');
    expect(shown().map((r) => r[0])).toEqual(['proof', 'rekey', 'verification']);
    expect($.continueButton()!.disabled).toBe(true);
    expect($.q('[data-continue] [data-approval]')!.textContent).toContain('Not yet: The budget is blocked');
  });
});

describe('after a reload', () => {
  it('approves nothing until the operator continues, and prices the rest from what the ledger holds now', async () => {
    const target = await readyToMigrate();
    local().onSend((s) => {
      if (stageOfSigned(s) === 'funding') local().setBalance(A, 150_000n);
    });
    await settle(() => click($.button('Migrate')!));
    await until(at('proof', 'failed'), 'the run to stop');
    // The account is funded again from elsewhere, and the page reloaded.
    local().setBalance(A, 10_000_000n);
    page = await reload(page, TIMING);
    await until(() => $.panel()?.dataset.origin === 'recovered', 'the recovered migration');
    await budgetFrom('proof');
    // The funding confirmed; the rest is priced from the target's balance now.
    expect(shown()).toEqual([['proof', 0n, 3000n], ['rekey', 0n, 1000n], ['verification', 0n, 3000n]]);
    expect($.q('[data-budget-target]')!.textContent).toContain('holds 0.103 ALGO');
    expect($.q('[data-budget-changed]')).toBeNull();
    await settle(() => setValue($.restoreInput()!, target.mnemonic!));
    await settle(() => click($.button('Restore the key')!));
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(local().balance(target.address)).toBe(100_000n);
  });

  it('continues a version-1 record with its original amount, fee and id, and writes version 2 only when it appends', async () => {
    // A funding the old code sent, and recorded before sending: 0.2 ALGO.
    const prepared = await prepareFunding(local().clients, { address: A, authorizer: A }, T1.address, 200_000n);
    const signer = algosdk.makeBasicAccountTransactionSigner(algosdk.mnemonicToSecretKey(SIGNER.phrase));
    await sendAttempt(local().clients, prepared, await signAttempt(prepared, signer));
    const legacy: MigrationRecord = {
      ...newRecord(
        {
          id: 'op-legacy-1',
          network: 'localnet',
          genesis: { id: LOCAL_GENESIS.genesisID, hash: algosdk.bytesToBase64(LOCAL_GENESIS.genesisHash) },
          sender: A,
          authorizer: A,
          target: T1.address,
          scan: { assets: '', apps: '' },
        },
        prepared.attempt,
      ),
      version: 1,
    };
    window.localStorage.setItem(JOURNAL_KEY, serializeRecord(legacy));
    page = await reload(page, TIMING);
    await until(() => $.panel()?.dataset.origin === 'recovered', 'the recovered migration');
    await budgetFrom('proof');
    // Saving what the ledger says keeps version 1.
    expect(JSON.parse(stored()!)).toMatchObject({ version: 1, attempts: [{ state: 'confirmed', amount: '200000', fee: '1000', txId: prepared.attempt.txId }] });
    await settle(() => setValue($.restoreInput()!, T1.mnemonic!));
    await settle(() => click($.button('Restore the key')!));
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration');
    const doc = JSON.parse(stored()!);
    expect(doc.version).toBe(2);
    expect(doc.attempts[0]).toMatchObject({ stage: 'funding', amount: '200000', fee: '1000', txId: prepared.attempt.txId });
    expect(doc.attempts.slice(1).map((a: { fee: string }) => a.fee)).toEqual(['3000', '1000', '3000']);
    // The old transfer is not spent again or topped up: the target keeps it, less its proof.
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(local().balance(T1.address)).toBe(197_000n);
  });
});

describe('a version-1 funding that never landed', () => {
  it('is kept as written, and replaced by a budgeted funding approved now', async () => {
    // Recorded by the old code before a send that never reached the node.
    const prepared = await prepareFunding(local().clients, { address: A, authorizer: A }, T1.address, 200_000n);
    const legacy: MigrationRecord = {
      ...newRecord(
        {
          id: 'op-legacy-2',
          network: 'localnet',
          genesis: { id: LOCAL_GENESIS.genesisID, hash: algosdk.bytesToBase64(LOCAL_GENESIS.genesisHash) },
          sender: A,
          authorizer: A,
          target: T1.address,
          scan: { assets: '', apps: '' },
        },
        prepared.attempt,
      ),
      version: 1,
    };
    window.localStorage.setItem(JOURNAL_KEY, serializeRecord(legacy));
    // Its validity window passes with every round readable.
    local().advance(prepared.attempt.lastValid - local().round + 1n);
    page = await reload(page, TIMING);
    await until(() => $.panel()?.dataset.origin === 'recovered', 'the recovered migration');
    await budgetFrom('funding');
    expect(JSON.parse(stored()!).attempts[0]).toMatchObject({ state: 'not-included', amount: '200000' });
    // The replacement is priced now: only what the target lacks, not the old 0.2 ALGO.
    expect(shown()[0]).toEqual(['funding', 103_000n, 1000n]);
    await settle(() => setValue($.restoreInput()!, T1.mnemonic!));
    await settle(() => click($.button('Restore the key')!));
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration');
    const doc = JSON.parse(stored()!);
    expect(doc.version).toBe(2);
    expect(doc.attempts[0]).toMatchObject({ stage: 'funding', state: 'not-included', amount: '200000', fee: '1000', txId: prepared.attempt.txId });
    expect(doc.attempts[1]).toMatchObject({ stage: 'funding', state: 'confirmed', amount: '103000', fee: '1000' });
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(local().balance(T1.address)).toBe(100_000n);
  });
});

describe('simulated congestion', () => {
  it('prices each step by its signed length, and the scripted pool accepts exactly those fees', async () => {
    local().setFeePerByte(2n);
    await readyToMigrate();
    const quoted = shown().map((r) => r[2] as bigint);
    // A Falcon envelope is over 3 kB, so its per-byte charge exceeds three minimum fees.
    expect(quoted[1]).toBeGreaterThan(6000n);
    expect(quoted[3]).toBeGreaterThan(quoted[1]!);
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration');
    expect(fees()).toEqual(quoted);
    for (const s of local().landed) expect(s.txn.fee).toBeGreaterThanOrEqual(2n * BigInt(algosdk.encodeMsgpack(s).length));
  });
});
