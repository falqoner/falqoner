/**
 * @vitest-environment jsdom
 */
/**
 * Recovery after reload (SAFE-02b), mounted.
 *
 * A "reload" unmounts the app and mounts a new one on the same storage and
 * the same lock manager, as a new page load would find them. Nothing else is
 * carried over: no key, no signer, no operation. What the new page knows
 * comes from the public record and from the scripted ledger, which is where
 * each test puts its faults - a lost request or response, lookups that answer
 * 404, a pruned round, another network, a changed authority.
 *
 * Every test checks what reached the ledger, so a duplicate funding or rekey
 * would show, and that storage never held a secret.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as Core from '@falqoner/core';
import type { AccountExposure, PqIdentity } from '@falqoner/core';

const mocks = vi.hoisted(() => ({
  analyzeAccount: vi.fn(),
  clientsFor: vi.fn(),
  generatePqIdentity: vi.fn(),
  preflight: vi.fn(),
}));

vi.mock('@falqoner/core', async (importOriginal) => ({
  ...(await importOriginal<typeof Core>()),
  ...mocks,
}));

import algosdk from 'algosdk';
import { VALIDITY_ROUNDS } from '@falqoner/core';
import type { Stage } from '../src/operation';
import { JOURNAL_KEY, browserJournal, serializeRecord, parseRecord } from '../src/journal';
import {
  A,
  OTHER_SIGNER,
  SHORT,
  SIGNER,
  STAGE_LIST,
  T1,
  T2,
  TIMING,
  click,
  expectNoSecrets,
  exposureOf,
  hideLookups,
  hold,
  installCore,
  landedStages,
  loseRequest,
  loseResponse,
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
import { deferred } from './fixtures';

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
  page = mount({ timing: SHORT });
});

afterEach(() => {
  unmount(page);
  expect(fetchTrap).not.toHaveBeenCalled();
  expect(XMLHttpRequest.prototype.open).not.toHaveBeenCalled();
  const text = stored();
  if (text) expectNoSecrets(text);
});

const record = () => JSON.parse(stored()!) as { revision: number; attempts: Array<{ stage: string; txId: string; state: string; source: string }> };
const status = () => $.status();
const at = (stage: Stage | '', s: string) => () => status() === s && $.panel()?.dataset.stage === stage;
const verified = at('verification', 'confirmed');

/** Scan, generate, type both phrases, and press Migrate. */
async function migrate(): Promise<PqIdentity> {
  await settle(() => setValue($.networkSelect(), 'localnet'));
  await settle(() => setValue($.addressInput(), A));
  await settle(() => click($.button('Scan')!));
  await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
  await settle(() => click($.button('Generate a post-quantum key')!));
  const target = mocks.generatePqIdentity.mock.results.at(-1)!.value as PqIdentity;
  await settle(() => setValue($.transcription()!, target.mnemonic!));
  await settle(() => setValue($.signing()!, SIGNER.phrase));
  await settle(() => click($.button('Migrate')!));
  return target;
}

/** Reload, and wait for the automatic read-only check to finish. */
async function reloadAndCheck(timing = SHORT) {
  page = await reload(page, timing);
  await until(() => $.panel()?.dataset.origin === 'recovered', 'the recovered migration');
  await until(() => !$.q('[data-status-text] .spinner'), 'the automatic check');
}

async function checkLedger() {
  await settle(() => click($.button('Check the ledger')!));
  await until(() => !!$.button('Check the ledger'), 'the check to finish');
}

async function restore(phrase: string) {
  await settle(() => setValue($.restoreInput()!, phrase));
  await settle(() => click($.button('Restore the key')!));
}

async function continueWith(signingPhrase?: string) {
  if (signingPhrase) await settle(() => setValue($.signing()!, signingPhrase));
  await settle(() => click($.continueButton()!));
}

describe('the record is written before each send', () => {
  it('holds every attempt, as recorded, at the moment it is sent, and nothing secret ever', async () => {
    const seen: Array<{ stage: string; state: string | undefined; txId: string }> = [];
    local().onSend((s) => {
      const text = window.localStorage.getItem(JOURNAL_KEY)!;
      expectNoSecrets(text);
      const doc = JSON.parse(text);
      const entry = doc.attempts.find((a: { txId: string }) => a.txId === s.txn.txID());
      seen.push({ stage: stageOfSigned(s), state: entry?.state, txId: s.txn.txID() });
      // Every earlier attempt is already confirmed in the record.
      expect(doc.attempts.slice(0, -1).every((a: { state: string }) => a.state === 'confirmed')).toBe(true);
    });
    page = await reload(page, TIMING);
    await migrate();
    await until(verified, 'the migration');
    expect(seen.map((x) => [x.stage, x.state])).toEqual(STAGE_LIST.map((s) => [s, 'recorded']));
    expect(record().attempts.map((a) => [a.txId, a.state])).toEqual(seen.map((x) => [x.txId, 'confirmed']));
  });
});

describe('a lost response, then a reload', () => {
  it.each(STAGE_LIST)('at %s: the ledger settles it, and the migration continues without repeating a step', async (stage) => {
    loseResponse(local(), stage);
    // While the page waits, the node answers 404 for it, so the page cannot tell.
    local().onSend((s) => {
      if (stageOfSigned(s) === stage) hideLookups(local(), 1000);
    });
    const target = await migrate();
    await until(at(stage, 'outcome-unknown'), 'an unknown outcome');
    expect(landedStages(local())).toEqual(STAGE_LIST.slice(0, STAGE_LIST.indexOf(stage) + 1));
    expect(record().attempts.at(-1)).toMatchObject({ stage, state: 'unknown' });

    // The node recovers; the page is reloaded.
    local().clearFaults();
    await reloadAndCheck();
    expect($.q('[data-recovery-phrase]')).toBeNull();
    expect($.q('[data-words-not-stored]')).not.toBeNull();
    // The scan controls show the recovered migration's network and account, locked.
    expect($.networkSelect().value).toBe('localnet');
    expect($.addressInput().value).toBe(A);
    expect($.networkSelect().disabled).toBe(true);
    expect(record().attempts.at(-1)).toMatchObject({ stage, state: 'confirmed', source: 'algod-pending' });

    if (stage === 'verification') {
      // Everything confirmed: nothing to continue, and it can be dismissed.
      expect(status()).toBe('confirmed');
      expect($.q('[data-dismissal]')).not.toBeNull();
      expect($.continueButton()).toBeUndefined();
    } else {
      expect(status()).toBe('confirmed');
      expect($.panel()!.dataset.stage).toBe(stage);
      // Nothing is signed before the key is restored.
      expect($.continueButton()).toBeUndefined();
      await restore(target.mnemonic!);
      const needsSigner = stage === 'funding' || stage === 'proof';
      expect(!!$.signing()).toBe(needsSigner);
      await continueWith(needsSigner ? SIGNER.phrase : undefined);
      await until(verified, 'the migration to finish');
    }
    // Every step reached the ledger exactly once.
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(local().authority(A)).toBe(target.address);
  });
});

describe('when nothing establishes whether it landed', () => {
  it('a crash between the record and the send stays locked until every round of its window is read', async () => {
    loseRequest(local(), 'funding');
    const target = await migrate();
    await until(at('funding', 'outcome-unknown'), 'an unknown outcome');
    expect(local().landed).toHaveLength(0);

    await reloadAndCheck();
    expect(status()).toBe('outcome-unknown');
    expect(record().attempts).toHaveLength(1);
    expect(record().attempts[0]!.state).toBe('unknown');
    // No way on: no restore, no continue, no dismissal, no new key.
    expect($.restoreInput()).toBeNull();
    expect($.continueButton()).toBeUndefined();
    expect($.q('[data-dismissal]')).toBeNull();
    expect($.button('Generate a post-quantum key')).toBeUndefined();
    await checkLedger();
    await checkLedger();
    expect(status()).toBe('outcome-unknown');

    // Its window passes, but one round cannot be read: still not established.
    const lastValid = BigInt(JSON.parse(stored()!).attempts[0].lastValid);
    local().advance(lastValid - local().round + 1n);
    local().prune(lastValid - 3n, lastValid - 3n);
    await checkLedger();
    expect(record().attempts[0]!.state).toBe('expired');
    expect($.continueButton()).toBeUndefined();
    expect($.text()).toContain('could not be read in full, so whether it landed is not established');

    // Every round read: it never landed, and a new attempt may replace it.
    local().unprune();
    await checkLedger();
    expect(record().attempts[0]!.state).toBe('not-included');
    expect(status()).toBe('failed');
    await restore(target.mnemonic!);
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    const attempts = record().attempts;
    expect(attempts.map((a) => [a.stage, a.state])).toEqual([
      ['funding', 'not-included'],
      ['funding', 'confirmed'],
      ['proof', 'confirmed'],
      ['rekey', 'confirmed'],
      ['verification', 'confirmed'],
    ]);
    expect(attempts[0]!.txId).not.toBe(attempts[1]!.txId);
  });

  it('a delayed confirmation: pending while waited for, confirmed later, then continued in place', async () => {
    local().setAutoConfirm(false);
    await migrate();
    await until(at('funding', 'outcome-unknown'), 'the wait to run out');
    expect(record().attempts[0]!.state).toBe('pending');
    expect($.text()).toContain('The node holds it in its pool');
    local().mine();
    local().setAutoConfirm(true);
    await checkLedger();
    expect(record().attempts[0]!.state).toBe('confirmed');
    // The key is still in this page: only the signing key is asked for.
    expect($.restoreInput()).toBeNull();
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('after a reload that cannot read the node, a recorded rekey is never described as not sent', async () => {
    loseResponse(local(), 'rekey');
    // From the rekey on, the node answers nothing.
    local().onSend((s) => {
      if (stageOfSigned(s) !== 'rekey') return;
      for (const m of ['params', 'status', 'pending', 'block', 'account', 'indexer'] as const) {
        local().failTimes(m, 'lose-request', 1000);
      }
    });
    const target = await migrate();
    await until(at('rekey', 'outcome-unknown'), 'an unknown outcome');
    await reloadAndCheck();
    // Nothing could be read, so the first step is the one named unsettled...
    expect(status()).toBe('outcome-unknown');
    expect($.panel()!.dataset.stage).toBe('funding');
    // ...but a rekey was recorded, and it landed.
    expect(local().authority(A)).toBe(target.address);
    const alert = $.q('[data-alert="outcome-unknown"]')!.textContent!;
    expect(alert).toContain(`The rekey may have taken effect. If it did, ${A} is now controlled only by ${target.address}`);
    expect(alert).not.toContain('has not been rekeyed');

    // Each control used here is withdrawn while it acts; focus stays on the
    // status line, ahead of whatever comes next.
    const statusLine = () => $.q('[data-status-text]');
    local().clearFaults();
    await checkLedger();
    expect(document.activeElement).toBe(statusLine());
    await restore(target.mnemonic!);
    expect(document.activeElement).toBe(statusLine());
    await continueWith();
    expect(document.activeElement).toBe(statusLine());
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('an attempt long expired that had already confirmed is found in its block, and not sent again', async () => {
    loseResponse(local(), 'rekey');
    local().onSend((s) => {
      if (stageOfSigned(s) === 'rekey') hideLookups(local(), 1000);
    });
    const target = await migrate();
    await until(at('rekey', 'outcome-unknown'), 'an unknown outcome');
    // Long after: past its window, and past what the node remembers.
    local().clearFaults();
    local().advance(1200n);
    await reloadAndCheck();
    expect(record().attempts.at(-1)).toMatchObject({ stage: 'rekey', state: 'confirmed', source: 'algod-block' });
    await restore(target.mnemonic!);
    await continueWith();
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });
});

describe('what stops a continuation', () => {
  async function rekeyedThenReloaded() {
    loseResponse(local(), 'rekey');
    local().onSend((s) => {
      if (stageOfSigned(s) === 'rekey') hideLookups(local(), 1000);
    });
    const target = await migrate();
    await until(at('rekey', 'outcome-unknown'), 'an unknown outcome');
    local().clearFaults();
    return target;
  }

  it('a phrase for another key restores nothing', async () => {
    const target = await rekeyedThenReloaded();
    await reloadAndCheck();
    await restore(T2.mnemonic!);
    expect($.q('[data-restore-error]')!.textContent).toContain(`derive ${T2.address}, not ${target.address}`);
    expect($.continueButton()).toBeUndefined();
    await restore(Array(25).fill('abandon').join(' '));
    expect($.q('[data-restore-error]')!.textContent).toMatch(/could not be decoded/);
    await restore(target.mnemonic!);
    expect($.continueButton()).toBeDefined();
    expect($.restoreInput()).toBeNull();
  });

  it('another network behind the endpoint stops it, and nothing is sent', async () => {
    const target = await rekeyedThenReloaded();
    local().setGenesis({ genesisID: 'elsewhere-v1', genesisHash: new Uint8Array(32).fill(9) });
    await reloadAndCheck();
    expect($.q('[data-conflict]')!.textContent).toContain('The node reports elsewhere-v1');
    expect(status()).toBe('outcome-unknown');
    // No way on while it stands: not even the key is asked for.
    expect($.restoreInput()).toBeNull();
    expect($.continueButton()).toBeUndefined();
    expect(target.address).toBe($.panel()!.querySelector('.mono')!.textContent);
    expect(landedStages(local())).toEqual(['funding', 'proof', 'rekey']);
  });

  it('an authority this migration did not set stops it', async () => {
    const target = await rekeyedThenReloaded();
    local().setAuthority(A, OTHER_SIGNER.address);
    await reloadAndCheck();
    expect($.q('[data-conflict]')!.textContent).toContain(`authority is now ${OTHER_SIGNER.address}`);
    // The confirmed rekey is still shown as confirmed: its history stays.
    expect(record().attempts.at(-1)).toMatchObject({ stage: 'rekey', state: 'confirmed' });
    expect($.q('[data-alert="rekeyed"]')).not.toBeNull();
    expect($.restoreInput()).toBeNull();
    expect($.continueButton()).toBeUndefined();
    expect($.text()).toContain(target.address);
    expect(landedStages(local())).toEqual(['funding', 'proof', 'rekey']);
  });

  it('a check and a continuation each run once for a burst of clicks', async () => {
    const target = await rekeyedThenReloaded();
    await reloadAndCheck();
    const lookups = local().count('pending');
    await settle(() => {
      click($.button('Check the ledger')!);
      click($.button('Check the ledger')!);
    });
    await until(() => !!$.button('Check the ledger'), 'the check');
    // Nothing was unresolved, so the burst read nothing more than the authority.
    expect(local().count('pending')).toBe(lookups);
    await restore(target.mnemonic!);
    const held = hold(local(), 'verification');
    await settle(() => {
      click($.continueButton()!);
      click($.continueButton()!);
    });
    await until(at('verification', 'submitted'), 'verification in flight');
    held.resolve();
    await until(verified, 'verification');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('a continuation whose read times out starts nothing when the answer comes late', async () => {
    const target = await rekeyedThenReloaded();
    await reloadAndCheck();
    await restore(target.mnemonic!);
    const late = deferred<void>();
    // The ceremony's read of the account answers after the page gave up.
    local().fail('account', { until: late.promise });
    await continueWith();
    await until(() => !!$.q('[data-error]'), 'the refusal');
    expect($.q('[data-error]')!.textContent).toMatch(/Nothing was sent for this step\. The account could not be read: No answer after 60 ms/);
    late.resolve();
    await new Promise((r) => setTimeout(r, 50));
    await settle();
    expect(landedStages(local())).toEqual(['funding', 'proof', 'rekey']);
    // It can be continued deliberately.
    await continueWith();
    await until(verified, 'verification');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });
});

describe('stored labels are claims (A-02b-01)', () => {
  /** Rewrite one attempt's stored fields, keeping a record the parser accepts. */
  function relabel(i: number, patch: Record<string, string | null>) {
    const doc = JSON.parse(stored()!);
    Object.assign(doc.attempts[i], patch);
    const text = JSON.stringify(doc);
    expect(parseRecord(text).ok).toBe(true);
    window.localStorage.setItem(JOURNAL_KEY, text);
  }
  const attemptRow = (i: number) => $.q(`[data-attempt="${JSON.parse(stored()!).attempts[i].txId}"]`)!;

  it('a not-included label on a funding that landed is corrected by the ledger, and nothing is funded twice', async () => {
    loseResponse(local(), 'funding');
    local().onSend((s) => {
      if (stageOfSigned(s) === 'funding') hideLookups(local(), 1000);
    });
    const target = await migrate();
    await until(at('funding', 'outcome-unknown'), 'an unknown outcome');
    local().clearFaults();
    local().advance(VALIDITY_ROUNDS + 2n);
    const lastValid = BigInt(JSON.parse(stored()!).attempts[0].lastValid);
    relabel(0, { state: 'not-included', source: 'algod-block', checkedRound: String(lastValid + 1n) });

    await reloadAndCheck();
    const notice = $.q('[data-notice]')!.textContent!;
    expect(notice).toContain('The saved record said not-included for fund the post-quantum address');
    expect(notice).toContain('but the ledger shows confirmed');
    expect(record().attempts[0]).toMatchObject({ state: 'confirmed' });
    expect(status()).toBe('confirmed');
    expect($.panel()!.dataset.stage).toBe('funding');
    await restore(target.mnemonic!);
    expect($.continueButton()!.textContent).toBe('Continue: prove the falcon key on chain');
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('a confirmed label on a funding that never left the page allows nothing until the ledger settles it', async () => {
    loseRequest(local(), 'funding');
    const target = await migrate();
    await until(at('funding', 'outcome-unknown'), 'an unknown outcome');
    const firstValid = BigInt(JSON.parse(stored()!).attempts[0].firstValid);
    relabel(0, {
      state: 'confirmed',
      confirmedRound: String(firstValid + 1n),
      source: 'algod-pending',
      checkedRound: String(firstValid + 2n),
    });

    await reloadAndCheck();
    // Read, not believed: no key asked for, nothing to continue or dismiss.
    expect(status()).toBe('outcome-unknown');
    expect($.restoreInput()).toBeNull();
    expect($.continueButton()).toBeUndefined();
    expect($.q('[data-dismissal]')).toBeNull();
    expect(attemptRow(0).getAttribute('data-attempt-state')).toBe('unknown');
    expect(attemptRow(0).getAttribute('data-saved-state')).toBe('confirmed');
    expect(local().landed).toHaveLength(0);

    // Its window passes and every round is read: the ledger settles it.
    local().advance(VALIDITY_ROUNDS + 2n);
    await checkLedger();
    expect(record().attempts[0]!.state).toBe('not-included');
    expect($.q('[data-notice]')!.textContent).toContain('said confirmed');
    await restore(target.mnemonic!);
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('a record claiming a verification that never landed cannot be dismissed', async () => {
    loseRequest(local(), 'verification');
    await migrate();
    await until(at('verification', 'outcome-unknown'), 'an unknown outcome');
    const firstValid = BigInt(JSON.parse(stored()!).attempts[3].firstValid);
    relabel(3, {
      state: 'confirmed',
      confirmedRound: String(firstValid + 1n),
      source: 'algod-pending',
      checkedRound: String(firstValid + 2n),
    });

    await reloadAndCheck();
    expect(status()).toBe('outcome-unknown');
    expect($.panel()!.dataset.stage).toBe('verification');
    expect($.q('[data-dismissal]')).toBeNull();
    expect(attemptRow(3).getAttribute('data-attempt-state')).toBe('unknown');
    expect(stored()).not.toBeNull();
    expect(landedStages(local())).toEqual(['funding', 'proof', 'rekey']);
  });

  it('a check that could not read one attempt blocks dismissal until it can', async () => {
    await migrate();
    await until(verified, 'the migration');
    const proof = JSON.parse(stored()!).attempts[1];
    const round = BigInt(proof.confirmedRound);
    // The proof can be read nowhere: not the lookup, not its block, not the indexer.
    local().prune(round, round);
    for (let i = 0; i < 4; i++) {
      local().fail('pending', 'not-found', (id) => id === proof.txId);
      local().fail('indexer', 'server-error', (id) => id === proof.txId);
    }

    await reloadAndCheck();
    expect(attemptRow(1).getAttribute('data-attempt-state')).toBe('unknown');
    expect(attemptRow(1).getAttribute('data-saved-state')).toBe('confirmed');
    expect($.q('[data-dismissal]')).toBeNull();

    local().clearFaults();
    local().unprune();
    await checkLedger();
    expect(attemptRow(1).getAttribute('data-attempt-state')).toBe('confirmed');
    expect($.q('[data-dismissal]')).not.toBeNull();
  });

  it('an authority read before the verified rekey is stale, and blocks dismissal', async () => {
    await migrate();
    await until(verified, 'the migration');
    const doc = JSON.parse(stored()!);
    const rekeyRound = BigInt(doc.attempts[2].confirmedRound);
    local().fail('account', {
      answer: { address: A, amount: 0n, authAddr: algosdk.Address.fromString(doc.target), round: rekeyRound - 1n },
    });

    await reloadAndCheck();
    expect($.q('[data-dismissal]')).toBeNull();
    expect($.q('[data-dismiss-blocked]')!.textContent).toMatch(/read at round \d+, before the rekey in round \d+, so that reading is stale/);
    await checkLedger();
    expect($.q('[data-dismiss-blocked]')).toBeNull();
    expect($.q('[data-dismissal]')).not.toBeNull();
  });

  it('another network at the authority read is a conflict, whatever the attempts said', async () => {
    await migrate();
    await until(verified, 'the migration');
    // Four attempts are read on the recorded network; the fifth network read, before the authority, is not.
    let calls = 0;
    local().fail(
      'params',
      {
        answer: {
          fee: 0n,
          minFee: 1000n,
          firstValid: local().round,
          lastValid: local().round + 1000n,
          genesisID: 'elsewhere-v1',
          genesisHash: new Uint8Array(32).fill(9),
        },
      },
      () => ++calls === 5,
    );

    await reloadAndCheck();
    expect($.q('[data-conflict]')!.textContent).toContain('The node now reports elsewhere-v1');
    expect($.q('[data-authority]')).toBeNull();
    expect($.q('[data-dismissal]')).toBeNull();
  });
});

describe('a record that lags the ledger', () => {
  it('a confirmation the record could not save is not continued until the ledger is checked again', async () => {
    // The second write - the funding's confirmation - fails once.
    let writes = 0;
    const storage = {
      getItem: (k: string) => window.localStorage.getItem(k),
      setItem: (k: string, v: string) => {
        if (++writes === 2) throw Object.assign(new Error('full'), { name: 'QuotaExceededError' });
        window.localStorage.setItem(k, v);
      },
      removeItem: (k: string) => window.localStorage.removeItem(k),
    };
    unmount(page);
    await settle();
    page = mount({ journal: browserJournal(() => storage), timing: TIMING });
    await migrate();
    await until(() => !!$.q('[data-error]'), 'the run to stop');
    expect($.q('[data-error]')!.textContent).toContain('This step confirmed, but the saved record could not be updated');
    expect(status()).toBe('confirmed');
    expect(landedStages(local())).toEqual(['funding']);
    // The ledger says confirmed; the record still says only recorded. Nothing
    // continues from that until the record agrees.
    expect(record().attempts[0]!.state).toBe('recorded');
    expect($.continueButton()).toBeUndefined();
    await checkLedger();
    expect(record().attempts[0]!.state).toBe('confirmed');
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });
});

describe('storage that cannot be used', () => {
  it.each([
    ['garbage', 'not a record', /not JSON/],
    ['an unsupported version', '{"format":"falconer-migration-journal","version":2}', /unexpected or missing fields|version 2/],
  ])('keeps %s, blocks a new migration, and leaves the audit working', async (_, text, reason) => {
    window.localStorage.setItem(JOURNAL_KEY, text);
    page = await reload(page);
    expect($.q('[data-journal-problem]')!.textContent).toMatch(reason);
    await settle(() => setValue($.networkSelect(), 'localnet'));
    await settle(() => setValue($.addressInput(), A));
    await settle(() => click($.button('Scan')!));
    await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
    expect($.text()).toContain('Verdict');
    expect($.button('Generate a post-quantum key')).toBeUndefined();
    expect($.q('[data-blocked]')).not.toBeNull();
    expect(stored()).toBe(text);
    expect(local().count('send')).toBe(0);
  });

  it('storage that cannot be read blocks a new migration too', async () => {
    unmount(page);
    page = mount({
      journal: browserJournal(() => {
        throw Object.assign(new Error('denied'), { name: 'SecurityError' });
      }),
    });
    expect($.q('[data-journal-problem]')!.textContent).toContain('SecurityError');
  });

  it('a record for MainNet, or with a tampered transaction, is refused as a whole', async () => {
    // A real record, from a run whose rekey outcome is unknown.
    loseResponse(local(), 'rekey');
    local().onSend((s) => {
      if (stageOfSigned(s) === 'rekey') hideLookups(local(), 1000);
    });
    await migrate();
    await until(at('rekey', 'outcome-unknown'), 'an unknown outcome');
    local().clearFaults();
    const doc = JSON.parse(stored()!);
    doc.attempts[2].rekeyTo = OTHER_SIGNER.address;
    const tampered = JSON.stringify(doc);
    window.localStorage.setItem(JOURNAL_KEY, tampered);
    page = await reload(page);
    expect($.q('[data-journal-problem]')!.textContent).toMatch(/not what its stage sends|does not match its fields/);
    expect($.panel()).toBeNull();
    expect(stored()).toBe(tampered);
  });
});

describe('two tabs', () => {
  it('a second tab only looks, and a tab that is not the owner cannot send', async () => {
    const locks = page.locks;
    // Tab B opens first, with nothing stored, and gets as far as Migrate.
    const tabB: Page = mount({ locks, timing: SHORT });
    const $B = queries(() => tabB);
    await settle(() => setValue($B.networkSelect(), 'localnet'));
    await settle(() => setValue($B.addressInput(), A));
    await settle(() => click($B.button('Scan')!));
    await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
    await settle(() => click($B.button('Generate a post-quantum key')!));
    const keyB = mocks.generatePqIdentity.mock.results.at(-1)!.value as PqIdentity;
    await settle(() => setValue($B.transcription()!, keyB.mnemonic!));
    await settle(() => setValue($B.signing()!, SIGNER.phrase));

    // Tab A starts, and holds the rekey in flight.
    page = await reload(page, TIMING);
    const held = hold(local(), 'rekey');
    const target = await migrate();
    await until(at('rekey', 'submitted'), 'the rekey in flight');
    const revision = record().revision;

    // B presses Migrate: refused, nothing sent, nothing written.
    await settle(() => click($B.button('Migrate')!));
    await until(() => $B.status() === 'failed', 'the refusal');
    expect($B.text()).toContain('Nothing was sent. This page could not take its exclusive hold');
    expect(local().count('send')).toBe(3);

    // A third tab opens now: it recovers the record, and can only look.
    const tabC: Page = mount({ locks, timing: SHORT });
    const $C = queries(() => tabC);
    await until(() => $C.panel()?.dataset.origin === 'recovered', 'the recovered migration');
    await until(() => !!$C.q('[data-read-only]'), 'the read-only notice');
    expect(record().revision).toBe(revision);

    held.resolve();
    await until(verified, 'the migration in tab A');
    // C reads A's progress, but still saves and sends nothing.
    await settle(() => click($C.button('Check the ledger')!));
    await until(() => !!$C.button('Check the ledger') && $C.status() === 'confirmed', 'C to see it');
    const after = record().revision;
    await settle(() => click($C.q('[data-dismissal] input[type="checkbox"]')!));
    await settle(() => click($C.button('Dismiss and remove the words from this page')!));
    expect($C.q('[data-error]')!.textContent).toContain('Another tab holds this migration');
    expect(record().revision).toBe(after);

    // A is closed; C can now take it over and dismiss it.
    unmount(page);
    page = tabB;
    await settle();
    await settle(() => click($C.button('Check the ledger')!));
    await until(() => !$C.q('[data-read-only]'), 'C to hold the record');
    await settle(() => click($C.button('Dismiss and remove the words from this page')!));
    expect(stored()).toBeNull();
    expect($C.panel()).toBeNull();
    unmount(tabC);
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(local().authority(A)).toBe(target.address);
  });
});

describe('settling without a rekey', () => {
  it('a migration whose only attempt never landed is dismissed after acknowledgement, and a new one can start', async () => {
    loseRequest(local(), 'funding');
    await migrate();
    await until(at('funding', 'outcome-unknown'), 'an unknown outcome');
    local().advance(VALIDITY_ROUNDS + 2n);
    await reloadAndCheck();
    expect(record().attempts[0]!.state).toBe('not-included');
    expect($.q('[data-dismissal]')!.textContent).toContain('Settled without a rekey');
    expect($.q('[data-dismissal]')!.textContent).toContain('Nothing it sent reached the ledger');
    await settle(() => click($.q('[data-dismissal] input[type="checkbox"]')!));
    await settle(() => click($.button('Dismiss and remove the words from this page')!));
    expect(stored()).toBeNull();
    expect($.panel()).toBeNull();
    expect(local().landed).toHaveLength(0);
    // Unlocked, and a new migration can start.
    await settle(() => setValue($.addressInput(), A));
    await settle(() => click($.button('Scan')!));
    await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
    expect($.button('Generate a post-quantum key')).toBeDefined();
  });

  it('a resolved record round-trips through the journal exactly', async () => {
    page = await reload(page, TIMING);
    await migrate();
    await until(verified, 'the migration');
    const parsed = parseRecord(stored()!);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(serializeRecord(parsed.record)).toBe(stored());
    // Nothing of the new key's phrase or the signing phrase, in any form.
    expectNoSecrets(stored()!, [T1.mnemonic!, SIGNER.phrase]);
  });
});

describe('the guarded ceremony behind the page (SAFE-03b)', () => {
  it('a proof still unresolved after a reload allows no rekey; once the ledger shows it, the rekey goes once', async () => {
    loseResponse(local(), 'proof');
    local().setIndexerLag(1000n);
    local().onSend((s) => {
      if (stageOfSigned(s) === 'proof') hideLookups(local(), 1000);
    });
    const target = await migrate();
    await until(at('proof', 'outcome-unknown'), 'an unknown proof');
    // Reloaded while the node still cannot say whether the proof landed.
    await reloadAndCheck();
    expect(status()).toBe('outcome-unknown');
    expect(record().attempts.at(-1)).toMatchObject({ stage: 'proof', state: 'unknown' });
    expect($.continueButton()).toBeUndefined();
    expect(landedStages(local())).toEqual(['funding', 'proof']);
    expect(local().authority(A)).toBe(A);
    // The node answers again: the proof is found, and only then does the rekey go.
    local().clearFaults();
    local().setIndexerLag(0n);
    await checkLedger();
    expect(record().attempts.at(-1)).toMatchObject({ stage: 'proof', state: 'confirmed' });
    await restore(target.mnemonic!);
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('a target that no longer answers to its own key after its proof gets no rekey', async () => {
    page = await reload(page, TIMING);
    local().onSend((s) => {
      if (stageOfSigned(s) === 'proof') local().setAuthority(s.txn.sender.toString(), OTHER_SIGNER.address);
    });
    const target = await migrate();
    await until(at('rekey', 'failed'), 'the rekey to be refused');
    expect($.q('[data-error]')!.textContent).toContain(`Nothing was sent for this step. ${target.address} answers to ${OTHER_SIGNER.address}`);
    expect(landedStages(local())).toEqual(['funding', 'proof']);
    expect(local().authority(A)).toBe(A);
    // Put right, the same migration goes on from the rekey.
    local().setAuthority(target.address, undefined);
    await until(() => $.q('[data-budget]')?.getAttribute('data-budget-from') === 'rekey' && !$.q('[data-budget-reading]'), 'the budget from the rekey');
    await continueWith(SIGNER.phrase);
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });
});
