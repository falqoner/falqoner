/**
 * @vitest-environment jsdom
 */
/**
 * The migration, mounted (SAFE-02a), on the real submission path (SAFE-02b).
 *
 * The whole app runs in a jsdom document against scripted ledgers (see
 * harness.tsx): every transaction is prepared, signed, recorded, sent and
 * reconciled by the real code, and a test holds, hangs or loses a send to act
 * while a step is in flight. Only the scan, key generation and the offline
 * phrase check are replaced. Network access is trapped and fails the test.
 *
 * Phrases come from fixed public seeds. None is printed.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import algosdk from 'algosdk';
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

import { useMigrationOperation, type ContextBase, type Stage } from '../src/operation';
import { JOURNAL_KEY, browserJournal, browserTabLock } from '../src/journal';
import {
  A,
  B,
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
  hold,
  installCore,
  landedStages,
  mount,
  pressEnter,
  queries,
  refusalOf,
  setValue,
  settle,
  stageOfSigned,
  stored,
  unmount,
  until,
  type Page,
  type World,
} from './harness';
import { MAINNET_GENESIS, deferred, fakeLocks } from './fixtures';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let EXPOSURE_A: AccountExposure;
let EXPOSURE_B: AccountExposure;
let POOR_A: AccountExposure;
let REFRESHED_A: AccountExposure;

let world: World;
let page: Page;
const $ = queries(() => page);
const local = () => world.ledgers.localnet;
const fetchTrap = vi.fn(() => Promise.reject(new Error('offline test: network access refused')));

/** An in-memory Storage, so a directly driven hook shares nothing with the page. */
function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
  };
}

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchTrap);
  vi.spyOn(XMLHttpRequest.prototype, 'open').mockImplementation(() => {
    throw new Error('offline test: network access refused');
  });
  [EXPOSURE_A, EXPOSURE_B, POOR_A, REFRESHED_A] = await Promise.all([
    exposureOf(A),
    exposureOf(B),
    exposureOf(A, { amount: 150_000n }),
    exposureOf(A, { authAddr: T1.address }),
  ]);
});

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  world = installCore(mocks);
  page = mount();
});

afterEach(() => {
  unmount(page);
  expect(fetchTrap).not.toHaveBeenCalled();
  expect(XMLHttpRequest.prototype.open).not.toHaveBeenCalled();
});

function remount(options: Parameters<typeof mount>[0] = {}) {
  unmount(page);
  page = mount(options);
}

const sends = () => local().count('send');

async function scanned(exposure: AccountExposure, network = 'localnet', assets = '') {
  if ($.networkSelect().value !== network) await settle(() => setValue($.networkSelect(), network));
  await settle(() => setValue($.addressInput(), exposure.address));
  await settle(() => setValue($.assetsInput(), assets));
  await settle(() => click($.button('Scan')!));
  await settle(() => world.scans.at(-1)!.d.resolve(exposure));
}

/** Scanned, a key generated, and both phrases typed. Returns the new key. */
async function ready({
  exposure = EXPOSURE_A,
  network = 'localnet',
  signingPhrase = SIGNER.phrase,
  assets = '',
} = {}): Promise<PqIdentity> {
  await scanned(exposure, network, assets);
  await settle(() => click($.button('Generate a post-quantum key')!));
  const target = mocks.generatePqIdentity.mock.results.at(-1)!.value as PqIdentity;
  await settle(() => setValue($.transcription()!, target.mnemonic!));
  await settle(() => setValue($.signing()!, signingPhrase));
  return target;
}

const atStage = (stage: Stage, status = 'submitted') => () =>
  $.status() === status && $.panel()?.dataset.stage === stage;
const verified = atStage('verification', 'confirmed');

/** Wait until the budget on screen starts at `from` and is no longer being read. */
const budgetFor = (from: Stage) =>
  until(() => $.q('[data-budget]')?.getAttribute('data-budget-from') === from && !$.q('[data-budget-reading]'), `the budget from ${from}`);

/**
 * Start a migration and stop while `point` is in flight. Returns the hold
 * to release.
 */
async function driveTo(point: 'checks' | Stage) {
  const held = deferred<void>();
  if (point !== 'checks') {
    const h = hold(local(), point);
    held.promise.then(() => h.resolve());
  }
  await ready();
  // The budget was read with the key; the next parameter read is the genesis check.
  const before = local().count('params');
  if (point === 'checks') local().fail('params', { until: held.promise });
  await settle(() => click($.button('Migrate')!));
  if (point === 'checks') await until(() => local().count('params') === before + 1, 'the genesis read');
  else await until(atStage(point), `${point} in flight`);
  return held;
}

/** Every control that could replace or drop the operation is off, and the words are on screen. */
function expectFrozen(target = T1) {
  expect($.q('[data-lock]')).not.toBeNull();
  expect($.addressInput().disabled).toBe(true);
  expect($.assetsInput().disabled).toBe(true);
  expect($.networkSelect().disabled).toBe(true);
  expect($.button('Scan')?.disabled ?? $.button('Scanning')?.disabled).toBe(true);
  for (const sample of ['USDC reserve', 'USDC manager']) expect($.button(sample)!.disabled).toBe(true);
  expect($.button('Generate a post-quantum key')).toBeUndefined();
  expect($.button('Generate a different key')?.disabled ?? true).toBe(true);
  expect($.button('Migrate')?.disabled ?? true).toBe(true);
  expect($.phraseShown()).toEqual(target.mnemonic!.split(' '));
}

/**
 * Events that reach the handlers even on disabled controls: a key press,
 * a change event, typing. Each must be refused by the handler itself.
 */
async function attemptBypass() {
  const before = {
    scans: world.scans.length,
    keys: mocks.generatePqIdentity.mock.calls.length,
    network: $.networkSelect().value,
    address: $.addressInput().value,
    typedBack: $.transcription()?.value,
    sends: sends(),
  };
  await settle(() => {
    pressEnter($.addressInput());
    pressEnter($.assetsInput());
    setValue($.networkSelect(), 'testnet');
    setValue($.addressInput(), B);
    const t = $.transcription();
    if (t) setValue(t, 'tampered');
  });
  expect(world.scans.length).toBe(before.scans);
  expect(mocks.generatePqIdentity).toHaveBeenCalledTimes(before.keys);
  expect($.networkSelect().value).toBe(before.network);
  expect($.addressInput().value).toBe(before.address);
  expect($.transcription()?.value).toBe(before.typedBack);
  expect(sends()).toBe(before.sends);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

describe('one operation, one context', () => {
  it('runs one operation for a burst of clicks in the same turn', async () => {
    await ready();
    const held = hold(local(), 'funding');
    const id = $.panel()!.dataset.operation;
    let stillEnabled = false;
    await settle(() => {
      click($.button('Migrate')!);
      // The page has not re-rendered yet, so these are still clickable:
      // only the operation's own guard stands in the way.
      stillEnabled = !$.button('Generate a different key')!.disabled && !$.button('Scan')!.disabled;
      click($.button('Migrate')!);
      click($.button('Generate a different key')!);
      click($.button('USDC reserve')!);
      click($.button('Scan')!);
      setValue($.networkSelect(), 'testnet');
    });
    await until(atStage('funding'), 'funding in flight');
    expect(stillEnabled).toBe(true);
    // The budget read with the key, one genesis read, the budget read again
    // before the funding, and one funding preparation; one send.
    expect(local().count('params')).toBe(4);
    expect(sends()).toBe(1);
    expect(mocks.generatePqIdentity).toHaveBeenCalledTimes(1);
    expect(world.scans).toHaveLength(1);
    expect($.networkSelect().value).toBe('localnet');
    expect($.panel()!.dataset).toMatchObject({ operation: id, status: 'submitted', stage: 'funding' });
    held.resolve();
    await until(verified, 'the migration to finish');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('sends each step once, for the same account, key and network, and refreshes the same scan', async () => {
    const target = await ready({ assets: '31566704' });
    // The budget on screen is what Migrate approves.
    const shown = STAGE_LIST.map((s) => {
      const row = $.q(`[data-budget-stage="${s}"]`)!;
      return [s, row.getAttribute('data-amount'), row.getAttribute('data-fee')];
    });
    expect(shown).toEqual([['funding', '103000', '1000'], ['proof', '0', '3000'], ['rekey', '0', '1000'], ['verification', '0', '3000']]);
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration to finish');

    const [fund, prove, rekey, verify] = local().landed;
    expect(local().landed.map(stageOfSigned)).toEqual([...STAGE_LIST]);
    expect(fund!.txn.sender.toString()).toBe(A);
    expect(fund!.txn.payment!.receiver.toString()).toBe(target.address);
    // Only what the new address lacks: its minimum balance and its proof fee.
    expect(fund!.txn.payment!.amount).toBe(103_000n);
    expect(fund!.sgnr).toBeUndefined();
    expect(local().landed.map((s) => s.txn.fee)).toEqual([1000n, 3000n, 1000n, 3000n]);
    // The ledger's own accounting: the account paid the transfer and its three
    // fees; the new address paid its proof from the transfer and keeps its minimum.
    expect(local().balance(A)).toBe(10_000_000n - 103_000n - 5000n);
    expect(local().balance(target.address)).toBe(100_000n);
    expect(prove!.txn.sender.toString()).toBe(target.address);
    expect(rekey!.txn.sender.toString()).toBe(A);
    expect(rekey!.txn.rekeyTo!.toString()).toBe(target.address);
    expect(verify!.txn.sender.toString()).toBe(A);
    expect(verify!.sgnr!.toString()).toBe(target.address);
    for (const s of local().landed) expect(s.txn.genesisID).toBe('dockernet-v1');
    expect(local().authority(A)).toBe(target.address);

    // The record names exactly these, each confirmed.
    const doc = JSON.parse(stored()!);
    expect(doc.attempts.map((a: { stage: string; txId: string; state: string }) => [a.stage, a.txId, a.state])).toEqual(
      local().landed.map((s) => [stageOfSigned(s), s.txn.txID(), 'confirmed']),
    );

    expect($.panel()!.dataset).toMatchObject({ status: 'confirmed', stage: 'verification' });
    expect($.text()).toContain('Migrated.');
    // Verified, so the account is read again: the same account, network and ids.
    const refresh = world.scans.at(-1)!;
    expect(world.scans).toHaveLength(2);
    expect(refresh).toMatchObject({ address: A, network: 'localnet' });
    expect(refresh.options.assetIds).toEqual([31566704n]);
    await settle(() => refresh.d.resolve(REFRESHED_A));
    // A new scan of the account does not replace or hide the operation.
    expect($.panel()!.dataset).toMatchObject({ status: 'confirmed', stage: 'verification' });
    expect($.text()).toContain(`${A} is unchanged`);
    expect($.text()).toContain(`Authority is now ${target.address}`);
    expect($.text()).not.toContain("already this account's authority");
    expect($.q('[data-step="rekey"]')!.getAttribute('data-state')).toBe('confirmed');
    expectFrozen(target);
  });

  it('takes nothing from a node that changes network part-way, and sends nothing more', async () => {
    await ready();
    // The funding lands, and at that moment the node starts reporting
    // another network: its confirmation, read from there, is not one.
    local().onSend((s) => {
      if (stageOfSigned(s) === 'funding') local().setGenesis({ genesisID: 'elsewhere-v1', genesisHash: new Uint8Array(32).fill(9) });
    });
    await settle(() => click($.button('Migrate')!));
    await until(atStage('funding', 'outcome-unknown'), 'the run to stop');
    expect(landedStages(local())).toEqual(['funding']);
    expect($.text()).toContain('The node reports elsewhere-v1');
    expect(JSON.parse(stored()!).attempts[0]).toMatchObject({ stage: 'funding', state: 'conflict' });
    expect($.q('[data-lock]')).not.toBeNull();
    expect($.continueButton()).toBeUndefined();
  });

  it.each(['checks', ...STAGE_LIST] as const)(
    'while %s is in flight, nothing on the page can replace the operation',
    async (point) => {
      const held = await driveTo(point);
      const done = point === 'checks' ? 0 : STAGE_LIST.indexOf(point);
      expect(landedStages(local())).toEqual(STAGE_LIST.slice(0, done));
      expect($.status()).toBe(point === 'checks' ? 'prepared' : 'submitted');
      expectFrozen();
      await attemptBypass();
      expectFrozen();
      // The words stay in the page, and no fresh start is offered.
      expect($.text()).not.toContain('Retry verification');
      held.resolve();
      await until(verified, 'the migration to finish');
    },
  );

  it('a slower, older scan cannot land on a running migration', async () => {
    await settle(() => setValue($.networkSelect(), 'localnet'));
    await settle(() => setValue($.addressInput(), B));
    await settle(() => pressEnter($.addressInput()));
    const stale = world.scans.at(-1)!;
    // A second scan before the first answers: the latest one wins.
    await settle(() => setValue($.addressInput(), A));
    await settle(() => pressEnter($.addressInput()));
    await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_A));
    await settle(() => click($.button('Generate a post-quantum key')!));
    await settle(() => setValue($.transcription()!, T1.mnemonic!));
    await settle(() => setValue($.signing()!, SIGNER.phrase));
    const held = hold(local(), 'proof');
    await settle(() => click($.button('Migrate')!));
    await until(atStage('proof'), 'proof in flight');

    await settle(() => {
      stale.options.onProgress?.('Reading a stale page');
      stale.d.resolve(EXPOSURE_B);
    });
    expect($.text()).not.toContain('Reading a stale page');
    expect($.text()).not.toContain(B);
    expect($.panel()!.dataset).toMatchObject({ status: 'submitted', stage: 'proof' });
    expectFrozen();
    // It finishes against the account it started with.
    held.resolve();
    await until(verified, 'the migration to finish');
    expect(local().landed.at(-1)!.txn.sender.toString()).toBe(A);
  });

  it('a scan from the network before a switch cannot land, or fail, on the new one', async () => {
    await settle(() => setValue($.networkSelect(), 'localnet'));
    await settle(() => setValue($.addressInput(), A));
    await settle(() => click($.button('Scan')!));
    const stale = world.scans.at(-1)!;
    await ready({ network: 'testnet' });
    const held = hold(world.ledgers.testnet, 'funding');
    await settle(() => click($.button('Migrate')!));
    await until(atStage('funding'), 'funding in flight');
    expect(world.ledgers.testnet.count('params')).toBeGreaterThan(0);
    expect(local().count('params')).toBe(0);

    await settle(() => stale.d.reject(new Error('stale scan failed')));
    expect($.text()).not.toContain('stale scan failed');
    expect($.button('Scanning')).toBeUndefined();
    expect($.networkSelect().value).toBe('testnet');
    expectFrozen();
    held.resolve();
    await until(verified, 'the migration to finish');
  });

  it('a key that sent nothing can still be replaced, or dropped by a scan or network change', async () => {
    await ready();
    const first = $.panel()!.dataset.operation;
    expect($.q('[data-lock]')).toBeNull();
    await settle(() => click($.button('Generate a different key')!));
    expect($.panel()!.dataset.operation).not.toBe(first);
    expect($.phraseShown()).toEqual(T2.mnemonic!.split(' '));
    expect($.transcription()!.value).toBe('');
    await settle(() => setValue($.networkSelect(), 'testnet'));
    expect($.panel()).toBeNull();
    expect($.text()).not.toContain(T2.address);
    expect(sends()).toBe(0);
    expect(stored()).toBeNull();
  });
});

describe('keyboard focus through the ceremony', () => {
  it('goes to the new key, then to the status line whenever a step withdraws the button used', async () => {
    await scanned(EXPOSURE_A);
    const generate = $.button('Generate a post-quantum key')!;
    generate.focus();
    await settle(() => click(generate));
    // The button went with the panel it was in; the new panel's heading has focus.
    expect(document.activeElement).toBe($.q('[data-operation] h2'));
    const target = mocks.generatePqIdentity.mock.results.at(-1)!.value as PqIdentity;
    await settle(() => setValue($.transcription()!, target.mnemonic!));
    await settle(() => setValue($.signing()!, SIGNER.phrase));
    const migrate = $.button('Migrate')!;
    migrate.focus();
    await settle(() => click(migrate));
    expect(document.activeElement).toBe($.q('[data-status-text]'));
    await until(verified, 'verification');
    expect(document.activeElement).toBe($.q('[data-status-text]'));
  });
});

describe('an account record the node cannot vouch for (CORE-04)', () => {
  const headings = () => Array.from(page.container.querySelectorAll('h2'), (h) => h.textContent);

  it('shows the refusal, and nothing of the earlier report or its migration', async () => {
    await scanned(EXPOSURE_A);
    expect(headings()).toContain('Verdict');
    expect($.button('Generate a post-quantum key')).toBeDefined();

    // REPO-01's record, refused by the real scan.
    const refusal = await refusalOf(B, { amount: 'not-a-number', minBalance: 1.5, authAddr: '' });
    await settle(() => setValue($.addressInput(), B));
    await settle(() => click($.button('Scan')!));
    expect(headings()).not.toContain('Verdict');
    await settle(() => world.scans.at(-1)!.d.reject(refusal));

    expect($.q('.err')!.textContent).toBe(
      'The node answered with an unusable account record (malformed account balance). Nothing was judged.',
    );
    expect(headings()).not.toContain('Verdict');
    expect($.button('Generate a post-quantum key')).toBeUndefined();
    expect($.panel()).toBeNull();
  });
});

describe('refused before anything is sent', () => {
  it('refuses a signing key for another account, and can then go ahead', async () => {
    await ready({ signingPhrase: OTHER_SIGNER.phrase });
    const id = $.panel()!.dataset.operation;
    // Only the budget has been read.
    expect(local().count('params')).toBe(1);
    await settle(() => click($.button('Migrate')!));
    expect($.panel()!.dataset).toMatchObject({ operation: id, status: 'failed', stage: '' });
    expect($.text()).toContain(`Nothing was sent. That phrase controls ${B}, not the account being migrated.`);
    expect(local().count('params')).toBe(1);
    expect(sends()).toBe(0);
    // Nothing is at stake, so nothing is locked, and nothing was saved.
    expect($.q('[data-lock]')).toBeNull();
    expect($.networkSelect().disabled).toBe(false);
    expect($.button('Generate a different key')!.disabled).toBe(false);
    expect(stored()).toBeNull();
    await settle(() => setValue($.signing()!, SIGNER.phrase));
    const held = hold(local(), 'funding');
    await settle(() => click($.button('Migrate')!));
    await until(atStage('funding'), 'funding in flight');
    expect($.panel()!.dataset.operation).toBe(id);
    held.resolve();
    await until(verified, 'the migration to finish');
  });

  it('refuses a node that reports a public network behind the LocalNet endpoint', async () => {
    local().setGenesis(MAINNET_GENESIS);
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed', 'the refusal');
    expect($.panel()!.dataset.stage).toBe('');
    expect($.text()).toContain('Nothing was sent. The node reports mainnet-v1.0');
    expect($.text()).toContain('a public network, behind the LocalNet endpoint');
    expect(sends()).toBe(0);
  });

  it('refuses when the network cannot be established', async () => {
    await ready();
    local().fail('params', 'server-error');
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed', 'the refusal');
    expect($.text()).toContain('Nothing was sent. Could not establish which network the node is on');
    expect(sends()).toBe(0);
    expect($.q('[data-lock]')).toBeNull();
  });

  it('bounds the network check, and ignores its late answer', async () => {
    remount({ timing: SHORT });
    const late = deferred<void>();
    await ready();
    local().fail('params', { until: late.promise });
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed', 'the refusal');
    expect($.text()).toMatch(/Nothing was sent\. Could not establish which network.*No answer after 60 ms/);
    late.resolve();
    await settle();
    await new Promise((r) => setTimeout(r, 50));
    await settle();
    // The late answer starts nothing.
    expect(sends()).toBe(0);
    expect($.status()).toBe('failed');
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration to finish');
  });

  it('runs on TestNet only when the node reports TestNet', async () => {
    await ready({ network: 'testnet' });
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'the migration to finish');
    expect(landedStages(world.ledgers.testnet)).toEqual([...STAGE_LIST]);
    expect(local().landed).toHaveLength(0);
  });

  it('offers no execution for a plan with blockers, or on MainNet', async () => {
    // The ledger holds what the scan reported: too little for the migration.
    local().setBalance(A, 150_000n);
    await scanned(POOR_A);
    await settle(() => click($.button('Generate a post-quantum key')!));
    expect($.q('[data-budget]')!.getAttribute('data-budget-status')).toBe('blocked');
    expect($.text()).toContain('the migration needs 0.108 ALGO');
    expect($.button('Migrate')).toBeUndefined();
    await settle(() => setValue($.networkSelect(), 'mainnet'));
    // Affordable on MainNet, so the only thing standing in the way is the network.
    world.ledgers.mainnet.setBalance(A, 10_000_000n);
    await scanned(EXPOSURE_A, 'mainnet');
    await settle(() => click($.button('Generate a post-quantum key')!));
    expect($.text()).toContain('Execution from this page is limited to TestNet and LocalNet.');
    expect($.button('Migrate')).toBeUndefined();
    expect(sends()).toBe(0);
  });

  it('keeps Migrate off until every check passes and the phrase is typed back', async () => {
    await ready();
    expect($.button('Migrate')!.disabled).toBe(false);
    const words = T1.mnemonic!.split(' ');
    await settle(() => setValue($.transcription()!, [words[1], words[0], ...words.slice(2)].join(' ')));
    expect($.button('Migrate')!.disabled).toBe(true);
    await settle(() => setValue($.transcription()!, T1.mnemonic!));
    world.selfTestPasses = false;
    await settle(() => setValue($.transcription()!, ` ${T1.mnemonic!} `));
    expect($.button('Migrate')!.disabled).toBe(true);
  });

  it('sends nothing where this browser cannot keep tabs apart', async () => {
    remount({ noLocks: true });
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed', 'the refusal');
    expect($.text()).toContain('Nothing was sent. This page could not take its exclusive hold on the migration record');
    expect(sends()).toBe(0);
    expect(stored()).toBeNull();
    expect($.q('[data-lock]')).toBeNull();
  });

  it('sends nothing when the record cannot be written', async () => {
    const full = {
      getItem: () => null,
      setItem: () => {
        throw Object.assign(new Error('full'), { name: 'QuotaExceededError' });
      },
      removeItem: () => undefined,
    };
    remount({ journal: browserJournal(() => full) });
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed', 'the refusal');
    expect($.text()).toMatch(/Nothing was sent for this step\. The attempt could not be recorded, so it was not sent: The record could not be saved \(QuotaExceededError\)/);
    expect(sends()).toBe(0);
    // Nothing is at stake: it can be retried or replaced.
    expect($.panel()!.dataset.stage).toBe('');
    expect($.q('[data-lock]')).toBeNull();
  });
});

describe('the command handler, called directly', () => {
  let handle: ReturnType<typeof useMigrationOperation>;
  let hookRoot: Root;
  let options: Parameters<typeof useMigrationOperation>[0];

  function Harness() {
    handle = useMigrationOperation(options);
    return null;
  }

  beforeEach(() => {
    const mem = memoryStorage();
    const locks = fakeLocks();
    options = { journal: browserJournal(() => mem), tabLock: browserTabLock(() => locks.manager), timing: TIMING };
    hookRoot = createRoot(document.createElement('div'));
    act(() => hookRoot.render(<Harness />));
  });
  afterEach(() => act(() => hookRoot.unmount()));

  const base = (exposure: AccountExposure, network: 'localnet' | 'mainnet' = 'localnet'): ContextBase => ({
    network,
    scan: { address: exposure.address, network, assets: '', apps: '' },
    exposure,
    sender: exposure.address,
    authorizer: exposure.authAddr ?? exposure.address,
    clients: mocks.clientsFor(network),
  });
  const good = { transcription: T1.mnemonic!, signingPhrase: SIGNER.phrase };

  const refusals: Array<[string, () => void, { exposure?: () => AccountExposure; network?: 'mainnet' }, RegExp]> = [
    ['a wrong transcription', () => undefined, {}, /does not re-derive/],
    // The ceremony runs the real preflight: a key whose private half is another key's fails its self-test.
    ['a failed preflight check', () => (world.identities[0] = { ...T1, privateKey: T2.privateKey }), {}, /preflight check failed: Falcon key signs and verifies/],
    ['a budget that cannot go ahead', () => local().setBalance(A, 150_000n), { exposure: () => POOR_A }, /budget is blocked: .*the migration needs/],
    ['MainNet', () => undefined, { network: 'mainnet' }, /limited to TestNet and LocalNet/],
  ];

  it.each(refusals)('refuses %s even though no button was pressed', async (name, arrange, setup, reason) => {
    arrange();
    await settle(() => void handle.commands.prepare(base(setup.exposure?.() ?? EXPOSURE_A, setup.network)));
    const inputs = name === 'a wrong transcription' ? { ...good, transcription: T2.mnemonic! } : good;
    await settle(() => void handle.commands.execute(inputs));
    expect(handle.state).toMatchObject({ status: 'failed', stage: null, error: expect.stringMatching(reason) });
    // Only the budget was read; nothing was prepared.
    expect(world.ledgers[setup.network ?? 'localnet'].count('params')).toBe(1);
    expect(sends()).toBe(0);
  });

  it('refuses to start before the budget has been read, and on a budget it cannot approve', async () => {
    // Prepared, and executed in the same turn: the budget is still being read.
    act(() => void handle.commands.prepare(base(EXPOSURE_A)));
    await settle(() => void handle.commands.execute(good));
    expect(handle.state).toMatchObject({ status: 'failed', stage: null, error: expect.stringMatching(/still being read/) });
    // An unavailable budget cannot be approved either.
    local().setProtocol('future');
    await settle(() => void handle.commands.refreshQuote());
    expect((handle.state as { quote: { status: string } }).quote.status).toBe('unavailable');
    await settle(() => void handle.commands.execute(good));
    expect(handle.state).toMatchObject({ status: 'failed', stage: null, error: expect.stringMatching(/budget is unavailable/) });
    expect(sends()).toBe(0);
  });

  it('starts once for two calls in the same turn, and never retries verification before a rekey', async () => {
    await settle(() => void handle.commands.prepare(base(EXPOSURE_A)));
    const held = hold(local(), 'funding');
    await settle(() => {
      void handle.commands.execute(good);
      void handle.commands.execute(good);
      void handle.commands.retryVerification();
      void handle.commands.resume({ signingPhrase: SIGNER.phrase });
      void handle.commands.reconcile();
    });
    await until(() => sends() === 1, 'the funding send');
    // The budget with the key, the genesis, the budget again, the funding.
    expect(local().count('params')).toBe(4);
    expect(handle.commands.prepare(base(EXPOSURE_B))).toBe(false);
    expect(handle.commands.discard()).toBe(false);
    expect(handle.commands.dismiss(true)).toBeNull();
    held.resolve();
    await until(() => handle.state.status === 'confirmed' && (handle.state as { stage: string }).stage === 'verification', 'the run');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });
});

describe('ambiguous outcomes stay locked', () => {
  it.each(STAGE_LIST)('a send that hangs while %s is in flight is an unknown outcome, not a failure', async (stage) => {
    remount({ timing: SHORT });
    local().fail('send', 'hang', (_id, bytes) => {
      try {
        return stageOfSigned(algosdk.decodeSignedTransaction(bytes as Uint8Array)) === stage;
      } catch {
        return false;
      }
    });
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(atStage(stage, 'outcome-unknown'), 'an unknown outcome');
    const alert = $.q('[data-alert="outcome-unknown"]')!.textContent!;
    expect(alert).toContain('Outcome unknown.');
    expect(alert).toContain('no retry, no new key and no other scan');
    expect(alert).toContain('the saved record lets the page pick this up again');
    if (stage === 'rekey') expect(alert).toContain(`The rekey may have taken effect. If it did, ${A} is now controlled only by ${T1.address}`);
    if (stage === 'verification') expect(alert).toContain('The rekey already succeeded');
    if (stage === 'funding' || stage === 'proof') expect(alert).toContain('The account itself has not been rekeyed.');
    expect($.text()).toContain('No answer after 60 ms while sending the transaction');
    // Nothing continues, and nothing offers to start again.
    const at = STAGE_LIST.indexOf(stage);
    expect(landedStages(local())).toEqual(STAGE_LIST.slice(0, at));
    for (const label of ['Retry verification', 'Migrate', 'Generate a different key', 'Dismiss and remove the words from this page']) {
      expect($.button(label), label).toBeUndefined();
    }
    expect($.continueButton()).toBeUndefined();
    expect($.button('Check the ledger')).toBeDefined();
    expectFrozen();
    await attemptBypass();
    expect($.status()).toBe('outcome-unknown');
    // The record says it was recorded, and the page cannot say more.
    const doc = JSON.parse(stored()!);
    expect(doc.attempts.at(-1)).toMatchObject({ stage, state: 'unknown' });
  });
});

describe('after a confirmed rekey', () => {
  /** The rekey confirms; verification cannot read the account, and sends nothing. */
  async function verificationStops() {
    // Once the rekey is in, the next account read - verification's own - fails.
    local().onSend((s) => {
      if (stageOfSigned(s) === 'rekey') local().fail('account', 'server-error');
    });
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(() => $.status() === 'failed' && $.panel()!.dataset.stage === 'verification', 'verification to stop');
    await budgetFor('verification');
  }

  it('keeps the rekey through a stopped verification, and retries only verification, once per click burst', async () => {
    await verificationStops();
    expect(landedStages(local())).toEqual(['funding', 'proof', 'rekey']);
    const alert = $.q('[data-alert="rekeyed"]')!.textContent!;
    expect(alert).toContain('The rekey already succeeded.');
    expect(alert).toContain('then retry the verification');
    expect($.q('[data-status-text]')!.textContent).toContain('Verification stopped before sending anything');
    expect($.button('Migrate')).toBeUndefined();
    expect($.button('Generate a different key')).toBeUndefined();
    expectFrozen();
    await attemptBypass();

    const held = hold(local(), 'verification');
    await settle(() => {
      click($.button('Retry verification')!);
      click($.button('Retry verification')!);
    });
    await until(atStage('verification'), 'verification in flight');
    expect(local().count('send')).toBe(4);
    expect($.q('[data-alert="rekeyed"]')!.textContent).toContain('It is being verified now.');
    held.resolve();
    await until(verified, 'verification');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
  });

  it('a retry whose outcome is unclear stays locked, with no further retry', async () => {
    remount({ timing: SHORT });
    await verificationStops();
    local().fail('send', 'hang');
    await settle(() => click($.button('Retry verification')!));
    await until(atStage('verification', 'outcome-unknown'), 'an unknown outcome');
    expect($.button('Retry verification')).toBeUndefined();
    expect($.q('[data-alert="outcome-unknown"]')!.textContent).toContain('The rekey already succeeded');
    expectFrozen();
  });

  it('a retry that verifies completes the migration, and reads the account again', async () => {
    await verificationStops();
    await settle(() => click($.button('Retry verification')!));
    await until(verified, 'verification');
    expect(landedStages(local())).toEqual([...STAGE_LIST]);
    expect(world.scans.at(-1)).toMatchObject({ address: A, network: 'localnet' });
  });

  it('a failed refresh after migrating keeps the result, the words and the lock', async () => {
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'verification');
    await settle(() => world.scans.at(-1)!.d.reject(new Error('indexer unavailable')));
    expect($.text()).toContain('The migration stands, but refreshing the report failed: indexer unavailable');
    expect($.panel()!.dataset).toMatchObject({ status: 'confirmed', stage: 'verification' });
    expect($.text()).toContain('Migrated.');
    expectFrozen();
  });

  it('is dismissed only when verified and acknowledged, which removes its record, and then offers no second key', async () => {
    await ready();
    await settle(() => click($.button('Migrate')!));
    await until(verified, 'verification');
    const refresh = world.scans.at(-1)!;
    const dismiss = () => $.button('Dismiss and remove the words from this page')!;
    expect(dismiss().disabled).toBe(true);
    await settle(() => click(dismiss()));
    expect($.panel()).not.toBeNull();
    expect(stored()).not.toBeNull();

    await settle(() => click($.q('[data-dismissal] input[type="checkbox"]')!));
    await settle(() => click(dismiss()));
    expect($.panel()).toBeNull();
    expect($.phraseShown()).toEqual([]);
    expect(stored()).toBeNull();
    expect($.q('[data-lock]')).toBeNull();
    expect($.networkSelect().disabled).toBe(false);
    // The same account, even before Indexer shows its new authority.
    expect($.text()).toContain(`This account was migrated to ${T1.address} earlier in this session`);
    expect($.button('Generate a post-quantum key')).toBeUndefined();

    // Unlocked: another scan runs, and the migration's refresh, still in
    // flight, lands on nothing.
    // Busy, the button keeps keyboard focus, and pressing it starts nothing.
    const scanning = $.button('Scanning')!;
    expect(scanning.getAttribute('aria-disabled')).toBe('true');
    const scans = world.scans.length;
    await settle(() => click(scanning));
    expect(world.scans.length).toBe(scans);
    await settle(() => setValue($.addressInput(), B));
    await settle(() => pressEnter($.addressInput()));
    await settle(() => refresh.d.resolve(REFRESHED_A));
    await settle(() => world.scans.at(-1)!.d.resolve(EXPOSURE_B));
    expect($.button('Generate a post-quantum key')).toBeDefined();
    expect($.text()).not.toContain('earlier in this session');
  });
});

describe('recovery material stays in memory', () => {
  it('saves only the public record: no phrase in storage, the URL, cookies or the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const spies = methods.map((m) => vi.spyOn(console, m));
    const href = window.location.href;
    try {
      await ready();
      await settle(() => click($.button('Migrate')!));
      await until(verified, 'verification');
      await settle(() => world.scans.at(-1)!.d.resolve(REFRESHED_A));
      expect(Object.keys(window.localStorage)).toEqual([JOURNAL_KEY]);
      expectNoSecrets(stored()!);
      expect(window.sessionStorage.length).toBe(0);
      expect(document.cookie).toBe('');
      expect(window.location.href).toBe(href);
      const logged = spies.flatMap((s) => s.mock.calls.flat().map(String)).join('\n');
      expectNoSecrets(logged);
      // The signing phrase left the page once the first step was entered.
      expect($.signing()).toBeNull();
      expect(page.container.innerHTML).not.toContain(SIGNER.phrase);
    } finally {
      for (const s of spies) s.mockRestore();
    }
  });
});
