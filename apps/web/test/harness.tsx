/**
 * The mounted app against scripted ledgers (SAFE-02a, SAFE-02b).
 *
 * Only the scan, key generation and the offline phrase check are replaced
 * (each test file mocks them and hands the mocks to `installCore`). Every
 * transaction is prepared, signed, recorded, sent and reconciled by the real
 * core and page code, against a scripted ledger per network that decodes and
 * checks each send. A test puts faults where it wants them on that ledger,
 * and reads the result from the ledger, the page and the browser's storage.
 *
 * The new keys are real Falcon-1024 keys from fixed public seeds, and the
 * signing keys come from fixed public seeds too. None is printed.
 */
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import algosdk from 'algosdk';
import {
  pqIdentityFromMnemonic,
  type AccountExposure,
  type FalconerClients,
  type PqIdentity,
} from '@falqoner/core';
// The real scan, from its own module: the test files mock it on '@falqoner/core'.
import { analyzeAccount as realAnalyze } from '../../../packages/core/src/exposure';
import { fakeProvider, type FakeSpec } from '../../../packages/core/test/fake-provider';
import { scriptedLedger, type ScriptedLedger } from '../../../packages/core/test/scripted-ledger';
import App, { type AppProps } from '../src/App';
import { JOURNAL_KEY, browserJournal, browserTabLock, type Journal } from '../src/journal';
import type { Stage, Timing } from '../src/operation';
import {
  LOCAL_GENESIS,
  MAINNET_GENESIS,
  TESTNET_GENESIS,
  deferred,
  fakeLocks,
  signingFixture,
  type Deferred,
} from './fixtures';

export const SIGNER = signingFixture(51);
export const OTHER_SIGNER = signingFixture(52);
export const A = SIGNER.address;
export const B = OTHER_SIGNER.address;
const real = (fill: number) => pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill)));
export const T1 = real(61);
export const T2 = real(62);
export const T3 = real(63);

export const STAGE_LIST = ['funding', 'proof', 'rekey', 'verification'] as const;

export const exposureOf = (
  address: string,
  account: { amount?: bigint; authAddr?: string } = {},
  history: FakeSpec['history'] = {},
) => realAnalyze(fakeProvider({ accounts: { [address]: { amount: 5_000_000n, ...account } }, history }).clients, address);

/** The real scan's refusal when the node answers `address`'s account read with `record` (CORE-04). */
export const refusalOf = (address: string, record: unknown) => {
  const { clients } = fakeProvider({});
  Object.assign(clients.algod, { accountInformation: () => ({ do: async () => record }) });
  return realAnalyze(clients, address).then(
    () => { throw new Error('the scan judged an unusable account record'); },
    (err: Error) => err,
  );
};

/** Fast enough for tests, slow enough that nothing times out unless a test makes it. */
export const TIMING: Timing = { requestMs: 2000, confirmMs: 1500, pollMs: 5, reconcileMs: 5000 };
/** For tests that make something time out. */
export const SHORT: Timing = { requestMs: 60, confirmMs: 120, pollMs: 5, reconcileMs: 2000 };

export interface CoreMocks {
  analyzeAccount: { mockImplementation(fn: (...a: any[]) => unknown): unknown };
  clientsFor: { mockImplementation(fn: (...a: any[]) => unknown): unknown };
  generatePqIdentity: { mockImplementation(fn: (...a: any[]) => unknown): unknown };
  preflight: { mockImplementation(fn: (...a: any[]) => unknown): unknown };
}

export interface ScanCall {
  address: string;
  network: string;
  options: { assetIds?: bigint[]; appIds?: bigint[]; onProgress?: (m: string) => void };
  d: Deferred<AccountExposure>;
}

/** Everything a test can script, and read back. */
export interface World {
  ledgers: Record<'localnet' | 'testnet' | 'mainnet', ScriptedLedger>;
  scans: ScanCall[];
  identities: PqIdentity[];
  selfTestPasses: boolean;
  clientLabels: string[];
}

export function installCore(mocks: CoreMocks): World {
  const world: World = {
    ledgers: {
      localnet: scriptedLedger({ genesis: LOCAL_GENESIS, accounts: { [A]: {}, [B]: {} } }),
      testnet: scriptedLedger({ genesis: TESTNET_GENESIS, accounts: { [A]: {}, [B]: {} } }),
      mainnet: scriptedLedger({ genesis: MAINNET_GENESIS }),
    },
    scans: [],
    identities: [T1, T2, T3],
    selfTestPasses: true,
    clientLabels: [],
  };
  mocks.analyzeAccount.mockImplementation((clients: FalconerClients, address: string, options: ScanCall['options']) => {
    const d = deferred<AccountExposure>();
    world.scans.push({ address, network: clients.network.name, options, d });
    return d.promise;
  });
  mocks.clientsFor.mockImplementation((net: 'mainnet' | 'testnet' | 'localnet') => {
    const label = `${net}#${world.clientLabels.length + 1}`;
    world.clientLabels.push(label);
    const base = world.ledgers[net].clients;
    return { ...base, label, network: { ...base.network, name: net } };
  });
  mocks.generatePqIdentity.mockImplementation(() => world.identities.shift());
  // Stands in for the real re-derivation, which is slow: the phrase must match exactly.
  mocks.preflight.mockImplementation((identity: PqIdentity, transcription?: string) => {
    const typed = transcription?.trim().split(/\s+/).join(' ');
    const confirmed = !!typed && typed === identity.mnemonic;
    const checks = [
      { name: 'Falcon key signs and verifies', passed: world.selfTestPasses, detail: 'fixture' },
      { name: 'Address is off-curve', passed: true, detail: 'fixture' },
      { name: 'Recovery phrase reproduces the key', passed: confirmed, detail: typed ? (confirmed ? 'matches' : 'differs') : 'Not checked.' },
    ];
    return { ok: typed ? checks.every((c) => c.passed) : world.selfTestPasses, transcriptionConfirmed: confirmed, checks };
  });
  return world;
}

/** Which step a signed transaction is, from its shape. */
export function stageOfSigned(s: algosdk.SignedTransaction): Stage {
  const t = s.txn;
  const sender = t.sender.toString();
  const receiver = t.payment?.receiver.toString();
  if (t.rekeyTo) return 'rekey';
  if (sender === receiver && s.sgnr) return 'verification';
  if (sender === receiver) return 'proof';
  return 'funding';
}

/** Which step sent bytes are, or null if they do not decode. */
export function stageOf(bytes: unknown): Stage | null {
  try {
    return stageOfSigned(algosdk.decodeSignedTransaction(bytes as Uint8Array));
  } catch {
    return null;
  }
}

/** The steps that reached `ledger`, in order. */
export const landedStages = (ledger: ScriptedLedger) => ledger.landed.map(stageOfSigned);

/** Hold the next send of `stage` until the test releases it. */
export function hold(ledger: ScriptedLedger, stage: Stage): Deferred<void> {
  const d = deferred<void>();
  ledger.fail('send', { until: d.promise }, (_id, bytes) => stageOf(bytes) === stage);
  return d;
}

/** The next send of `stage` reaches the ledger, and its response is lost. */
export function loseResponse(ledger: ScriptedLedger, stage: Stage) {
  ledger.fail('send', 'lose-response', (_id, bytes) => stageOf(bytes) === stage);
}

/** The next send of `stage` never reaches the ledger. */
export function loseRequest(ledger: ScriptedLedger, stage: Stage) {
  ledger.fail('send', 'lose-request', (_id, bytes) => stageOf(bytes) === stage);
}

/** Transaction lookups answer 404 `times` times, as a node that forgot would. */
export function hideLookups(ledger: ScriptedLedger, times = 1000) {
  ledger.failTimes('pending', 'not-found', times);
}

/* ------------------------------------------------------------------ */
/* The page                                                            */
/* ------------------------------------------------------------------ */

export interface Page {
  container: HTMLDivElement;
  root: Root;
  locks: ReturnType<typeof fakeLocks>;
  journal: Journal;
  timing: Timing;
}

/** Mount the app, as a page load does. */
export function mount(
  { locks = fakeLocks(), journal = browserJournal(), timing = TIMING, noLocks = false }: {
    locks?: ReturnType<typeof fakeLocks>;
    journal?: Journal;
    timing?: Timing;
    noLocks?: boolean;
  } = {},
): Page {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  const props: AppProps = {
    journal,
    timing,
    tabLock: browserTabLock(() => (noLocks ? undefined : locks.manager)),
  };
  act(() => root.render(<App {...props} />));
  return { container, root, locks, journal, timing };
}

export function unmount(page: Page) {
  act(() => page.root.unmount());
  page.container.remove();
}

/**
 * Close the page and open it again, sharing this browser's storage and locks.
 * A browser releases a document's locks as it unloads, before the next page
 * runs, so this waits for the release too.
 */
export async function reload(page: Page, timing = page.timing): Promise<Page> {
  unmount(page);
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
  return mount({ locks: page.locks, journal: page.journal, timing });
}

/** Run `fn` and let every promise it started settle. */
export async function settle(fn?: () => void) {
  await act(async () => {
    fn?.();
    await new Promise((r) => setTimeout(r, 0));
  });
}

/** Wait, in real time, until `ready` holds. */
export async function until(ready: () => boolean, what: string, ms = 6000) {
  const deadline = Date.now() + ms;
  while (!ready()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
  }
}

export function queries(page: () => Page) {
  const c = () => page().container;
  const q = <T extends Element>(selector: string) => c().querySelector<T>(selector);
  const button = (label: string): HTMLButtonElement | undefined =>
    Array.from(c().querySelectorAll('button')).find((b) => b.textContent?.trim() === label);
  /** The input a visible label names, found through that label. */
  const labelled = (text: string) =>
    Array.from(c().querySelectorAll('label')).find((l) => l.textContent?.trim() === text)!.control as HTMLInputElement;
  return {
    q,
    button,
    addressInput: () => labelled('Algorand address'),
    assetsInput: () => labelled('Asset ids to check exactly'),
    networkSelect: () => q<HTMLSelectElement>('select[aria-label="Network"]')!,
    transcription: () => q<HTMLTextAreaElement>('textarea[aria-label="Recovery phrase, typed back"]'),
    signing: () => q<HTMLTextAreaElement>('textarea[aria-label="Signing key phrase"]'),
    restoreInput: () => q<HTMLTextAreaElement>('textarea[aria-label="Recovery phrase of the new key"]'),
    panel: () => q<HTMLElement>('[data-operation]'),
    status: () => q<HTMLElement>('[data-operation]')?.dataset.status,
    text: () => c().textContent ?? '',
    phraseShown: () =>
      Array.from(c().querySelectorAll('[data-recovery-phrase] div'), (d) => (d.textContent ?? '').replace(/^\d+/, '')),
    continueButton: () =>
      Array.from(c().querySelectorAll('[data-continue] button')).at(-1) as HTMLButtonElement | undefined,
  };
}

export function click(el: Element) {
  el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
}

/** Set a control's value the way a user would, and fire the event React listens for. */
export function setValue(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

export function pressEnter(el: Element) {
  el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
}

/** What this browser's storage holds for the journal. */
export const stored = () => window.localStorage.getItem(JOURNAL_KEY);

/**
 * The stored text holds no phrase and no key: not one pair of consecutive
 * words from any phrase in play, no private key and no endpoint.
 */
export function expectNoSecrets(text: string, phrases: string[] = [T1.mnemonic!, T2.mnemonic!, SIGNER.phrase, OTHER_SIGNER.phrase]) {
  for (const phrase of phrases) {
    const w = phrase.split(' ');
    for (let i = 0; i + 1 < w.length; i++) {
      if (text.includes(`${w[i]} ${w[i + 1]}`)) throw new Error('a phrase fragment was found');
    }
  }
  for (const key of [T1.privateKey, T2.privateKey]) {
    if (text.includes(algosdk.bytesToBase64(key).slice(0, 40))) throw new Error('a private key was found');
  }
  if (/scripted:\/\/|http|token|privateKey|mnemonic/i.test(text)) throw new Error('an endpoint or secret field was found');
}
