/**
 * Coverage: what a scan actually read, and what it could not.
 *
 * A report is only as complete as the reads behind it. A read by id ends in
 * one of four ways: a usable record, an established absence (the provider
 * answered 404 for an id that was asked for), a failure, or a response that
 * cannot be used. Only the first two are results. A timeout, an error or a
 * malformed response is never read as "nothing there", and a search that
 * stops early says so instead of presenting what it found as all there is.
 *
 * Searches are bounded twice, by the results they may collect and by the
 * requests they may make, so a provider that pages slowly or loops cannot
 * turn one scan into an unbounded one. Discovery stays bounded too:
 * completing every check here never amounts to a census of the ledger.
 */
import algosdk from 'algosdk';
import { describeEvidence, type AuthorityAssessment } from './authority.js';
import type { FalconerClients } from './networks.js';
import type {
  AccountExposure,
  CoverageCheck,
  CoverageStatus,
  IdReadTally,
  IncomingCoverage,
  SampleCoverage,
} from './types.js';

/**
 * The most distinct accounts rekeyed to one address that a scan reads: the
 * same maximum as the single page this search replaced.
 */
export const INCOMING_ACCOUNT_LIMIT = 1_000;

/** The most requests one incoming search makes, whatever page size is served. */
export const INCOMING_REQUEST_LIMIT = 10;

/** Page size asked of the provider by the ledger sample. */
const SAMPLE_PAGE_SIZE = 1_000;

/** Failure reasons kept per check. */
const ERRORS_KEPT = 5;

/** Longest failure reason kept. */
const REASON_CHARS = 120;

/* ------------------------------------------------------------------ */
/* Reading provider responses                                           */
/* ------------------------------------------------------------------ */

/** Pull a field that may arrive kebab-cased or camel-cased. */
function field(obj: unknown, ...names: string[]): unknown {
  for (const n of names) {
    const v = (obj as Record<string, unknown> | null | undefined)?.[n];
    if (v !== undefined) return v;
  }
  return undefined;
}

/** A provider field as text: algosdk returns addresses as objects. */
function asText(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  const s = typeof v === 'string' ? v : String((v as any)?.toString?.() ?? v);
  return s.length ? s : undefined;
}

/** A non-negative amount, from algosdk's bigints or the REST API's integers. */
function amountOf(v: unknown): bigint | undefined {
  if (typeof v === 'bigint') return v >= 0n ? v : undefined;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  return undefined;
}

/** A positive asset or application id. */
function idOf(v: unknown): bigint | undefined {
  const n = amountOf(v);
  return n !== undefined && n > 0n ? n : undefined;
}

/** An address: text from the REST API and most algosdk models, an Address from some. */
function addressOf(v: unknown): string | undefined {
  if (typeof v !== 'string' && (typeof v !== 'object' || v === null)) return undefined;
  const s = asText(v);
  return s && algosdk.isValidAddress(s) ? s : undefined;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** Padded standard base64, the only form algod and Indexer send. */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Decode base64 without Buffer, so this runs in the browser too. */
function fromB64(s: string): Uint8Array | undefined {
  try {
    if (typeof atob === 'function') {
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return Uint8Array.from((globalThis as any).Buffer.from(s, 'base64'));
  } catch {
    return undefined;
  }
}

/**
 * A byte string: algosdk hands back raw bytes, the REST API base64 text.
 * Anything else, including text that is not base64, is not a byte string.
 */
function bytesOf(v: unknown): Uint8Array | undefined {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return BASE64.test(v) ? fromB64(v) : undefined;
  if (Array.isArray(v) && v.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    return Uint8Array.from(v);
  }
  return undefined;
}

/**
 * A continuation token: absent, or non-empty text. Anything else is a
 * malformed response, never a sign that the results are finished.
 */
function tokenOf(res: unknown): { ok: true; next?: string } | { ok: false } {
  const token = field(res, 'next-token', 'nextToken');
  if (token === undefined || token === null) return { ok: true };
  if (typeof token !== 'string' || token.trim() === '') return { ok: false };
  return { ok: true, next: token };
}

/** The HTTP status a provider error carries, when it carries one. */
export function providerStatus(err: unknown): number | undefined {
  const status =
    (err as any)?.response?.status ?? (err as any)?.status ?? undefined;
  return typeof status === 'number' ? status : undefined;
}

/**
 * A failure reason fit for a report: one short line. An HTTP failure is
 * reported by its status alone, since the body is arbitrary provider text.
 */
export function failureReason(err: unknown): string {
  const status = providerStatus(err);
  if (status !== undefined) return `HTTP ${status}`;
  const message = String((err as any)?.message ?? err ?? '')
    .replace(/\s+/g, ' ')
    .replace(/[^\x20-\x7e]/g, '')
    .trim();
  return message.slice(0, REASON_CHARS) || 'unknown error';
}

function keep(errors: string[], reason: string): void {
  if (errors.length < ERRORS_KEPT && !errors.includes(reason)) errors.push(reason);
}

/* ------------------------------------------------------------------ */
/* Reads by id                                                          */
/* ------------------------------------------------------------------ */

export type ReadOutcome<T> =
  | { kind: 'read'; value: T }
  | { kind: 'not-found' }
  | { kind: 'failed'; reason: string }
  | { kind: 'invalid'; reason: string };

/** A record a parser can use, or the fixed reason it cannot. */
export type Parsed<T> = { ok: true; value: T } | { ok: false; fault: string };

const usable = <T>(value: T): Parsed<T> => ({ ok: true, value });
const unusable = (fault: string): { ok: false; fault: string } => ({ ok: false, fault });

/**
 * Read one record by id. A 404 establishes that the id does not exist;
 * every other failure, and a record `parse` cannot use, is reported as what
 * it is.
 */
export async function readById<T>(
  read: () => Promise<unknown>,
  parse: (raw: unknown) => Parsed<T>,
): Promise<ReadOutcome<T>> {
  let raw: unknown;
  try {
    raw = await read();
  } catch (err) {
    return providerStatus(err) === 404
      ? { kind: 'not-found' }
      : { kind: 'failed', reason: failureReason(err) };
  }
  const parsed = parse(raw);
  return parsed.ok
    ? { kind: 'read', value: parsed.value }
    : { kind: 'invalid', reason: parsed.fault };
}

/** Asset parameters, checked, in one shape whichever form they arrived in. */
export interface AssetParamsRecord {
  creator: string;
  total: bigint;
  decimals: number;
  manager?: string;
  reserve?: string;
  freeze?: string;
  clawback?: string;
  name?: string;
  unitName?: string;
  defaultFrozen?: boolean;
}

export interface AssetRecord {
  assetId: bigint;
  params: AssetParamsRecord;
}

const ROLE_FIELDS = ['manager', 'reserve', 'freeze', 'clawback'] as const;

/** An optional field: absent, or of the one type the API gives it. */
function optional<T>(v: unknown, is: (x: unknown) => x is T): { ok: boolean; value?: T } {
  if (v === undefined || v === null) return { ok: true };
  return is(v) ? { ok: true, value: v } : { ok: false };
}
const isString = (x: unknown): x is string => typeof x === 'string';
const isBoolean = (x: unknown): x is boolean => typeof x === 'boolean';

/**
 * Asset parameters as algod and Indexer define them: a creator, a total and
 * decimals are always present, and each role is absent or an address.
 * Anything else cannot be told apart from an asset that grants no roles, so
 * it is unusable rather than empty. A role that is simply absent is not set,
 * which is ordinary and fine.
 */
export function assetParamsOf(raw: unknown): Parsed<AssetParamsRecord> {
  const bad = unusable('malformed asset parameters');
  if (!isObject(raw)) return unusable('malformed asset record');
  const creator = addressOf(field(raw, 'creator'));
  const total = amountOf(field(raw, 'total'));
  const decimals = amountOf(field(raw, 'decimals'));
  if (!creator || total === undefined || decimals === undefined || decimals > 19n) {
    return bad;
  }
  const params: AssetParamsRecord = { creator, total, decimals: Number(decimals) };
  for (const role of ROLE_FIELDS) {
    const v = field(raw, role);
    if (v === undefined || v === null) continue;
    const address = addressOf(v);
    if (!address) return bad;
    params[role] = address;
  }
  const name = optional(field(raw, 'name'), isString);
  const unitName = optional(field(raw, 'unitName', 'unit-name'), isString);
  const frozen = optional(field(raw, 'defaultFrozen', 'default-frozen'), isBoolean);
  if (!name.ok || !unitName.ok || !frozen.ok) return bad;
  if (name.value !== undefined) params.name = name.value;
  if (unitName.value !== undefined) params.unitName = unitName.value;
  if (frozen.value !== undefined) params.defaultFrozen = frozen.value;
  return usable(params);
}

/**
 * An asset record, as algod returns one by id and Indexer returns them in a
 * page. Read by id, it has to be the record for the id asked for: one for
 * any other asset says nothing about it.
 */
export function assetRecordOf(raw: unknown, requested?: bigint): Parsed<AssetRecord> {
  if (!isObject(raw)) return unusable('malformed asset record');
  const assetId = idOf(field(raw, 'index'));
  if (assetId === undefined) return unusable('malformed asset record');
  if (requested !== undefined && assetId !== requested) {
    return unusable('asset record for a different id');
  }
  const params = assetParamsOf(field(raw, 'params'));
  return params.ok ? usable({ assetId, params: params.value }) : params;
}

/** What a scan reads from an account record, checked. */
export interface AccountRecord {
  amount: bigint;
  minBalance: bigint;
  authAddr?: string;
  heldAssetIds: bigint[];
  createdAssets: AssetRecord[];
  createdAppIds: bigint[];
  optedInAppIds: bigint[];
}

/**
 * An account record as algod returns one (CORE-04). It has to be for the
 * address asked for, with a usable balance and minimum balance, and an
 * authority that is absent or an address. Each list a scan reads must hold
 * usable entries, and as many as the total the account reports for it: a
 * list withheld or cut short would hide exactly what a scan looks for. A
 * list or total that is absent is empty, as algosdk leaves it; one that is
 * present and malformed is not.
 */
export function accountRecordOf(raw: unknown, requested: string): Parsed<AccountRecord> {
  if (!isObject(raw)) return unusable('malformed account record');
  const address = field(raw, 'address');
  if (address !== undefined && asText(address) !== requested) {
    return unusable('account record for a different address');
  }
  const amount = amountOf(field(raw, 'amount'));
  const minBalance = amountOf(field(raw, 'minBalance', 'min-balance'));
  if (amount === undefined) return unusable('malformed account balance');
  if (minBalance === undefined) return unusable('malformed account minimum balance');
  const auth = field(raw, 'authAddr', 'auth-addr');
  const authAddr = auth === null ? undefined : addressOf(auth);
  if (auth !== undefined && auth !== null && !authAddr) return unusable('malformed account authority');

  const list = <T>(names: string[], total: string[], item: (x: unknown) => T | undefined) => {
    const v = field(raw, ...names);
    const t = field(raw, ...total);
    const count = t === undefined ? undefined : amountOf(t);
    if ((v !== undefined && !Array.isArray(v)) || (t !== undefined && count === undefined)) return undefined;
    const items = ((v ?? []) as unknown[]).map(item);
    if (count !== undefined && BigInt(items.length) !== count) return undefined;
    return items.every((x) => x !== undefined) ? (items as T[]) : undefined;
  };
  const idIn = (...names: string[]) => (x: unknown) => (isObject(x) ? idOf(field(x, ...names)) : undefined);
  const record = (x: unknown) => {
    const r = assetRecordOf(x);
    return r.ok ? r.value : undefined;
  };

  const heldAssetIds = list(['assets'], ['totalAssetsOptedIn', 'total-assets-opted-in'], idIn('assetId', 'asset-id'));
  if (!heldAssetIds) return unusable('malformed account asset holdings');
  const createdAssets = list(['createdAssets', 'created-assets'], ['totalCreatedAssets', 'total-created-assets'], record);
  if (!createdAssets) return unusable('malformed account created assets');
  const createdAppIds = list(['createdApps', 'created-apps'], ['totalCreatedApps', 'total-created-apps'], idIn('id', 'index'));
  if (!createdAppIds) return unusable('malformed account created applications');
  const optedInAppIds = list(['appsLocalState', 'apps-local-state'], ['totalAppsOptedIn', 'total-apps-opted-in'], idIn('id', 'appId'));
  if (!optedInAppIds) return unusable('malformed account application opt-ins');

  return usable({ amount, minBalance, authAddr, heldAssetIds, createdAssets, createdAppIds, optedInAppIds });
}

/** One global-state entry. Only a byte-string value is kept: a uint is never an address. */
export interface StateEntry {
  key: Uint8Array;
  bytes?: Uint8Array;
}

/** TealValue types, as algod and Indexer number them. */
const TEAL_BYTES = 1n;
const TEAL_UINT = 2n;

function stateEntryOf(raw: unknown): StateEntry | undefined {
  if (!isObject(raw)) return undefined;
  const key = bytesOf(field(raw, 'key'));
  const value = field(raw, 'value');
  if (!key || !isObject(value)) return undefined;
  const type = amountOf(field(value, 'type'));
  if (type === TEAL_BYTES) {
    const bytes = bytesOf(field(value, 'bytes'));
    return bytes ? { key, bytes } : undefined;
  }
  if (type === TEAL_UINT) {
    return amountOf(field(value, 'uint')) !== undefined ? { key } : undefined;
  }
  return undefined;
}

/**
 * The global state of the application record read for `requested`. The
 * record has to be for that id and carry parameters with a creator, and
 * every entry has to be a key and a typed value: skipping an entry that
 * cannot be read would turn it into "names nobody". An application with no
 * global state is ordinary, and reads as empty.
 */
export function appStateOf(raw: unknown, requested: bigint): Parsed<StateEntry[]> {
  if (!isObject(raw)) return unusable('malformed application record');
  const appId = idOf(field(raw, 'id'));
  if (appId === undefined) return unusable('malformed application record');
  if (appId !== requested) return unusable('application record for a different id');
  const params = field(raw, 'params');
  if (!isObject(params) || !addressOf(field(params, 'creator'))) {
    return unusable('malformed application record');
  }
  const state = field(params, 'globalState', 'global-state');
  if (state === undefined || state === null) return usable([]);
  if (!Array.isArray(state)) return unusable('malformed global state');
  const entries: StateEntry[] = [];
  for (const item of state) {
    const entry = stateEntryOf(item);
    if (!entry) return unusable('malformed global state');
    entries.push(entry);
  }
  return usable(entries);
}

export function newTally(): IdReadTally {
  return { requested: 0, attempted: 0, read: 0, notFound: 0, failed: 0, invalid: 0 };
}

export function countRead(
  t: IdReadTally,
  outcome: ReadOutcome<unknown>,
  errors: string[],
): void {
  t.attempted++;
  switch (outcome.kind) {
    case 'read':
      t.read++;
      break;
    case 'not-found':
      t.notFound++;
      break;
    case 'failed':
      t.failed++;
      keep(errors, outcome.reason);
      break;
    case 'invalid':
      t.invalid++;
      keep(errors, outcome.reason);
      break;
  }
}

/**
 * The status of a set of reads by id. Ids asked for and answered 404 count
 * as done; ids skipped at a cap, failed or malformed do not.
 */
export function tallyStatus(
  t: IdReadTally,
  { requestedByCaller = false }: { requestedByCaller?: boolean } = {},
): CoverageStatus {
  if (t.requested === 0) return requestedByCaller ? 'not-requested' : 'complete';
  if (t.invalid > 0) return 'invalid-response';
  if (t.failed > 0 && t.read + t.notFound === 0) return 'unavailable';
  if (t.failed > 0 || t.attempted < t.requested) return 'partial';
  return 'complete';
}

/** What fell short in a set of reads, one phrase each. */
export function tallyGaps(t: IdReadTally, noun: string, cap?: number): string[] {
  const gaps: string[] = [];
  if (t.failed) gaps.push(`${t.failed} ${noun} read${t.failed === 1 ? '' : 's'} failed`);
  if (t.invalid) {
    gaps.push(`${t.invalid} ${noun} record${t.invalid === 1 ? ' was' : 's were'} unusable`);
  }
  const skipped = t.requested - t.attempted;
  if (skipped) {
    gaps.push(
      `${skipped} ${noun}${skipped === 1 ? ' was' : 's were'} not read` +
        (cap ? `, past the limit of ${cap}` : ''),
    );
  }
  return gaps;
}

/** One status for several checks: complete only if every one that ran is. */
export function combineStatus(statuses: CoverageStatus[]): CoverageStatus {
  const ran = statuses.filter((s) => s !== 'not-requested');
  if (!ran.length) return 'not-requested';
  const first = ran.find((s) => s !== 'complete');
  if (!first) return 'complete';
  return ran.every((s) => s === first) ? first : 'partial';
}

/** Statuses that keep a verdict from being complete. */
export function isShortfall(s: CoverageStatus): boolean {
  return s === 'partial' || s === 'unavailable' || s === 'invalid-response';
}

/* ------------------------------------------------------------------ */
/* Signing history                                                      */
/* ------------------------------------------------------------------ */

/**
 * The history check, read straight off the authority evidence: the lookup
 * already records how the search for a signing record ended, so this states
 * it as coverage rather than reaching a second verdict.
 */
export function historyCoverage(a: AuthorityAssessment): CoverageCheck {
  const e = a.evidence;
  const status: CoverageStatus =
    e.lookup === 'history-limited'
      ? 'partial'
      : e.lookup === 'unavailable'
        ? 'unavailable'
        : e.lookup === 'invalid-response'
          ? 'invalid-response'
          : 'complete';
  const text = describeEvidence(a);
  return {
    status,
    detail:
      e.lookup === 'not-needed'
        ? 'No lookup needed: the authority is on the Ed25519 curve, which ' +
          'establishes classical exposure from the address alone.'
        : `${text[0]!.toUpperCase()}${text.slice(1)}.`,
    errors: e.responseFault ? [e.responseFault] : [],
  };
}

/** Why the history check fell short, when it did. */
export function historyGap(a: AuthorityAssessment): string | undefined {
  switch (a.evidence.lookup) {
    case 'history-limited':
      return (
        `only the ${a.evidence.lookback} most recent transactions this ` +
        'account sent were searched for what signs for it'
      );
    case 'unavailable':
      return 'what signs for this account could not be checked';
    case 'invalid-response':
      return (
        'the search for what signs for this account returned an unusable ' +
        'response'
      );
    default:
      return undefined;
  }
}

/* ------------------------------------------------------------------ */
/* Accounts rekeyed to an address                                       */
/* ------------------------------------------------------------------ */

type Stop =
  | 'no-indexer'
  | 'result-limit'
  | 'request-limit'
  | 'request-failed'
  | 'invalid-response'
  | 'repeated-token';

export interface IncomingSearch {
  /** Distinct accounts found, in the order the provider returned them. */
  accounts: Array<{ address: string; microAlgos: bigint }>;
  requests: number;
  duplicates: number;
  errors: string[];
  /** Why the search stopped before the end of the results, when it did. */
  stop?: Stop;
}

type AccountPage =
  | {
      ok: true;
      records: Array<{ address: string; microAlgos: bigint }>;
      malformed: number;
      next?: string;
    }
  | { ok: false; fault: string };

function accountPage(res: unknown): AccountPage {
  if (!isObject(res)) return { ok: false, fault: 'response is not an object' };
  const list = field(res, 'accounts');
  if (list === undefined) return { ok: false, fault: 'no account list' };
  if (!Array.isArray(list)) return { ok: false, fault: 'account list is not a list' };
  const token = tokenOf(res);
  if (!token.ok) return { ok: false, fault: 'malformed continuation token' };
  const records: Array<{ address: string; microAlgos: bigint }> = [];
  let malformed = 0;
  for (const r of list) {
    const address = asText(field(r, 'address'));
    const microAlgos = amountOf(field(r, 'amount'));
    if (!address || !algosdk.isValidAddress(address) || microAlgos === undefined) {
      malformed++;
      continue;
    }
    records.push({ address, microAlgos });
  }
  return { ok: true, records, malformed, next: token.next };
}

/**
 * Find the accounts whose auth-addr is `address`, page by page.
 *
 * Stops at the end of the results, at INCOMING_ACCOUNT_LIMIT distinct
 * accounts, or at INCOMING_REQUEST_LIMIT requests, and says which. A
 * repeated continuation token, a malformed page or a failed request ends
 * the search too, keeping whatever earlier pages found. Duplicates are
 * dropped, so no balance is counted twice.
 */
export async function searchIncoming(
  clients: FalconerClients,
  address: string,
): Promise<IncomingSearch> {
  const found = new Map<string, bigint>();
  const errors: string[] = [];
  const done = (stop: Stop | undefined, requests: number, duplicates: number) => ({
    accounts: [...found].map(([a, microAlgos]) => ({ address: a, microAlgos })),
    requests,
    duplicates,
    errors,
    stop,
  });

  if (!clients.indexer) {
    keep(errors, 'no indexer is configured');
    return done('no-indexer', 0, 0);
  }

  const tokens = new Set<string>();
  let next: string | undefined;
  let requests = 0;
  let duplicates = 0;
  for (;;) {
    if (requests >= INCOMING_REQUEST_LIMIT) return done('request-limit', requests, duplicates);
    let query: any = clients.indexer
      .searchAccounts()
      .authAddr(address)
      .limit(INCOMING_ACCOUNT_LIMIT - found.size);
    if (next) query = query.nextToken(next);
    requests++;

    let res: unknown;
    try {
      res = await query.do();
    } catch (err) {
      keep(errors, failureReason(err));
      return done('request-failed', requests, duplicates);
    }
    const page = accountPage(res);
    if (!page.ok) {
      keep(errors, page.fault);
      return done('invalid-response', requests, duplicates);
    }

    let overflow = false;
    for (const r of page.records) {
      if (r.address === address) continue;
      if (found.has(r.address)) {
        duplicates++;
        continue;
      }
      if (found.size >= INCOMING_ACCOUNT_LIMIT) {
        overflow = true;
        continue;
      }
      found.set(r.address, r.microAlgos);
    }
    if (page.malformed) {
      keep(errors, `${page.malformed} malformed account record(s)`);
      return done('invalid-response', requests, duplicates);
    }
    if (!page.next) return done(overflow ? 'result-limit' : undefined, requests, duplicates);
    if (found.size >= INCOMING_ACCOUNT_LIMIT) return done('result-limit', requests, duplicates);
    if (tokens.has(page.next)) {
      keep(errors, 'the provider repeated a continuation token');
      return done('repeated-token', requests, duplicates);
    }
    tokens.add(page.next);
    next = page.next;
  }
}

const accountsText = (n: number) =>
  `${n} account${n === 1 ? '' : 's'} rekeyed to this address`;

/**
 * Coverage for the incoming search, once what signs for each account found
 * has been resolved: an account whose authority could not be checked keeps
 * the check from being complete even when the search itself finished.
 */
export function incomingCoverage(
  s: IncomingSearch,
  authorityUnchecked: number,
): IncomingCoverage {
  const n = s.accounts.length;
  const reason = s.errors[0] ?? 'unknown error';
  let detail: string;
  let status: CoverageStatus;
  switch (s.stop) {
    case undefined:
      status = 'complete';
      detail = n
        ? `Found ${accountsText(n)}; the search reached the end of the provider's results.`
        : 'Found no account rekeyed to this address; the search reached the end ' +
          "of the provider's results.";
      break;
    case 'result-limit':
      status = 'partial';
      detail =
        `Found ${accountsText(n)}, the most one scan reads. The provider has ` +
        'more, which were not read.';
      break;
    case 'request-limit':
      status = 'partial';
      detail =
        `Found ${accountsText(n)} in ${s.requests} requests, the most one scan ` +
        'makes. The provider has more, which were not read.';
      break;
    case 'no-indexer':
      status = 'unavailable';
      detail =
        'No indexer is configured, so accounts rekeyed to this address could ' +
        'not be searched for.';
      break;
    case 'request-failed':
      status = s.requests === 1 ? 'unavailable' : 'partial';
      detail =
        s.requests === 1
          ? `The search could not run (${reason}), so any account rekeyed to ` +
            'this address is unknown.'
          : `Found ${accountsText(n)} before a later request failed (${reason}); ` +
            'any beyond them are unknown.';
      break;
    case 'invalid-response':
    case 'repeated-token':
      status = 'invalid-response';
      detail =
        `The provider's response could not be used (${reason})` +
        (n
          ? `. The ${accountsText(n)} found before it are kept, and any beyond ` +
            'them are unknown.'
          : ', so any account rekeyed to this address is unknown.');
      break;
  }
  if (s.duplicates) {
    detail +=
      ` ${s.duplicates} repeated record${s.duplicates === 1 ? ' was' : 's were'} ` +
      'dropped, so no balance is counted twice.';
  }
  if (authorityUnchecked) {
    detail += ` What signs for ${authorityUnchecked} of them could not be checked.`;
    if (status === 'complete') status = 'partial';
  }
  return {
    status,
    detail,
    errors: s.errors,
    found: n,
    limit: INCOMING_ACCOUNT_LIMIT,
    requests: s.requests,
    requestLimit: INCOMING_REQUEST_LIMIT,
    duplicates: s.duplicates,
    authorityUnchecked,
    exhausted: s.stop === undefined,
  };
}

/** Why the incoming check fell short, when it did. */
export function incomingGap(
  s: IncomingSearch,
  authorityUnchecked: number,
): string | undefined {
  const unchecked = authorityUnchecked
    ? `what signs for ${authorityUnchecked} of the accounts rekeyed to this ` +
      'address could not be checked'
    : undefined;
  let gap: string | undefined;
  switch (s.stop) {
    case undefined:
      return unchecked;
    case 'result-limit':
      gap =
        'the search for accounts rekeyed to this address stopped at ' +
        `${INCOMING_ACCOUNT_LIMIT}, with more remaining`;
      break;
    case 'request-limit':
      gap =
        'the search for accounts rekeyed to this address stopped after ' +
        `${s.requests} requests, with more remaining`;
      break;
    case 'no-indexer':
      gap = 'accounts rekeyed to this address could not be checked';
      break;
    case 'request-failed':
      gap =
        s.requests === 1
          ? 'accounts rekeyed to this address could not be checked'
          : 'the search for accounts rekeyed to this address failed after ' +
            `${s.accounts.length} were found`;
      break;
    case 'invalid-response':
    case 'repeated-token':
      gap =
        'the search for accounts rekeyed to this address returned an ' +
        'unusable response';
      break;
  }
  return unchecked ? `${gap}, and ${unchecked}` : gap;
}

/* ------------------------------------------------------------------ */
/* Ledger sample                                                        */
/* ------------------------------------------------------------------ */

type AssetPage =
  | { ok: true; records: AssetRecord[]; malformed: number; next?: string }
  | { ok: false; fault: string };

/** A page of Indexer's asset list, each record checked as a read by id is. */
function assetPage(res: unknown): AssetPage {
  if (!isObject(res)) return { ok: false, fault: 'response is not an object' };
  const list = field(res, 'assets');
  if (list === undefined) return { ok: false, fault: 'no asset list' };
  if (!Array.isArray(list)) return { ok: false, fault: 'asset list is not a list' };
  const token = tokenOf(res);
  if (!token.ok) return { ok: false, fault: 'malformed continuation token' };
  const records: AssetRecord[] = [];
  let malformed = 0;
  for (const r of list) {
    const record = assetRecordOf(r);
    if (record.ok) records.push(record.value);
    else malformed++;
  }
  return { ok: true, records, malformed, next: token.next };
}

/**
 * The most requests a sample of `limit` assets makes: full pages to reach
 * the limit, plus one, because Indexer sends a continuation token with every
 * page that has results, so only the next, empty page shows the list ended.
 */
export function sampleRequestLimit(limit: number): number {
  return Math.ceil(limit / SAMPLE_PAGE_SIZE) + 1;
}

/**
 * Sweep the ledger's assets in id order, visiting up to `limit` distinct
 * assets, each once.
 *
 * Indexer cannot filter assets by role, so this is a sample, never a
 * census, unless it reads every asset to the end of the list. Both bounds
 * hold whatever the provider does: no page is asked for more assets than
 * the sample still wants, nothing past the limit is visited even from a
 * page that holds more, repeats do not count, and the request bound is fixed
 * up front, so pages of repeats or empty pages cannot stretch the sample.
 * An empty page that still points onward is followed like any other; only
 * a page with nowhere to go next ends the list.
 */
export async function sampleAssets(
  clients: FalconerClients,
  limit: number,
  visit: (assetId: bigint, params: AssetParamsRecord) => void,
  progress: (message: string) => void,
  network: string,
): Promise<SampleCoverage> {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new Error(`A ledger sample needs a positive integer limit, not ${limit}`);
  }
  const errors: string[] = [];
  const requestLimit = sampleRequestLimit(limit);
  const seen = new Set<string>();
  let requests = 0;
  let duplicates = 0;
  const result = (status: CoverageStatus, exhaustive: boolean): SampleCoverage => ({
    status,
    detail: sampleDetail(status, seen.size, exhaustive, network, errors[0], duplicates),
    errors,
    limit,
    read: seen.size,
    requests,
    requestLimit,
    duplicates,
    exhaustive,
  });

  if (!clients.indexer) {
    keep(errors, 'no indexer is configured');
    return result('unavailable', false);
  }

  const tokens = new Set<string>();
  let next: string | undefined;
  for (;;) {
    if (requests >= requestLimit) return result('partial', false);
    let query: any = clients.indexer
      .searchForAssets()
      .limit(Math.min(SAMPLE_PAGE_SIZE, limit - seen.size));
    if (next) query = query.nextToken(next);
    requests++;

    let res: unknown;
    try {
      res = await query.do();
    } catch (err) {
      keep(errors, failureReason(err));
      return result(requests === 1 ? 'unavailable' : 'partial', false);
    }
    const page = assetPage(res);
    if (!page.ok) {
      keep(errors, page.fault);
      return result('invalid-response', false);
    }
    let overflow = false;
    for (const a of page.records) {
      const key = a.assetId.toString();
      if (seen.has(key)) {
        duplicates++;
        continue;
      }
      if (seen.size >= limit) {
        overflow = true;
        continue;
      }
      seen.add(key);
      visit(a.assetId, a.params);
    }
    if (page.malformed) {
      keep(errors, `${page.malformed} malformed asset record(s)`);
      return result('invalid-response', false);
    }
    // The end of the list. Only a sample that visited everything up to it
    // has read the whole list.
    if (!page.next) return result('complete', !overflow);
    // The full sample was read and the provider has more: complete for the
    // scope asked for, and not a census.
    if (seen.size >= limit) return result('complete', false);
    if (tokens.has(page.next)) {
      keep(errors, 'the provider repeated a continuation token');
      return result('invalid-response', false);
    }
    tokens.add(page.next);
    next = page.next;
    progress(`Sampled ${seen.size.toLocaleString()} assets`);
  }
}

/** What the sample statement says for every outcome, including none asked for. */
export function sampleDetail(
  status: CoverageStatus,
  read: number,
  exhaustive: boolean,
  network: string,
  reason?: string,
  duplicates = 0,
): string {
  if (status === 'not-requested') {
    return (
      'Roles on assets this account neither created, holds, nor named were ' +
      'not searched for. Name asset ids, or run a ledger sample, to look ' +
      'further.'
    );
  }
  if (status === 'unavailable' && read === 0) {
    return `A ledger sample was requested but could not run (${reason ?? 'unknown error'}).`;
  }
  const scope =
    `Sampled ${read.toLocaleString()} assets from the ledger. Indexer cannot ` +
    'filter assets by role, and does not index role addresses as ' +
    'participants in the transaction that grants them, so this is a sweep ' +
    'in id order rather than a search. ';
  const extent = exhaustive
    ? 'It reached the end of the asset list the provider serves.'
    : network === 'mainnet'
      ? 'On MainNet that covers a small fraction of the asset set, so a clean ' +
        'result here means nothing was found in the sample, not that no roles ' +
        'are held.'
      : 'Coverage depends entirely on how much of the ledger was read.';
  const short =
    status === 'complete'
      ? ''
      : status === 'invalid-response'
        ? ` The sample stopped at an unusable response (${reason ?? 'unknown'}).`
        : ` The sample stopped before its limit (${reason ?? 'request limit reached'}).`;
  const repeats = duplicates
    ? ` ${duplicates} repeated record${duplicates === 1 ? ' was' : 's were'} ` +
      'dropped, so no asset is counted twice.'
    : '';
  return scope + extent + short + repeats;
}

/** Why a requested sample fell short, when it did. */
export function sampleGap(s: SampleCoverage): string | undefined {
  switch (s.status) {
    case 'unavailable':
      return s.read ? 'the requested ledger sample stopped early' : 'the requested ledger sample could not run';
    case 'partial':
      return `the requested ledger sample stopped early, after ${s.read} assets`;
    case 'invalid-response':
      return 'the requested ledger sample returned an unusable response';
    default:
      return undefined;
  }
}

/* ------------------------------------------------------------------ */
/* Shared presentation                                                  */
/* ------------------------------------------------------------------ */

/**
 * The scope every score carries. Stated wherever a verdict is, because a
 * zero read on its own looks like a certification, and it is not one.
 */
export const SCORE_SCOPE =
  'Scores are a heuristic for the checks listed, not a security ' +
  'certification: nothing outside them was examined.';

export interface CoverageLine {
  check: 'history' | 'incoming' | 'assets' | 'apps' | 'app-permissions';
  label: string;
  /** The check's status, or `unverified` for application permissions. */
  status: CoverageStatus | 'unverified';
  detail: string;
  /** True when this line keeps the verdict from being complete. */
  blocking: boolean;
}

/**
 * Every check, in the order a report states them. The CLI and the web app
 * both render this, so they cannot disagree about what was covered.
 */
export function coverageLines(e: AccountExposure): CoverageLine[] {
  const c = e.coverage;
  const line = (
    check: CoverageLine['check'],
    label: string,
    k: CoverageCheck,
  ): CoverageLine => ({
    check,
    label,
    status: k.status,
    detail: k.detail,
    blocking: isShortfall(k.status),
  });
  const lines = [
    line('history', 'signing history', c.history),
    line('incoming', 'rekeyed to it', c.incoming),
    line('assets', 'asset roles', c.assets),
    line('apps', 'app state', c.apps),
  ];
  if (c.appPermissions === 'unverified') {
    const n = e.reach.appReferences;
    lines.push({
      check: 'app-permissions',
      label: 'app permissions',
      status: 'unverified',
      detail:
        `This address created, or is named in the state of, ${n} ` +
        `application${n === 1 ? '' : 's'}. Falconer does not analyse ` +
        'application programs, so what they let this address do is not ' +
        'established: a reference, not a privilege.',
      blocking: true,
    });
  }
  return lines;
}

export interface ReachNotice {
  /** True when some of this reach is exercised by a key not established as post-quantum. */
  exposed: boolean;
  text: string;
}

const count = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`;

/**
 * What this address reaches beyond its own balance, stated as found: each
 * capability, and separately whether the key exercising it is exposed. An
 * address that only signs for protected accounts is described as exactly
 * that, never as holding asset powers it does not have.
 */
export function describeReach(e: AccountExposure): ReachNotice | undefined {
  const r = e.reach;
  const sentences: string[] = [];
  const powers: string[] = [];
  if (r.seize.length) powers.push(`seize ${count(r.seize.length, 'asset')} from any holder`);
  if (r.freeze.length) {
    powers.push(`freeze ${count(r.freeze.length, 'asset')} in any holder's account`);
  }
  if (powers.length) {
    sentences.push(
      `This address can ${powers.join(' and ')}. Those roles are exercised ` +
        "under this account's own authority, which " +
        (r.assetRolesExposed
          ? 'is not established as post-quantum.'
          : 'is post-quantum on a provider-confirmed record.'),
    );
  }
  const atLeast = e.coverage.incoming.exhausted ? '' : 'at least ';
  if (r.incomingExposed) {
    sentences.push(
      `It signs for ${atLeast}${count(r.incomingExposed, 'account')} rekeyed to ` +
        'it with a key not established as post-quantum.',
    );
  }
  if (r.incomingProtected) {
    sentences.push(
      `It signs for ${atLeast}${count(r.incomingProtected, 'account')} rekeyed to ` +
        'it with a post-quantum key, on a provider-confirmed record.',
    );
  }
  if (!sentences.length) return undefined;
  const exposed = (powers.length > 0 && r.assetRolesExposed) || r.incomingExposed > 0;
  if (exposed) {
    sentences.push('Breaking the exposed key would reach beyond this account.');
  }
  return { exposed, text: sentences.join(' ') };
}
