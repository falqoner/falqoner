/**
 * The migration journal (SAFE-02b): a versioned, public record of one
 * migration and every transaction it has attempted, kept in this browser's
 * local storage so that a reload finds it.
 *
 * It holds only public data: the network and its genesis, the account, whose
 * key signs for it, the new address, and for each attempt the fields that
 * rebuild the exact transaction, with what the ledger was last seen to say
 * about it. It never holds a phrase, a key, a signer, the operation object,
 * an endpoint or signed bytes. `serializeRecord` writes an allowlist of
 * fields and `parseRecord` accepts nothing else: an unknown field, a missing
 * one, a malformed integer or an attempt whose id does not match its own
 * fields makes the whole record invalid.
 *
 * What is stored is a hint, not evidence (A-02b-01). A valid record says
 * which transactions to ask the ledger about; only the ledger says what
 * happened. Its state labels - `confirmed` and `not-included` included - are
 * claims: strict parsing checks their shape, not their truth, so nothing is
 * continued or dismissed on a label until this session has read the same
 * from the ledger (`verifiedView`). An invalid or unreadable record is never
 * cleared silently: it stays, and it blocks a new migration from this page.
 *
 * Only one tab may write. `browserTabLock` takes an exclusive Web Lock and
 * fails closed where the browser cannot provide one, and every write is a
 * compare-and-swap against the exact text last read, read back after it is
 * written.
 *
 * Versions (SAFE-03a). Version 1 attempts carried fixed amounts and fees, and
 * a version-1 record is still read strictly against exactly those, so its
 * transactions rebuild with their original amounts, fees and ids. Version 2
 * attempts are budgeted: each stage's senders, receivers and rekey target are
 * as fixed as before, but its fee and funding amount are whatever the
 * approved budget set, within bounds. Appending an attempt writes version 2;
 * saving a reading keeps the version it found. A stored amount or fee is a
 * record of what was prepared, never an approval to spend it again. Any other
 * version is kept, unread, and blocks a new migration.
 */
import algosdk from 'algosdk';
import {
  MAX_STAGE_FEE_MICROALGOS,
  STAGE_ORDER,
  VALIDITY_ROUNDS,
  attemptTransaction,
  genesisRefusal,
  isFinalEvidence,
  isHashDerivedAddress,
  stageShape,
  withTimeout,
  type AttemptEvidence,
  type EvidenceSource,
  type NetworkGenesis,
  type SubmissionStage,
  type TransactionAttempt,
} from '@falconer/core';

export { STAGE_ORDER, isFinalEvidence };

export const JOURNAL_KEY = 'falconer.migration';
export const JOURNAL_FORMAT = 'falconer-migration-journal';
/** The version this page writes when it records a new attempt. */
export const JOURNAL_VERSION = 2;
/** The versions this page reads. */
export const JOURNAL_VERSIONS = [1, 2] as const;
export type JournalVersion = (typeof JOURNAL_VERSIONS)[number];

/**
 * What every version-1 attempt carried. Historical facts about records
 * already written, used only to read them; nothing is priced from them.
 */
const VERSION_1 = { fundingAmount: 200_000n, classicalFee: 1000n, falconFee: 3000n } as const;
/** The most attempts one record may hold. */
export const MAX_ATTEMPTS = 32;
const MAX_TEXT = 64 * 1024;

export type AttemptState =
  /** Recorded before its send. Whether the send happened is unknown. */
  | 'recorded'
  | 'confirmed'
  | 'pending'
  | 'rejected'
  /** Its window passed, and whether it landed is not established. */
  | 'expired'
  /** Its window passed and every round was read: it never landed. */
  | 'not-included'
  | 'unknown'
  | 'conflict';

const STATES: readonly AttemptState[] = [
  'recorded', 'confirmed', 'pending', 'rejected', 'expired', 'not-included', 'unknown', 'conflict',
];
const SOURCES: readonly EvidenceSource[] = ['algod-pending', 'algod-block', 'indexer', 'none'];

/** A settled state: it landed, or it never landed and never can. */
export const isFinal = (s: AttemptState) => s === 'confirmed' || s === 'not-included';

export interface JournalAttempt extends TransactionAttempt {
  readonly state: AttemptState;
  readonly confirmedRound: bigint | null;
  /** The node's round when the state was last read; null before any read. */
  readonly checkedRound: bigint | null;
  readonly source: EvidenceSource;
}

export interface MigrationRecord {
  /** The stored format's version: 1 for fixed-fee attempts, 2 once any attempt is budgeted. */
  readonly version: JournalVersion;
  readonly id: string;
  /** Increases by one with every write. */
  readonly revision: number;
  readonly network: 'testnet' | 'localnet';
  readonly genesis: NetworkGenesis;
  /** The account being migrated. */
  readonly sender: string;
  /** Whose key signed the funding and the rekey. */
  readonly authorizer: string;
  /** The new post-quantum address. */
  readonly target: string;
  /** Asset and app ids the account was scanned with, to read it again the same way. */
  readonly scan: { readonly assets: string; readonly apps: string };
  readonly attempts: readonly JournalAttempt[];
}

/* ------------------------------------------------------------------ */
/* Building and reading a record                                       */
/* ------------------------------------------------------------------ */

/** The state evidence puts an attempt in. */
export function stateOf(e: AttemptEvidence): AttemptState {
  if (e.outcome === 'expired') return e.nonInclusion ? 'not-included' : 'expired';
  return e.outcome;
}

export function newRecord(
  base: Omit<MigrationRecord, 'version' | 'revision' | 'attempts'>,
  first: TransactionAttempt,
): MigrationRecord {
  return freezeRecord({ ...base, version: JOURNAL_VERSION, revision: 1, attempts: [recorded(first)] });
}

const recorded = (a: TransactionAttempt): JournalAttempt => ({
  ...a,
  state: 'recorded',
  confirmedRound: null,
  checkedRound: null,
  source: 'none',
});

/**
 * `record` with `attempt` appended, as recorded before its send. The attempt
 * is budgeted, so the record is written as version 2; the attempts already
 * in it are kept exactly as they are.
 */
export function withAttempt(record: MigrationRecord, attempt: TransactionAttempt): MigrationRecord {
  return freezeRecord({
    ...record,
    version: JOURNAL_VERSION,
    revision: record.revision + 1,
    attempts: [...record.attempts, recorded(attempt)],
  });
}

/**
 * `record` with what `evidence` says about one attempt. A reading that
 * settles the attempt replaces whatever its label says, because the label is
 * only a claim. A weaker reading - pending, unknown, an unread window - never
 * replaces a settled label, but nothing trusts that label for it either.
 */
export function withEvidence(record: MigrationRecord, evidence: AttemptEvidence): MigrationRecord {
  let changed = false;
  const attempts = record.attempts.map((a) => {
    if (a.txId !== evidence.txId) return a;
    if (isFinal(a.state) && !isFinalEvidence(evidence)) return a;
    const next = {
      ...a,
      state: stateOf(evidence),
      confirmedRound: evidence.outcome === 'confirmed' ? evidence.confirmedRound : null,
      checkedRound: evidence.observedRound,
      source: evidence.source,
    };
    // A reading that says exactly what is recorded is not a new revision.
    if (
      next.state === a.state &&
      next.confirmedRound === a.confirmedRound &&
      next.checkedRound === a.checkedRound &&
      next.source === a.source
    ) {
      return a;
    }
    changed = true;
    return next;
  });
  return changed ? freezeRecord({ ...record, revision: record.revision + 1, attempts }) : record;
}

/** `record` with every reading in `evidence`, as one revision. */
export function withAllEvidence(record: MigrationRecord, evidence: readonly AttemptEvidence[]): MigrationRecord {
  let next = record;
  for (const e of evidence) next = withEvidence(next, e);
  return next === record ? record : freezeRecord({ ...next, revision: record.revision + 1 });
}

/**
 * The record as this session has read the ledger: each attempt's state is
 * the reading in `evidence`, never its stored label, and an attempt not read
 * this session is `unknown`. In memory only; never written.
 */
export function verifiedView(
  record: MigrationRecord,
  evidence: Readonly<Record<string, AttemptEvidence>>,
): MigrationRecord {
  return freezeRecord({
    ...record,
    attempts: record.attempts.map((a) => {
      const e = evidence[a.txId];
      return e
        ? {
            ...a,
            state: stateOf(e),
            confirmedRound: e.outcome === 'confirmed' ? e.confirmedRound : null,
            checkedRound: e.observedRound,
            source: e.source,
          }
        : { ...a, state: 'unknown' as const, confirmedRound: null, checkedRound: null, source: 'none' as const };
    }),
  });
}

function freezeRecord(r: MigrationRecord): MigrationRecord {
  return Object.freeze({
    ...r,
    genesis: Object.freeze({ ...r.genesis }),
    scan: Object.freeze({ ...r.scan }),
    attempts: Object.freeze(r.attempts.map((a) => Object.freeze({ ...a }))),
  });
}

export type StageStatus = 'not-started' | 'confirmed' | 'unresolved' | 'not-included';

export function attemptsFor(record: MigrationRecord, stage: SubmissionStage): JournalAttempt[] {
  return record.attempts.filter((a) => a.stage === stage);
}

export function stageStatus(record: MigrationRecord, stage: SubmissionStage): StageStatus {
  const list = attemptsFor(record, stage);
  if (list.length === 0) return 'not-started';
  if (list.some((a) => a.state === 'confirmed')) return 'confirmed';
  if (list.every((a) => a.state === 'not-included')) return 'not-included';
  return 'unresolved';
}

export const unresolvedAttempts = (record: MigrationRecord) =>
  record.attempts.filter((a) => !isFinal(a.state));

/** The confirmed attempt for a stage, if there is one. */
export const confirmedAttempt = (record: MigrationRecord, stage: SubmissionStage) =>
  attemptsFor(record, stage).find((a) => a.state === 'confirmed') ?? null;

/**
 * Whether the record may be removed once its words are acknowledged: nothing
 * is unresolved, and either the migration was verified or the rekey never
 * landed, so the account's authority is where it was.
 */
export function isResolved(record: MigrationRecord): boolean {
  if (unresolvedAttempts(record).length > 0) return false;
  return stageStatus(record, 'verification') === 'confirmed' || stageStatus(record, 'rekey') !== 'confirmed';
}

/* ------------------------------------------------------------------ */
/* Serialization                                                       */
/* ------------------------------------------------------------------ */

/** The stored text for `record`: an allowlist of fields, integers as decimal strings. */
export function serializeRecord(r: MigrationRecord): string {
  return JSON.stringify({
    format: JOURNAL_FORMAT,
    version: r.version,
    id: r.id,
    revision: r.revision,
    network: r.network,
    genesis: { id: r.genesis.id, hash: r.genesis.hash },
    sender: r.sender,
    authorizer: r.authorizer,
    target: r.target,
    scan: { assets: r.scan.assets, apps: r.scan.apps },
    attempts: r.attempts.map((a) => ({
      txId: a.txId,
      stage: a.stage,
      genesisId: a.genesisId,
      genesisHash: a.genesisHash,
      sender: a.sender,
      authorizer: a.authorizer,
      receiver: a.receiver,
      amount: a.amount.toString(),
      fee: a.fee.toString(),
      firstValid: a.firstValid.toString(),
      lastValid: a.lastValid.toString(),
      rekeyTo: a.rekeyTo,
      state: a.state,
      confirmedRound: a.confirmedRound === null ? null : a.confirmedRound.toString(),
      checkedRound: a.checkedRound === null ? null : a.checkedRound.toString(),
      source: a.source,
    })),
  });
}

class Invalid extends Error {}
const fail = (why: string): never => {
  throw new Invalid(why);
};

function fields(x: unknown, keys: readonly string[], at: string): Record<string, unknown> {
  if (typeof x !== 'object' || x === null || Array.isArray(x) || Object.getPrototypeOf(x) !== Object.prototype) {
    fail(`${at} is not an object`);
  }
  const o = x as Record<string, unknown>;
  const got = Object.keys(o).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) {
    fail(`${at} has unexpected or missing fields`);
  }
  return o;
}

const text = (x: unknown, at: string, pattern: RegExp): string =>
  typeof x === 'string' && pattern.test(x) ? x : fail(`${at} is malformed`);

const address = (x: unknown, at: string): string =>
  typeof x === 'string' && algosdk.isValidAddress(x) ? x : fail(`${at} is not an address`);

const U64 = (1n << 64n) - 1n;
function uint(x: unknown, at: string): bigint {
  if (typeof x !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(x)) fail(`${at} is not an exact integer`);
  const v = BigInt(x as string);
  return v <= U64 ? v : fail(`${at} is out of range`);
}

const nullable = <T>(x: unknown, parse: (x: unknown) => T): T | null => (x === null ? null : parse(x));

const oneOf = <T extends string>(x: unknown, allowed: readonly T[], at: string): T =>
  allowed.includes(x as T) ? (x as T) : fail(`${at} is not one of ${allowed.join(', ')}`);

const GENESIS_ID = /^[A-Za-z0-9._-]{1,64}$/;
const GENESIS_HASH = /^[A-Za-z0-9+/]{43}=$/;
const TX_ID = /^[A-Z2-7]{52}$/;
const RECORD_ID = /^op-[a-z0-9-]{1,64}$/;
const IDS = /^[0-9,\s]{0,512}$/;

/** Why an attempt's amount or fee is not one its record's version allows, or null. */
function valueProblem(version: JournalVersion, a: JournalAttempt): string | null {
  if (version === 1) {
    const signedByFalcon = a.stage === 'proof' || a.stage === 'verification';
    const amount = a.stage === 'funding' ? VERSION_1.fundingAmount : 0n;
    const fee = signedByFalcon ? VERSION_1.falconFee : VERSION_1.classicalFee;
    if (a.amount !== amount) return 'amount is not what its stage sends';
    if (a.fee !== fee) return 'fee is not what its stage sends';
    return null;
  }
  if (a.stage !== 'funding' && a.amount !== 0n) return 'amount is not what its stage sends';
  if (a.fee < 1n || a.fee > MAX_STAGE_FEE_MICROALGOS) return 'fee is out of range';
  return null;
}

const ATTEMPT_KEYS = [
  'txId', 'stage', 'genesisId', 'genesisHash', 'sender', 'authorizer', 'receiver', 'amount', 'fee',
  'firstValid', 'lastValid', 'rekeyTo', 'state', 'confirmedRound', 'checkedRound', 'source',
] as const;

function parseAttempt(x: unknown, at: string, record: Omit<MigrationRecord, 'attempts'>): JournalAttempt {
  const o = fields(x, ATTEMPT_KEYS, at);
  const a: JournalAttempt = {
    txId: text(o.txId, `${at}.txId`, TX_ID),
    stage: oneOf(o.stage, STAGE_ORDER, `${at}.stage`),
    genesisId: text(o.genesisId, `${at}.genesisId`, GENESIS_ID),
    genesisHash: text(o.genesisHash, `${at}.genesisHash`, GENESIS_HASH),
    sender: address(o.sender, `${at}.sender`),
    authorizer: address(o.authorizer, `${at}.authorizer`),
    receiver: address(o.receiver, `${at}.receiver`),
    amount: uint(o.amount, `${at}.amount`),
    fee: uint(o.fee, `${at}.fee`),
    firstValid: uint(o.firstValid, `${at}.firstValid`),
    lastValid: uint(o.lastValid, `${at}.lastValid`),
    rekeyTo: nullable(o.rekeyTo, (v) => address(v, `${at}.rekeyTo`)),
    state: oneOf(o.state, STATES, `${at}.state`),
    confirmedRound: nullable(o.confirmedRound, (v) => uint(v, `${at}.confirmedRound`)),
    checkedRound: nullable(o.checkedRound, (v) => uint(v, `${at}.checkedRound`)),
    source: oneOf(o.source, SOURCES, `${at}.source`),
  };
  if (a.genesisId !== record.genesis.id || a.genesisHash !== record.genesis.hash) {
    fail(`${at} was built for another network`);
  }
  const want = stageShape(record, a.stage);
  for (const k of ['sender', 'authorizer', 'receiver', 'rekeyTo'] as const) {
    if (a[k] !== want[k]) fail(`${at}.${k} is not what its stage sends`);
  }
  const value = valueProblem(record.version, a);
  if (value) fail(`${at}.${value}`);
  if (a.firstValid < 1n || a.lastValid < a.firstValid || a.lastValid - a.firstValid > VALIDITY_ROUNDS) {
    fail(`${at} has an invalid validity window`);
  }
  // The id must be the id of the transaction its own fields describe.
  if (attemptTransaction(a).txID() !== a.txId) fail(`${at}.txId does not match its fields`);
  if ((a.state === 'confirmed') !== (a.confirmedRound !== null)) {
    fail(`${at} has a confirmed round only if it is confirmed`);
  }
  if (a.confirmedRound !== null && (a.confirmedRound < a.firstValid || a.confirmedRound > a.lastValid)) {
    fail(`${at} is confirmed outside its validity window`);
  }
  if (a.state === 'recorded' && (a.checkedRound !== null || a.source !== 'none')) {
    fail(`${at} has evidence but is only recorded`);
  }
  return a;
}

/** A stored text, strictly: anything unexpected makes the whole record invalid. */
export function parseRecord(raw: string): { ok: true; record: MigrationRecord } | { ok: false; reason: string } {
  try {
    if (raw.length > MAX_TEXT) fail('the record is too large');
    let doc: unknown;
    try {
      doc = JSON.parse(raw);
    } catch {
      fail('the record is not JSON');
    }
    const top = fields(doc, [
      'format', 'version', 'id', 'revision', 'network', 'genesis', 'sender', 'authorizer', 'target', 'scan', 'attempts',
    ], 'record');
    if (top.format !== JOURNAL_FORMAT) fail('the record is not a Falconer migration journal');
    if (!JOURNAL_VERSIONS.includes(top.version as JournalVersion)) {
      fail(`version ${String(top.version).slice(0, 20)} is not supported`);
    }
    const genesis = fields(top.genesis, ['id', 'hash'], 'genesis');
    const scan = fields(top.scan, ['assets', 'apps'], 'scan');
    const base = {
      version: top.version as JournalVersion,
      id: text(top.id, 'id', RECORD_ID),
      revision:
        typeof top.revision === 'number' && Number.isSafeInteger(top.revision) && top.revision >= 1
          ? top.revision
          : fail('revision is malformed'),
      network: oneOf(top.network, ['testnet', 'localnet'] as const, 'network'),
      genesis: {
        id: text(genesis.id, 'genesis.id', GENESIS_ID),
        hash: text(genesis.hash, 'genesis.hash', GENESIS_HASH),
      },
      sender: address(top.sender, 'sender'),
      authorizer: address(top.authorizer, 'authorizer'),
      target: address(top.target, 'target'),
      scan: { assets: text(scan.assets, 'scan.assets', IDS), apps: text(scan.apps, 'scan.apps', IDS) },
    };
    const refused = genesisRefusal(base.network, base.genesis);
    if (refused) fail(`its network is refused: ${refused}`);
    if (!isHashDerivedAddress(base.target) || base.target === base.sender) {
      fail('target is not a post-quantum address for this account');
    }
    if (!Array.isArray(top.attempts) || top.attempts.length < 1 || top.attempts.length > MAX_ATTEMPTS) {
      fail('attempts is empty or too long');
    }
    const attempts = (top.attempts as unknown[]).map((x, i) => parseAttempt(x, `attempts[${i}]`, base));

    // The order the migration runs in: a stage only after the one before it
    // confirmed, and a replacement only after the attempt it replaces was
    // shown never to have landed.
    const seen = new Set<string>();
    let at = 0;
    for (const [i, a] of attempts.entries()) {
      if (seen.has(a.txId)) fail(`attempts[${i}] repeats an id`);
      seen.add(a.txId);
      const idx = STAGE_ORDER.indexOf(a.stage);
      if (idx < at) fail(`attempts[${i}] goes back to an earlier stage`);
      if (idx > at) {
        const before = attempts.slice(0, i);
        if (!before.some((b) => b.stage === STAGE_ORDER[idx - 1] && b.state === 'confirmed')) {
          fail(`attempts[${i}] starts ${a.stage} before ${STAGE_ORDER[idx - 1]} confirmed`);
        }
        if (idx - at > 1 || i === 0) fail(`attempts[${i}] skips a stage`);
        at = idx;
      }
      const later = attempts.slice(i + 1).filter((b) => b.stage === a.stage);
      if (later.length > 0 && a.state !== 'not-included') {
        fail(`attempts[${i}] was replaced before it was shown never to have landed`);
      }
    }
    if (attempts[0]!.stage !== 'funding') fail('the first attempt is not the funding');
    return { ok: true, record: freezeRecord({ ...base, attempts }) };
  } catch (err) {
    if (err instanceof Invalid) return { ok: false, reason: err.message };
    return { ok: false, reason: 'the record could not be read' };
  }
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

export type JournalRead =
  | { kind: 'empty' }
  | { kind: 'record'; record: MigrationRecord }
  /** Something is stored, and it is not a record this version accepts. */
  | { kind: 'invalid'; reason: string }
  /** Storage itself could not be read. */
  | { kind: 'unavailable'; reason: string };

export class JournalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JournalError';
  }
}

export interface Journal {
  read(): JournalRead;
  /**
   * Store `next` over `previous` (null to create). Refuses unless storage
   * still holds exactly `previous`, and reads `next` back after writing it.
   */
  write(next: MigrationRecord, previous: MigrationRecord | null): void;
  /** Remove `record`, only if storage still holds exactly it. */
  remove(record: MigrationRecord): void;
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export function browserJournal(
  storage: () => StorageLike | null | undefined = () => window.localStorage,
): Journal {
  const open = (): StorageLike => {
    let s: StorageLike | null | undefined;
    try {
      s = storage();
    } catch (err) {
      throw new JournalError(`This browser's storage cannot be opened (${(err as Error)?.name ?? 'error'}).`);
    }
    if (!s) throw new JournalError("This browser's storage is not available.");
    return s;
  };
  const get = (s: StorageLike): string | null => {
    try {
      return s.getItem(JOURNAL_KEY);
    } catch (err) {
      throw new JournalError(`This browser's storage cannot be read (${(err as Error)?.name ?? 'error'}).`);
    }
  };

  return {
    read() {
      let raw: string | null;
      try {
        raw = get(open());
      } catch (err) {
        return { kind: 'unavailable', reason: (err as Error).message };
      }
      if (raw === null) return { kind: 'empty' };
      const parsed = parseRecord(raw);
      return parsed.ok ? { kind: 'record', record: parsed.record } : { kind: 'invalid', reason: parsed.reason };
    },

    write(next, previous) {
      const s = open();
      const text = serializeRecord(next);
      // A record this code could not read back is never written.
      const check = parseRecord(text);
      if (!check.ok) throw new JournalError(`The record to be saved is invalid: ${check.reason}.`);
      if (previous ? next.id !== previous.id || next.revision !== previous.revision + 1 : next.revision !== 1) {
        throw new JournalError('The record to be saved does not follow the one stored.');
      }
      const stored = get(s);
      const want = previous ? serializeRecord(previous) : null;
      if (stored !== want) {
        throw new JournalError(
          stored === null
            ? 'The saved record has disappeared from this browser, so it was not overwritten.'
            : 'The saved record was changed elsewhere, perhaps by another tab, so it was not overwritten.',
        );
      }
      try {
        s.setItem(JOURNAL_KEY, text);
      } catch (err) {
        throw new JournalError(`The record could not be saved (${(err as Error)?.name ?? 'error'}).`);
      }
      if (get(s) !== text) throw new JournalError('The record did not read back as it was saved.');
    },

    remove(record) {
      const s = open();
      if (get(s) !== serializeRecord(record)) {
        throw new JournalError('The saved record is not the one shown here, so it was not removed.');
      }
      try {
        s.removeItem(JOURNAL_KEY);
      } catch (err) {
        throw new JournalError(`The record could not be removed (${(err as Error)?.name ?? 'error'}).`);
      }
      if (get(s) !== null) throw new JournalError('The record is still there after removing it.');
    },
  };
}

/* ------------------------------------------------------------------ */
/* One tab at a time                                                   */
/* ------------------------------------------------------------------ */

export interface TabLock {
  /**
   * This tab's exclusive hold on the journal. False when another tab holds
   * it, or when exclusivity cannot be established at all.
   */
  acquire(): Promise<boolean>;
  held(): boolean;
  release(): void;
}

type LockManagerLike = {
  request(
    name: string,
    options: { mode: 'exclusive'; ifAvailable: true },
    callback: (lock: unknown) => Promise<void> | void,
  ): Promise<unknown>;
};

export const TAB_LOCK_NAME = 'falconer.migration';

export function browserTabLock(
  locks: () => LockManagerLike | undefined = () =>
    (globalThis.navigator as { locks?: LockManagerLike } | undefined)?.locks,
  timeoutMs = 5_000,
): TabLock {
  let release: (() => void) | null = null;
  return {
    async acquire() {
      if (release) return true;
      let manager: LockManagerLike | undefined;
      try {
        manager = locks();
      } catch {
        manager = undefined;
      }
      // Without Web Locks there is no way to keep a second tab out: refuse.
      if (!manager || typeof manager.request !== 'function') return false;
      let gaveUp = false;
      const taken = new Promise<boolean>((resolve) => {
        manager!
          .request(TAB_LOCK_NAME, { mode: 'exclusive', ifAvailable: true }, (lock) => {
            // A lock granted after this gave up is let go at once.
            if (!lock || gaveUp) {
              resolve(false);
              return;
            }
            return new Promise<void>((done) => {
              release = () => {
                release = null;
                done();
              };
              resolve(true);
            });
          })
          .catch(() => resolve(false));
      });
      try {
        return await withTimeout(taken, timeoutMs, 'taking the tab lock');
      } catch {
        gaveUp = true;
        return false;
      }
    },
    held: () => release !== null,
    release() {
      release?.();
    },
  };
}
