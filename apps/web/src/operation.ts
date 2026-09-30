/**
 * The migration operation: one new key, one account and one network, from the
 * moment the key is generated until the operator dismisses the result.
 *
 * The operation lives in `App`, above the conditional render of the migration
 * panel, so nothing that unmounts or re-renders the panel can drop it. There
 * is exactly one, and every change to it goes through `transition`, which
 * refuses anything the current state does not allow. The controller keeps the
 * current state in a ref as well as in React state, so an event handler or a
 * late async callback always checks the real state, never the one it closed
 * over - that ref is the single-flight guard.
 *
 * What is public and what is secret are held apart (SAFE-02b). The context and
 * the journal record are public: the record is written to this browser's
 * storage before anything is sent, so a reload can find it (see journal.ts).
 * The new key (`identity`) and any signing key live only in memory. After a
 * reload the operation is rebuilt from the record with no key at all, and the
 * key comes back only when its phrase is typed in and derives the recorded
 * address.
 *
 * The record's state labels are claims (A-02b-01). What the ledger was read
 * to say in this session is held apart, in `evidence`, and only that decides
 * where the migration stands, whether it may continue and whether it may be
 * dismissed. A reading that settles an attempt is a fact for the rest of the
 * session; two that contradict each other are a conflict.
 *
 * Statuses:
 * - `prepared`: a key exists, bound to its context. Nothing has been sent.
 * - `submitted`: `stage` is being prepared, recorded, sent or awaited. It may
 *   or may not have reached the network.
 * - `confirmed`: `stage` confirmed. While a run continues it moves straight
 *   on; a recovered or paused migration rests here until continued.
 * - `failed`: stopped with nothing sent for this attempt, or with an attempt
 *   shown never to have landed. At stage `null` nothing was ever sent.
 * - `outcome-unknown`: an attempt may have landed and nothing yet shows
 *   whether it did. Only a read-only reconciliation moves it on.
 *
 * `rekeyConfirmed` is separate from the status and is never cleared: once the
 * rekey has confirmed, no later failure can offer a fresh key.
 *
 * Execution (SAFE-03b). Nothing here prepares, signs or sends a transaction.
 * Every step goes through core's guarded ceremony (`openCeremony`), one per
 * operation: it pins the network, admits the new key and the signing key,
 * reads the ledger itself and refuses any step the ledger, the authorities or
 * the approved budget do not allow. This file keeps what is the page's own:
 * the state on screen, the journal it writes before each send, and the tab
 * lock. What it shows follows what the ceremony read.
 *
 * Budget (SAFE-03a). `quote` is the budget for the steps still to run, as last
 * read from the network; it is public and never saved. Starting or continuing
 * approves the quote on screen, and that approval (`approved`) binds the run:
 * before each step the budget is read again, and a step that would cost more,
 * send more, or be signed or paid differently than was approved is not sent.
 * The run stops with the new reading on screen, and only continuing approves
 * it. After a reload nothing is approved until the operator approves again.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  CEREMONY_TIMING,
  clientsFor,
  exceedsApproved,
  generatePqIdentity,
  mergeEvidence,
  openCeremony,
  planMigration,
  pqIdentityFromMnemonic,
  publicMessage,
  quoteMigration,
  readAuthority,
  readNetwork,
  signerFromAuthority,
  signerRefusal,
  type AccountExposure,
  type AttemptEvidence,
  type AuthorityObservation,
  type BudgetSpec,
  type Ceremony,
  type CeremonyTiming,
  type FalconerClients,
  type MigrationBudget,
  type MigrationPlan,
  type PqIdentity,
  type TransactionAttempt,
} from '@falqoner/core';
import {
  attemptsFor,
  browserJournal,
  browserTabLock,
  confirmedAttempt,
  isFinalEvidence,
  isResolved,
  newRecord,
  stageStatus,
  stateOf,
  verifiedView,
  withAllEvidence,
  withAttempt,
  withEvidence,
  type Journal,
  type JournalRead,
  type MigrationRecord,
  type TabLock,
} from './journal';
import type { Genesis, NetworkName } from './network';

export { genesisOf, genesisRefusal, pinClients } from './network';
export type { Genesis, NetworkName } from './network';

/** The on-chain steps, in the order they run. */
export const STAGES = ['funding', 'proof', 'rekey', 'verification'] as const;
export type Stage = (typeof STAGES)[number];

export const STAGE_LABEL: Record<Stage, string> = {
  funding: 'Fund the post-quantum address',
  proof: 'Prove the Falcon key on chain',
  rekey: 'Rekey the account',
  verification: 'Verify the new authority',
};

/** The steps signed by the account's current authority rather than the new key. */
const NEEDS_SIGNER: readonly Stage[] = ['funding', 'rekey'];

export type Status =
  | 'idle'
  | 'prepared'
  | 'submitted'
  | 'confirmed'
  | 'failed'
  | 'outcome-unknown';

/** What was scanned, so a refresh reads exactly the same thing again. */
export interface ScanRequest {
  address: string;
  network: NetworkName;
  assets: string;
  apps: string;
}

/** Fixed when the key is generated, or rebuilt from the record. Public. */
export interface OperationContext {
  readonly network: NetworkName;
  readonly scan: ScanRequest;
  /** The scan the plan was made from; null for a recovered migration. */
  readonly exposure: AccountExposure | null;
  /** The account being migrated. */
  readonly sender: string;
  /** Whose key signs the funding and the rekey: the account's current authority. */
  readonly authorizer: string;
  /** The new post-quantum address. */
  readonly targetAddress: string;
  readonly plan: MigrationPlan | null;
  /** The clients for `network`, from this page's own configuration. */
  readonly clients: FalconerClients;
}

export type Task = 'checks' | 'steps' | 'reconcile';

export interface Operation {
  readonly id: string;
  /** Started on this page, or found in the journal after a reload. */
  readonly origin: 'session' | 'recovered';
  readonly status: Exclude<Status, 'idle'>;
  /** The step `status` refers to; `null` before the first one is entered. */
  readonly stage: Stage | null;
  /** Something this operation awaits is outstanding. */
  readonly inFlight: boolean;
  /** What is outstanding. */
  readonly task: Task | null;
  readonly context: OperationContext;
  /** The new key. Memory only; null after a reload until its phrase is restored. */
  readonly identity: PqIdentity | null;
  /**
   * Pinned before the first step of a run. Every transaction of the run is
   * prepared from `clients`, which refuse parameters from any other network.
   */
  readonly pinned: { readonly genesis: Genesis; readonly clients: FalconerClients } | null;
  /** The public record as it is stored; null until the first attempt is recorded. */
  readonly record: MigrationRecord | null;
  /** Sticky: set when the rekey confirms, and never cleared by a failure. */
  readonly rekeyConfirmed: boolean;
  readonly verification: 'not-started' | 'in-flight' | 'passed' | 'failed' | 'unknown';
  /** What each confirmed step reported. */
  readonly results: Readonly<Partial<Record<Stage, string>>>;
  /**
   * What the ledger was read to say in this session, by transaction id. A
   * settling reading is kept for the session; the record's labels are not
   * evidence.
   */
  readonly evidence: Readonly<Record<string, AttemptEvidence>>;
  /** The account's authority at the last reading. */
  readonly authority: AuthorityObservation | null;
  /** Something read contradicts the record. Nothing continues while it stands. */
  readonly conflict: string | null;
  /** Why this tab may only look: another tab holds the migration, or tabs cannot be kept apart. */
  readonly readOnly: string | null;
  /** Something the last reading changed in the saved record, for the operator to see. */
  readonly notice: string | null;
  readonly error: string | null;
  /** The budget for the steps still to run, as last read. Public; never saved. */
  readonly quote: MigrationBudget | null;
  /** A budget reading is outstanding. It signs and sends nothing. */
  readonly quoting: boolean;
  /** What the operator approved for this run. Nothing is sent beyond it. Never saved. */
  readonly approved: MigrationBudget | null;
}

export type OperationState = { readonly status: 'idle' } | Operation;

export const IDLE: OperationState = Object.freeze({ status: 'idle' as const });

export type OperationEvent =
  /** A new key for a new context. Replaces an operation only if it is unlocked. */
  | { type: 'prepare'; id: string; context: OperationContext; identity: PqIdentity }
  /** A migration found in the journal, with no key. */
  | { type: 'recover'; record: MigrationRecord; context: OperationContext }
  /** Drop an operation that never sent anything. */
  | { type: 'discard' }
  /** Clear a resolved migration the operator confirmed they have recorded. */
  | { type: 'dismiss'; acknowledged: boolean }
  /** Take the guard and begin the checks before the first send, approving `approved`. */
  | { type: 'start'; approved: MigrationBudget | null }
  /** Take the guard and begin the checks before continuing a stopped migration, approving `approved`. */
  | { type: 'resume'; approved: MigrationBudget | null }
  /** Begin reading the budget for the remaining steps. */
  | { type: 'quote' }
  /**
   * The budget as read now: by a `quote` request, or by a run before one of
   * its steps. A requested reading that lands during a run is not shown: the
   * run reads its own.
   */
  | { type: 'quoted'; quote: MigrationBudget; by: 'request' | 'run' }
  /** A check failed. Nothing was sent. */
  | { type: 'refuse'; reason: string }
  | { type: 'pin'; genesis: Genesis; clients: FalconerClients }
  /** About to prepare, record and send `stage`. */
  | { type: 'submit'; stage: Stage }
  /** The journal now holds `record`. */
  | { type: 'recorded'; record: MigrationRecord }
  | { type: 'confirm'; stage: Stage; detail: string }
  /** The attempt stopped before it was sent, or was shown never to have landed. */
  | { type: 'halt'; stage: Stage; reason: string }
  /** The attempt may have landed, and nothing shows whether it did. */
  | { type: 'unknown'; stage: Stage; reason: string }
  /** Verification read another authority, and so sent nothing. */
  | { type: 'verification-failed'; reason: string }
  /** Stop after a confirmed step without going on. */
  | { type: 'pause'; reason: string }
  /** Something the operator must see, which changes nothing else. */
  | { type: 'note'; error: string }
  /** What the ledger was read to say in this session. */
  | { type: 'observed'; evidence?: AttemptEvidence; authority?: AuthorityObservation }
  /** The new key, from its phrase, matching the recorded address. */
  | { type: 'restore'; identity: PqIdentity }
  /** Begin a read-only reconciliation. */
  | { type: 'reconcile' }
  | {
      type: 'reconciled';
      record: MigrationRecord;
      evidence: Record<string, AttemptEvidence>;
      authority: AuthorityObservation | null;
      conflict: string | null;
      readOnly: string | null;
      notice: string | null;
      error: string | null;
    };

const isOp = (s: OperationState): s is Operation => s.status !== 'idle';

const STAGE_BEFORE: Record<Stage, Stage | null> = {
  funding: null,
  proof: 'funding',
  rekey: 'proof',
  verification: 'rekey',
};

/** The step a continuation would run next, or null if none may run. */
export function nextStage(op: Operation): Stage | null {
  if (op.status === 'prepared') return 'funding';
  if (op.status === 'failed') return op.stage ?? 'funding';
  if (op.status === 'confirmed' && op.stage !== 'verification') {
    return STAGES[STAGES.indexOf(op.stage!) + 1]!;
  }
  return null;
}

/**
 * Where a record's states put the migration. Called with a `verifiedView`,
 * so the states are what this session read, never stored labels.
 */
export function positionOf(record: MigrationRecord): Pick<
  Operation,
  'status' | 'stage' | 'rekeyConfirmed' | 'verification' | 'results'
> {
  const results: Partial<Record<Stage, string>> = {};
  for (const s of STAGES) {
    const a = confirmedAttempt(record, s);
    if (a) results[s] = `Transaction ${a.txId} confirmed in round ${a.confirmedRound}.`;
  }
  const rekeyConfirmed = stageStatus(record, 'rekey') === 'confirmed';
  for (const stage of STAGES) {
    const s = stageStatus(record, stage);
    if (s === 'confirmed') continue;
    const verification = stage !== 'verification' ? 'not-started' : s === 'unresolved' ? 'unknown' : s === 'not-included' ? 'failed' : 'not-started';
    if (s === 'unresolved') return { status: 'outcome-unknown', stage, rekeyConfirmed, verification, results };
    if (s === 'not-included') return { status: 'failed', stage, rekeyConfirmed, verification, results };
    return { status: 'confirmed', stage: STAGE_BEFORE[stage], rekeyConfirmed, verification, results };
  }
  return { status: 'confirmed', stage: 'verification', rekeyConfirmed, verification: 'passed', results };
}

/** The record as this session read it, or null before anything was recorded. */
export const viewOf = (op: Operation): MigrationRecord | null =>
  op.record ? verifiedView(op.record, op.evidence) : null;

/**
 * Why the record cannot yet be acted on, or null. Every attempt must have
 * been read as settled in this session, the saved labels must say the same,
 * no step may hold two confirmations and nothing may contradict it. A label
 * that says `confirmed` or `not-included` counts for nothing on its own.
 */
export function unsettled(op: Operation): string | null {
  if (!op.record) return 'Nothing has been sent.';
  if (op.conflict) return `The ledger contradicts this migration: ${op.conflict}`;
  for (const a of op.record.attempts) {
    const e = op.evidence[a.txId];
    if (!e) {
      return (
        `${STAGE_LABEL[a.stage]} (${a.txId}) has not been read from the ledger in ` +
        'this session, and its saved state is only a claim. Check the ledger first.'
      );
    }
    if (!isFinalEvidence(e)) {
      return `An attempt is still unresolved (${STAGE_LABEL[a.stage]}). Check the ledger to settle it first.`;
    }
    if (stateOf(e) !== a.state) {
      return 'The saved record does not yet say what the ledger shows. Check the ledger again so that it is saved.';
    }
  }
  const view = viewOf(op)!;
  for (const s of STAGES) {
    if (attemptsFor(view, s).filter((a) => a.state === 'confirmed').length > 1) {
      return `Two attempts of "${STAGE_LABEL[s]}" confirmed. Nothing more is done from this page.`;
    }
  }
  return null;
}

/**
 * Why the account's authority, as read this session, does not support
 * dismissing: not read, read before the verified rekey, or not what the
 * verified steps leave it with.
 */
export function authorityProblem(op: Operation): string | null {
  const view = viewOf(op);
  const a = op.authority;
  if (!view) return 'Nothing has been sent.';
  if (!a) return "The account's authority has not been read in this session. Check the ledger first.";
  const rekey = confirmedAttempt(view, 'rekey');
  if (rekey && a.round < rekey.confirmedRound!) {
    return (
      `The account's authority was read at round ${a.round}, before the rekey in round ` +
      `${rekey.confirmedRound}, so that reading is stale. Check the ledger again.`
    );
  }
  const expected = rekey ? op.context.targetAddress : op.context.authorizer;
  return a.authority === expected ? null : `The account answers to ${a.authority}, not ${expected}.`;
}

/**
 * Why `state` must not be replaced or dropped, or `null` when nothing is at
 * stake. This is the lock the page's other controls respect.
 */
export function lockReason(state: OperationState): string | null {
  if (!isOp(state)) return null;
  if (state.inFlight) {
    if (state.task === 'reconcile') return 'This migration is being checked against the ledger. Nothing is sent while it is.';
    return state.status === 'prepared' || state.task === 'checks'
      ? 'A migration is checking the network before it sends anything.'
      : `A migration is in progress: ${STAGE_LABEL[state.stage!].toLowerCase()}.`;
  }
  if (state.status === 'outcome-unknown') {
    return (
      `The outcome of step "${STAGE_LABEL[state.stage!]}" is unknown. Check the ` +
      'ledger to settle it; until then nothing else can start here.'
    );
  }
  if (state.record) {
    if (state.status === 'confirmed' && state.stage === 'verification') {
      return 'The migration finished. Confirm its 25 words are written down, then dismiss it.';
    }
    if (state.rekeyConfirmed) return 'The rekey confirmed, but its verification did not finish.';
    if (!unsettled(state) && isResolved(viewOf(state)!)) {
      return 'This migration settled without a rekey. Acknowledge and dismiss it to start another.';
    }
    return 'This migration has sent transactions, and it is not finished.';
  }
  // Prepared, or stopped before anything was sent.
  return null;
}

/** Why `event` is not allowed in `state`, or `null` if it is. */
export function refusal(state: OperationState, event: OperationEvent): string | null {
  switch (event.type) {
    case 'prepare':
    case 'recover':
    case 'discard':
      return lockReason(state);
    case 'dismiss': {
      if (!isOp(state) || state.inFlight || !state.record) return 'There is nothing to dismiss.';
      const why = unsettled(state);
      if (why) return why;
      if (!isResolved(viewOf(state)!)) {
        return (
          'Only a resolved migration can be dismissed: verified, or with every ' +
          'attempt settled and the account not rekeyed.'
        );
      }
      const authority = authorityProblem(state);
      if (authority) return authority;
      return event.acknowledged ? null : 'Confirm the 25 words are written down first.';
    }
  }
  if (!isOp(state)) return 'There is no migration.';
  switch (event.type) {
    case 'start':
      return !state.inFlight &&
        state.stage === null &&
        state.record === null &&
        state.identity !== null &&
        (state.status === 'prepared' || state.status === 'failed')
        ? null
        : 'This migration has already started.';
    case 'resume': {
      const c = continuationOf(state);
      if (!c.next) return c.blockedBy;
      return state.identity ? null : 'Restore the new key from its 25 words first.';
    }
    case 'refuse':
    case 'pin':
      if (!state.inFlight || state.task !== 'checks') return 'The checks before sending are not running.';
      return event.type === 'pin' && state.pinned ? 'The network is already pinned.' : null;
    case 'submit': {
      if (!state.inFlight || !state.pinned || (state.task !== 'checks' && state.task !== 'steps')) {
        return 'Nothing may be sent now.';
      }
      if (state.status === 'submitted' || state.status === 'outcome-unknown') return 'A step is already out.';
      return nextStage(state) === event.stage ? null : `"${STAGE_LABEL[event.stage]}" cannot start now.`;
    }
    case 'recorded':
      if (event.record.id !== state.id) return 'That record belongs to another migration.';
      return state.record && event.record.revision <= state.record.revision ? 'That record is older than the one held.' : null;
    case 'confirm':
    case 'unknown':
    case 'halt':
      return state.status === 'submitted' && state.stage === event.stage
        ? null
        : `"${STAGE_LABEL[event.stage]}" is not awaiting a result.`;
    case 'verification-failed':
      return state.status === 'submitted' && state.stage === 'verification'
        ? null
        : 'Verification is not awaiting a result.';
    case 'pause':
      return state.inFlight && state.task === 'steps' && state.status === 'confirmed' ? null : 'Nothing to pause.';
    case 'note':
      return state.inFlight ? 'Something is in progress.' : null;
    case 'observed':
      return null;
    case 'quote':
      return state.inFlight || state.quoting ? 'Something is in progress.' : null;
    case 'quoted':
      if (event.by === 'request') return state.quoting ? null : 'No budget reading is outstanding.';
      return state.inFlight && (state.task === 'checks' || state.task === 'steps') ? null : 'No run is reading the budget.';
    case 'restore':
      if (state.inFlight) return 'Something is in progress.';
      if (state.identity) return 'The key is already here.';
      return event.identity.address === state.context.targetAddress
        ? null
        : 'That key is not the one this migration rekeys to.';
    case 'reconcile':
      return !state.inFlight && state.record ? null : 'There is nothing to check now.';
    case 'reconciled':
      return state.inFlight && state.task === 'reconcile' && event.record.id === state.id
        ? null
        : 'No check is running.';
  }
}

/**
 * Whether a stopped migration may continue, and what continuing needs. The
 * command refuses on exactly the same conditions.
 */
export function continuationOf(op: Operation):
  | { next: Stage; needsIdentity: boolean; needsSigner: boolean; blockedBy: null }
  | { next: null; blockedBy: string } {
  const no = (blockedBy: string) => ({ next: null, blockedBy }) as const;
  if (op.inFlight) return no('Something is already in progress.');
  if (!op.record) return no('Nothing has been sent, so there is nothing to continue.');
  const why = unsettled(op);
  if (why) return no(why);
  const resting =
    (op.status === 'failed' && op.stage !== null) || (op.status === 'confirmed' && op.stage !== 'verification');
  const next = resting ? nextStage(op) : null;
  if (!next) return no('There is no step to continue.');
  return { next, needsIdentity: !op.identity, needsSigner: needsSigner(next), blockedBy: null };
}

export class TransitionError extends Error {}

function fresh(): Omit<Operation, 'id' | 'origin' | 'context' | 'identity'> {
  return {
    status: 'prepared',
    stage: null,
    inFlight: false,
    task: null,
    pinned: null,
    record: null,
    rekeyConfirmed: false,
    verification: 'not-started',
    results: {},
    evidence: {},
    authority: null,
    conflict: null,
    readOnly: null,
    notice: null,
    error: null,
    quote: null,
    quoting: false,
    approved: null,
  };
}

/** The only way an operation changes. Throws on anything `refusal` names. */
export function transition(state: OperationState, event: OperationEvent): OperationState {
  const why = refusal(state, event);
  if (why) throw new TransitionError(why);
  switch (event.type) {
    case 'prepare':
      return Object.freeze<Operation>({
        ...fresh(),
        id: event.id,
        origin: 'session',
        context: event.context,
        identity: event.identity,
      });
    case 'recover':
      return Object.freeze<Operation>({
        ...fresh(),
        // Nothing is read yet, so nothing is taken from the labels.
        ...positionOf(verifiedView(event.record, {})),
        id: event.record.id,
        origin: 'recovered',
        context: event.context,
        identity: null,
        record: event.record,
      });
    case 'discard':
    case 'dismiss':
      return IDLE;
  }
  const op = state as Operation;
  const next = (patch: Partial<Operation>) => Object.freeze<Operation>({ ...op, ...patch });
  switch (event.type) {
    case 'start':
      return next({
        status: 'prepared',
        inFlight: true,
        task: 'checks',
        pinned: null,
        results: {},
        error: null,
        approved: event.approved,
      });
    case 'resume':
      return next({ inFlight: true, task: 'checks', pinned: null, error: null, approved: event.approved });
    case 'quote':
      return next({ quoting: true });
    case 'quoted':
      // A requested reading that lands mid-run ends the request, and shows nothing.
      return event.by === 'request' && op.inFlight
        ? next({ quoting: false })
        : next({ quote: event.quote, quoting: event.by === 'run' ? op.quoting : false });
    case 'refuse':
      return op.stage === null && op.record === null
        ? next({ status: 'failed', inFlight: false, task: null, pinned: null, error: event.reason })
        : next({ inFlight: false, task: null, pinned: null, error: event.reason });
    case 'pin':
      return next({ pinned: Object.freeze({ genesis: event.genesis, clients: event.clients }) });
    case 'submit':
      return next({
        status: 'submitted',
        stage: event.stage,
        task: 'steps',
        error: null,
        ...(event.stage === 'verification' ? { verification: 'in-flight' as const } : {}),
      });
    case 'recorded':
      return next({ record: event.record });
    case 'confirm': {
      const last = event.stage === 'verification';
      return next({
        status: 'confirmed',
        inFlight: !last,
        task: last ? null : 'steps',
        results: { ...op.results, [event.stage]: event.detail },
        ...(event.stage === 'rekey' ? { rekeyConfirmed: true } : {}),
        ...(last ? { verification: 'passed' as const } : {}),
      });
    }
    case 'halt':
      return next({
        status: 'failed',
        // With nothing ever recorded, nothing was ever sent: a fresh start.
        stage: op.record ? event.stage : null,
        inFlight: false,
        task: null,
        error: event.reason,
        ...(event.stage === 'verification' ? { verification: 'failed' as const } : {}),
      });
    case 'unknown':
      return next({
        status: 'outcome-unknown',
        inFlight: false,
        task: null,
        error: event.reason,
        ...(event.stage === 'verification' ? { verification: 'unknown' as const } : {}),
      });
    case 'verification-failed':
      return next({ status: 'failed', inFlight: false, task: null, verification: 'failed', error: event.reason });
    case 'pause':
      return next({ inFlight: false, task: null, error: event.reason });
    case 'note':
      return next({ error: event.error });
    case 'observed': {
      const merged = event.evidence
        ? mergeEvidence(op.evidence, [event.evidence])
        : { evidence: op.evidence, conflict: null };
      return next({
        evidence: merged.evidence,
        conflict: op.conflict ?? merged.conflict,
        ...(event.authority ? { authority: event.authority } : {}),
      });
    }
    case 'restore':
      return next({ identity: event.identity, error: null });
    case 'reconcile':
      return next({ inFlight: true, task: 'reconcile', error: null });
    case 'reconciled': {
      const merged = mergeEvidence(op.evidence, Object.values(event.evidence));
      const position = positionOf(verifiedView(event.record, merged.evidence));
      return next({
        ...position,
        // A rekey confirmed in this session stays confirmed, whatever is read later.
        rekeyConfirmed: op.rekeyConfirmed || position.rekeyConfirmed,
        results: { ...op.results, ...position.results },
        record: event.record,
        evidence: merged.evidence,
        authority: event.authority,
        conflict: event.conflict ?? merged.conflict,
        readOnly: event.readOnly,
        notice: event.notice,
        inFlight: false,
        task: null,
        pinned: null,
        error: event.error,
      });
    }
  }
}

/** Where each step stands, for display. */
export function stageState(
  op: Operation,
  stage: Stage,
): 'not-reached' | 'in-flight' | 'confirmed' | 'unknown' | 'failed' {
  if (op.status === 'submitted' && op.stage === stage) return 'in-flight';
  const view = viewOf(op);
  if (view) {
    // What this session read, never what the saved labels claim.
    const s = stageStatus(view, stage);
    if (s === 'confirmed') return 'confirmed';
    if (s === 'unresolved') return 'unknown';
    if (s === 'not-included') return 'failed';
    return op.status === 'failed' && op.stage === stage ? 'failed' : 'not-reached';
  }
  if (op.stage === null) return 'not-reached';
  const at = STAGES.indexOf(op.stage);
  const i = STAGES.indexOf(stage);
  if (i < at) return 'confirmed';
  if (i > at) return 'not-reached';
  switch (op.status) {
    case 'confirmed':
      return 'confirmed';
    case 'outcome-unknown':
      return 'unknown';
    default:
      return 'failed';
  }
}

/* ------------------------------------------------------------------ */
/* What the operator supplies                                          */
/* ------------------------------------------------------------------ */

/** Checked by the ceremony, not here. */
export interface ExecuteInputs {
  /** The new phrase, typed back from what the operator wrote down. */
  transcription: string;
  /** The 25-word phrase of the account's current authority. */
  signingPhrase: string;
}

export interface ResumeInputs {
  /** The phrase of the account's current authority, when a remaining step needs it. */
  signingPhrase?: string;
}

/** Whether the steps from `next` on need the account's current authority to sign. */
export const needsSigner = (next: Stage) => STAGES.slice(STAGES.indexOf(next)).some((s) => NEEDS_SIGNER.includes(s));

/* ------------------------------------------------------------------ */
/* Budget                                                              */
/* ------------------------------------------------------------------ */

/** The budget request for the steps from `from` on. */
export function budgetSpecOf(context: OperationContext, from: Stage): BudgetSpec {
  const { sender, authorizer, targetAddress, exposure } = context;
  return {
    sender,
    authorizer,
    target: targetAddress,
    from,
    // What the scan established; for a recovered migration, the address shape.
    signer: signerFromAuthority(exposure?.authority, authorizer),
  };
}

/** The step a budget reading should start from now, or null if none would run. */
export function quoteFrom(op: Operation): Stage | null {
  if (op.inFlight) return null;
  if (!op.record && op.stage === null && (op.status === 'prepared' || op.status === 'failed')) return 'funding';
  return continuationOf(op).next;
}

/**
 * Why the budget on screen cannot be approved to run from `from`, or null.
 * The command refuses on exactly these conditions; a disabled button is not
 * a guard.
 */
export function approvalRefusal(op: Operation, from: Stage): string | null {
  const q = op.quote;
  if (op.quoting) return 'The budget is still being read.';
  if (!q) return 'The budget has not been read yet. Read it before going on.';
  if (q.status !== 'available') {
    return `The budget is ${q.status}: ${q.problems.join(' ') || 'nothing usable was read.'}`;
  }
  const s = q.spec;
  if (s.sender !== op.context.sender || s.authorizer !== op.context.authorizer || s.target !== op.context.targetAddress || !s.drill) {
    return 'The budget on screen is for a different migration. Read it again.';
  }
  if (s.from !== from) {
    return `The budget on screen starts at "${STAGE_LABEL[s.from]}", not "${STAGE_LABEL[from]}". Read it again.`;
  }
  // The ceremony refuses the same: this only keeps it from being approved.
  return needsSigner(from) ? signerRefusal(s.signer) : null;
}

/* ------------------------------------------------------------------ */
/* The controller                                                      */
/* ------------------------------------------------------------------ */

export type ContextBase = Omit<OperationContext, 'targetAddress' | 'plan'>;

export type Timing = CeremonyTiming;

export const DEFAULT_TIMING: Timing = CEREMONY_TIMING;

export interface OperationOptions {
  onVerified?: (op: Operation) => void;
  journal?: Journal;
  tabLock?: TabLock;
  timing?: Partial<Timing>;
}

export interface OperationCommands {
  /** The live state, not a render's copy. */
  current(): OperationState;
  lockReason(): string | null;
  /** What the journal held when the page opened, if it blocks a new migration. */
  journalProblem(): string | null;
  /** Generate a key for `base`. Refused while an operation is locked. */
  prepare(base: ContextBase): boolean;
  /** Take up a migration found in the journal. */
  recover(record: MigrationRecord): boolean;
  /** Drop an operation that never sent anything. */
  discard(): boolean;
  /** Check, pin and run every step. A second call while one runs does nothing. */
  execute(inputs: ExecuteInputs): Promise<void>;
  /** Read what the ledger says about every unresolved attempt. Never signs or sends. */
  reconcile(): Promise<void>;
  /** Restore the new key from its phrase. Returns why not, or null. */
  restore(phrase: string): string | null;
  /** Continue a stopped migration from its next step. */
  resume(inputs: ResumeInputs): Promise<void>;
  /** Verification again, after a confirmed rekey whose verification sent nothing. */
  retryVerification(): Promise<void>;
  /** Clear a resolved migration, and its record. Returns what was cleared. */
  dismiss(acknowledged: boolean): Operation | null;
  /** Read the budget for the steps still to run. Read-only; signs and sends nothing. */
  refreshQuote(): Promise<void>;
}

const newId = () => {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return `op-${Date.now().toString(36)}-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
};

/** What a journal read says about starting something new. */
function problemOf(read: JournalRead): string | null {
  switch (read.kind) {
    case 'invalid':
      return (
        'A saved migration record in this browser could not be used ' +
        `(${read.reason}). It is kept, not cleared, and no new migration can ` +
        'start from this page until it is dealt with.'
      );
    case 'unavailable':
      return (
        `This browser's storage could not be read (${read.reason}), so an ` +
        'unfinished migration may be hidden. No new migration can start from this page.'
      );
    default:
      return null;
  }
}

/**
 * The one owner of the migration operation. `onVerified` runs once the
 * migration is verified, with that operation.
 */
export function useMigrationOperation(
  options: OperationOptions = {},
): { state: OperationState; commands: OperationCommands } {
  const ref = useRef<OperationState>(IDLE);
  const [state, setState] = useState<OperationState>(IDLE);
  const optionsRef = useRef(options);
  optionsRef.current = options;
  const journalRef = useRef<Journal>(options.journal ?? browserJournal());
  const lockRef = useRef<TabLock>(options.tabLock ?? browserTabLock());
  const problemRef = useRef<string | null>(null);
  /** The guarded ceremony of the current operation. It holds the admitted key, so it goes with the operation. */
  const ceremonyRef = useRef<{ id: string; ceremony: Ceremony } | null>(null);
  const [, setProblem] = useState<string | null>(null);

  const commands = useMemo<OperationCommands>(() => {
    const journal = journalRef.current;
    const tabLock = lockRef.current;
    const timing = (): Timing => ({ ...DEFAULT_TIMING, ...optionsRef.current.timing });

    const apply = (next: OperationState) => {
      ref.current = next;
      setState(next);
    };

    /** The operation `id`, if it is still the current one. */
    const live = (id: string): Operation | null => {
      const cur = ref.current;
      return isOp(cur) && cur.id === id ? cur : null;
    };

    /**
     * Apply `event` to operation `id`, if it is still the current one and
     * the event is allowed. A continuation that finds otherwise stops.
     */
    const step = (id: string, event: OperationEvent): boolean => {
      const cur = live(id);
      if (!cur || refusal(cur, event)) return false;
      apply(transition(cur, event));
      return true;
    };

    const refuse = (id: string, reason: string) => void step(id, { type: 'refuse', reason: `Nothing was sent. ${reason}` });

    /**
     * Everything that must hold before a run sends: this tab's hold on the
     * journal, a journal that still says what this page thinks it says, and
     * the ceremony's own check of the network, which it then pins.
     */
    const readyToSend = async (id: string, ceremony: Ceremony): Promise<boolean> => {
      if (!(await tabLock.acquire())) {
        refuse(
          id,
          'This page could not take its exclusive hold on the migration record: another tab ' +
            'has it open, or this browser cannot keep tabs apart. Close the other tab, or use one ' +
            'with Web Locks.',
        );
        return false;
      }
      const op = live(id);
      if (!op || op.task !== 'checks') return false;
      const read = journal.read();
      if (op.record) {
        if (read.kind !== 'record' || read.record.id !== op.record.id || read.record.revision !== op.record.revision) {
          refuse(id, 'The saved record no longer matches this page. Reload the page to recover it.');
          return false;
        }
      } else if (read.kind !== 'empty') {
        refuse(
          id,
          read.kind === 'record'
            ? 'Another migration is saved in this browser. Reload the page to recover it first.'
            : problemOf(read) ?? 'The saved record cannot be read.',
        );
        return false;
      }
      const pinned = await ceremony.pin(timing());
      const cur = live(id);
      if (!cur || cur.task !== 'checks') return false;
      if ('refused' in pinned) {
        refuse(id, pinned.refused);
        return false;
      }
      return step(id, { type: 'pin', genesis: pinned.genesis, clients: pinned.clients });
    };

    /**
     * Write `attempt` to the journal before it is sent. Throws, so the send
     * does not happen, unless this is still the step in flight and the write
     * read back. A continuation that timed out or was replaced cannot get
     * past this.
     */
    const recordAttempt = (id: string, attempt: TransactionAttempt) => {
      const op = live(id);
      if (!op || op.status !== 'submitted' || op.stage !== attempt.stage || op.task !== 'steps') {
        throw new Error('This step is no longer the one in flight.');
      }
      if (!tabLock.held()) throw new Error('This tab no longer holds the migration record.');
      const next = op.record
        ? withAttempt(op.record, attempt)
        : newRecord(
            {
              id: op.id,
              network: op.context.network as 'testnet' | 'localnet',
              genesis: op.pinned!.genesis,
              sender: op.context.sender,
              authorizer: op.context.authorizer,
              target: op.context.targetAddress,
              scan: { assets: op.context.scan.assets, apps: op.context.scan.apps },
            },
            attempt,
          );
      journal.write(next, op.record);
      step(id, { type: 'recorded', record: next });
    };

    /** Save what the ledger said. Returns why it could not be saved, or null. */
    const recordEvidence = (id: string, evidence: AttemptEvidence): string | null => {
      const op = live(id);
      if (!op?.record) return 'The migration is no longer current.';
      const next = withEvidence(op.record, evidence);
      if (next === op.record) return null;
      try {
        journal.write(next, op.record);
      } catch (err) {
        return publicMessage(err);
      }
      step(id, { type: 'recorded', record: next });
      return null;
    };

    /**
     * The ceremony for `op`, kept for as long as `op` is the operation, and
     * holding every attempt its record holds. A string says why there is none.
     */
    const ceremonyOf = (op: Operation): Ceremony | string => {
      try {
        const held = ceremonyRef.current;
        if (!held || held.id !== op.id) {
          const { network, sender, authorizer, targetAddress, clients } = op.context;
          const ceremony = openCeremony(clients, {
            network,
            sender,
            authorizer,
            target: targetAddress,
            genesis: op.record?.genesis,
            attempts: op.record?.attempts,
          });
          ceremonyRef.current = { id: op.id, ceremony };
          return ceremony;
        }
        const why = op.record ? held.ceremony.include(op.record.attempts) : null;
        return why ?? held.ceremony;
      } catch (err) {
        return publicMessage(err);
      }
    };

    /** One step, through the ceremony. True if it confirmed and the run goes on. */
    const runStage = async (id: string, ceremony: Ceremony, stage: Stage, signingPhrase?: string): Promise<boolean> => {
      if (!step(id, { type: 'submit', stage })) return false;
      const op = live(id)!;
      const run = await ceremony.run(stage, {
        approved: op.approved,
        signingPhrase,
        // Throws, so nothing is sent, unless this is still the step in flight.
        record: (attempt) => recordAttempt(id, attempt),
        timing: timing(),
      });
      if (!live(id)) return false;
      // The budget it read is shown, whether or not it allowed the step.
      if (run.quote) step(id, { type: 'quoted', quote: run.quote, by: 'run' });
      if (run.authority) step(id, { type: 'observed', authority: run.authority });

      if (!run.sent) {
        if (stage === 'verification' && run.authority && run.authority.authority !== op.context.targetAddress) {
          step(id, { type: 'verification-failed', reason: run.reason });
          return false;
        }
        const beyond = run.quote && op.approved ? exceedsApproved(op.approved, run.quote) : null;
        const then = !beyond
          ? ''
          : run.quote!.status === 'available'
            ? ' Review the budget below: going on approves it.'
            : ' Nothing can go on until the budget below can be approved.';
        step(id, { type: 'halt', stage, reason: `Nothing was sent for this step. ${run.reason}${then}` });
        return false;
      }

      const { evidence, send } = run;
      step(id, { type: 'observed', evidence });
      const unsaved = recordEvidence(id, evidence);
      const state = stateOf(evidence);
      if (state === 'confirmed') {
        const detail = `Transaction ${evidence.txId} confirmed in round ${evidence.confirmedRound}.`;
        if (!step(id, { type: 'confirm', stage, detail })) return false;
        if (unsaved) {
          if (stage !== 'verification') {
            step(id, {
              type: 'pause',
              reason: `This step confirmed, but the saved record could not be updated (${unsaved}). Nothing more was sent.`,
            });
          }
          return false;
        }
        return stage !== 'verification';
      }
      const said = send.status === 'accepted' ? '' : ` The send itself ${send.status === 'rejected' ? 'was refused' : 'got no usable answer'}: ${send.reason}`;
      if (state === 'not-included') {
        step(id, { type: 'halt', stage, reason: `It never landed and can no longer land, so this step can be sent again.${said}` });
      } else {
        step(id, { type: 'unknown', stage, reason: `${evidence.detail}${said}` });
      }
      return false;
    };

    const runSteps = async (id: string, ceremony: Ceremony, signingPhrase?: string) => {
      for (;;) {
        const op = live(id);
        if (!op || !op.inFlight) return;
        const stage = nextStage(op);
        if (!stage) return;
        if (!(await runStage(id, ceremony, stage, signingPhrase))) return;
        if (stage === 'verification') return;
      }
    };

    const afterVerified = (id: string) => {
      const op = live(id);
      if (op && op.status === 'confirmed' && op.stage === 'verification') optionsRef.current.onVerified?.(op);
    };

    /**
     * Once a run or a check ends with a step still to run, read its budget,
     * unless the one on screen already starts there.
     */
    const requoteIfStale = (id: string) => {
      const op = live(id);
      if (!op) return;
      const from = quoteFrom(op);
      if (from && op.quote?.spec.from !== from) void commands.refreshQuote();
    };

    const commands: OperationCommands = {
      current: () => ref.current,
      lockReason: () => lockReason(ref.current),
      journalProblem: () => problemRef.current,

      prepare(base) {
        if (problemRef.current || lockReason(ref.current)) return false;
        const identity = generatePqIdentity();
        const context: OperationContext = Object.freeze({
          ...base,
          targetAddress: identity.address,
          plan: planMigration(base.exposure!, identity.address),
        });
        ceremonyRef.current = null;
        apply(transition(ref.current, { type: 'prepare', id: newId(), context, identity }));
        void commands.refreshQuote();
        return true;
      },

      async refreshQuote() {
        const op = ref.current;
        if (!isOp(op) || refusal(op, { type: 'quote' })) return;
        const from = quoteFrom(op);
        if (!from) return;
        const id = op.id;
        apply(transition(op, { type: 'quote' }));
        const quote = await quoteMigration(op.context.clients, budgetSpecOf(op.context, from), {
          requestTimeoutMs: timing().requestMs,
        });
        step(id, { type: 'quoted', quote, by: 'request' });
      },

      recover(record) {
        if (lockReason(ref.current)) return false;
        const context: OperationContext = Object.freeze({
          network: record.network,
          scan: Object.freeze({ address: record.sender, network: record.network, assets: record.scan.assets, apps: record.scan.apps }),
          exposure: null,
          sender: record.sender,
          authorizer: record.authorizer,
          targetAddress: record.target,
          plan: null,
          // This page's own endpoints for the recorded network; the record names none.
          clients: clientsFor(record.network),
        });
        ceremonyRef.current = null;
        apply(transition(ref.current, { type: 'recover', record, context }));
        return true;
      },

      discard() {
        if (!isOp(ref.current)) return true;
        if (refusal(ref.current, { type: 'discard' })) return false;
        ceremonyRef.current = null;
        apply(transition(ref.current, { type: 'discard' }));
        return true;
      },

      async execute(inputs) {
        const op = ref.current;
        // The guard: taken synchronously, before any await, so a second
        // click in the same turn finds the operation already started.
        if (!isOp(op) || refusal(op, { type: 'start', approved: null })) return;
        const { id, identity } = op;
        // Starting approves the budget on screen, and only it.
        const unapprovable = approvalRefusal(op, 'funding');
        apply(transition(op, { type: 'start', approved: unapprovable ? null : op.quote }));

        // Offline first: the network and the target, the new key with its
        // phrase typed back, and the signing key. The ceremony checks each.
        const ceremony = ceremonyOf(op);
        if (typeof ceremony === 'string') return refuse(id, ceremony);
        const why = ceremony.admitKey(identity!, inputs.transcription) ?? ceremony.signingRefusal(inputs.signingPhrase);
        if (why) return refuse(id, why);
        if (unapprovable) return refuse(id, unapprovable);
        if (!(await readyToSend(id, ceremony))) return;
        await runSteps(id, ceremony, inputs.signingPhrase);
        afterVerified(id);
        requoteIfStale(id);
      },

      async reconcile() {
        const op = ref.current;
        if (!isOp(op) || refusal(op, { type: 'reconcile' })) return;
        const id = op.id;
        apply(transition(op, { type: 'reconcile' }));
        const t = timing();

        // Writing what is read needs this tab's hold on the journal. Without
        // it, what is read is shown and not saved.
        const canWrite = await tabLock.acquire();
        let stored = live(id)?.record ?? op.record!;
        let conflict: string | null = null;
        let error: string | null = null;
        let storageMoved = false;
        // The stored record is the one to build on, whether or not this tab
        // may write: another tab may have moved it on.
        const read = journal.read();
        if (read.kind === 'record' && read.record.id === stored.id && read.record.revision >= stored.revision) {
          stored = read.record;
        } else {
          storageMoved = true;
          conflict = 'The saved record changed or disappeared while this page showed it. Reload the page.';
        }
        // Every attempt is read by the ceremony, whatever its label says: a
        // stored `confirmed` or `not-included` is a claim. Only what it already
        // read as settled is not read again. A stored confirmed round is a
        // hint of which block to read first, nothing more.
        const held = live(id)?.evidence ?? op.evidence;
        const evidence: Record<string, AttemptEvidence> = {};
        const ceremony = ceremonyOf(op);
        const taken = typeof ceremony === 'string' ? ceremony : ceremony.include(stored.attempts);
        if (taken) {
          conflict ??= taken;
        } else {
          let readings: AttemptEvidence[] = [];
          try {
            const hints = Object.fromEntries(stored.attempts.map((a) => [a.txId, a.confirmedRound]));
            readings = (await (ceremony as Ceremony).reconcile({ hints, timing: t })).readings;
          } catch (err) {
            error = publicMessage(err);
          }
          if (!live(id)) return;
          for (const e of readings) {
            evidence[e.txId] = e;
            if (e.outcome === 'conflict') conflict ??= e.detail;
          }
        }
        const merged = mergeEvidence(held, Object.values(evidence));
        conflict ??= merged.conflict;
        // The record takes every settled reading of this session, correcting a
        // label that said otherwise; a weaker reading changes no settled label.
        const working = withAllEvidence(stored, Object.values(merged.evidence));
        const corrected = stored.attempts.filter((a) => {
          const e = merged.evidence[a.txId];
          return e && isFinalEvidence(e) && a.state !== stateOf(e) && a.state !== 'recorded';
        });
        const notice = corrected.length
          ? corrected
              .map((a) => `The saved record said ${a.state} for ${STAGE_LABEL[a.stage].toLowerCase()} (${a.txId}), but the ledger shows ${stateOf(merged.evidence[a.txId]!)}.`)
              .join(' ') + ' The ledger decides; the record now says what it shows.'
          : null;

        let authority: AuthorityObservation | null = null;
        try {
          // The network again, so an authority from another one is not read as this one's.
          const network = await readNetwork(op.context.clients, { requestTimeoutMs: t.requestMs });
          if (network.genesis.id !== stored.genesis.id || network.genesis.hash !== stored.genesis.hash) {
            conflict ??= `The node now reports ${network.genesis.id}, not ${stored.genesis.id} as this migration recorded.`;
          } else {
            authority = await readAuthority(op.context.clients, op.context.sender, { requestTimeoutMs: t.requestMs });
          }
        } catch (err) {
          error ??= `The account's authority could not be read: ${publicMessage(err)}`;
        }
        if (!live(id)) return;
        if (authority) {
          const { authorizer, targetAddress } = op.context;
          const rekey = stageStatus(verifiedView(stored, merged.evidence), 'rekey');
          const allowed =
            rekey === 'confirmed' ? [targetAddress] : rekey === 'unresolved' ? [authorizer, targetAddress] : [authorizer];
          if (!allowed.includes(authority.authority)) {
            conflict ??=
              `The account's authority is now ${authority.authority}, which this migration ` +
              `did not set` +
              (rekey === 'confirmed' ? '. Its rekey to the new key is still recorded as confirmed.' : '.');
          }
        }

        let record = stored;
        let readOnly: string | null = null;
        if (!canWrite) {
          readOnly =
            'Another tab holds this migration, or this browser cannot keep tabs apart, so this ' +
            'tab only shows what the ledger says: it saves nothing and sends nothing.';
        } else if (working !== stored && !storageMoved) {
          try {
            journal.write(working, stored);
            record = working;
          } catch (err) {
            error = `What the ledger says could not be saved: ${publicMessage(err)}`;
          }
        }
        step(id, { type: 'reconciled', record, evidence, authority, conflict, readOnly, notice, error });
        requoteIfStale(id);
      },

      restore(phrase) {
        const op = ref.current;
        if (!isOp(op) || op.inFlight) return 'Nothing can be restored now.';
        if (op.identity) return null;
        let identity: PqIdentity;
        try {
          identity = pqIdentityFromMnemonic(phrase);
        } catch {
          return 'The phrase could not be decoded. Check each word against what you wrote down.';
        }
        if (identity.address !== op.context.targetAddress) {
          return `Those words derive ${identity.address}, not ${op.context.targetAddress}. Nothing was restored.`;
        }
        // The phrase just typed is its own transcription: the ceremony checks it again.
        const ceremony = ceremonyOf(op);
        const why = typeof ceremony === 'string' ? ceremony : ceremony.admitKey(identity, phrase);
        if (why) return why;
        apply(transition(op, { type: 'restore', identity }));
        return null;
      },

      async resume(inputs) {
        const op = ref.current;
        if (!isOp(op) || refusal(op, { type: 'resume', approved: null })) return;
        const { id } = op;
        const next = nextStage(op)!;
        // Continuing approves the budget on screen for the remaining steps, and only it.
        const unapprovable = approvalRefusal(op, next);
        apply(transition(op, { type: 'resume', approved: unapprovable ? null : op.quote }));
        if (unapprovable) return refuse(id, unapprovable);
        const ceremony = ceremonyOf(op);
        if (typeof ceremony === 'string') return refuse(id, ceremony);
        if (needsSigner(next)) {
          const why = ceremony.signingRefusal(inputs.signingPhrase ?? '');
          if (why) return refuse(id, why);
        }
        if (!(await readyToSend(id, ceremony))) return;
        // The ceremony reads each authority again before each step.
        await runSteps(id, ceremony, inputs.signingPhrase);
        afterVerified(id);
        requoteIfStale(id);
      },

      async retryVerification() {
        const op = ref.current;
        if (!isOp(op) || op.status !== 'failed' || op.stage !== 'verification') return;
        await commands.resume({});
      },

      dismiss(acknowledged) {
        const op = ref.current;
        if (!isOp(op)) return null;
        const why = refusal(op, { type: 'dismiss', acknowledged });
        if (why) {
          if (acknowledged && !op.inFlight) step(op.id, { type: 'note', error: why });
          return null;
        }
        if (!tabLock.held()) {
          step(op.id, { type: 'note', error: 'Another tab holds this migration, so its record was not removed.' });
          return null;
        }
        try {
          journal.remove(op.record!);
        } catch (err) {
          step(op.id, { type: 'note', error: `The saved record was not removed: ${publicMessage(err)}` });
          return null;
        }
        tabLock.release();
        ceremonyRef.current = null;
        apply(transition(op, { type: 'dismiss', acknowledged }));
        return op;
      },
    };
    return commands;
  }, []);

  // Once, on mount: an unfinished migration in the journal takes precedence
  // over anything new, and is checked against the ledger straight away.
  useEffect(() => {
    const read = journalRef.current.read();
    problemRef.current = problemOf(read);
    setProblem(problemRef.current);
    if (read.kind === 'record' && commands.recover(read.record)) void commands.reconcile();
    const tabLock = lockRef.current;
    return () => tabLock.release();
  }, [commands]);

  return { state, commands };
}
