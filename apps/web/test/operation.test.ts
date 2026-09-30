/**
 * The migration operation's transitions and network pin (SAFE-02a), and its
 * record-driven recovery rules (SAFE-02b), as pure functions. What may be
 * sent is the ceremony's to check (SAFE-03b): see core's ceremony.test.ts.
 * The mounted interaction tests are in migration.test.tsx and
 * recovery.test.tsx; these pin down the rules they rely on.
 *
 * Records here are built from real attempts that core prepared, so every
 * transaction id is genuine. What the ledger was read to say in a session
 * arrives as `observed` or `reconciled` events; a record's labels alone
 * decide nothing.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  ED25519_BY_PHRASE,
  V42_PROTOCOL,
  computeBudget,
  analyzeAccount,
  planMigration,
  type AccountExposure,
  type FalconerClients,
  type PqIdentity,
  type TransactionAttempt,
} from '@falconer/core';
import { fakeProvider } from '../../../packages/core/test/fake-provider';
import {
  IDLE,
  STAGES,
  TransitionError,
  approvalRefusal,
  budgetSpecOf,
  quoteFrom,
  continuationOf,
  genesisOf,
  genesisRefusal,
  lockReason,
  pinClients,
  positionOf,
  refusal,
  stageState,
  transition,
  type Operation,
  type OperationContext,
  type OperationEvent,
  type OperationState,
  type Stage,
} from '../src/operation';
import { newRecord, withAttempt, withEvidence, type MigrationRecord } from '../src/journal';
import {
  LOCAL_GENESIS,
  MAINNET_GENESIS,
  TESTNET_GENESIS,
  confirmedEvidence,
  identityFixture,
  neverLandedEvidence,
  signingFixture,
  stageAttempts,
  unknownEvidence,
} from './fixtures';

const SIGNER = signingFixture(21);
const OTHER_SIGNER = signingFixture(22);
const TARGET = identityFixture(40, 'unit');
const OTHER_TARGET = identityFixture(41, 'other');

async function exposureOf(address: string, extra: { amount?: bigint; authAddr?: string } = {}) {
  const { clients } = fakeProvider({
    accounts: { [address]: { amount: extra.amount ?? 5_000_000n, authAddr: extra.authAddr } },
  });
  return analyzeAccount(clients, address);
}

function contextFor(
  exposure: AccountExposure,
  target: PqIdentity = TARGET,
  network: OperationContext['network'] = 'localnet',
): OperationContext {
  return Object.freeze({
    network,
    scan: { address: exposure.address, network, assets: '', apps: '' },
    exposure,
    sender: exposure.address,
    authorizer: exposure.authAddr ?? exposure.address,
    targetAddress: target.address,
    plan: planMigration(exposure, target.address),
    clients: fakeProvider({}).clients,
  });
}

const genesis = genesisOf(LOCAL_GENESIS);
const pinned = { type: 'pin', genesis, clients: fakeProvider({}).clients } as const;

/** Apply events in order, each of which must be allowed. */
function run(state: OperationState, ...events: OperationEvent[]): OperationState {
  return events.reduce((s, e) => transition(s, e), state);
}

let attempts: Record<Stage, TransactionAttempt>;
let exposure: AccountExposure;
let prepared: OperationState;

beforeAll(async () => {
  exposure = await exposureOf(SIGNER.address);
  attempts = await stageAttempts(SIGNER.address, TARGET.address);
  prepared = transition(IDLE, { type: 'prepare', id: 'op-1', context: contextFor(exposure), identity: TARGET });
});

const baseOf = () => ({
  id: 'op-1',
  network: 'localnet' as const,
  genesis,
  sender: SIGNER.address,
  authorizer: SIGNER.address,
  target: TARGET.address,
  scan: { assets: '', apps: '' },
});

/**
 * The events of a run up to `stage` in flight: each earlier step recorded,
 * sent, read from the ledger as confirmed and confirmed, and `stage`
 * recorded and sent.
 */
function through(stage: Stage): OperationEvent[] {
  const events: OperationEvent[] = [{ type: 'start', approved: null }, pinned];
  let record: MigrationRecord | null = null;
  for (const s of STAGES) {
    events.push({ type: 'submit', stage: s });
    record = record ? withAttempt(record, attempts[s]) : newRecord(baseOf(), attempts[s]);
    events.push({ type: 'recorded', record });
    if (s === stage) break;
    record = withEvidence(record, confirmedEvidence(attempts[s]));
    events.push(
      { type: 'observed', evidence: confirmedEvidence(attempts[s]) },
      { type: 'recorded', record },
      { type: 'confirm', stage: s, detail: `${s} ok` },
    );
  }
  return events;
}

/** The record `through` ends with, and the same with `stage` settled by `e`. */
function recordThrough(stage: Stage, settle?: (a: TransactionAttempt) => ReturnType<typeof confirmedEvidence>) {
  const events = through(stage).filter((e): e is Extract<OperationEvent, { type: 'recorded' }> => e.type === 'recorded');
  const last = events.at(-1)!.record;
  return settle ? withEvidence(last, settle(attempts[stage])) : last;
}

const recover = (record: MigrationRecord) =>
  transition(IDLE, { type: 'recover', record, context: { ...contextFor(exposure), exposure: null, plan: null } }) as Operation;

/** Every attempt of `record` read as `settle` says. */
const readings = (record: MigrationRecord, settle: (a: TransactionAttempt) => ReturnType<typeof confirmedEvidence>) =>
  Object.fromEntries(record.attempts.map((a) => [a.txId, settle(a)]));

/** The account's authority as read at `round`. */
const authorityAt = (authority: string, round: bigint) => ({
  address: SIGNER.address,
  authority,
  rekeyed: authority !== SIGNER.address,
  round,
});

/** A recovered migration after a read-only check that read `evidence`. */
function checked(
  record: MigrationRecord,
  evidence: Record<string, ReturnType<typeof confirmedEvidence>>,
  extra: Partial<Extract<OperationEvent, { type: 'reconciled' }>> = {},
): Operation {
  return run(recover(record), { type: 'reconcile' }, {
    type: 'reconciled',
    record,
    evidence,
    authority: null,
    conflict: null,
    readOnly: null,
    notice: null,
    error: null,
    ...extra,
  }) as Operation;
}

describe('operation transitions', () => {
  it('prepares one operation with a fixed context, its key apart from it, and nothing sent', () => {
    const op = prepared as Operation;
    expect(op).toMatchObject({ id: 'op-1', origin: 'session', status: 'prepared', stage: null, inFlight: false, rekeyConfirmed: false, record: null });
    expect(op.identity).toBe(TARGET);
    expect(op.context).not.toHaveProperty('target');
    expect(Object.isFrozen(op)).toBe(true);
    expect(Object.isFrozen(op.context)).toBe(true);
    expect(lockReason(op)).toBeNull();
  });

  it('runs the four steps in order, and no other order', () => {
    let s = run(prepared, { type: 'start', approved: null });
    // Nothing is submitted before the network is pinned.
    expect(refusal(s, { type: 'submit', stage: 'funding' })).not.toBeNull();
    s = run(s, pinned);
    let record: MigrationRecord | null = null;
    for (const stage of STAGES) {
      for (const other of STAGES.filter((x) => x !== stage)) {
        expect(refusal(s, { type: 'submit', stage: other }), `${other} before ${stage}`).not.toBeNull();
      }
      s = run(s, { type: 'submit', stage });
      expect(s).toMatchObject({ status: 'submitted', stage, inFlight: true, task: 'steps' });
      record = record ? withAttempt(record, attempts[stage]) : newRecord(baseOf(), attempts[stage]);
      s = run(s, { type: 'recorded', record });
      expect(refusal(s, { type: 'confirm', stage: STAGES.find((x) => x !== stage)!, detail: '' })).not.toBeNull();
      record = withEvidence(record, confirmedEvidence(attempts[stage]));
      s = run(s, { type: 'observed', evidence: confirmedEvidence(attempts[stage]) }, { type: 'recorded', record }, { type: 'confirm', stage, detail: `${stage} ok` });
    }
    expect(s).toMatchObject({ status: 'confirmed', stage: 'verification', inFlight: false, rekeyConfirmed: true, verification: 'passed' });
    expect((s as Operation).results).toEqual({
      funding: 'funding ok',
      proof: 'proof ok',
      rekey: 'rekey ok',
      verification: 'verification ok',
    });
  });

  it('locks from the moment the guard is taken, and refuses a second start', () => {
    const s = run(prepared, { type: 'start', approved: null });
    expect(lockReason(s)).toMatch(/checking the network/);
    for (const e of [{ type: 'start', approved: null }, { type: 'resume', approved: null }, { type: 'prepare', id: 'x', context: (prepared as Operation).context, identity: TARGET }, { type: 'discard' }] as OperationEvent[]) {
      expect(refusal(s, e), e.type).not.toBeNull();
      expect(() => transition(s, e)).toThrow(TransitionError);
    }
  });

  it('a failure before anything was recorded unlocks, and can be retried or replaced', () => {
    const failed = run(prepared, { type: 'start', approved: null }, { type: 'refuse', reason: 'Nothing was sent. no' });
    expect(failed).toMatchObject({ status: 'failed', stage: null, inFlight: false, pinned: null });
    expect(lockReason(failed)).toBeNull();
    expect(refusal(failed, { type: 'start', approved: null })).toBeNull();
    expect(refusal(failed, { type: 'discard' })).toBeNull();
    // A step that stopped before its record was written sent nothing ever.
    const halted = run(prepared, { type: 'start', approved: null }, pinned, { type: 'submit', stage: 'funding' }, { type: 'halt', stage: 'funding', reason: 'no' });
    expect(halted).toMatchObject({ status: 'failed', stage: null, record: null });
    expect(lockReason(halted)).toBeNull();
    // Refusing is only possible during the checks.
    const funding = run(prepared, ...through('funding'));
    expect(refusal(funding, { type: 'refuse', reason: 'x' })).not.toBeNull();
  });

  it.each(STAGES)('an unknown outcome at %s locks everything but a read-only check', (stage) => {
    const s = run(prepared, ...through(stage), { type: 'unknown', stage, reason: 'timed out' });
    expect(s).toMatchObject({ status: 'outcome-unknown', stage, inFlight: false, error: 'timed out' });
    expect(lockReason(s)).toMatch(/unknown/);
    const everything: OperationEvent[] = [
      { type: 'prepare', id: 'x', context: (prepared as Operation).context, identity: OTHER_TARGET },
      { type: 'recover', record: (s as Operation).record!, context: (s as Operation).context },
      { type: 'discard' },
      { type: 'dismiss', acknowledged: true },
      { type: 'start', approved: null },
      { type: 'resume', approved: null },
      { type: 'refuse', reason: 'x' },
      ...STAGES.map((st) => ({ type: 'submit', stage: st }) as const),
      ...STAGES.map((st) => ({ type: 'confirm', stage: st, detail: '' }) as const),
      { type: 'verification-failed', reason: 'x' },
    ];
    for (const e of everything) {
      expect(refusal(s, e), `${e.type} ${'stage' in e ? e.stage : ''}`).not.toBeNull();
    }
    expect(refusal(s, { type: 'reconcile' })).toBeNull();
    expect(continuationOf(s as Operation).next).toBeNull();
    expect((s as Operation).rekeyConfirmed).toBe(stage === 'verification');
  });

  it('keeps the confirmed rekey through every later failure, retry and reading', () => {
    const rekeyed = run(prepared, ...through('verification'));
    expect(rekeyed).toMatchObject({ rekeyConfirmed: true, verification: 'in-flight' });
    // Verification read another authority, and its attempt never landed.
    const before = (rekeyed as Operation).record!;
    const dropped = withEvidence(before, neverLandedEvidence(attempts.verification));
    const failed = run(
      rekeyed,
      { type: 'observed', evidence: neverLandedEvidence(attempts.verification) },
      { type: 'recorded', record: dropped },
      { type: 'verification-failed', reason: 'other authority' },
    );
    expect(failed).toMatchObject({ status: 'failed', stage: 'verification', rekeyConfirmed: true, verification: 'failed' });
    expect(lockReason(failed)).toMatch(/rekey confirmed/);
    // The only thing it allows is verification again: never a fresh start,
    // a new key or another funding or rekey.
    expect(refusal(failed, { type: 'start', approved: null })).not.toBeNull();
    expect(refusal(failed, { type: 'prepare', id: 'x', context: (prepared as Operation).context, identity: OTHER_TARGET })).not.toBeNull();
    expect(refusal(failed, { type: 'discard' })).not.toBeNull();
    expect(refusal(failed, { type: 'dismiss', acknowledged: true })).not.toBeNull();
    expect(continuationOf(failed as Operation)).toMatchObject({ next: 'verification', needsSigner: false, needsIdentity: false });
    const resuming = run(failed, { type: 'resume', approved: null }, pinned);
    for (const st of ['funding', 'proof', 'rekey'] as const) {
      expect(refusal(resuming, { type: 'submit', stage: st })).not.toBeNull();
    }
    const retried = run(resuming, { type: 'submit', stage: 'verification' });
    expect(retried).toMatchObject({ status: 'submitted', rekeyConfirmed: true });
    expect(refusal(retried, { type: 'submit', stage: 'verification' })).not.toBeNull();
    const unknown = run(retried, { type: 'unknown', stage: 'verification', reason: 'lost' });
    expect(unknown).toMatchObject({ status: 'outcome-unknown', rekeyConfirmed: true, verification: 'unknown' });
    expect(refusal(unknown, { type: 'resume', approved: null })).not.toBeNull();
    // A later check that reads less, and another authority, keeps the rekey's history.
    const read = run(unknown, { type: 'reconcile' }, {
      type: 'reconciled',
      record: (unknown as Operation).record!,
      evidence: { [attempts.rekey.txId]: unknownEvidence(attempts.rekey) },
      authority: authorityAt(OTHER_SIGNER.address, 9n),
      conflict: 'changed',
      readOnly: null,
      notice: null,
      error: null,
    }) as Operation;
    expect(read).toMatchObject({ rekeyConfirmed: true, conflict: 'changed' });
    expect(read.evidence[attempts.rekey.txId]!.outcome).toBe('confirmed');
    expect(continuationOf(read).next).toBeNull();
  });

  it('dismisses only a verified migration read this session, with a fresh authority, when acknowledged', () => {
    const verification = recordThrough('verification', confirmedEvidence);
    const done = run(
      prepared,
      ...through('verification'),
      { type: 'observed', evidence: confirmedEvidence(attempts.verification) },
      { type: 'recorded', record: verification },
      { type: 'confirm', stage: 'verification', detail: 'ok' },
    );
    expect(lockReason(done)).toMatch(/written down/);
    // Its authority has not been read this session.
    expect(refusal(done, { type: 'dismiss', acknowledged: true })).toMatch(/authority has not been read/);
    const rekeyRound = confirmedEvidence(attempts.rekey).confirmedRound!;
    // Read before the rekey it has to reflect: stale.
    const stale = run(done, { type: 'observed', authority: authorityAt(TARGET.address, rekeyRound - 1n) });
    expect(refusal(stale, { type: 'dismiss', acknowledged: true })).toMatch(/stale/);
    const elsewhere = run(done, { type: 'observed', authority: authorityAt(OTHER_SIGNER.address, rekeyRound + 5n) });
    expect(refusal(elsewhere, { type: 'dismiss', acknowledged: true })).toMatch(/answers to/);
    const fresh = run(done, { type: 'observed', authority: authorityAt(TARGET.address, rekeyRound + 1n) });
    expect(refusal(fresh, { type: 'dismiss', acknowledged: false })).not.toBeNull();
    expect(refusal(fresh, { type: 'discard' })).not.toBeNull();
    expect(transition(fresh, { type: 'dismiss', acknowledged: true })).toBe(IDLE);
    expect(refusal(prepared, { type: 'dismiss', acknowledged: true })).not.toBeNull();
    // Confirmed in memory, but the record still says the proof is out: not settled.
    const lagging = run(
      prepared,
      ...through('verification'),
      { type: 'observed', evidence: confirmedEvidence(attempts.verification) },
      { type: 'confirm', stage: 'verification', detail: 'ok' },
      { type: 'observed', authority: authorityAt(TARGET.address, rekeyRound + 1n) },
    );
    expect(refusal(lagging, { type: 'dismiss', acknowledged: true })).toMatch(/does not yet say what the ledger shows/);
  });

  it('reports where each step stands, from what was read', () => {
    const s = run(prepared, ...through('rekey'), { type: 'unknown', stage: 'rekey', reason: 'x' }) as Operation;
    expect(STAGES.map((st) => stageState(s, st))).toEqual(['confirmed', 'confirmed', 'unknown', 'not-reached']);
    expect(STAGES.map((st) => stageState(prepared as Operation, st))).toEqual(Array(4).fill('not-reached'));
    // Labels alone show nothing as done.
    const unread = recover(recordThrough('verification', confirmedEvidence));
    expect(STAGES.map((st) => stageState(unread, st))).toEqual(['unknown', 'unknown', 'unknown', 'unknown']);
  });
});

describe('recovering from a record (A-02b-01)', () => {
  it('trusts no label before the ledger is read', () => {
    // Every label says confirmed; nothing has been read.
    const op = recover(recordThrough('verification', confirmedEvidence));
    expect(op).toMatchObject({ origin: 'recovered', identity: null, status: 'outcome-unknown', stage: 'funding', rekeyConfirmed: false, verification: 'not-started' });
    expect(lockReason(op)).toMatch(/unknown/);
    expect(continuationOf(op).blockedBy).toMatch(/has not been read from the ledger in this session/);
    expect(refusal(op, { type: 'dismiss', acknowledged: true })).toMatch(/has not been read/);
  });

  it('takes its position from what the check read', () => {
    const rekeyedRecord = recordThrough('rekey', confirmedEvidence);
    const rekeyed = checked(rekeyedRecord, readings(rekeyedRecord, confirmedEvidence));
    expect(rekeyed).toMatchObject({ status: 'confirmed', stage: 'rekey', rekeyConfirmed: true, verification: 'not-started' });
    expect(continuationOf(rekeyed)).toMatchObject({ next: 'verification', needsIdentity: true, needsSigner: false });
    expect(refusal(rekeyed, { type: 'resume', approved: null })).toMatch(/Restore the new key/);

    const provenRecord = recordThrough('proof', confirmedEvidence);
    expect(continuationOf(checked(provenRecord, readings(provenRecord, confirmedEvidence)))).toMatchObject({ next: 'rekey', needsSigner: true });

    const neverRecord = withEvidence(newRecord(baseOf(), attempts.funding), neverLandedEvidence(attempts.funding));
    const neverFunded = checked(neverRecord, readings(neverRecord, neverLandedEvidence));
    expect(neverFunded).toMatchObject({ status: 'failed', stage: 'funding' });
    expect(continuationOf(neverFunded)).toMatchObject({ next: 'funding', needsSigner: true });

    const doneRecord = recordThrough('verification', confirmedEvidence);
    const done = checked(doneRecord, readings(doneRecord, confirmedEvidence), {
      authority: authorityAt(TARGET.address, confirmedEvidence(attempts.rekey).confirmedRound! + 1n),
    });
    expect(done).toMatchObject({ status: 'confirmed', stage: 'verification', verification: 'passed' });
    expect(refusal(done, { type: 'dismiss', acknowledged: true })).toBeNull();
    expect(positionOf(done.record!).results.verification).toContain(attempts.verification.txId);
  });

  it('a not-included label the ledger contradicts authorizes no replacement', () => {
    // The funding landed; its label was changed to say it never did.
    const tampered = withEvidence(newRecord(baseOf(), attempts.funding), neverLandedEvidence(attempts.funding));
    expect(tampered.attempts[0]!.state).toBe('not-included');
    expect(continuationOf(recover(tampered)).next).toBeNull();
    const read = checked(tampered, readings(tampered, confirmedEvidence));
    // The ledger decides the position; the stale label still blocks until it is saved.
    expect(read).toMatchObject({ status: 'confirmed', stage: 'funding' });
    expect(continuationOf(read).blockedBy).toMatch(/does not yet say what the ledger shows/);
    expect(refusal(read, { type: 'dismiss', acknowledged: true })).not.toBeNull();
    // Once the record says what the ledger shows, the next step is the proof: never a second funding.
    const saved = withEvidence(tampered, confirmedEvidence(attempts.funding));
    expect(saved.attempts[0]!.state).toBe('confirmed');
    expect(continuationOf(checked(saved, readings(saved, confirmedEvidence)))).toMatchObject({ next: 'proof' });
  });

  it('a confirmed label the ledger does not bear out allows nothing', () => {
    const claimed = withEvidence(newRecord(baseOf(), attempts.funding), confirmedEvidence(attempts.funding));
    // Unread, unresolved, or read as never landed: none continues from the claim.
    expect(continuationOf(checked(claimed, {})).next).toBeNull();
    expect(continuationOf(checked(claimed, readings(claimed, unknownEvidence))).blockedBy).toMatch(/unresolved/);
    const never = checked(claimed, readings(claimed, neverLandedEvidence));
    expect(never).toMatchObject({ status: 'failed', stage: 'funding', rekeyConfirmed: false });
    expect(continuationOf(never).blockedBy).toMatch(/does not yet say/);
    // A confirmed rekey label alone is not rekey history.
    const rekeyClaim = recordThrough('rekey', confirmedEvidence);
    expect(recover(rekeyClaim).rekeyConfirmed).toBe(false);
    expect(checked(rekeyClaim, readings(rekeyClaim, unknownEvidence)).rekeyConfirmed).toBe(false);
  });

  it('a partial or failed check leaves it blocked', () => {
    const record = recordThrough('rekey', confirmedEvidence);
    const all = readings(record, confirmedEvidence);
    const missing = { ...all };
    delete missing[attempts.proof.txId];
    expect(continuationOf(checked(record, missing)).blockedBy).toMatch(/has not been read/);
    const failedRead = { ...all, [attempts.proof.txId]: unknownEvidence(attempts.proof) };
    expect(continuationOf(checked(record, failedRead)).blockedBy).toMatch(/unresolved/);
    expect(refusal(checked(record, failedRead), { type: 'dismiss', acknowledged: true })).not.toBeNull();
  });

  it('a check that reports another network or a conflict blocks continuing and dismissing', () => {
    const record = recordThrough('verification', confirmedEvidence);
    const op = checked(record, readings(record, confirmedEvidence), {
      authority: authorityAt(TARGET.address, 99_999n),
      conflict: 'The node now reports elsewhere-v1, not dockernet-v1 as this migration recorded.',
    });
    expect(continuationOf(op).blockedBy).toMatch(/elsewhere-v1/);
    expect(refusal(op, { type: 'dismiss', acknowledged: true })).toMatch(/contradicts/);
  });

  it('two settled readings that disagree are a conflict; a weaker one changes nothing', () => {
    const record = recordThrough('rekey', confirmedEvidence);
    const first = checked(record, readings(record, confirmedEvidence));
    const weaker = run(first, { type: 'observed', evidence: unknownEvidence(attempts.funding) }) as Operation;
    expect(weaker.evidence[attempts.funding.txId]!.outcome).toBe('confirmed');
    expect(weaker.conflict).toBeNull();
    const contrary = run(first, { type: 'observed', evidence: neverLandedEvidence(attempts.funding) }) as Operation;
    expect(contrary.conflict).toMatch(/read as confirmed, and later as not-included/);
    expect(continuationOf(contrary).next).toBeNull();
  });

  it('restores only the key the record names, and only while nothing runs', () => {
    const record = recordThrough('rekey', confirmedEvidence);
    const op = checked(record, readings(record, confirmedEvidence));
    expect(refusal(op, { type: 'restore', identity: OTHER_TARGET })).toMatch(/not the one/);
    const restored = transition(op, { type: 'restore', identity: TARGET }) as Operation;
    expect(restored.identity).toBe(TARGET);
    expect(refusal(restored, { type: 'restore', identity: TARGET })).toMatch(/already/);
    expect(refusal(restored, { type: 'resume', approved: null })).toBeNull();
    const busy = transition(op, { type: 'reconcile' });
    expect(refusal(busy, { type: 'restore', identity: TARGET })).not.toBeNull();
  });

  it('refuses to recover over a locked operation, and a reading from another record', () => {
    const running = run(prepared, { type: 'start', approved: null });
    expect(refusal(running, { type: 'recover', record: recordThrough('funding'), context: (prepared as Operation).context })).not.toBeNull();
    const op = transition(recover(recordThrough('rekey', unknownEvidence)), { type: 'reconcile' });
    const foreign = { ...recordThrough('rekey', unknownEvidence), id: 'op-other' };
    expect(
      refusal(op, { type: 'reconciled', record: foreign, evidence: {}, authority: null, conflict: null, readOnly: null, notice: null, error: null }),
    ).not.toBeNull();
  });
});

describe('network identity', () => {
  it('reads a genesis from bytes or base64, and refuses a missing one', () => {
    expect(genesisOf(TESTNET_GENESIS)).toEqual({ id: 'testnet-v1.0', hash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=' });
    expect(genesisOf({ genesisID: 'x', genesisHash: 'aGFzaA==' })).toEqual({ id: 'x', hash: 'aGFzaA==' });
    expect(() => genesisOf({ genesisID: 'x' })).toThrow(/which network/);
    expect(() => genesisOf({ genesisHash: new Uint8Array(32) })).toThrow(/which network/);
  });

  it('accepts only TestNet as TestNet, and never a public network as LocalNet', () => {
    const [testnet, mainnet, local] = [TESTNET_GENESIS, MAINNET_GENESIS, LOCAL_GENESIS].map(genesisOf);
    expect(genesisRefusal('testnet', testnet!)).toBeNull();
    expect(genesisRefusal('testnet', local!)).toMatch(/not TestNet/);
    expect(genesisRefusal('testnet', { id: 'testnet-v1.0', hash: local!.hash })).toMatch(/not TestNet/);
    expect(genesisRefusal('localnet', local!)).toBeNull();
    for (const g of [mainnet!, testnet!, { id: 'betanet-v1.0', hash: local!.hash }, { id: 'mine', hash: mainnet!.hash }]) {
      expect(genesisRefusal('localnet', g)).toMatch(/public network/);
    }
    expect(genesisRefusal('mainnet', mainnet!)).toMatch(/limited to TestNet and LocalNet/);
  });

  it('pins every transaction built through the clients to one genesis', async () => {
    let answer: object = LOCAL_GENESIS;
    const base = {
      label: 'fake algod',
      getTransactionParams: () => ({ do: async () => ({ ...answer, fee: 0n }) }),
      describe(this: { label: string }) {
        return this.label;
      },
    };
    const clients = { algod: base, network: { name: 'localnet' } } as unknown as FalconerClients;
    const pinnedClients = pinClients(clients, genesis);
    expect(Object.isFrozen(pinnedClients)).toBe(true);
    expect(pinnedClients.network).toBe(clients.network);
    await expect(pinnedClients.algod.getTransactionParams().do()).resolves.toMatchObject({ genesisID: 'dockernet-v1' });
    // Everything else is the original client, with `this` intact.
    expect((pinnedClients.algod as unknown as typeof base).describe()).toBe('fake algod');
    answer = MAINNET_GENESIS;
    await expect(pinnedClients.algod.getTransactionParams().do()).rejects.toThrow(/now reports mainnet-v1.0.*Nothing was signed/);
    answer = { genesisID: 'dockernet-v1', genesisHash: new Uint8Array(32).fill(4) };
    await expect(pinnedClients.algod.getTransactionParams().do()).rejects.toThrow(/Nothing was signed/);
    answer = {};
    await expect(pinnedClients.algod.getTransactionParams().do()).rejects.toThrow(/which network/);
  });
});

describe('the budget an operation may approve (SAFE-03a)', () => {
  const spec = (over: Partial<Parameters<typeof computeBudget>[1]> = {}) => ({
    sender: SIGNER.address,
    authorizer: SIGNER.address,
    target: TARGET.address,
    signer: ED25519_BY_PHRASE,
    ...over,
  });
  const inputs = (over: { balance?: bigint; target?: string } = {}) => ({
    params: { genesis, protocol: V42_PROTOCOL, minFee: 1000n, feePerByte: 0n, round: 1000n, upgrade: null },
    source: { address: SIGNER.address, exists: true, balance: over.balance ?? 10_000_000n, minBalance: 100_000n, authAddr: null, round: 1000n },
    target: { address: over.target ?? TARGET.address, exists: false, balance: 0n, minBalance: 100_000n, authAddr: null, round: 1000n },
  });
  const quoted = (quote: ReturnType<typeof computeBudget>) =>
    run(prepared, { type: 'quote' }, { type: 'quoted', quote, by: 'request' }) as Operation;

  it('reads a quote only while nothing is running, and drops one that arrives after a run began', () => {
    const q = computeBudget(inputs(), spec());
    const reading = run(prepared, { type: 'quote' }) as Operation;
    expect(reading.quoting).toBe(true);
    expect(refusal(reading, { type: 'quote' })).not.toBeNull();
    const started = run(reading, { type: 'start', approved: null }) as Operation;
    expect(started.inFlight).toBe(true);
    // A requested reading that lands mid-run ends the request and shows nothing...
    const late = run(started, { type: 'quoted', quote: q, by: 'request' }) as Operation;
    expect(late).toMatchObject({ quoting: false, quote: null });
    // ...while the run's own reading is shown.
    expect((run(late, pinned, { type: 'quoted', quote: q, by: 'run' }) as Operation).quote).toBe(q);
    // Neither kind lands where none is outstanding.
    expect(refusal(prepared, { type: 'quoted', quote: computeBudget(inputs(), spec()), by: 'request' })).not.toBeNull();
    expect(refusal(prepared, { type: 'quoted', quote: computeBudget(inputs(), spec()), by: 'run' })).not.toBeNull();
  });

  it('binds the approved budget to the run when it starts or continues', () => {
    const quote = computeBudget(inputs(), spec());
    const op = quoted(quote);
    expect(approvalRefusal(op, 'funding')).toBeNull();
    const started = run(op, { type: 'start', approved: quote }) as Operation;
    expect(started.approved).toBe(quote);
  });

  it('refuses to approve a budget that is missing, blocked, unavailable, stale or for another step', () => {
    expect(approvalRefusal(prepared as Operation, 'funding')).toMatch(/not been read/);
    expect(approvalRefusal(quoted(computeBudget(inputs({ balance: 1000n }), spec())), 'funding')).toMatch(/budget is blocked/);
    expect(approvalRefusal(quoted(computeBudget(null, spec())), 'funding')).toMatch(/budget is unavailable/);
    expect(approvalRefusal(quoted(computeBudget(inputs(), spec({ from: 'rekey' }))), 'funding')).toMatch(/starts at "Rekey the account"/);
    expect(approvalRefusal(quoted(computeBudget(inputs({ target: OTHER_TARGET.address }), spec({ target: OTHER_TARGET.address }))), 'funding')).toMatch(/different migration/);
  });

  it('refuses a budget priced for a signer this page cannot sign with', () => {
    const falcon = computeBudget(inputs(), spec({ signer: { supported: true, scheme: 'falcon-1024', basis: 'fixture' } }));
    expect(falcon.status).toBe('available');
    expect(approvalRefusal(quoted(falcon), 'funding')).toMatch(/cannot sign with it/);
  });

  it('asks for a quote from the step a continuation would run', () => {
    expect(quoteFrom(prepared as Operation)).toBe('funding');
    expect(budgetSpecOf((prepared as Operation).context, 'rekey')).toMatchObject({
      sender: SIGNER.address,
      authorizer: SIGNER.address,
      target: TARGET.address,
      from: 'rekey',
      signer: { supported: true, scheme: 'ed25519' },
    });
  });
});
