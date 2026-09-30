/**
 * The migration journal (SAFE-02b): its record format, its storage and its
 * tab lock, directly. Records are built from attempts the real core code
 * prepared against a scripted ledger, so every id in them is genuine.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  VALIDITY_ROUNDS,
  pqIdentityFromMnemonic,
  prepareControlProof,
  prepareAttempt,
  prepareFunding,
  prepareProof,
  prepareRekey,
  type AttemptEvidence,
  type TransactionAttempt,
} from '@falqoner/core';
import { LEDGER_GENESIS, scriptedLedger } from '../../../packages/core/test/scripted-ledger';
import {
  JOURNAL_KEY,
  JournalError,
  MAX_ATTEMPTS,
  browserJournal,
  browserTabLock,
  isResolved,
  newRecord,
  parseRecord,
  serializeRecord,
  stageStatus,
  verifiedView,
  withAttempt,
  withEvidence,
  type MigrationRecord,
} from '../src/journal';
import { fakeLocks, signingFixture } from './fixtures';

const SENDER = signingFixture(31);
const TARGET = pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(32)));
const GENESIS = { id: LEDGER_GENESIS.genesisID, hash: algosdk.bytesToBase64(LEDGER_GENESIS.genesisHash) };

let funding: TransactionAttempt;
/** Another funding attempt, from a later round: a replacement. */
let funding2: TransactionAttempt;
let proof: TransactionAttempt;
let rekey: TransactionAttempt;
let verification: TransactionAttempt;
/** A funding exactly as version 1 wrote it: 0.2 ALGO, and the minimum fee. */
let legacyFunding: TransactionAttempt;
/** A proof priced under a doubled minimum fee: a budgeted fee version 1 never wrote. */
let dearProof: TransactionAttempt;
/** A funding of only what a new address lacks: a budgeted amount version 1 never wrote. */
let budgetedFunding: TransactionAttempt;

beforeAll(async () => {
  const { clients } = scriptedLedger({ round: 4_000_000n, accounts: { [SENDER.address]: {} } });
  legacyFunding = (await prepareFunding(clients, { address: SENDER.address }, TARGET.address, 200_000n)).attempt;
  budgetedFunding = (await prepareFunding(clients, { address: SENDER.address }, TARGET.address, 103_000n)).attempt;
  dearProof = (
    await prepareAttempt(clients, { stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, amount: 0n, fee: 6000n })
  ).attempt;
  funding = (await prepareFunding(clients, { address: SENDER.address }, TARGET.address)).attempt;
  funding2 = (await prepareFunding(scriptedLedger({ round: 4_000_100n, accounts: { [SENDER.address]: {} } }).clients, { address: SENDER.address }, TARGET.address)).attempt;
  proof = (await prepareProof(clients, TARGET.address)).attempt;
  rekey = (await prepareRekey(clients, { address: SENDER.address }, TARGET.address)).attempt;
  verification = (await prepareControlProof(clients, SENDER.address, TARGET.address)).attempt;
});

const base = () => ({
  id: 'op-kx1-abc123',
  network: 'localnet' as const,
  genesis: GENESIS,
  sender: SENDER.address,
  authorizer: SENDER.address,
  target: TARGET.address,
  scan: { assets: '31566704', apps: '' },
});

const confirmed = (a: TransactionAttempt, round = a.firstValid + 1n): AttemptEvidence => ({
  txId: a.txId,
  outcome: 'confirmed',
  confirmedRound: round,
  observedRound: round + 2n,
  source: 'algod-pending',
  nonInclusion: false,
  detail: '',
});
const neverLanded = (a: TransactionAttempt): AttemptEvidence => ({
  txId: a.txId,
  outcome: 'expired',
  confirmedRound: null,
  observedRound: a.lastValid + 1n,
  source: 'algod-block',
  nonInclusion: true,
  detail: '',
});
const unknown = (a: TransactionAttempt): AttemptEvidence => ({
  txId: a.txId,
  outcome: 'unknown',
  confirmedRound: null,
  observedRound: a.firstValid,
  source: 'none',
  nonInclusion: false,
  detail: '',
});

/** A record through every stage, each confirmed. */
function complete(): MigrationRecord {
  let r = newRecord(base(), funding);
  r = withEvidence(r, confirmed(funding));
  for (const a of [proof, rekey, verification]) r = withEvidence(withAttempt(r, a), confirmed(a));
  return r;
}

/** Edit the stored JSON and parse it again. */
function tampered(r: MigrationRecord, edit: (doc: any) => void) {
  const doc = JSON.parse(serializeRecord(r));
  edit(doc);
  return parseRecord(JSON.stringify(doc));
}

describe('version-1 records, from before budgets', () => {
  /** A record exactly as version 1 would have stored it. */
  const legacy = (evidence: (a: TransactionAttempt) => AttemptEvidence = confirmed): MigrationRecord => ({
    ...withEvidence(newRecord(base(), legacyFunding), evidence(legacyFunding)),
    version: 1,
  });

  it('are read with their original amounts, fees and ids, confirmed or unresolved', () => {
    for (const r of [legacy(), legacy(unknown)]) {
      const text = serializeRecord(r);
      expect(JSON.parse(text).version).toBe(1);
      const parsed = parseRecord(text);
      expect(parsed.ok).toBe(true);
      const record = (parsed as { record: MigrationRecord }).record;
      expect(record.version).toBe(1);
      expect(record.attempts[0]).toMatchObject({ amount: 200_000n, fee: 1000n, txId: legacyFunding.txId, state: r.attempts[0]!.state });
    }
  });

  it('are held to exactly what version 1 wrote', () => {
    // A budgeted amount, or a budgeted fee, is not a version-1 one.
    const budgeted = { ...newRecord(base(), budgetedFunding), version: 1 } as MigrationRecord;
    expect(parseRecord(serializeRecord(budgeted))).toMatchObject({ ok: false, reason: /amount is not what its stage sends/ });
    const dear = { ...withAttempt(legacy(), dearProof), version: 1 } as MigrationRecord;
    expect(parseRecord(serializeRecord(dear))).toMatchObject({ ok: false, reason: /fee is not what its stage sends/ });
  });

  it('keep version 1 when a reading is saved, and become version 2 only when a budgeted attempt is appended', () => {
    const r = legacy(unknown);
    const read = withEvidence(r, confirmed(legacyFunding));
    expect(read.version).toBe(1);
    expect(parseRecord(serializeRecord(read))).toEqual({ ok: true, record: read });
    const next = withAttempt(read, proof);
    expect(next.version).toBe(2);
    // The version-1 attempt is carried over untouched, and still reads back.
    expect(next.attempts[0]).toEqual(read.attempts[0]);
    expect(parseRecord(serializeRecord(next))).toEqual({ ok: true, record: next });
  });
});

describe('the record format', () => {
  it('round-trips exactly, integers included', () => {
    const r = complete();
    const parsed = parseRecord(serializeRecord(r));
    expect(parsed).toEqual({ ok: true, record: r });
    const text = serializeRecord(r);
    expect(text).toContain(`"firstValid":"${funding.firstValid}"`);
    expect(text).not.toMatch(/"(amount|fee|firstValid|lastValid|confirmedRound|checkedRound)":\d/);
  });

  it('writes only the allowlisted public fields, whatever else the object carries', () => {
    const leaky = {
      ...base(),
      identity: TARGET,
      mnemonic: TARGET.mnemonic,
      signingPhrase: SENDER.phrase,
      clients: { network: { algodUrl: 'https://secret.example/?token=abc', algodToken: 'tok' } },
    };
    const r = newRecord(leaky as unknown as ReturnType<typeof base>, { ...funding, signed: new Uint8Array([9, 9]) } as TransactionAttempt);
    const text = serializeRecord(r);
    const doc = JSON.parse(text);
    expect(Object.keys(doc).sort()).toEqual(
      ['attempts', 'authorizer', 'format', 'genesis', 'id', 'network', 'revision', 'scan', 'sender', 'target', 'version'].sort(),
    );
    expect(Object.keys(doc.attempts[0]).sort()).toEqual(
      ['amount', 'authorizer', 'checkedRound', 'confirmedRound', 'fee', 'firstValid', 'genesisHash', 'genesisId', 'lastValid', 'receiver', 'rekeyTo', 'sender', 'source', 'stage', 'state', 'txId'].sort(),
    );
    for (const secret of [...TARGET.mnemonic!.split(' ').slice(0, 3), 'secret.example', 'tok', 'signed', 'privateKey']) {
      expect(text).not.toContain(secret);
    }
    const w = SENDER.phrase.split(' ');
    for (let i = 0; i + 1 < w.length; i++) expect(text).not.toContain(`${w[i]} ${w[i + 1]}`);
  });

  const invalid: Array<[string, (doc: any) => void, RegExp]> = [
    ['an unknown top-level field', (d) => (d.mnemonic = 'x'), /unexpected or missing/],
    ['a missing field', (d) => delete d.scan, /unexpected or missing/],
    ['an unknown attempt field', (d) => (d.attempts[0].signedBytes = 'AAAA'), /unexpected or missing/],
    ['an unsupported version', (d) => (d.version = 3), /version 3 is not supported/],
    ['another format', (d) => (d.format = 'other'), /not a Falconer/],
    ['an integer as a number', (d) => (d.attempts[0].fee = 1000), /not an exact integer/],
    ['an integer with a leading zero', (d) => (d.attempts[0].fee = '01000'), /not an exact integer/],
    ['a negative integer', (d) => (d.attempts[0].amount = '-1'), /not an exact integer/],
    ['an integer past u64', (d) => (d.attempts[0].lastValid = '18446744073709551616'), /out of range/],
    ['MainNet', (d) => (d.network = 'mainnet'), /not one of testnet, localnet/],
    ['a public genesis behind LocalNet', (d) => (d.genesis.id = 'mainnet-v1.0'), /network is refused/],
    ['TestNet with another genesis', (d) => (d.network = 'testnet'), /network is refused/],
    ['an amount on a step that sends none', (d) => (d.attempts[1].amount = '1'), /amount is not what its stage sends/],
    // A budgeted funding may send any amount, but not one its id was not derived from.
    ['a tampered funding amount', (d) => (d.attempts[0].amount = '300000'), /does not match its fields/],
    ['a zero fee', (d) => (d.attempts[0].fee = '0'), /fee is out of range/],
    ['a fee past the ceiling', (d) => (d.attempts[0].fee = '1000001'), /fee is out of range/],
    ['a tampered window', (d) => (d.attempts[0].lastValid = String(BigInt(d.attempts[0].lastValid) - 1n)), /does not match its fields/],
    ['a tampered id', (d) => (d.attempts[0].txId = 'A'.repeat(52)), /does not match its fields/],
    ['an attempt for another network', (d) => (d.attempts[0].genesisId = 'other-v1'), /another network/],
    ['a funding to someone else', (d) => (d.target = SENDER.address), /not a post-quantum address/],
    ['a window wider than allowed', (d) => (d.attempts[0].lastValid = String(BigInt(d.attempts[0].firstValid) + VALIDITY_ROUNDS + 1n)), /invalid validity window|does not match/],
    ['a confirmation outside the window', (d) => (d.attempts[0].confirmedRound = String(BigInt(d.attempts[0].lastValid) + 1n)), /outside its validity window/],
    ['a confirmed round without confirmation', (d) => (d.attempts[0].state = 'unknown'), /only if it is confirmed/],
    ['a stage out of order', (d) => d.attempts.reverse(), /earlier stage|before \w+ confirmed|skips|first attempt/],
    ['a stage skipped', (d) => d.attempts.splice(1, 1), /before proof confirmed|skips/],
    ['an unknown state', (d) => (d.attempts[1].state = 'maybe'), /not one of/],
    ['a revision that is not a positive integer', (d) => (d.revision = 0), /revision/],
  ];

  it.each(invalid)('refuses %s', (_, edit, why) => {
    const parsed = tampered(complete(), edit);
    expect(parsed.ok).toBe(false);
    expect((parsed as { reason: string }).reason).toMatch(why);
  });

  it('writes new records as version 2, with budgeted amounts and fees', () => {
    const r = complete();
    expect(r.version).toBe(2);
    expect(JSON.parse(serializeRecord(r)).version).toBe(2);
    expect(r.attempts[0]).toMatchObject({ amount: funding.amount, fee: funding.fee });
    const dear = withAttempt(withEvidence(newRecord(base(), funding), confirmed(funding)), dearProof);
    expect(parseRecord(serializeRecord(dear))).toEqual({ ok: true, record: dear });
  });

  it('accepts a replacement only after the replaced attempt was shown never to have landed', () => {
    const early = withAttempt(withEvidence(newRecord(base(), funding), unknown(funding)), funding2);
    expect(parseRecord(serializeRecord(early))).toMatchObject({ ok: false, reason: /replaced before it was shown never to have landed/ });
    const settled = withAttempt(withEvidence(newRecord(base(), funding), neverLanded(funding)), funding2);
    expect(parseRecord(serializeRecord(settled))).toEqual({ ok: true, record: settled });
  });

  it('refuses an attempt recorded twice', () => {
    const r = withEvidence(newRecord(base(), funding), neverLanded(funding));
    const parsed = tampered(r, (d) => d.attempts.push({ ...d.attempts[0] }));
    expect(parsed).toMatchObject({ ok: false, reason: /repeats an id/ });
  });

  it('refuses what is not a record at all', () => {
    expect(parseRecord('not json')).toMatchObject({ ok: false, reason: /not JSON/ });
    expect(parseRecord('[]')).toMatchObject({ ok: false, reason: /not an object/ });
    expect(parseRecord('x'.repeat(70_000))).toMatchObject({ ok: false, reason: /too large/ });
    const r = complete();
    const many = JSON.parse(serializeRecord(r));
    many.attempts = Array.from({ length: MAX_ATTEMPTS + 1 }, () => many.attempts[0]);
    expect(parseRecord(JSON.stringify(many))).toMatchObject({ ok: false, reason: /too long/ });
  });
});

describe('what a record says', () => {
  it('makes no new revision for a reading that says what is already recorded', () => {
    const r = withEvidence(newRecord(base(), funding), unknown(funding));
    expect(r.revision).toBe(2);
    expect(withEvidence(r, unknown(funding))).toBe(r);
    expect(withEvidence(r, { ...unknown(funding), observedRound: funding.firstValid + 1n }).revision).toBe(3);
  });

  it('a weaker reading changes no settled label; a settling reading corrects one (A-02b-01)', () => {
    let r = withEvidence(newRecord(base(), funding), confirmed(funding));
    expect(withEvidence(r, unknown(funding))).toBe(r);
    r = withAttempt(r, proof);
    r = withEvidence(r, neverLanded(proof));
    expect(r.attempts[1]!.state).toBe('not-included');
    // A label is a claim: the ledger read as confirmed replaces it.
    const corrected = withEvidence(r, confirmed(proof));
    expect(corrected.attempts[1]).toMatchObject({ state: 'confirmed', confirmedRound: proof.firstValid + 1n, source: 'algod-pending' });
    expect(corrected.revision).toBe(r.revision + 1);
    // And a confirmed label the ledger reads as never landed is corrected too.
    const claimed = withEvidence(newRecord(base(), funding), confirmed(funding));
    expect(withEvidence(claimed, neverLanded(funding)).attempts[0]!.state).toBe('not-included');
  });

  it('shows the record as this session read it, never its labels', () => {
    const r = withEvidence(newRecord(base(), funding), confirmed(funding));
    expect(verifiedView(r, {}).attempts[0]).toMatchObject({ state: 'unknown', confirmedRound: null, source: 'none' });
    expect(verifiedView(r, { [funding.txId]: neverLanded(funding) }).attempts[0]!.state).toBe('not-included');
    expect(verifiedView(r, { [funding.txId]: confirmed(funding) }).attempts[0]!.state).toBe('confirmed');
    // The view is never what gets saved.
    expect(r.attempts[0]!.state).toBe('confirmed');
  });

  it('reads each stage, and resolves only when nothing is unresolved and the rekey is verified or never landed', () => {
    let r = newRecord(base(), funding);
    expect(stageStatus(r, 'funding')).toBe('unresolved');
    expect(isResolved(r)).toBe(false);
    r = withEvidence(r, neverLanded(funding));
    expect(stageStatus(r, 'funding')).toBe('not-included');
    expect(isResolved(r)).toBe(true);

    const done = complete();
    expect(['funding', 'proof', 'rekey', 'verification'].map((s) => stageStatus(done, s as never))).toEqual([
      'confirmed', 'confirmed', 'confirmed', 'confirmed',
    ]);
    expect(isResolved(done)).toBe(true);

    // Rekeyed but not verified: never resolved.
    let rekeyed = withEvidence(newRecord(base(), funding), confirmed(funding));
    rekeyed = withEvidence(withAttempt(rekeyed, proof), confirmed(proof));
    rekeyed = withEvidence(withAttempt(rekeyed, rekey), confirmed(rekey));
    expect(stageStatus(rekeyed, 'verification')).toBe('not-started');
    expect(isResolved(rekeyed)).toBe(false);
  });
});

/** A Storage stand-in whose faults a test sets. */
function memoryStorage() {
  const map = new Map<string, string>();
  const faults = { get: false, set: false, dropWrites: false };
  return {
    map,
    faults,
    storage: {
      getItem: (k: string) => {
        if (faults.get) throw Object.assign(new Error('denied'), { name: 'SecurityError' });
        return map.get(k) ?? null;
      },
      setItem: (k: string, v: string) => {
        if (faults.set) throw Object.assign(new Error('full'), { name: 'QuotaExceededError' });
        if (!faults.dropWrites) map.set(k, v);
      },
      removeItem: (k: string) => void map.delete(k),
    },
  };
}

describe('storage', () => {
  it('creates a record only where none is stored, and advances it only from what is stored', () => {
    const m = memoryStorage();
    const j = browserJournal(() => m.storage);
    expect(j.read()).toEqual({ kind: 'empty' });
    const r1 = newRecord(base(), funding);
    j.write(r1, null);
    expect(j.read()).toEqual({ kind: 'record', record: r1 });
    expect(() => j.write(r1, null)).toThrow(/changed elsewhere/);

    const r2 = withEvidence(r1, confirmed(funding));
    j.write(r2, r1);
    // Another tab advanced it: a write from the older copy is refused.
    expect(() => j.write(withEvidence(r1, neverLanded(funding)), r1)).toThrow(/changed elsewhere/);
    expect(() => j.write({ ...r2, revision: r2.revision + 5 }, r2)).toThrow(/does not follow/);
    expect(j.read()).toEqual({ kind: 'record', record: r2 });
  });

  it('fails a write that throws or does not read back, and leaves the stored record as it was', () => {
    const m = memoryStorage();
    const j = browserJournal(() => m.storage);
    const r1 = newRecord(base(), funding);
    m.faults.set = true;
    expect(() => j.write(r1, null)).toThrow(JournalError);
    expect(m.map.size).toBe(0);
    m.faults.set = false;
    m.faults.dropWrites = true;
    expect(() => j.write(r1, null)).toThrow(/did not read back/);
    m.faults.dropWrites = false;
    j.write(r1, null);
    m.faults.set = true;
    expect(() => j.write(withEvidence(r1, confirmed(funding)), r1)).toThrow(JournalError);
    expect(m.map.get(JOURNAL_KEY)).toBe(serializeRecord(r1));
  });

  it('reports unreadable storage and invalid records, and never overwrites or removes an invalid record', () => {
    const m = memoryStorage();
    const j = browserJournal(() => m.storage);
    m.faults.get = true;
    expect(j.read()).toMatchObject({ kind: 'unavailable', reason: /SecurityError/ });
    m.faults.get = false;
    m.map.set(JOURNAL_KEY, '{"format":"falconer-migration-journal","version":9}');
    expect(j.read()).toMatchObject({ kind: 'invalid' });
    expect(() => j.write(newRecord(base(), funding), null)).toThrow(/changed elsewhere/);
    expect(() => j.remove(newRecord(base(), funding))).toThrow(/not the one shown/);
    expect(m.map.get(JOURNAL_KEY)).toContain('"version":9');
    expect(browserJournal(() => null).read()).toMatchObject({ kind: 'unavailable' });
    expect(
      browserJournal(() => {
        throw new Error('blocked');
      }).read(),
    ).toMatchObject({ kind: 'unavailable' });
  });

  it('removes only the exact record it was given', () => {
    const m = memoryStorage();
    const j = browserJournal(() => m.storage);
    const r = complete();
    m.map.set(JOURNAL_KEY, serializeRecord(r));
    expect(() => j.remove(newRecord(base(), funding))).toThrow(/not the one shown/);
    j.remove(r);
    expect(j.read()).toEqual({ kind: 'empty' });
  });
});

describe('one tab at a time', () => {
  it('gives the lock to one tab, and to the next only once it is released', async () => {
    const locks = fakeLocks();
    const a = browserTabLock(() => locks.manager);
    const b = browserTabLock(() => locks.manager);
    expect(await a.acquire()).toBe(true);
    expect(await a.acquire()).toBe(true);
    expect(await b.acquire()).toBe(false);
    a.release();
    await new Promise((r) => setTimeout(r, 0));
    expect(await b.acquire()).toBe(true);
    expect(b.held()).toBe(true);
  });

  it('fails closed without Web Locks, or when the request fails or never answers', async () => {
    expect(await browserTabLock(() => undefined).acquire()).toBe(false);
    expect(
      await browserTabLock(() => ({ request: () => Promise.reject(new Error('SecurityError')) })).acquire(),
    ).toBe(false);
    let grant!: () => void;
    const slow = browserTabLock(
      () => ({
        request: (_n: string, _o: unknown, cb: (lock: unknown) => unknown) =>
          new Promise((r) => (grant = () => r(cb({})))),
      }),
      20,
    );
    expect(await slow.acquire()).toBe(false);
    grant();
    await new Promise((r) => setTimeout(r, 0));
    // A lock granted after giving up is not kept.
    expect(slow.held()).toBe(false);
  });
});
