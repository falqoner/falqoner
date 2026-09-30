/**
 * The guarded ceremony (SAFE-03b), called directly, against a scripted ledger.
 *
 * Each attack is paired with a valid control: the same ceremony, once the
 * condition is put right, goes on. Every transaction is built, signed and
 * sent by the real core code with real keys from fixed public seeds, and the
 * ledger checks each send as algod would, so "nothing was sent" is read from
 * the ledger, not from the ceremony's own answer.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  ED25519_BY_PHRASE,
  VALIDITY_ROUNDS,
  genesisRefusal,
  openCeremony,
  pqIdentityFromMnemonic,
  prepareAttempt,
  prepareProof,
  quoteMigration,
  sendAttempt,
  signAttempt,
  type Ceremony,
  type CeremonyTiming,
  type SignerSupport,
  type SubmissionStage,
  type TransactionAttempt,
} from '../src/index.js';
import { LEDGER_PROTOCOL, scriptedLedger, type ScriptedLedger } from './scripted-ledger.js';

const phraseAccount = (fill: number) => {
  const phrase = algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill));
  return { phrase, address: algosdk.mnemonicToSecretKey(phrase).addr.toString() };
};
const falconKey = (fill: number) => pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill)));

const SIGNER = phraseAccount(71);
const OTHER = phraseAccount(72);
const KEY = falconKey(81);
const OTHER_KEY = falconKey(82);
const TIMING: CeremonyTiming = { requestMs: 2000, confirmMs: 300, pollMs: 5, reconcileMs: 5000 };

/** Which stage a signed transaction is, from its shape. */
function stageOfSigned(s: algosdk.SignedTransaction): SubmissionStage {
  const t = s.txn;
  if (t.rekeyTo) return 'rekey';
  if (t.sender.toString() !== t.payment?.receiver.toString()) return 'funding';
  return s.sgnr ? 'verification' : 'proof';
}
const stageOf = (bytes: unknown) => stageOfSigned(algosdk.decodeSignedTransaction(bytes as Uint8Array));
/** The stages that reached the ledger, in order. */
const sendsOf = (ledger: ScriptedLedger) => ledger.landed.map(stageOfSigned);

interface World {
  ledger: ScriptedLedger;
  ceremony: Ceremony;
  /** What the caller recorded before each send: a stand-in for the page's journal. */
  journal: TransactionAttempt[];
  run(stage: SubmissionStage, over?: { approved?: unknown; signingPhrase?: string; record?: (a: TransactionAttempt) => void }): ReturnType<Ceremony['run']>;
  approve(from?: SubmissionStage, signer?: SignerSupport): Promise<void>;
}

/** A ceremony on a fresh ledger, its key admitted and its network pinned. */
async function world({
  authorizer = SIGNER.address,
  admit = true,
  pin = true,
  ledger = scriptedLedger({ accounts: { [SIGNER.address]: {} } }),
}: { authorizer?: string; admit?: boolean; pin?: boolean; ledger?: ScriptedLedger } = {}): Promise<World> {
  const ceremony = openCeremony(ledger.clients, { network: 'localnet', sender: SIGNER.address, authorizer, target: KEY.address });
  if (admit) expect(ceremony.admitKey(KEY, KEY.mnemonic!)).toBeNull();
  if (pin) expect(await ceremony.pin(TIMING)).toMatchObject({ genesis: { id: 'scripted-v1' } });
  const journal: TransactionAttempt[] = [];
  let approved: unknown = null;
  const w: World = {
    ledger,
    ceremony,
    journal,
    run: (stage, over = {}) =>
      ceremony.run(stage, {
        approved: ('approved' in over ? over.approved : approved) as never,
        signingPhrase: over.signingPhrase ?? SIGNER.phrase,
        record: over.record ?? ((a) => void journal.push(a)),
        timing: TIMING,
      }),
    async approve(from = 'funding', signer = ED25519_BY_PHRASE) {
      approved = await quoteMigration(ledger.clients, { sender: SIGNER.address, authorizer, target: KEY.address, signer, from });
      expect((approved as { status: string }).status).toBe('available');
    },
  };
  await w.approve();
  return w;
}

/** Run `stages` in order, each of which must confirm. */
async function confirmAll(w: World, ...stages: SubmissionStage[]) {
  for (const stage of stages) {
    const r = await w.run(stage);
    expect(r, `${stage}: ${r.sent ? '' : r.reason}`).toMatchObject({ sent: true, evidence: { outcome: 'confirmed' } });
  }
}

describe('a ceremony that runs', () => {
  it('sends the four stages once each, in order, and then nothing more', async () => {
    const w = await world();
    expect(w.ceremony.next()).toEqual({ stage: 'funding', blockedBy: null });
    await confirmAll(w, 'funding', 'proof', 'rekey', 'verification');
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof', 'rekey', 'verification']);
    expect(w.ledger.authority(SIGNER.address)).toBe(KEY.address);
    expect(w.journal.map((a) => a.stage)).toEqual(['funding', 'proof', 'rekey', 'verification']);
    expect(w.ceremony.next()).toMatchObject({ stage: null, blockedBy: 'Every stage has confirmed.' });
    // Nothing is sent again, whichever stage is asked for.
    for (const stage of ['funding', 'proof', 'rekey', 'verification'] as const) {
      expect(await w.run(stage)).toMatchObject({ sent: false });
    }
    expect(w.ledger.count('send')).toBe(4);
  });
});

describe('stages run only in order', () => {
  it('refuses a skipped or reordered stage, and runs each once its turn comes', async () => {
    const w = await world();
    for (const stage of ['proof', 'rekey', 'verification'] as const) {
      expect(await w.run(stage)).toMatchObject({ sent: false, reason: expect.stringMatching(/cannot run now: .* at "funding"/) });
    }
    await confirmAll(w, 'funding');
    expect(await w.run('rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/at "proof"/) });
    expect(await w.run('funding')).toMatchObject({ sent: false });
    await confirmAll(w, 'proof', 'rekey', 'verification');
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof', 'rekey', 'verification']);
  });

  it('never sends a rekey for a proof that did not confirm, whatever the caller adds', async () => {
    const w = await world();
    await confirmAll(w, 'funding');
    // The proof never reaches the ledger.
    w.ledger.fail('send', 'lose-request', (_id, bytes) => stageOf(bytes) === 'proof');
    expect(await w.run('proof')).toMatchObject({ sent: true, evidence: { outcome: 'unknown' } });
    // An extra "it worked" flag is not an input the ceremony reads.
    const forged = { proofConfirmed: true, transcriptionConfirmed: true, evidence: { outcome: 'confirmed' } };
    expect(await w.ceremony.run('rekey', { ...forged, approved: null, record: () => undefined } as never)).toMatchObject({ sent: false });
    expect(await w.run('rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/not settled by the ledger/) });
    // The evidence it hands out is a copy: changing it changes nothing.
    const copy = w.ceremony.evidence() as Record<string, { outcome: string }>;
    expect(() => {
      copy[w.journal[1]!.txId] = { outcome: 'confirmed' };
    }).toThrow();
    expect(sendsOf(w.ledger)).toEqual(['funding']);
    // Once its window has passed and every round was read, it is replaced.
    w.ledger.advance(VALIDITY_ROUNDS + 2n);
    await w.ceremony.reconcile({ timing: TIMING });
    expect(w.ceremony.next()).toEqual({ stage: 'proof', blockedBy: null });
    await w.approve('proof');
    await confirmAll(w, 'proof', 'rekey', 'verification');
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof', 'rekey', 'verification']);
  });
});

describe('what the ceremony is given to recover from', () => {
  async function recorded() {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    return w;
  }
  const reopen = (w: World, attempts: readonly TransactionAttempt[]) =>
    openCeremony(w.ledger.clients, {
      network: 'localnet',
      sender: SIGNER.address,
      authorizer: SIGNER.address,
      target: KEY.address,
      genesis: w.ceremony.genesis()!,
      attempts,
    });

  it('takes no stored label or round as evidence: only its own reading of the ledger', async () => {
    const w = await recorded();
    // As a journal holds them, with labels claiming both confirmed.
    const labelled = w.journal.map((a) => ({ ...a, state: 'confirmed', confirmedRound: a.firstValid }));
    const c = reopen(w, labelled);
    expect(c.next()).toMatchObject({ stage: null, blockedBy: expect.stringMatching(/not settled by the ledger/) });
    expect(c.attempts().every((a) => !('state' in a) && !('confirmedRound' in a))).toBe(true);
    await c.reconcile({ timing: TIMING });
    expect(c.next()).toEqual({ stage: 'rekey', blockedBy: null });
  });

  it('refuses a proof for another target, another network, or with an id its fields do not make', async () => {
    const w = await recorded();
    const [funding, proof] = w.journal as [TransactionAttempt, TransactionAttempt];
    const otherTarget = (await prepareProof(w.ledger.clients, OTHER_KEY.address)).attempt;
    const elsewhere = scriptedLedger({ genesis: { genesisID: 'elsewhere-v1', genesisHash: new Uint8Array(32).fill(9) } });
    const otherNetwork = (await prepareProof(elsewhere.clients, KEY.address)).attempt;
    const cases: Array<[TransactionAttempt, RegExp]> = [
      [otherTarget, /not the transaction its stage sends/],
      [otherNetwork, /built for another network/],
      [{ ...proof, firstValid: proof.firstValid + 1n }, /not the id of the transaction its fields describe/],
      [{ ...proof, amount: 1n }, /amount its stage never sends/],
    ];
    for (const [bad, why] of cases) {
      expect(() => reopen(w, [funding, bad])).toThrow(why);
      const c = reopen(w, [funding]);
      expect(c.include([funding, bad])).toMatch(why);
      expect(c.attempts()).toHaveLength(1);
    }
    // What it already holds must be where a longer list starts.
    const c = reopen(w, [funding, proof]);
    expect(c.include([proof])).toMatch(/not the ones this migration sent/);
    expect(c.include([funding, proof])).toBeNull();
    // The real attempts, read from the ledger, go on.
    await c.reconcile({ timing: TIMING });
    expect(c.next()).toEqual({ stage: 'rekey', blockedBy: null });
  });

  it('after a lost rekey response and a reload, settles it from the ledger and verifies without a second rekey', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    w.ledger.fail('send', 'lose-response', (_id, bytes) => stageOf(bytes) === 'rekey');
    w.ledger.failTimes('pending', 'not-found', 1000);
    w.ledger.setIndexerLag(1000n);
    expect(await w.run('rekey')).toMatchObject({ sent: true, send: { status: 'unknown' }, evidence: { outcome: 'unknown' } });
    expect(w.ceremony.next()).toMatchObject({ stage: null, blockedBy: expect.stringMatching(/not settled/) });
    for (const stage of ['rekey', 'verification'] as const) expect(await w.run(stage)).toMatchObject({ sent: false });

    // The page reloads: a new ceremony from what was recorded, with no key.
    w.ledger.clearFaults();
    const c = reopen(w, w.journal);
    expect(c.hasKey()).toBe(false);
    await c.reconcile({ timing: TIMING });
    expect(c.next()).toEqual({ stage: 'verification', blockedBy: null });
    expect(await c.pin(TIMING)).toMatchObject({ genesis: w.ceremony.genesis() });
    const approved = await quoteMigration(w.ledger.clients, { sender: SIGNER.address, authorizer: SIGNER.address, target: KEY.address, signer: ED25519_BY_PHRASE, from: 'verification' });
    const run = () => c.run('verification', { approved, record: () => undefined, timing: TIMING });
    expect(await run()).toMatchObject({ sent: false, reason: expect.stringMatching(/key has not been admitted/) });
    expect(c.admitKey(KEY, OTHER_KEY.mnemonic!)).toMatch(/does not re-derive/);
    expect(c.admitKey(KEY, KEY.mnemonic!)).toBeNull();
    expect(await run()).toMatchObject({ sent: true, evidence: { outcome: 'confirmed' } });
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof', 'rekey', 'verification']);
  });

  it('refuses to go on when the node now reports another network', async () => {
    const w = await recorded();
    const c = reopen(w, w.journal);
    await c.reconcile({ timing: TIMING });
    w.ledger.setGenesis({ genesisID: 'elsewhere-v1', genesisHash: new Uint8Array(32).fill(9) });
    expect(await c.pin(TIMING)).toEqual({ refused: expect.stringMatching(/reports elsewhere-v1, not scripted-v1 as when this migration started/) });
    expect(c.admitKey(KEY, KEY.mnemonic!)).toBeNull();
    expect(await c.run('rekey', { approved: null, signingPhrase: SIGNER.phrase, record: () => undefined })).toMatchObject({
      sent: false,
      reason: expect.stringMatching(/network has not been established/),
    });
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof']);
  });
});

describe('a proof counts only with the target’s own Falcon signature on the ledger', () => {
  const reopen = (w: World, attempts: readonly TransactionAttempt[]) => {
    const c = openCeremony(w.ledger.clients, {
      network: 'localnet', sender: SIGNER.address, authorizer: SIGNER.address, target: KEY.address,
      genesis: w.ceremony.genesis()!, attempts,
    });
    expect(c.admitKey(KEY, KEY.mnemonic!)).toBeNull();
    return c;
  };
  const rekey = async (w: World, c: Ceremony) => {
    await c.pin(TIMING);
    const approved = await quoteMigration(w.ledger.clients, { sender: SIGNER.address, authorizer: SIGNER.address, target: KEY.address, signer: ED25519_BY_PHRASE, from: 'rekey' });
    return c.run('rekey', { approved, signingPhrase: SIGNER.phrase, record: () => undefined, timing: TIMING });
  };
  const rekeys = (w: World) => w.ledger.sends((t) => t.rekeyTo !== undefined).length;
  /** The node's lookup of `txId` answers 404 `times` times, so only the block or the indexer can say. */
  const hideLookup = (w: World, txId: string, times = 2) => {
    for (let i = 0; i < times; i++) w.ledger.fail('pending', 'not-found', (id) => id === txId);
  };

  it.each(['node', 'indexer'])(
    'refuses an Ed25519-signed payment recorded as the proof, read from the %s; a real proof goes on',
    async (source) => {
      const w = await world();
      await confirmAll(w, 'funding');
      // Injected history: the target answers to the signing key for one payment, then to itself again.
      w.ledger.setAuthority(KEY.address, SIGNER.address);
      const prepared = await prepareAttempt(w.ledger.clients, {
        stage: 'proof', sender: KEY.address, authorizer: SIGNER.address, receiver: KEY.address, amount: 0n, fee: 3000n,
      });
      const ed25519 = algosdk.makeBasicAccountTransactionSigner(algosdk.mnemonicToSecretKey(SIGNER.phrase));
      expect(await sendAttempt(w.ledger.clients, prepared, await signAttempt(prepared, ed25519))).toEqual({ status: 'accepted' });
      w.ledger.setAuthority(KEY.address, undefined);
      // The id does not cover who signed: relabelled, it is exactly the id a proof with these fields has.
      const claimed = { ...prepared.attempt, authorizer: KEY.address };
      if (source === 'indexer') hideLookup(w, claimed.txId);
      const c = reopen(w, [w.journal[0]!, claimed]);
      await c.reconcile({ timing: TIMING });
      expect(c.evidence()[claimed.txId]).toMatchObject({
        outcome: 'conflict',
        confirmedRound: null,
        detail: expect.stringMatching(new RegExp(`signed by ${SIGNER.address} with an Ed25519 signature`)),
      });
      expect(c.next()).toMatchObject({ stage: null });
      expect(await rekey(w, c)).toMatchObject({ sent: false });
      expect(rekeys(w)).toBe(0);
      expect(w.ledger.authority(SIGNER.address)).toBe(SIGNER.address);

      // The control: the new key's own proof, read from the same source, lets the rekey go.
      // The payment spent the fee the funding sent; it is replaced as a transfer from outside would.
      w.ledger.setBalance(KEY.address, w.ledger.balance(KEY.address) + 3000n);
      await w.approve('proof');
      await confirmAll(w, 'proof');
      const proof = w.journal[1]!;
      if (source === 'indexer') hideLookup(w, proof.txId);
      const d = reopen(w, w.journal);
      await d.reconcile({ timing: TIMING });
      expect(d.evidence()[proof.txId]).toMatchObject({ outcome: 'confirmed', source: source === 'node' ? 'algod-pending' : 'indexer' });
      expect(await rekey(w, d)).toMatchObject({ sent: true, evidence: { outcome: 'confirmed' } });
      expect(rekeys(w)).toBe(1);
    },
  );

  it('keeps the rekey blocked while the proof’s signature cannot be read or does not verify, and goes on once it does', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    const proof = w.journal[1]!;
    const hints = { [proof.txId]: w.ledger.confirmedRound(proof.txId)! };
    const indexed = (await w.ledger.clients.indexer!.lookupTransactionByID(proof.txId).do()) as unknown as {
      transaction: { signature: { pqsig: { signature: Uint8Array } } };
    };
    const pqsig = indexed.transaction.signature.pqsig;
    const flipped = pqsig.signature.slice();
    flipped[40]! ^= 1;
    const signedWith = (signature: object) => ({ answer: { ...indexed, transaction: { ...indexed.transaction, signature } } });
    const c = reopen(w, w.journal);
    const cases: Array<[Parameters<ScriptedLedger['fail']>[1], string, RegExp]> = [
      ['server-error', 'unknown', /neither the node nor the indexer showed how it was signed/],
      [signedWith({ pqsig: { ...pqsig, signature: flipped } }), 'conflict', /signature does not verify over it/],
      [signedWith({ pqsig: { ...pqsig, publicKey: OTHER_KEY.publicKey } }), 'conflict', /key does not derive .* \(address-mismatch\)/],
      [signedWith({}), 'conflict', /with no signature/],
    ];
    for (const [fault, outcome, why] of cases) {
      // The block shows the proof confirmed; only the indexer can say how it was signed.
      hideLookup(w, proof.txId);
      w.ledger.fail('indexer', fault, (id) => id === proof.txId);
      await c.reconcile({ hints, timing: TIMING });
      expect(c.evidence()[proof.txId], String(why)).toMatchObject({ outcome, detail: expect.stringMatching(why) });
      expect(c.next()).toMatchObject({ stage: null, blockedBy: expect.stringMatching(/not settled by the ledger/) });
      expect(await rekey(w, c)).toMatchObject({ sent: false });
    }
    expect(rekeys(w)).toBe(0);
    // Readable and valid: it goes on.
    await c.reconcile({ hints, timing: TIMING });
    expect(c.next()).toEqual({ stage: 'rekey', blockedBy: null });
    expect(await rekey(w, c)).toMatchObject({ sent: true, evidence: { outcome: 'confirmed' } });
  });
});

describe('the network', () => {
  it('refuses MainNet by label before anything is read, and a public network behind LocalNet', async () => {
    const ledger = scriptedLedger({ accounts: { [SIGNER.address]: {} } });
    const init = { sender: SIGNER.address, authorizer: SIGNER.address, target: KEY.address };
    expect(() => openCeremony(ledger.clients, { ...init, network: 'mainnet' })).toThrow(/limited to TestNet and LocalNet/);
    expect(ledger.requests).toHaveLength(0);
    ledger.setGenesis({ genesisID: 'mainnet-v1.0', genesisHash: algosdk.base64ToBytes('wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=') });
    const local = openCeremony(ledger.clients, { ...init, network: 'localnet' });
    expect(await local.pin(TIMING)).toEqual({ refused: expect.stringMatching(/a public network, behind the LocalNet endpoint/) });
    const test = openCeremony(ledger.clients, { ...init, network: 'testnet' });
    expect(await test.pin(TIMING)).toEqual({ refused: expect.stringMatching(/not TestNet/) });
    expect(genesisRefusal('mainnet', { id: 'mainnet-v1.0', hash: 'x' })).toMatch(/limited to TestNet and LocalNet/);
    expect(ledger.count('send')).toBe(0);
  });

  it('refuses a target that is not a new post-quantum address for this account', () => {
    const { clients } = scriptedLedger();
    const open = (target: string, authorizer = SIGNER.address) =>
      () => openCeremony(clients, { network: 'localnet', sender: SIGNER.address, authorizer, target });
    expect(open(OTHER.address)).toThrow(/not a post-quantum address/);
    expect(open(SIGNER.address)).toThrow(/not a post-quantum address/);
    expect(open(KEY.address, KEY.address)).toThrow(/already this account's authority/);
    expect(open('not an address')).toThrow(/not a valid address/);
    expect(open(KEY.address)).not.toThrow();
  });
});

describe('the new key and the signing key', () => {
  it('admits the new key only with its phrase typed back, and a key that signs and derives the target', async () => {
    const w = await world({ admit: false });
    expect(await w.run('funding')).toMatchObject({ sent: false, reason: expect.stringMatching(/key has not been admitted/) });
    const words = KEY.mnemonic!.split(' ');
    for (const typed of ['', [words[1], words[0], ...words.slice(2)].join(' '), OTHER_KEY.mnemonic!]) {
      expect(w.ceremony.admitKey(KEY, typed)).toBe('The phrase typed back does not re-derive the new address.');
    }
    expect(w.ceremony.admitKey(OTHER_KEY, OTHER_KEY.mnemonic!)).toMatch(/not the one this migration rekeys to/);
    // Claiming the target's address with another key's public key.
    expect(w.ceremony.admitKey({ ...OTHER_KEY, address: KEY.address }, KEY.mnemonic!)).toMatch(/does not derive the address/);
    // The right key, whose private half does not match: the self-test fails.
    expect(w.ceremony.admitKey({ ...KEY, privateKey: OTHER_KEY.privateKey }, KEY.mnemonic!)).toMatch(
      /preflight check failed: Falcon key signs and verifies/,
    );
    expect(w.ceremony.hasKey()).toBe(false);
    expect(w.ledger.count('send')).toBe(0);
    expect(w.ceremony.admitKey(KEY, `  ${KEY.mnemonic!.replace(/ /g, '\n ')} `)).toBeNull();
    await confirmAll(w, 'funding');
  });

  it('signs the funding and the rekey only with the phrase of the pinned Ed25519 authority', async () => {
    const w = await world();
    expect(w.ceremony.signingRefusal('not a phrase')).toBe('The signing phrase is not a valid 25-word Algorand phrase.');
    expect(w.ceremony.signingRefusal(OTHER.phrase)).toBe(`That phrase controls ${OTHER.address}, not the account being migrated.`);
    expect(await w.run('funding', { signingPhrase: OTHER.phrase })).toMatchObject({ sent: false, reason: expect.stringMatching(/That phrase controls/) });
    expect(w.ledger.count('send')).toBe(0);
    // No refusal repeats any part of a phrase.
    for (const reason of [w.ceremony.signingRefusal(OTHER.phrase)!, w.ceremony.signingRefusal(SIGNER.phrase.split(' ').reverse().join(' '))!]) {
      for (const phrase of [SIGNER.phrase, OTHER.phrase, KEY.mnemonic!]) {
        const words = phrase.split(' ');
        for (let i = 0; i + 1 < words.length; i++) expect(reason).not.toContain(`${words[i]} ${words[i + 1]}`);
      }
    }
    expect(w.ceremony.signingRefusal(SIGNER.phrase)).toBeNull();
    await confirmAll(w, 'funding');
  });

  it('asks a rekeyed account for its authority’s phrase', async () => {
    const ledger = scriptedLedger({ accounts: { [SIGNER.address]: { authAddr: OTHER.address } } });
    const w = await world({ ledger, authorizer: OTHER.address });
    expect(w.ceremony.signingRefusal(SIGNER.phrase)).toMatch(/is rekeyed to .*so that key has to sign/);
    expect(await w.run('funding')).toMatchObject({ sent: false });
    await confirmAll({ ...w, run: (stage) => w.run(stage, { signingPhrase: OTHER.phrase }) }, 'funding', 'proof', 'rekey', 'verification');
    expect(ledger.authority(SIGNER.address)).toBe(KEY.address);
  });

  it('refuses multisig, logic-signature and post-quantum authorities by name, and a budget priced for one', async () => {
    // An account already rekeyed to a hash-derived authority.
    const ledger = scriptedLedger({ accounts: { [SIGNER.address]: { authAddr: OTHER_KEY.address } } });
    const w = await world({ ledger, authorizer: OTHER_KEY.address });
    for (const phrase of [SIGNER.phrase, OTHER.phrase]) {
      expect(w.ceremony.signingRefusal(phrase)).toMatch(/is not an Ed25519 key: it is a multisig, a logic signature or a post-quantum key/);
    }
    await w.approve('funding', { supported: true, scheme: 'falcon-1024', basis: 'fixture' });
    expect(await w.run('funding')).toMatchObject({ sent: false, reason: expect.stringMatching(/falcon-1024 key: the budget prices it, but it cannot sign with it here/) });
    expect(ledger.count('send')).toBe(0);
  });
});

describe('fresh authority before each step', () => {
  it('refuses the rekey when the account answers to someone else now, and goes on once it does not', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    w.ledger.setAuthority(SIGNER.address, OTHER.address);
    expect(await w.run('rekey')).toMatchObject({
      sent: false,
      reason: `The account's authority is ${OTHER.address}, not ${SIGNER.address} as this step needs. Check the ledger before going on.`,
      authority: { authority: OTHER.address },
    });
    w.ledger.setAuthority(SIGNER.address, undefined);
    await confirmAll(w, 'rekey', 'verification');
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof', 'rekey', 'verification']);
  });

  it('refuses the rekey when the target no longer answers to its own key, though its proof confirmed', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    w.ledger.setAuthority(KEY.address, OTHER.address);
    expect(await w.run('rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/answers to .*not to its own Falcon key/) });
    expect(w.ledger.authority(SIGNER.address)).toBe(SIGNER.address);
    w.ledger.setAuthority(KEY.address, undefined);
    await confirmAll(w, 'rekey');
  });

  it('keeps a confirmed proof past its validity window, rechecking what it proved', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    w.ledger.advance(VALIDITY_ROUNDS * 3n);
    await w.approve('rekey');
    await confirmAll(w, 'rekey', 'verification');
  });

  it('refuses verification before the account answers to the new key, and sends nothing', async () => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof', 'rekey');
    w.ledger.setAuthority(SIGNER.address, undefined);
    expect(await w.run('verification')).toMatchObject({ sent: false, reason: 'Account still has no auth-addr; the rekey did not take effect.' });
    expect(w.ledger.count('send')).toBe(3);
    // The confirmed rekey is still what the ceremony knows: verification stays open.
    w.ledger.setAuthority(SIGNER.address, KEY.address);
    expect(w.ceremony.next()).toEqual({ stage: 'verification', blockedBy: null });
    await confirmAll(w, 'verification');
  });
});

describe('the approved budget and the consensus it assumes', () => {
  it('refuses a step whose fee rose after approval, and goes on once the new reading is approved', async () => {
    const w = await world();
    w.ledger.setMinFee(1001n);
    const r = await w.run('funding');
    expect(r).toMatchObject({ sent: false, reason: expect.stringMatching(/budget changed since it was approved/), quote: { status: 'available' } });
    expect(w.ledger.count('send')).toBe(0);
    await w.approve();
    await confirmAll(w, 'funding');
  });

  it.each([
    ['an unknown protocol', (l: ScriptedLedger) => l.setProtocol('future'), /does not encode/],
    ['a scheduled upgrade', (l: ScriptedLedger) => l.scheduleUpgrade({ protocol: 'next', round: l.round + 10n }), /switches to consensus protocol next/],
    ['a node catching up', (l: ScriptedLedger) => l.setCatchingUp(true), /catching up/],
  ])('refuses %s before signing, and goes on once it is gone', async (_name, arrange, why) => {
    const w = await world();
    await confirmAll(w, 'funding', 'proof');
    arrange(w.ledger);
    expect(await w.run('rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(why), quote: { status: 'unavailable' } });
    expect(sendsOf(w.ledger)).toEqual(['funding', 'proof']);
    w.ledger.setProtocol(LEDGER_PROTOCOL);
    w.ledger.scheduleUpgrade(null);
    w.ledger.setCatchingUp(false);
    await confirmAll(w, 'rekey');
  });

  it('refuses a run with no approval, or an approval for another migration', async () => {
    const w = await world();
    expect(await w.run('funding', { approved: undefined })).toMatchObject({ sent: false });
    const other = await quoteMigration(w.ledger.clients, { sender: SIGNER.address, authorizer: SIGNER.address, target: OTHER_KEY.address, signer: ED25519_BY_PHRASE });
    expect(await w.run('funding', { approved: other })).toMatchObject({ sent: false, reason: expect.stringMatching(/different migration/) });
    expect(w.ledger.count('send')).toBe(0);
  });
});

describe('record, then send', () => {
  it('sends nothing when the record cannot be written, and then sends once it can', async () => {
    const w = await world();
    const r = await w.run('funding', {
      record: () => {
        throw new Error('storage full');
      },
    });
    expect(r).toMatchObject({ sent: false, reason: expect.stringMatching(/could not be recorded, so it was not sent: storage full/) });
    expect(w.ledger.count('send')).toBe(0);
    expect(w.ceremony.attempts()).toHaveLength(0);
    expect(w.ceremony.next()).toEqual({ stage: 'funding', blockedBy: null });
    await confirmAll(w, 'funding');
    expect(w.journal).toHaveLength(1);
    expect(w.journal[0]!.txId).toBe(w.ceremony.attempts()[0]!.txId);
  });

  it('runs one step at a time', async () => {
    const w = await world();
    let release!: () => void;
    w.ledger.fail('send', { until: new Promise<void>((r) => (release = r)) });
    const first = w.run('funding');
    await new Promise((r) => setTimeout(r, 20));
    expect(await w.run('funding')).toMatchObject({ sent: false, reason: expect.stringMatching(/already in progress/) });
    await expect(w.ceremony.reconcile()).rejects.toThrow(/already in progress/);
    release();
    expect(await first).toMatchObject({ sent: true });
    expect(w.ledger.count('send')).toBe(1);
  });
});
