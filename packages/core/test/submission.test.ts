/**
 * Submission and reconciliation, against a scripted ledger (SAFE-02b).
 *
 * Every transaction here is built, signed and sent by the real core code,
 * with real keys from fixed public seeds. The ledger decodes each send and
 * checks it as algod would, and the tests put faults exactly where they want
 * them: a lost request, a lost response, a hang, a pool error, a lagging
 * indexer, pruned blocks, another network. What they check is that no such
 * fault is read as "not sent", that nothing is sent twice, and that only a
 * read of every round in a passed validity window permits a replacement.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  ED25519_BY_PHRASE,
  VALIDITY_ROUNDS,
  prepareStage,
  quoteMigration,
  stageOf,
  RecordError,
  TimeoutError,
  attemptTransaction,
  awaitAttempt,
  isTransactionId,
  fundPqAddress,
  makeFalconSigner,
  pqIdentityFromMnemonic,
  prepareControlProof,
  prepareFunding,
  prepareProof,
  prepareRekey,
  proveControl,
  publicMessage,
  readAuthority,
  reconcileAttempt,
  rekeyToPq,
  replaceable,
  sendAttempt,
  signAttempt,
  submitAndConfirm,
  verifyMigration,
  withTimeout,
} from '../src/index.js';
import { LEDGER_GENESIS, scriptedLedger, type ScriptedLedger } from './scripted-ledger.js';

const seeded = (fill: number) => {
  const account = algosdk.mnemonicToSecretKey(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill)));
  return {
    address: account.addr.toString(),
    signer: algosdk.makeBasicAccountTransactionSigner(account),
  };
};
const OWNER = seeded(11);
const OTHER = seeded(12);
const TARGET = pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(new Uint8Array(32).fill(13)));
const GENESIS = { id: LEDGER_GENESIS.genesisID, hash: algosdk.bytesToBase64(LEDGER_GENESIS.genesisHash) };

const fast = { requestTimeoutMs: 200, timeoutMs: 300, pollMs: 5 };

function ledger(extra: Parameters<typeof scriptedLedger>[0] = {}): ScriptedLedger {
  return scriptedLedger({
    accounts: { [OWNER.address]: { amount: 10_000_000n } },
    ...extra,
  });
}

async function signedFunding(l: ScriptedLedger) {
  const prepared = await prepareFunding(l.clients, { address: OWNER.address }, TARGET.address);
  return { prepared, signed: await signAttempt(prepared, OWNER.signer) };
}

describe('preparation', () => {
  it('derives the id and validity window before anything is signed or sent', async () => {
    const l = ledger({ round: 5000n });
    const { attempt, txn } = await prepareFunding(l.clients, { address: OWNER.address }, TARGET.address);
    // Only reads: the budget's inputs, then the parameters the attempt is built from.
    expect(l.requests.every((r) => /^(params|status|account)\b/.test(r))).toBe(true);
    expect(l.requests.at(-1)).toBe('params');
    expect(attempt).toMatchObject({
      stage: 'funding',
      sender: OWNER.address,
      authorizer: OWNER.address,
      receiver: TARGET.address,
      // What the budget says the new address lacks: its minimum balance and its proof fee.
      amount: 103_000n,
      fee: 1000n,
      firstValid: 5000n,
      lastValid: 5000n + VALIDITY_ROUNDS,
      genesisId: GENESIS.id,
      genesisHash: GENESIS.hash,
      rekeyTo: null,
    });
    expect(attempt.txId).toBe(txn.txID());
    // The public fields alone rebuild the same transaction, so the id can
    // always be checked against them.
    expect(attemptTransaction(attempt).txID()).toBe(attempt.txId);
    expect(algosdk.bytesToBase64(attemptTransaction(attempt).bytesToSign())).toBe(
      algosdk.bytesToBase64(txn.bytesToSign()),
    );
  });

  it('binds each step to its sender, authorizer, receiver and target', async () => {
    const l = ledger();
    const byAuthority = { address: OWNER.address, authorizer: OTHER.address };
    const proof = (await prepareProof(l.clients, TARGET.address)).attempt;
    const rekey = (await prepareRekey(l.clients, byAuthority, TARGET.address)).attempt;
    const control = (await prepareControlProof(l.clients, OWNER.address, TARGET.address)).attempt;
    expect(proof).toMatchObject({ stage: 'proof', sender: TARGET.address, authorizer: TARGET.address, receiver: TARGET.address, amount: 0n, fee: 3000n });
    expect(rekey).toMatchObject({ stage: 'rekey', sender: OWNER.address, authorizer: OTHER.address, receiver: OWNER.address, amount: 0n, fee: 1000n, rekeyTo: TARGET.address });
    expect(control).toMatchObject({ stage: 'verification', sender: OWNER.address, authorizer: TARGET.address, receiver: OWNER.address, amount: 0n, fee: 3000n });
  });

  it('refuses a node on another network, and a classical rekey target, before signing anything', async () => {
    const l = ledger();
    await expect(
      prepareFunding(l.clients, { address: OWNER.address }, TARGET.address, undefined, {
        genesis: { id: 'testnet-v1.0', hash: GENESIS.hash },
      }),
    ).rejects.toThrow(/not testnet-v1.0\. Nothing was signed/);
    await expect(prepareRekey(l.clients, { address: OWNER.address }, OTHER.address)).rejects.toThrow(/not a post-quantum address/);
    expect(l.count('send')).toBe(0);
    expect(l.requests.every((r) => /^(params|status|account)\b/.test(r))).toBe(true);
  });

  it('bounds the parameter read', async () => {
    const l = ledger();
    // The budget's own read, reported as an unavailable budget.
    l.fail('params', 'hang');
    await expect(
      prepareFunding(l.clients, { address: OWNER.address }, TARGET.address, undefined, { requestTimeoutMs: 20 }),
    ).rejects.toThrow(/No answer after 20 ms/);
    // The attempt's read, once the budget has been read.
    const stage = stageOf(
      await quoteMigration(l.clients, { sender: OWNER.address, authorizer: OWNER.address, target: TARGET.address, signer: ED25519_BY_PHRASE }),
      'funding',
    );
    l.fail('params', 'hang');
    await expect(prepareStage(l.clients, stage, { requestTimeoutMs: 20 })).rejects.toBeInstanceOf(TimeoutError);
  });

  it('prepares only what the budget allows, on the network it was read on', async () => {
    const l = ledger();
    const budget = await quoteMigration(l.clients, { sender: OWNER.address, authorizer: OWNER.address, target: TARGET.address, signer: ED25519_BY_PHRASE });
    const stage = stageOf(budget, 'funding');
    const { attempt } = await prepareStage(l.clients, stage);
    expect(attempt).toMatchObject({ amount: stage.amount, fee: stage.fee });
    l.setGenesis({ genesisID: 'testnet-v1.0', genesisHash: algosdk.base64ToBytes(GENESIS.hash) });
    await expect(prepareStage(l.clients, stage)).rejects.toThrow(/Nothing was signed/);
    l.setGenesis(LEDGER_GENESIS);
    l.advance(stage.validThroughRound - l.round + 1n);
    await expect(prepareStage(l.clients, stage)).rejects.toThrow(/read too long ago.*Nothing was signed/);
    expect(l.count('send')).toBe(0);
  });
});

describe('signing', () => {
  it('refuses a signer that signs another transaction, and sends nothing', async () => {
    const l = ledger();
    const prepared = await prepareFunding(l.clients, { address: OWNER.address }, TARGET.address);
    const swapped: algosdk.TransactionSigner = async (txns) => {
      const other = attemptTransaction({ ...prepared.attempt, amount: 5_000_000n });
      return OWNER.signer([other, ...txns.slice(1)], [0]);
    };
    await expect(signAttempt(prepared, swapped)).rejects.toThrow(/not the prepared .* Nothing was sent/);
    await expect(signAttempt(prepared, async () => [new Uint8Array([1, 2, 3])])).rejects.toThrow(/not a signed transaction/);
    await expect(signAttempt(prepared, async () => [])).rejects.toThrow(/exactly one/);
    expect(l.count('send')).toBe(0);
  });

  it('refuses a signature from any key but the attempt’s authorizer', async () => {
    const l = ledger();
    const byAuthority = await prepareRekey(l.clients, { address: OWNER.address, authorizer: OTHER.address }, TARGET.address);
    await expect(signAttempt(byAuthority, OWNER.signer)).rejects.toThrow(`authorised by ${OWNER.address}, not ${OTHER.address}`);
    // The authority's own key signs it, as a rekeyed account's authority does.
    const signed = await signAttempt(byAuthority, OTHER.signer);
    expect(algosdk.decodeSignedTransaction(signed).sgnr?.toString()).toBe(OTHER.address);
  });

  it('binds both Falcon signatures: the drill as itself, the control proof for the account', async () => {
    const l = ledger();
    const proof = await prepareProof(l.clients, TARGET.address);
    expect(algosdk.decodeSignedTransaction(await signAttempt(proof, makeFalconSigner(TARGET))).sgnr).toBeUndefined();
    const control = await prepareControlProof(l.clients, OWNER.address, TARGET.address);
    await expect(signAttempt(control, OWNER.signer)).rejects.toThrow(/Nothing was sent/);
    const signed = await signAttempt(control, makeFalconSigner(TARGET, OWNER.address));
    expect(algosdk.decodeSignedTransaction(signed).sgnr?.toString()).toBe(TARGET.address);
  });
});

describe('record, then send', () => {
  it('awaits the record before the send, and sends the recorded attempt', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    let release!: () => void;
    const recording = new Promise<void>((r) => (release = r));
    const recorded: string[] = [];
    const sending = sendAttempt(l.clients, prepared, signed, {
      record: async (a) => {
        recorded.push(a.txId);
        await recording;
      },
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(recorded).toEqual([prepared.attempt.txId]);
    expect(l.count('send')).toBe(0);
    release();
    expect(await sending).toEqual({ status: 'accepted' });
    expect(l.landed.map((s) => s.txn.txID())).toEqual([prepared.attempt.txId]);
  });

  it('sends nothing when the record cannot be written', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    await expect(
      sendAttempt(l.clients, prepared, signed, {
        record: () => {
          throw new Error('QuotaExceededError');
        },
      }),
    ).rejects.toBeInstanceOf(RecordError);
    expect(l.count('send')).toBe(0);
    expect(l.landed).toHaveLength(0);
  });

  it('refuses bytes that are not the prepared attempt before recording', async () => {
    const l = ledger();
    const { prepared } = await signedFunding(l);
    const other = await prepareProof(l.clients, TARGET.address);
    const wrong = await signAttempt(other, makeFalconSigner(TARGET));
    let recorded = 0;
    await expect(sendAttempt(l.clients, prepared, wrong, { record: () => void recorded++ })).rejects.toThrow(/Nothing was sent/);
    expect(recorded).toBe(0);
    expect(l.count('send')).toBe(0);
  });

  it('a lost request is unknown, not a failure: it stays unresolved until its window passes and every round is read', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    l.fail('send', 'lose-request');
    const sent = await sendAttempt(l.clients, prepared, signed);
    expect(sent.status).toBe('unknown');
    expect(l.landed).toHaveLength(0);

    const inWindow = await reconcileAttempt(l.clients, prepared.attempt);
    expect(inWindow).toMatchObject({ outcome: 'unknown', nonInclusion: false, observedRound: l.round });
    expect(inWindow.detail).toMatch(/does not show that it was never sent/);
    expect(replaceable(inWindow)).toBe(false);

    l.advance(VALIDITY_ROUNDS + 1n);
    const passed = await reconcileAttempt(l.clients, prepared.attempt);
    expect(passed).toMatchObject({ outcome: 'expired', nonInclusion: true, source: 'algod-block' });
    expect(replaceable(passed)).toBe(true);
    const width = Number(prepared.attempt.lastValid - prepared.attempt.firstValid + 1n);
    expect(l.count('block')).toBe(width);
    expect(l.count('send')).toBe(1);
  });

  it('a lost response is unknown at the time, and confirmed by reconciliation', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    l.fail('send', 'lose-response');
    const sent = await sendAttempt(l.clients, prepared, signed);
    expect(sent.status).toBe('unknown');
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'confirmed', source: 'algod-pending', confirmedRound: l.confirmedRound(prepared.attempt.txId) });
    expect(l.landed).toHaveLength(1);
  });

  it('distrusts a send answer with another id', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    l.fail('send', { wrongId: 'A'.repeat(52) });
    const sent = await sendAttempt(l.clients, prepared, signed);
    expect(sent).toMatchObject({ status: 'conflict' });
    expect((sent as { reason: string }).reason).toContain(prepared.attempt.txId);
  });

  it('a send that times out is unknown, and its late answer changes nothing it returned', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    let release!: () => void;
    l.fail('send', { until: new Promise<void>((r) => (release = r)) });
    const sent = await sendAttempt(l.clients, prepared, signed, { requestTimeoutMs: 20 });
    expect(sent.status).toBe('unknown');
    expect((sent as { reason: string }).reason).toMatch(/No answer after 20 ms/);
    release();
    await new Promise((r) => setTimeout(r, 5));
    // It landed after all, and only reconciliation shows it.
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed' });
  });

  it('a refusal can mean it is already in the ledger, and a second send never duplicates it', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    expect(await sendAttempt(l.clients, prepared, signed)).toEqual({ status: 'accepted' });
    const again = await sendAttempt(l.clients, prepared, signed);
    expect(again).toMatchObject({ status: 'rejected', httpStatus: 400 });
    expect((again as { reason: string }).reason).toContain('already in ledger');
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed' });
    expect(l.landed).toHaveLength(1);
    await expect(submitAndConfirm(l.clients, prepared, OWNER.signer)).rejects.toThrow(/already in ledger/);
    expect(l.landed).toHaveLength(1);
  });
});

describe('waiting, bounded', () => {
  it('confirmation after the wait ran out: pending then, confirmed later', async () => {
    const l = ledger({ autoConfirm: false });
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    const waited = await awaitAttempt(l.clients, prepared.attempt, fast);
    expect(waited).toMatchObject({ outcome: 'pending', source: 'algod-pending' });
    expect(replaceable(waited)).toBe(false);
    l.mine();
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed' });
  });

  it('a pool error is an observed rejection, which permits nothing until the window passes', async () => {
    const l = ledger({ autoConfirm: false });
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    l.drop(prepared.attempt.txId, 'overspend');
    const e = await awaitAttempt(l.clients, prepared.attempt, fast);
    expect(e).toMatchObject({ outcome: 'rejected' });
    expect(e.detail).toMatch(/overspend.*does not show that it failed/);
    expect(replaceable(e)).toBe(false);
    l.advance(VALIDITY_ROUNDS + 1n);
    expect(replaceable(await reconcileAttempt(l.clients, prepared.attempt))).toBe(true);
  });

  it('a later poll that cannot read the node does not replace what the node said', async () => {
    const l = ledger({ autoConfirm: false });
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    // The first poll reads it pending; every later one cannot read the node.
    let polls = 0;
    const e = await awaitAttempt(l.clients, prepared.attempt, {
      requestTimeoutMs: 20,
      timeoutMs: 150,
      pollMs: 5,
      sleep: async (ms) => {
        if (++polls === 1) l.failTimes('status', 'hang', 1000);
        await new Promise((r) => setTimeout(r, ms));
      },
    });
    expect(e).toMatchObject({ outcome: 'pending', source: 'algod-pending' });
  });

  it('a lookup that hangs is bounded, and ends unknown', async () => {
    const l = ledger({ autoConfirm: false });
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    l.failTimes('pending', 'hang', 100);
    const started = Date.now();
    const e = await awaitAttempt(l.clients, prepared.attempt, { requestTimeoutMs: 20, timeoutMs: 100, pollMs: 5 });
    expect(Date.now() - started).toBeLessThan(1000);
    expect(e.outcome).toBe('unknown');
  });
});

describe('block entries (A-02b-02)', () => {
  /** An attempt that confirmed, long enough ago that the node's lookup no longer answers. */
  async function confirmedLongAgo(extra: Parameters<typeof scriptedLedger>[0] = {}) {
    const l = ledger(extra);
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    const at = l.confirmedRound(prepared.attempt.txId)!;
    l.advance(VALIDITY_ROUNDS + 2n);
    l.failTimes('pending', 'not-found', 100);
    return { l, prepared, at };
  }

  /** An attempt that never landed, whose window has passed. */
  async function neverLanded() {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    l.fail('send', 'lose-request');
    await sendAttempt(l.clients, prepared, signed);
    l.advance(VALIDITY_ROUNDS + 2n);
    return { l, prepared };
  }

  it('recognises only well-formed transaction ids', () => {
    expect(isTransactionId('HNCQUHKLWYEHDPM35YUI7BRSGBR36FGX2VQNUIPN3EZS7LV64O2Q')).toBe(true);
    expect(isTransactionId('XH7OIO6VAZZYBOREAZB2XXC525WUBRLPTAA3TCHRWE6CIR4TP2RA')).toBe(true);
    for (const bad of ['not-a-transaction-id', '', 'A'.repeat(51), 'A'.repeat(53), `${'A'.repeat(51)}B`, `${'a'.repeat(51)}A`, 42, null]) {
      expect(isTransactionId(bad), String(bad)).toBe(false);
    }
  });

  it('a malformed entry in the block that holds it cannot prove it never landed', async () => {
    const { l, prepared, at } = await confirmedLongAgo({ noIndexer: true });
    l.setBlockAnswer(at, { blocktxids: ['not-a-transaction-id'] });
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'expired', nonInclusion: false });
    expect(replaceable(e)).toBe(false);
  });

  it('with a gap, valid positive evidence elsewhere still settles it', async () => {
    const { l, prepared, at } = await confirmedLongAgo();
    l.setBlockAnswer(at, { blocktxids: ['not-a-transaction-id'] });
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed', source: 'indexer', confirmedRound: at });
  });

  it('a mixed list is a gap unless a valid entry names it', async () => {
    const other = 'HNCQUHKLWYEHDPM35YUI7BRSGBR36FGX2VQNUIPN3EZS7LV64O2Q';
    const hidden = await confirmedLongAgo({ noIndexer: true });
    hidden.l.setBlockAnswer(hidden.at, { blocktxids: [other, 'garbage', 7] });
    expect(await reconcileAttempt(hidden.l.clients, hidden.prepared.attempt)).toMatchObject({ outcome: 'expired', nonInclusion: false });
    const named = await confirmedLongAgo({ noIndexer: true });
    named.l.setBlockAnswer(named.at, { blocktxids: ['garbage', named.prepared.attempt.txId] });
    expect(await reconcileAttempt(named.l.clients, named.prepared.attempt)).toMatchObject({ outcome: 'confirmed', source: 'algod-block', confirmedRound: named.at });
  });

  it('valid empty and populated blocks do show absence', async () => {
    const { l, prepared } = await neverLanded();
    const other = 'HNCQUHKLWYEHDPM35YUI7BRSGBR36FGX2VQNUIPN3EZS7LV64O2Q';
    l.setBlockAnswer(prepared.attempt.firstValid, { blocktxids: [] });
    l.setBlockAnswer(prepared.attempt.firstValid + 1n, { blocktxids: [other] });
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'expired', nonInclusion: true });
    expect(replaceable(e)).toBe(true);
  });

  it('a list that is not a list is a gap', async () => {
    const { l, prepared } = await neverLanded();
    l.setBlockAnswer(prepared.attempt.firstValid, { blocktxids: 'AAAA' });
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'expired', nonInclusion: false });
  });

  it('a claimed round is read, and only the block decides', async () => {
    const { l, prepared, at } = await confirmedLongAgo({ noIndexer: true });
    // Beyond the window scan's reach, the hint alone is read, and it holds it.
    const e = await reconcileAttempt(l.clients, prepared.attempt, { hintRound: at, maxScanRounds: 1n });
    expect(e).toMatchObject({ outcome: 'confirmed', source: 'algod-block', confirmedRound: at });
    // A false hint proves nothing either way.
    const wrong = await reconcileAttempt(l.clients, prepared.attempt, { hintRound: at + 1n, maxScanRounds: 1n });
    expect(wrong).toMatchObject({ outcome: 'expired', nonInclusion: false });
  });
});

describe('reconciliation', () => {
  async function landedFunding(extra: Parameters<typeof scriptedLedger>[0] = {}) {
    const l = ledger(extra);
    const { prepared, signed } = await signedFunding(l);
    await sendAttempt(l.clients, prepared, signed);
    return { l, prepared };
  }

  it('an expired attempt that already confirmed is confirmed, from the lookup or from its block', async () => {
    const { l, prepared } = await landedFunding();
    l.advance(VALIDITY_ROUNDS + 5n);
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed', source: 'algod-pending' });
    // Long after, algod no longer answers the lookup; the block still holds it.
    l.advance(1200n);
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'confirmed', source: 'algod-block', confirmedRound: l.confirmedRound(prepared.attempt.txId) });
  });

  it('insufficient history: an unreadable round leaves an expired attempt unresolved', async () => {
    const l = ledger();
    const { prepared, signed } = await signedFunding(l);
    l.fail('send', 'lose-request');
    await sendAttempt(l.clients, prepared, signed);
    l.advance(VALIDITY_ROUNDS + 1n);
    l.prune(prepared.attempt.firstValid + 3n, prepared.attempt.firstValid + 3n);
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'expired', nonInclusion: false });
    expect(e.detail).toMatch(/1 of the 51 rounds .* could not be read/);
    expect(replaceable(e)).toBe(false);
  });

  it('a lagging indexer is never evidence of absence, and a caught-up one confirms', async () => {
    const { l, prepared } = await landedFunding({ indexerLag: 5000n });
    l.advance(1200n);
    l.prune(prepared.attempt.firstValid, prepared.attempt.lastValid);
    const lagging = await reconcileAttempt(l.clients, prepared.attempt);
    expect(lagging).toMatchObject({ outcome: 'expired', nonInclusion: false });
    expect(replaceable(lagging)).toBe(false);
    l.setIndexerLag(0n);
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed', source: 'indexer' });
  });

  it('a 404 while the window is open is not evidence either way', async () => {
    const l = ledger();
    const { prepared } = await signedFunding(l);
    // Recorded, never sent: a crash between the record and the send.
    const e = await reconcileAttempt(l.clients, prepared.attempt);
    expect(e.outcome).toBe('unknown');
    expect(replaceable(e)).toBe(false);
    expect(l.count('block')).toBe(0);
  });

  it('stops on another network, a node catching up, and malformed or contradictory answers', async () => {
    const { l, prepared } = await landedFunding();
    l.setGenesis({ genesisID: 'mainnet-v1.0', genesisHash: new Uint8Array(32).fill(1) });
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'conflict' });
    l.setGenesis(LEDGER_GENESIS);
    l.setCatchingUp(true);
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'unknown' });
    l.setCatchingUp(false);
    l.fail('pending', 'malformed');
    expect(await reconcileAttempt(l.clients, prepared.attempt)).toMatchObject({ outcome: 'conflict' });
    const forged = { ...prepared.attempt, firstValid: prepared.attempt.firstValid + 5n };
    // An attempt whose window excludes the round it confirmed in.
    expect((await reconcileAttempt(l.clients, { ...forged, txId: prepared.attempt.txId })).outcome).toBe('conflict');
  });

  it('refuses to read a window wider than its bound, and stays within its time budget', async () => {
    const l = ledger();
    const { prepared } = await signedFunding(l);
    l.advance(VALIDITY_ROUNDS + 2n);
    expect(await reconcileAttempt(l.clients, prepared.attempt, { maxScanRounds: 10n })).toMatchObject({ outcome: 'expired', nonInclusion: false });
    expect(l.count('block')).toBe(0);
    l.failTimes('block', 'hang', 100);
    const started = Date.now();
    const e = await reconcileAttempt(l.clients, prepared.attempt, { requestTimeoutMs: 50, totalTimeoutMs: 200 });
    expect(Date.now() - started).toBeLessThan(1500);
    expect(e).toMatchObject({ outcome: 'expired', nonInclusion: false });
  });

  it('never sends, whatever it finds', async () => {
    const { l, prepared } = await landedFunding();
    for (let i = 0; i < 3; i++) await reconcileAttempt(l.clients, prepared.attempt);
    l.advance(VALIDITY_ROUNDS + 1n);
    await reconcileAttempt(l.clients, prepared.attempt);
    expect(l.count('send')).toBe(1);
    expect(l.requests.every((r) => /^(params|status|account|pending|block|indexer)\b/.test(r) || r.startsWith('send '))).toBe(true);
  });
});

describe('authority', () => {
  it('reads the account’s current authority, bounded, and refuses malformed answers', async () => {
    const l = ledger();
    expect(await readAuthority(l.clients, OWNER.address)).toMatchObject({ authority: OWNER.address, rekeyed: false, round: l.round });
    l.setAuthority(OWNER.address, TARGET.address);
    expect(await readAuthority(l.clients, OWNER.address)).toMatchObject({ authority: TARGET.address, rekeyed: true });
    l.fail('account', 'malformed');
    await expect(readAuthority(l.clients, OWNER.address)).rejects.toThrow(/malformed|different account/);
    l.fail('account', 'hang');
    await expect(readAuthority(l.clients, OWNER.address, { requestTimeoutMs: 20 })).rejects.toBeInstanceOf(TimeoutError);
  });
});

describe('the helpers that keep no record', () => {
  it('run the migration against the ledger, one transaction per step', async () => {
    const l = ledger();
    await fundPqAddress(l.clients, OWNER, TARGET.address);
    await proveControl(l.clients, TARGET);
    await rekeyToPq(l.clients, OWNER, TARGET.address);
    const v = await verifyMigration(l.clients, OWNER.address, TARGET);
    expect(v).toMatchObject({ authAddrMatches: true, controlProven: true });
    expect(l.landed.map((s) => [s.txn.sender.toString(), s.sgnr?.toString() ?? null, s.txn.rekeyTo?.toString() ?? null])).toEqual([
      [OWNER.address, null, null],
      [TARGET.address, null, null],
      [OWNER.address, null, TARGET.address],
      [OWNER.address, TARGET.address, null],
    ]);
    expect(l.authority(OWNER.address)).toBe(TARGET.address);
  });

  it('verification sends nothing when the authority does not match', async () => {
    const l = ledger();
    const v = await verifyMigration(l.clients, OWNER.address, TARGET);
    expect(v).toMatchObject({ authAddrMatches: false, controlProven: false });
    expect(v.proofTxId).toBeUndefined();
    expect(l.count('send')).toBe(0);
  });

  it('a rekey after the key changed is refused by the ledger for its authoriser', async () => {
    const l = ledger();
    l.setAuthority(OWNER.address, OTHER.address);
    await expect(rekeyToPq(l.clients, OWNER, TARGET.address)).rejects.toThrow(
      `should have been authorized by ${OTHER.address} but was actually authorized by ${OWNER.address}`,
    );
  });
});

describe('messages', () => {
  it('bounds a message and drops anything shaped like a phrase', () => {
    const phrase = algosdk.mnemonicFromSeed(new Uint8Array(32).fill(3));
    const m = publicMessage(new Error(`bad input: ${phrase}`));
    expect(m).toBe('bad input: [redacted]');
    expect(publicMessage('x'.repeat(500)).length).toBeLessThanOrEqual(241);
  });

  it('a timeout drops a late answer', async () => {
    let resolve!: (v: string) => void;
    const late = new Promise<string>((r) => (resolve = r));
    await expect(withTimeout(late, 10, 'waiting')).rejects.toBeInstanceOf(TimeoutError);
    resolve('too late');
  });
});
