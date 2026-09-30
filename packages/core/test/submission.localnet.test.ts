/**
 * Submission and reconciliation against a real LocalNet node (SAFE-02b).
 *
 * The node, its pool, its blocks and its indexer are real. What is injected
 * is the loss: a client wrapper throws after a send has reached the node, or
 * hides a lookup, so the code under test sees the failure while the ledger
 * holds the truth. Each test says which part was injected and which was
 * observed.
 *
 * LocalNet runs in dev mode: a block is made only when a transaction arrives.
 * To let a validity window pass, a test sends unrelated self-payments.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  ED25519_BY_PHRASE,
  quoteMigration,
  awaitAttempt,
  generatePqIdentity,
  makeFalconSigner,
  prepareControlProof,
  prepareFunding,
  prepareProof,
  prepareRekey,
  readAuthority,
  reconcileAttempt,
  replaceable,
  sendAttempt,
  signAttempt,
  submitAndConfirm,
  type FalconerClients,
  type PreparedTransaction,
} from '../src/index.js';
import { dispenser, fundedAccount, localnet, waitForIndexer, type LocalAccount } from './helpers.js';

const clients = localnet();
let funder: LocalAccount;
/** What the budget sends a new address on LocalNet: its minimum balance and its proof fee. */
const FUNDED = 103_000n;

beforeAll(async () => {
  funder = await dispenser(clients);
});

interface Injection {
  /** The send reaches the node; its response is thrown away. */
  loseSendResponse?: boolean;
  /** The send never reaches the node. */
  loseSendRequest?: boolean;
  /** Transaction lookups answer 404, as a node that forgot it would. */
  hideLookups?: boolean;
  /** The indexer answers 404, as a lagging indexer does. */
  hideIndexer?: boolean;
}

const notFound = () => Object.assign(new Error('injected 404'), { response: { status: 404 } });

/** The real clients, with the injected failures, and a count of real sends. */
function injected(injection: Injection) {
  const sends: string[] = [];
  const base = clients.algod;
  const algod: typeof base = Object.create(base);
  algod.sendRawTransaction = (bytes) => {
    const id = algosdk.decodeSignedTransaction(bytes as Uint8Array).txn.txID();
    return {
      do: async () => {
        if (injection.loseSendRequest) throw new TypeError('fetch failed (injected: request lost)');
        sends.push(id);
        const answer = await base.sendRawTransaction(bytes).do();
        if (injection.loseSendResponse) throw new TypeError('fetch failed (injected: response lost)');
        return answer;
      },
    } as ReturnType<typeof base.sendRawTransaction>;
  };
  algod.pendingTransactionInformation = (id) => {
    if (!injection.hideLookups) return base.pendingTransactionInformation(id);
    return { do: async () => { throw notFound(); } } as unknown as ReturnType<typeof base.pendingTransactionInformation>;
  };
  let indexer = clients.indexer;
  if (injection.hideIndexer && indexer) {
    const real = indexer;
    indexer = Object.create(real);
    indexer!.lookupTransactionByID = () =>
      ({ do: async () => { throw notFound(); } }) as unknown as ReturnType<typeof real.lookupTransactionByID>;
  }
  return { clients: { ...clients, algod, indexer } as FalconerClients, sends };
}

/** Let rounds pass: dev mode makes a block only for a transaction. */
async function advance(rounds: number) {
  let last = '';
  for (let i = 0; i < rounds; i++) {
    const sp = await clients.algod.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: funder.address,
      receiver: funder.address,
      amount: 0,
      note: new TextEncoder().encode(`falconer-advance-${Date.now()}-${i}`),
      suggestedParams: sp,
    });
    last = (await clients.algod.sendRawTransaction(txn.signTxn(funder.sk)).do()).txid;
  }
  await algosdk.waitForConfirmation(clients.algod, last, 10);
}

async function balance(address: string): Promise<bigint> {
  return BigInt((await clients.algod.accountInformation(address).do()).amount);
}

describe('submission against LocalNet', () => {
  it('a rekey whose response is lost is confirmed by reconciliation, and is not sent again', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const lossy = injected({ loseSendResponse: true });
    const prepared = await prepareRekey(lossy.clients, { address: account.address }, target.address);
    const signed = await signAttempt(prepared, account.signer);

    // Injected: the response is dropped after the node accepted the send.
    const sent = await sendAttempt(lossy.clients, prepared, signed);
    expect(sent.status).toBe('unknown');
    expect(lossy.sends).toEqual([prepared.attempt.txId]);

    // Observed: the node confirms it, and the account's authority moved.
    const e = await reconcileAttempt(clients, prepared.attempt);
    expect(e).toMatchObject({ outcome: 'confirmed', source: 'algod-pending' });
    expect(e.confirmedRound).toBeGreaterThanOrEqual(prepared.attempt.firstValid);
    expect((await readAuthority(clients, account.address)).authority).toBe(target.address);

    // Sending the same bytes again cannot duplicate it: the node refuses it
    // as already in the ledger, and reconciliation still reads one rekey.
    const again = await sendAttempt(clients, prepared, signed);
    expect(again).toMatchObject({ status: 'rejected', httpStatus: 400 });
    expect((again as { reason: string }).reason).toContain('already in ledger');
    expect(await reconcileAttempt(clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed', confirmedRound: e.confirmedRound });
  });

  it('confirmation after the wait timed out: unknown while hidden, confirmed once read', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const hidden = injected({ hideLookups: true, hideIndexer: true });
    const prepared = await prepareFunding(hidden.clients, { address: account.address }, target.address);
    const signed = await signAttempt(prepared, account.signer);
    expect(await sendAttempt(hidden.clients, prepared, signed)).toEqual({ status: 'accepted' });

    // Injected: every lookup answers 404, so the bounded wait ends unknown.
    const waited = await awaitAttempt(hidden.clients, prepared.attempt, { timeoutMs: 400, pollMs: 50 });
    expect(waited.outcome).toBe('unknown');
    expect(replaceable(waited)).toBe(false);

    // Observed: the real node has it.
    expect(await reconcileAttempt(clients, prepared.attempt)).toMatchObject({ outcome: 'confirmed' });
    expect(await balance(target.address)).toBe(FUNDED);
  });

  it('a lagging indexer and a forgetful node establish nothing; a caught-up indexer confirms', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const prepared = await prepareFunding(clients, { address: account.address }, target.address);
    await submitAndConfirm(clients, prepared, account.signer);

    // Injected: lookups and the indexer answer 404 while the window is open.
    const hidden = injected({ hideLookups: true, hideIndexer: true });
    const e = await reconcileAttempt(hidden.clients, prepared.attempt);
    expect(e.outcome).toBe('unknown');
    expect(replaceable(e)).toBe(false);

    // Observed: with only the lookup hidden, the real indexer confirms it.
    await waitForIndexer(clients);
    const viaIndexer = await reconcileAttempt(injected({ hideLookups: true }).clients, prepared.attempt);
    expect(viaIndexer).toMatchObject({ outcome: 'confirmed', source: 'indexer' });
  });

  it('an attempt that never landed is replaceable only once its window has passed and every round was read', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const lost = injected({ loseSendRequest: true });
    const first = await prepareFunding(lost.clients, { address: account.address }, target.address, undefined, { validityRounds: 3n });
    const signed = await signAttempt(first, account.signer);

    // Injected: the request never reaches the node.
    expect((await sendAttempt(lost.clients, first, signed)).status).toBe('unknown');
    expect(lost.sends).toEqual([]);
    const open = await reconcileAttempt(clients, first.attempt);
    expect(open.outcome).toBe('unknown');
    expect(replaceable(open)).toBe(false);

    // Observed: once rounds pass its last valid round, every round is read.
    await advance(5);
    const passed = await reconcileAttempt(clients, first.attempt);
    expect(passed).toMatchObject({ outcome: 'expired', nonInclusion: true, source: 'algod-block' });
    expect(replaceable(passed)).toBe(true);

    // The old bytes can no longer land.
    const late = await sendAttempt(clients, first, signed);
    expect(late).toMatchObject({ status: 'rejected' });
    expect((late as { reason: string }).reason).toMatch(/txn dead/);

    // A replacement is a new attempt with a new id, and lands once.
    const second = await prepareFunding(clients, { address: account.address }, target.address);
    expect(second.attempt.txId).not.toBe(first.attempt.txId);
    await submitAndConfirm(clients, second, account.signer);
    expect(await balance(target.address)).toBe(FUNDED);
  });

  it('after a confirmed rekey, a lost verification proof is confirmed by reconciliation, never re-sent', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    const run = async (p: Promise<PreparedTransaction>, signer: algosdk.TransactionSigner) =>
      submitAndConfirm(clients, await p, signer);
    await run(prepareFunding(clients, { address: account.address }, target.address), account.signer);
    await run(prepareProof(clients, target.address), makeFalconSigner(target));
    await run(prepareRekey(clients, { address: account.address }, target.address), account.signer);
    expect((await readAuthority(clients, account.address)).authority).toBe(target.address);

    // Injected: the proof's response is lost.
    const lossy = injected({ loseSendResponse: true });
    const proof = await prepareControlProof(lossy.clients, account.address, target.address);
    const signed = await signAttempt(proof, makeFalconSigner(target, account.address));
    expect((await sendAttempt(lossy.clients, proof, signed)).status).toBe('unknown');

    // Observed: it confirmed, and reconciling again and again sends nothing.
    const watching = injected({});
    for (let i = 0; i < 3; i++) {
      expect(await reconcileAttempt(watching.clients, proof.attempt)).toMatchObject({ outcome: 'confirmed' });
    }
    expect(watching.sends).toEqual([]);
  });

  it('a stale signer is refused by the ledger after the rekey: the old key cannot fund again', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const target = generatePqIdentity();
    await submitAndConfirm(clients, await prepareRekey(clients, { address: account.address }, target.address), account.signer);
    // The recorded authorizer no longer controls the account. The budget says
    // so before anything is signed...
    const stale = { sender: account.address, authorizer: account.address, target: target.address, signer: ED25519_BY_PHRASE };
    expect((await quoteMigration(clients, stale)).problems.join(' ')).toContain(`answers to ${target.address}`);
    // ...and the ledger refuses a transaction signed by it regardless.
    const funding = await prepareFunding(clients, { address: account.address, authorizer: account.address }, target.address, FUNDED);
    const sent = await sendAttempt(clients, funding, await signAttempt(funding, account.signer));
    expect(sent).toMatchObject({ status: 'rejected' });
    expect((sent as { reason: string }).reason).toMatch(/should have been authorized by/);
  });
});
