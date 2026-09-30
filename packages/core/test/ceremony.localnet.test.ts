/**
 * The guarded ceremony (SAFE-03b) against real LocalNet consensus: the four
 * stages through `openCeremony` alone, and a ceremony rebuilt from its
 * recorded attempts, as after a reload, that sends no rekey until the ledger
 * has been read to show its proof - and none for a payment recorded as the
 * proof that an Ed25519 key signed while the target answered to it.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  ED25519_BY_PHRASE,
  generatePqIdentity,
  makeFalconSigner,
  openCeremony,
  prepareAttempt,
  quoteMigration,
  readAuthority,
  submitAndConfirm,
  type AttemptSpec,
  type Ceremony,
  type PqIdentity,
  type SubmissionStage,
  type TransactionAttempt,
} from '../src/index.js';
import { dispenser, fundedAccount, localnet, type LocalAccount } from './helpers.js';

const clients = localnet();
let funder: LocalAccount;

beforeAll(async () => {
  funder = await dispenser(clients);
});

async function begin() {
  const account = await fundedAccount(clients, funder, 5_000_000n);
  const phrase = algosdk.secretKeyToMnemonic(account.sk);
  const target = generatePqIdentity();
  const init = { network: 'localnet', sender: account.address, authorizer: account.address, target: target.address };
  const ceremony = openCeremony(clients, init);
  expect(ceremony.admitKey(target, target.mnemonic!)).toBeNull();
  expect(await ceremony.pin()).toMatchObject({ genesis: { id: expect.any(String) } });
  const approved = await quoteMigration(clients, { sender: account.address, authorizer: account.address, target: target.address, signer: ED25519_BY_PHRASE });
  expect(approved.status).toBe('available');
  const journal: TransactionAttempt[] = [];
  const run = (c: Ceremony, stage: SubmissionStage) =>
    c.run(stage, { approved, signingPhrase: phrase, record: (a) => void journal.push(a) });
  return { account, phrase, target, init, ceremony, journal, run };
}

async function confirm(run: Promise<Awaited<ReturnType<Ceremony['run']>>>) {
  const r = await run;
  expect(r, r.sent ? '' : r.reason).toMatchObject({ sent: true, evidence: { outcome: 'confirmed' } });
}

describe('the guarded ceremony on LocalNet', () => {
  it('runs the four stages in order, and refuses one out of order before anything is sent', async () => {
    const { account, target, ceremony, journal, run } = await begin();
    for (const stage of ['proof', 'rekey', 'verification'] as const) {
      expect(await run(ceremony, stage)).toMatchObject({ sent: false });
    }
    expect(journal).toHaveLength(0);
    for (const stage of ['funding', 'proof', 'rekey', 'verification'] as const) await confirm(run(ceremony, stage));
    expect(journal.map((a) => a.stage)).toEqual(['funding', 'proof', 'rekey', 'verification']);
    expect((await readAuthority(clients, account.address)).authority).toBe(target.address);
    // The account paid the transfer and its three fees; nothing more.
    expect(BigInt((await clients.algod.accountInformation(account.address).do()).amount)).toBe(5_000_000n - 108_000n);
    expect(ceremony.next()).toMatchObject({ stage: null });
  });

  it('rebuilt from its record, sends no rekey until it has read the proof from the ledger itself', async () => {
    const { account, target, init, ceremony, journal, run } = await begin();
    await confirm(run(ceremony, 'funding'));
    await confirm(run(ceremony, 'proof'));

    // As after a reload: the recorded attempts, no evidence and no key.
    const again = openCeremony(clients, { ...init, genesis: ceremony.genesis()!, attempts: journal });
    expect(await again.pin()).toMatchObject({ genesis: ceremony.genesis() });
    expect(await run(again, 'rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/not settled by the ledger/) });
    await again.reconcile();
    expect(again.next()).toEqual({ stage: 'rekey', blockedBy: null });
    expect(await run(again, 'rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/key has not been admitted/) });
    expect((await readAuthority(clients, account.address)).authority).toBe(account.address);

    expect(again.admitKey(target as PqIdentity, target.mnemonic!)).toBeNull();
    await confirm(run(again, 'rekey'));
    await confirm(run(again, 'verification'));
    expect(journal.map((a) => a.stage)).toEqual(['funding', 'proof', 'rekey', 'verification']);
    expect((await readAuthority(clients, account.address)).authority).toBe(target.address);
  });

  it('refuses a payment the target made while it answered to an Ed25519 key, recorded as its proof, and sends no rekey', async ({ task }) => {
    const { account, target, init, ceremony, journal, run } = await begin();
    await confirm(run(ceremony, 'funding'));
    // Real history, not the product's: the target, topped up, is rekeyed to the
    // account's Ed25519 key, pays itself nothing with that key, and is rekeyed back.
    const t = target.address;
    const send = async (spec: AttemptSpec, signer: algosdk.TransactionSigner) =>
      submitAndConfirm(clients, await prepareAttempt(clients, spec), signer);
    const topUp = await send({ stage: 'funding', sender: funder.address, authorizer: funder.address, receiver: t, amount: 1_000_000n, fee: 1000n }, funder.signer);
    const away = await send({ stage: 'rekey', sender: t, authorizer: t, receiver: t, amount: 0n, fee: 3000n, rekeyTo: account.address }, makeFalconSigner(target));
    const prepared = await prepareAttempt(clients, { stage: 'proof', sender: t, authorizer: account.address, receiver: t, amount: 0n, fee: 1000n });
    const delegated = await submitAndConfirm(clients, prepared, account.signer);
    const back = await send({ stage: 'rekey', sender: t, authorizer: account.address, receiver: t, amount: 0n, fee: 1000n, rekeyTo: t }, account.signer);
    expect((await readAuthority(clients, t)).authority).toBe(t);

    // Recorded as the proof. The id does not cover who signed, so it is the one a proof with these fields has.
    const claimed = { ...prepared.attempt, authorizer: t };
    const again = openCeremony(clients, { ...init, genesis: ceremony.genesis()!, attempts: [journal[0]!, claimed] });
    await again.reconcile();
    expect(again.evidence()[claimed.txId]).toMatchObject({
      outcome: 'conflict',
      detail: expect.stringMatching(new RegExp(`signed by ${account.address} with an Ed25519 signature`)),
    });
    expect(again.admitKey(target, target.mnemonic!)).toBeNull();
    expect(await again.pin()).toMatchObject({ genesis: ceremony.genesis() });
    expect(await run(again, 'rekey')).toMatchObject({ sent: false, reason: expect.stringMatching(/not settled by the ledger/) });
    expect((await readAuthority(clients, account.address)).authority).toBe(account.address);
    expect(journal).toHaveLength(1);

    // Public ids, for a report to reconcile against the ledger (JSON reporter `meta`).
    const round = (r: { confirmedRound: bigint }) => Number(r.confirmedRound);
    const funding = again.evidence()[journal[0]!.txId]!;
    Object.assign(task.meta, {
      ledger: {
        account: account.address,
        target: t,
        funding: [funding.txId, Number(funding.confirmedRound)],
        topUp: [topUp.txId, round(topUp)],
        rekeyedAway: [away.txId, round(away)],
        delegatedPayment: [delegated.txId, round(delegated)],
        rekeyedBack: [back.txId, round(back)],
        reading: again.evidence()[claimed.txId]!.outcome,
      },
    });
  });
});
