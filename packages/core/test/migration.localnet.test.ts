/**
 * End-to-end migration against a real Algorand node.
 *
 * These tests need LocalNet running (npm run localnet:start) on algod 5.0+,
 * which is the first release with native Falcon-1024 accounts. They are
 * required, not optional: `test/localnet.globalSetup.ts` checks every
 * prerequisite before this file is imported and fails the run when one is
 * missing, so an unreachable node can never be reported as a pass.
 *
 * Run them with `npm run test:localnet` (or `npm run test:all`), which selects
 * `vitest.localnet.config.ts`. The offline suite excludes this file.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import algosdk from 'algosdk';
import {
  analyzeAccount,
  generatePqIdentity,
  preflight,
  planMigration,
  fundPqAddress,
  proveControl,
  rekeyToPq,
  verifyMigration,
  makeFalconSigner,
  isHashDerivedAddress,
  assessRisk,
  quoteMigration,
  signerFromAuthority,
} from '../src/index.js';
import type { FalconerClients } from '../src/index.js';

/**
 * What consensus v42 charges on LocalNet, with no congestion: the minimum
 * fee, and three times it for a Falcon-1024 signature. Expected values the
 * budget is checked against, never used to price anything.
 */
const ED25519_FEE = 1000n;
const FALCON_FEE = 3000n;
import {
  localnet,
  dispenser,
  fundedAccount,
  createAsset,
  rekey,
  waitForIndexer,
  waitForIndexedTxn,
  waitForIncoming,
  waitForProvenAuthority,
  type LocalAccount,
} from './helpers.js';
import { createAppNaming, IMMUTABLE_APPROVAL } from './helpers.app.js';

let nonce = 0;
/** A unique note, so two otherwise identical attempts are distinct txns. */
const unique = () =>
  new TextEncoder().encode(`falconer-direct-${Date.now()}-${nonce++}`);

/** Submit a zero-value self-payment from `sender`, signed by `signer`. */
async function zeroPay(
  clients: FalconerClients,
  sender: string,
  signer: algosdk.TransactionSigner,
  fee: bigint,
): Promise<string> {
  const sp = await clients.algod.getTransactionParams().do();
  sp.flatFee = true;
  sp.fee = fee;
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender,
    receiver: sender,
    amount: 0,
    note: unique(),
    suggestedParams: sp,
  });
  const { txid } = await clients.algod
    .sendRawTransaction(await signer([txn], [0]))
    .do();
  await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return txid;
}

/** Exercise an asset's manager role: a config sent by `sender`. */
async function reconfigure(
  clients: FalconerClients,
  sender: string,
  assetIndex: bigint,
  signer: algosdk.TransactionSigner,
  fee: bigint,
): Promise<string> {
  const sp = await clients.algod.getTransactionParams().do();
  sp.flatFee = true;
  sp.fee = fee;
  const txn = algosdk.makeAssetConfigTxnWithSuggestedParamsFromObject({
    sender,
    assetIndex,
    manager: sender,
    reserve: sender,
    freeze: sender,
    clawback: sender,
    strictEmptyAddressChecking: false,
    note: unique(),
    suggestedParams: sp,
  });
  const { txid } = await clients.algod
    .sendRawTransaction(await signer([txn], [0]))
    .do();
  await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return txid;
}

/**
 * Require the ledger to reject a transaction *for its authoriser* - naming
 * exactly which authoriser it wanted and which one it got. A rejection for
 * fees, funds or a stale round would not match, so it cannot pass as proof
 * that a key has no authority.
 */
async function rejectedForAuthority(
  attempt: Promise<unknown>,
  expected: string,
  actual: string,
): Promise<void> {
  const outcome = await attempt.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(outcome, 'the ledger accepted a transaction it should reject').toBeDefined();
  const message = String((outcome as Error)?.message ?? outcome);
  const m =
    /should have been authorized by ([A-Z2-7]{58}) but was actually authorized by ([A-Z2-7]{58})/.exec(
      message,
    );
  expect(m, `not an authorisation rejection: ${message.slice(0, 300)}`).not.toBeNull();
  expect(m![1], 'authoriser the ledger required').toBe(expected);
  expect(m![2], 'authoriser the transaction carried').toBe(actual);
}

describe('migration against LocalNet', () => {
  const clients = localnet();
  let funder: LocalAccount;

  beforeAll(async () => {
    funder = await dispenser(clients);
  });

  it('finds the authority a key holds beyond its own balance', async () => {
    const owner = await fundedAccount(clients, funder, 20_000_000n);
    const assetId = await createAsset(clients, owner, { unitName: 'CLAW' });

    // A second account that hands its authority to the first.
    const satellite = await fundedAccount(clients, funder, 5_000_000n);
    await rekey(clients, satellite, owner.address);
    await waitForIndexer(clients);

    const exposure = await analyzeAccount(clients, owner.address);

    expect(exposure.isPostQuantum).toBe(false);
    expect(exposure.microAlgos).toBeGreaterThan(0n);

    const kinds = exposure.findings.map((f) => f.kind);
    expect(kinds).toContain('asa-clawback');
    expect(kinds).toContain('asa-manager');
    expect(kinds).toContain('asa-freeze');
    expect(kinds).toContain('self-custody');
    expect(kinds).toContain('controls-account');

    expect(exposure.createdAssets.map((a) => a.assetId)).toContain(assetId);
    expect(exposure.controlsAccounts).toContain(satellite.address);

    // Clawback reaches third parties, so this must read as systemic.
    expect(exposure.risk.systemic).toBe(true);
    expect(exposure.risk.band).toBe('critical');
    expect(exposure.risk.score).toBeGreaterThanOrEqual(75);

    // The satellite's balance counts as value this key controls.
    expect(exposure.risk.directMicroAlgos).toBeGreaterThan(
      exposure.microAlgos,
    );
  });

  it('treats a manager as able to seize only when clawback is live', async () => {
    const owner = await fundedAccount(clients, funder, 10_000_000n);
    // clawback explicitly unset: permanently disabled for this asset.
    await createAsset(clients, owner, { unitName: 'NOCLW', clawback: undefined });

    const exposure = await analyzeAccount(clients, owner.address);
    const manager = exposure.findings.find((f) => f.kind === 'asa-manager');

    expect(manager).toBeDefined();
    expect(exposure.findings.some((f) => f.kind === 'asa-clawback')).toBe(false);
    // Without a live clawback the manager cannot take anyone's tokens.
    expect(manager!.severity).toBe('high');
    expect(manager!.detail).toContain('permanently disabled');
    expect(exposure.risk.band).not.toBe('critical');
  });

  it('never reports a post-quantum address itself as a classical key', async () => {
    const account = await fundedAccount(clients, funder, 10_000_000n);
    const identity = generatePqIdentity();

    // The drill funds the post-quantum address, so it is a real on-chain
    // account before any rekey happens and can be scanned like any other.
    await fundPqAddress(clients, account, identity.address);
    await waitForIndexer(clients);

    const unproven = await analyzeAccount(clients, identity.address);
    expect(isHashDerivedAddress(identity.address)).toBe(true);
    expect(unproven.authority.authorityClass).toBe('unknown-hash-derived');
    expect(unproven.authority.detail).not.toContain('already fully published');

    // Once it has signed for itself, the same evidence path that proves a
    // rekeyed account proves this one.
    await proveControl(clients, identity);
    const proven = await waitForProvenAuthority(clients, identity.address);
    expect(proven.authorityClass).toBe('post-quantum');
    expect(proven.quantumSafe).toBe(true);
  });

  it('does not call clawback disabled when this key is the clawback', async () => {
    const owner = await fundedAccount(clients, funder, 10_000_000n);
    // The default ASA shape: the creator keeps every role, clawback included.
    await createAsset(clients, owner, { unitName: 'ALLRL' });

    const exposure = await analyzeAccount(clients, owner.address);
    const manager = exposure.findings.find((f) => f.kind === 'asa-manager');

    expect(manager).toBeDefined();
    // Clawback is live and pointed at this very key. Saying it is disabled
    // is the exact failure this tool exists to avoid.
    expect(manager!.detail).not.toContain('permanently disabled');
    expect(manager!.severity).toBe('critical');
    expect(exposure.findings.some((f) => f.kind === 'asa-clawback')).toBe(true);
  });

  it('migrates an account and preserves everything attached to it', async () => {
    const account = await fundedAccount(clients, funder, 30_000_000n);
    const assetId = await createAsset(clients, account, { unitName: 'KEEP' });

    const before = await analyzeAccount(clients, account.address);
    expect(before.isPostQuantum).toBe(false);

    /* --- build and check the new identity, entirely offline --------- */
    const identity = generatePqIdentity();
    const checks = preflight(identity, identity.mnemonic!);
    expect(checks.ok).toBe(true);
    expect(checks.checks.every((c) => c.passed)).toBe(true);

    const budget = await quoteMigration(clients, {
      sender: account.address,
      authorizer: account.address,
      target: identity.address,
      signer: signerFromAuthority(before.authority, account.address),
    });
    const plan = planMigration(before, identity.address, { drill: true, budget });
    expect(plan.blockers).toEqual([]);
    expect(plan.budget.status).toBe('available');
    expect(plan.steps.map((s) => s.kind)).toEqual([
      'fund',
      'verify',
      'rekey',
      'verify',
    ]);
    expect(plan.steps.map((s) => s.feeMicroAlgos)).toEqual([ED25519_FEE, FALCON_FEE, ED25519_FEE, FALCON_FEE]);
    expect(plan.postMigrationFeeMicroAlgos).toBe(FALCON_FEE);
    expect(plan.warnings.join(' ')).toContain('roles on 1 asset');

    /* --- drill: prove the key works before anything depends on it --- */
    await fundPqAddress(clients, account, identity.address);
    const proof = await proveControl(clients, identity);
    expect(proof.confirmedRound).toBeGreaterThan(0n);

    /* --- the irreversible step ------------------------------------- */
    await rekeyToPq(clients, account, identity.address);

    const verified = await verifyMigration(clients, account.address, identity);
    expect(verified.authAddrMatches).toBe(true);
    expect(verified.controlProven).toBe(true);

    /* --- nothing about the account moved --------------------------- */
    // Everything asserted here comes from algod, so it holds regardless of
    // indexer catch-up. The evidence-based classification needs the indexer
    // and is covered by its own test.
    expect(verified.proofTxId).toBeTruthy();
    const after = await analyzeAccount(clients, account.address);
    expect(after.address).toBe(before.address);
    expect(after.authAddr).toBe(identity.address);
    expect(after.assetsHeld).toBe(before.assetsHeld);
    expect(after.createdAssets.map((a) => a.assetId)).toContain(assetId);

    /* --- the old classical key is now inert ------------------------ */
    const sp = await clients.algod.getTransactionParams().do();
    const attempt = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: account.address,
      receiver: account.address,
      amount: 1,
      suggestedParams: sp,
    });
    await expect(
      clients.algod.sendRawTransaction(attempt.signTxn(account.sk)).do(),
    ).rejects.toThrow();

    /* --- and the asset role still works, now under Falcon ---------- */
    const reconfigParams = await clients.algod.getTransactionParams().do();
    reconfigParams.flatFee = true;
    reconfigParams.fee = FALCON_FEE;
    const reconfig = algosdk.makeAssetConfigTxnWithSuggestedParamsFromObject({
      sender: account.address,
      assetIndex: assetId,
      manager: account.address,
      reserve: account.address,
      freeze: account.address,
      clawback: account.address,
      strictEmptyAddressChecking: false,
      suggestedParams: reconfigParams,
    });
    const signer = makeFalconSigner(identity, account.address);
    const { txid } = await clients.algod
      .sendRawTransaction(await signer([reconfig], [0]))
      .do();
    const res = await algosdk.waitForConfirmation(clients.algod, txid, 10);
    expect(BigInt(res.confirmedRound ?? 0)).toBeGreaterThan(0n);
  });

  it('migrates an account whose authority already lives elsewhere', async () => {
    // A is rekeyed to B, a plain classical key: the rekeyed-away finding the
    // engine reports as fixedByRekey. Migrating it means B signs for A.
    const a = await fundedAccount(clients, funder, 20_000_000n);
    const b = await fundedAccount(clients, funder, 5_000_000n);
    await rekey(clients, a, b.address);
    await waitForIndexer(clients);

    const exposure = await analyzeAccount(clients, a.address);
    expect(exposure.authAddr).toBe(b.address);

    // A's own key is no longer able to authorise anything for A, so a flow
    // that insists on it cannot migrate this account at all.
    const identity = generatePqIdentity();
    await expect(rekeyToPq(clients, a, identity.address)).rejects.toThrow();

    const from = { address: a.address, signer: b.signer };
    await fundPqAddress(clients, from, identity.address);
    await proveControl(clients, identity);
    await rekeyToPq(clients, from, identity.address);

    const verified = await verifyMigration(clients, a.address, identity);
    expect(verified.authAddrMatches).toBe(true);
    expect(verified.controlProven).toBe(true);
  }, 120_000);

  it('keeps every rekey direct: migrating B neither migrates A nor lets C sign for it', async () => {
    // A is rekeyed to B, then B to a post-quantum C. Algorand checks a
    // signature against the sender's auth-addr and never follows that
    // address's own auth-addr, so B's original key must still sign for A and
    // C must not. Each authority claim below is settled by the ledger
    // accepting or rejecting a real transaction, not by Falconer's model.
    const a = await fundedAccount(clients, funder, 10_000_000n);
    const b = await fundedAccount(clients, funder, 10_000_000n);
    // An address-bound role, to show roles *do* follow B's own rekey.
    const assetId = await createAsset(clients, b, { unitName: 'BROLE' });
    await waitForIndexedTxn(clients, await rekey(clients, a, b.address));
    await waitForIncoming(clients, b.address, [a.address]);

    const c = generatePqIdentity();
    const byB = b.signer; // B's original Ed25519 key
    const byCForA = makeFalconSigner(c, a.address);
    const byCForB = makeFalconSigner(c, b.address);

    /* --- before B migrates, the plan must not promise A follows ---- */
    const bBefore = await analyzeAccount(clients, b.address);
    expect(bBefore.controlsAccounts).toEqual([a.address]);
    const bPlan = planMigration(bBefore, c.address);
    const bPlanText = bPlan.warnings.join(' ');
    expect(bPlanText).not.toMatch(/follow this migration automatically/);
    expect(bPlanText).toContain('will not follow this migration');
    expect(bPlanText).toContain(`key behind ${b.address}`);

    /* --- B -> C, signed by B's original key ------------------------ */
    await fundPqAddress(clients, b, c.address);
    await proveControl(clients, c);
    await rekeyToPq(clients, b, c.address);

    /* --- ledger: A is still authorised by B's original key, not C --- */
    await zeroPay(clients, a.address, byB, ED25519_FEE);
    await rejectedForAuthority(
      zeroPay(clients, a.address, byCForA, FALCON_FEE),
      b.address,
      c.address,
    );

    /* --- ledger: C authorises B, and B's original key no longer does - */
    const bUnderC = await zeroPay(clients, b.address, byCForB, FALCON_FEE);
    await rejectedForAuthority(
      zeroPay(clients, b.address, byB, ED25519_FEE),
      c.address,
      b.address,
    );

    /* --- ledger: B's address-bound asset role moved with B --------- */
    await reconfigure(clients, b.address, assetId, byCForB, FALCON_FEE);
    await rejectedForAuthority(
      reconfigure(clients, b.address, assetId, byB, ED25519_FEE),
      c.address,
      b.address,
    );

    /* --- reported: B is post-quantum, A is residual exposure -------- */
    await waitForIndexedTxn(clients, bUnderC);
    expect((await waitForProvenAuthority(clients, b.address)).authorityClass).toBe(
      'post-quantum',
    );
    const bReport = await analyzeAccount(clients, b.address);
    expect(bReport.authAddr).toBe(c.address);
    expect(bReport.authority.authorityClass).toBe('post-quantum');
    expect(bReport.isPostQuantum).toBe(true);

    expect(bReport.incoming).toHaveLength(1);
    const aSeenFromB = bReport.incoming[0]!;
    expect(aSeenFromB.address).toBe(a.address);
    expect(aSeenFromB.authority.authAddr).toBe(b.address);
    expect(aSeenFromB.authority.authorityClass).toBe('classical-key');
    expect(aSeenFromB.authority.quantumSafe).toBe(false);

    expect(bReport.risk.band).not.toBe('safe');
    expect(bReport.risk.residualAccounts).toBe(1);
    expect(bReport.risk.residualMicroAlgos).toBe(aSeenFromB.microAlgos);
    expect(bReport.risk.residualMicroAlgos).toBeGreaterThan(0n);

    const residual = bReport.findings.filter((f) => f.kind === 'controls-account');
    expect(residual).toHaveLength(1);
    expect(residual[0]!.accounts).toEqual([a.address]);
    expect(residual[0]!.fixedByRekey).toBe(false);
    expect(residual[0]!.microAlgos).toBe(aSeenFromB.microAlgos);
    for (const kind of ['asa-manager', 'asa-clawback'] as const) {
      const role = bReport.findings.find((f) => f.kind === kind);
      expect(role, kind).toBeDefined();
      expect(role!.fixedByRekey, kind).toBe(true);
    }

    /* --- reported: A is classical, and was not migrated by B -------- */
    const aReport = await analyzeAccount(clients, a.address);
    expect(aReport.authAddr).toBe(b.address);
    expect(aReport.authority.authorityClass).toBe('classical-key');
    expect(aReport.isPostQuantum).toBe(false);
    expect(aReport.risk.band).not.toBe('safe');
    const away = aReport.findings.find((f) => f.kind === 'rekeyed-away');
    expect(away).toBeDefined();
    expect(away!.fixedByRekey).toBe(true);
    expect(away!.detail).toContain('needs its own rekey');
    const aPlan = planMigration(aReport, c.address);
    expect(aPlan.blockers).toHaveLength(0);
    expect(aPlan.warnings.join(' ')).toContain(`already rekeyed to ${b.address}`);

    /* --- A's own, separate, explicit rekey to C -------------------- */
    // Signed by B's original key: after B's migration it is still the only
    // key that can sign for A. Nothing did this for A automatically.
    await rekeyToPq(clients, { address: a.address, signer: byB }, c.address);
    const aVerified = await verifyMigration(clients, a.address, c);
    expect(aVerified.authAddrMatches).toBe(true);
    expect(aVerified.controlProven).toBe(true);
    // The new signer works, and B's original key has now lost A.
    await rejectedForAuthority(
      zeroPay(clients, a.address, byB, ED25519_FEE),
      c.address,
      b.address,
    );

    /* --- reported after A's own migration -------------------------- */
    await waitForIndexedTxn(clients, aVerified.proofTxId!);
    expect((await waitForProvenAuthority(clients, a.address)).authorityClass).toBe(
      'post-quantum',
    );
    await waitForIncoming(clients, b.address, []);
    await waitForIncoming(clients, c.address, [a.address, b.address]);

    const aAfter = await analyzeAccount(clients, a.address);
    expect(aAfter.authAddr).toBe(c.address);
    expect(aAfter.isPostQuantum).toBe(true);

    const bAfter = await analyzeAccount(clients, b.address);
    expect(bAfter.incoming).toEqual([]);
    expect(bAfter.risk.residualAccounts).toBe(0);
    expect(bAfter.risk.band).toBe('safe');

    // C signs for itself and is proven, so it protects both directly.
    await waitForProvenAuthority(clients, c.address);
    const cReport = await analyzeAccount(clients, c.address);
    expect(cReport.isPostQuantum).toBe(true);
    expect(cReport.incoming.map((i) => i.address).sort()).toEqual(
      [a.address, b.address].sort(),
    );
    for (const i of cReport.incoming) {
      expect(i.authority.authAddr, i.address).toBe(c.address);
      expect(i.authority.authorityClass, i.address).toBe('post-quantum');
    }
    expect(cReport.risk.residualAccounts).toBe(0);
    expect(cReport.risk.band).toBe('safe');
  }, 240_000);

  it('recovers the migrated account from the phrase alone', async () => {
    const account = await fundedAccount(clients, funder, 20_000_000n);
    const identity = generatePqIdentity();
    const phrase = identity.mnemonic!;

    await fundPqAddress(clients, account, identity.address);
    await proveControl(clients, identity);
    await rekeyToPq(clients, account, identity.address);

    // Simulate a new device: nothing but the written-down phrase.
    const { pqIdentityFromMnemonic } = await import('../src/falcon.js');
    const restored = pqIdentityFromMnemonic(phrase);
    expect(restored.address).toBe(identity.address);

    const verified = await verifyMigration(clients, account.address, restored);
    expect(verified.authAddrMatches).toBe(true);
    expect(verified.controlProven).toBe(true);
  });

  it('never calls an off-curve multisig post-quantum', async () => {
    // A multisig address is a hash, so roughly half of them fall off the
    // Ed25519 curve. Those are the dangerous ones: they look exactly like a
    // post-quantum address while still being N classical keys.
    let members: ReturnType<typeof algosdk.generateAccount>[] = [];
    let msigParams: algosdk.MultisigMetadata | undefined;
    let msigAddress = '';
    for (let attempt = 0; attempt < 40; attempt++) {
      members = [
        algosdk.generateAccount(),
        algosdk.generateAccount(),
        algosdk.generateAccount(),
      ];
      const params: algosdk.MultisigMetadata = {
        version: 1,
        threshold: 2,
        addrs: members.map((m) => m.addr.toString()),
      };
      const addr = algosdk.multisigAddress(params);
      if (isHashDerivedAddress(addr.toString())) {
        msigParams = params;
        msigAddress = addr.toString();
        break;
      }
    }
    expect(msigParams, 'failed to find an off-curve multisig').toBeDefined();
    expect(isHashDerivedAddress(msigAddress)).toBe(true);

    const account = await fundedAccount(clients, funder, 10_000_000n);
    await rekey(clients, account, msigAddress);

    // Use the multisig so the chain records what kind of authority it is.
    const sp = await clients.algod.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: account.address,
      receiver: account.address,
      amount: 0,
      suggestedParams: sp,
    });
    let signed = algosdk.signMultisigTransaction(
      txn,
      msigParams!,
      members[0]!.sk,
    ).blob;
    signed = algosdk.appendSignMultisigTransaction(
      signed,
      msigParams!,
      members[1]!.sk,
    ).blob;
    const { txid } = await clients.algod.sendRawTransaction(signed).do();
    await algosdk.waitForConfirmation(clients.algod, txid, 10);
    await waitForIndexedTxn(clients, txid);

    // The safety property holds without the indexer: whatever else is
    // concluded, an off-curve multisig must never read as post-quantum.
    const exposure = await analyzeAccount(clients, account.address);
    expect(exposure.authority.quantumSafe).toBe(false);
    expect(exposure.isPostQuantum).toBe(false);
    expect(exposure.risk.band).not.toBe('safe');

    // Once the evidence is queryable it is identified precisely.
    const proven = await waitForProvenAuthority(clients, account.address);
    expect(proven.authorityClass).toBe('classical-multisig');
    expect(proven.quantumSafe).toBe(false);
  });

  it('proves post-quantum authority from the chain once indexed', async () => {
    const account = await fundedAccount(clients, funder, 20_000_000n);
    const identity = generatePqIdentity();

    await fundPqAddress(clients, account, identity.address);
    await proveControl(clients, identity);
    await rekeyToPq(clients, account, identity.address);
    const verified = await verifyMigration(clients, account.address, identity);
    expect(verified.controlProven).toBe(true);

    const proven = await waitForProvenAuthority(clients, account.address);
    expect(proven.authorityClass).toBe('post-quantum');
    expect(proven.quantumSafe).toBe(true);
    expect(proven.evidenceTxId).toBeTruthy();

    const after = await analyzeAccount(clients, account.address);
    expect(after.isPostQuantum).toBe(true);
    expect(after.risk.band).toBe('safe');
    expect(after.risk.score).toBe(0);
  });

  it('keeps proving post-quantum once the account receives traffic', async () => {
    const account = await fundedAccount(clients, funder, 20_000_000n);
    const identity = generatePqIdentity();

    await fundPqAddress(clients, account, identity.address);
    await proveControl(clients, identity);
    await rekeyToPq(clients, account, identity.address);
    await verifyMigration(clients, account.address, identity);
    await waitForIndexer(clients);
    expect((await waitForProvenAuthority(clients, account.address)).authorityClass)
      .toBe('post-quantum');

    // Ordinary inbound traffic. None of it is signed by the authority, and
    // there is more of it than the lookback window holds, so an evidence
    // query that is not scoped to the sender role returns none of the
    // transactions that prove anything.
    const sp = await clients.algod.getTransactionParams().do();
    let last = '';
    for (let i = 0; i < 60; i++) {
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: funder.address,
        receiver: account.address,
        amount: 1000n,
        note: new TextEncoder().encode('inbound-' + i),
        suggestedParams: sp,
      });
      last = (await clients.algod.sendRawTransaction(txn.signTxn(funder.sk)).do()).txid;
    }
    await algosdk.waitForConfirmation(clients.algod, last, 10);
    await waitForIndexer(clients);

    const after = await analyzeAccount(clients, account.address);
    expect(after.authority.authorityClass).toBe('post-quantum');
    expect(after.isPostQuantum).toBe(true);
    expect(after.risk.band).toBe('safe');
  }, 120_000);

  it('warns that a close-out would undo a completed migration', async () => {
    const account = await fundedAccount(clients, funder, 20_000_000n);
    const identity = generatePqIdentity();

    await fundPqAddress(clients, account, identity.address);
    await proveControl(clients, identity);
    await rekeyToPq(clients, account, identity.address);
    await verifyMigration(clients, account.address, identity);
    await waitForIndexer(clients);
    await waitForProvenAuthority(clients, account.address);

    const after = await analyzeAccount(clients, account.address);
    expect(after.isPostQuantum).toBe(true);
    // Safe, and told why that could stop being true.
    expect(after.risk.band).toBe('safe');
    const revert = after.findings.find((f) => f.kind === 'closeout-reverts');
    expect(revert).toBeDefined();
    expect(revert!.detail).toContain('Ed25519');
  }, 120_000);

  it('finds a granted role exactly when the asset is named', async () => {
    // The blind spot this exists for: Indexer does not index role
    // addresses as participants in the acfg that grants them, so there is
    // no query for assets where this account is clawback.
    const creator = await fundedAccount(clients, funder, 10_000_000n);
    const grantee = await fundedAccount(clients, funder, 5_000_000n);
    const assetId = await createAsset(clients, creator, {
      unitName: 'GRANT',
      clawback: grantee.address,
    });
    await waitForIndexer(clients);

    // The grantee created nothing and holds nothing, so a default scan has
    // no way to reach the asset and honestly says it did not look.
    const blind = await analyzeAccount(clients, grantee.address);
    expect(blind.foreignRoles).toEqual([]);
    expect(blind.findings.some((f) => f.kind === 'asa-clawback')).toBe(false);
    expect(blind.roleScan.assetsExamined).toBe(0);
    expect(blind.roleScan.detail).toContain('not searched for');

    // Named explicitly, the same role is found exactly and immediately.
    const named = await analyzeAccount(clients, grantee.address, {
      assetIds: [assetId],
    });
    expect(named.roleScan.explicitChecked).toBe(1);
    // A real algod record, as algosdk decodes it, passes the same checks a
    // malformed or wrong-id record fails (CORE-03 A-03-02).
    expect(named.coverage.assets).toMatchObject({
      status: 'complete',
      named: { requested: 1, read: 1, invalid: 0 },
      errors: [],
    });
    expect(named.foreignRoles.map((a) => a.assetId)).toContain(assetId);
    const claw = named.findings.find((f) => f.kind === 'asa-clawback');
    expect(claw).toBeDefined();
    expect(claw!.severity).toBe('critical');
    expect(named.risk.systemic).toBe(true);
  }, 120_000);

  it('checks roles on assets the account holds, without being asked', async () => {
    const creator = await fundedAccount(clients, funder, 10_000_000n);
    const grantee = await fundedAccount(clients, funder, 5_000_000n);
    const assetId = await createAsset(clients, creator, {
      unitName: 'HELD',
      clawback: grantee.address,
    });

    // The grantee opts in, which is the ordinary reason to hold a role on
    // someone else's asset in the first place.
    const sp = await clients.algod.getTransactionParams().do();
    const optIn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: grantee.address,
      receiver: grantee.address,
      amount: 0,
      assetIndex: assetId,
      suggestedParams: sp,
    });
    const { txid } = await clients.algod
      .sendRawTransaction(optIn.signTxn(grantee.sk))
      .do();
    await algosdk.waitForConfirmation(clients.algod, txid, 10);
    await waitForIndexer(clients);

    const exposure = await analyzeAccount(clients, grantee.address);
    expect(exposure.roleScan.optedInChecked).toBe(1);
    expect(exposure.coverage.assets.held).toMatchObject({ read: 1, invalid: 0 });
    expect(exposure.foreignRoles.map((a) => a.assetId)).toContain(assetId);
    expect(exposure.findings.some((f) => f.kind === 'asa-clawback')).toBe(true);
    expect(exposure.roleScan.detail).toContain('exactly');
  }, 120_000);

  it('reports a ledger sample as a sample, not as a scan', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const exposure = await analyzeAccount(clients, account.address, {
      deepScan: true,
      scanLimit: 1000,
    });
    expect(exposure.roleScan.sampled).toBeGreaterThan(0);
    expect(exposure.roleScan.detail).toContain('Sampled');
    expect(exposure.roleScan.detail).toContain('sweep in id order');
    // Real Indexer pages pass the record checks, and the sample stays within
    // both of its bounds (CORE-03 A-03-01/A-03-02).
    const sample = exposure.coverage.assets.sample;
    expect(sample).toMatchObject({ status: 'complete', errors: [], duplicates: 0 });
    expect(sample.read).toBeLessThanOrEqual(1000);
    expect(sample.requests).toBeLessThanOrEqual(sample.requestLimit);
    // Either it read its whole limit, or it reached the end of the list.
    expect(sample.read === 1000 || sample.exhaustive).toBe(true);
  }, 120_000);
  it('finds this address held as an admin in application state', async () => {
    // An app that keeps an admin address in global state hands real power
    // to an account that never created it. Following only the creator
    // relationship misses it entirely.
    const deployer = await fundedAccount(clients, funder, 10_000_000n);
    const admin = await fundedAccount(clients, funder, 5_000_000n);
    const appId = await createAppNaming(clients, deployer, admin.address);
    await waitForIndexer(clients);

    // The admin created nothing and is opted into nothing, so it has to be
    // named before the app can be read - and the report says as much.
    const blind = await analyzeAccount(clients, admin.address);
    expect(blind.appAdminRoles).toEqual([]);
    expect(blind.roleScan.appsExamined).toBe(0);
    expect(blind.roleScan.detail).toContain('app admin');

    const named = await analyzeAccount(clients, admin.address, {
      appIds: [appId],
    });
    expect(named.roleScan.appsExamined).toBe(1);
    // Real global state, decoded by algosdk, passes the entry checks.
    expect(named.coverage.apps).toMatchObject({
      status: 'complete',
      reads: { requested: 1, read: 1, invalid: 0 },
      errors: [],
    });
    expect(named.appAdminRoles).toHaveLength(1);
    expect(named.appAdminRoles[0]!.appId).toBe(appId);
    expect(named.appAdminRoles[0]!.key).toBe('admin');
    expect(named.appAdminRoles[0]!.createdByThisAccount).toBe(false);

    const finding = named.findings.find((f) => f.kind === 'app-admin');
    expect(finding).toBeDefined();
    expect(finding!.appIds).toContain(appId);
    // A reference, not a privilege (CORE-03): this program lets anyone call
    // it, so being named grants nothing Falconer could establish. No
    // permission, third-party reach or fix from a rekey is claimed, and the
    // verdict cannot be complete while it stays unverified.
    expect(named.appAdminRoles[0]!.permission).toBe('unverified');
    expect(finding!.title).toContain('permissions unverified');
    expect(finding!.fixedByRekey).toBe(false);
    expect(finding!.thirdParty).toBe(false);
    expect(named.coverage.appPermissions).toBe('unverified');
    expect(named.risk.complete).toBe(false);
    const edge = named.edges.find((e) => e.relation === 'app-admin');
    expect(edge?.basis).toBe('reference');
  }, 120_000);

  it('does not confuse the app creator with an admin named in state', async () => {
    // The deployer creates the app but is not the address in state, so it
    // gets the creator finding and no admin finding.
    const deployer = await fundedAccount(clients, funder, 10_000_000n);
    const admin = await fundedAccount(clients, funder, 5_000_000n);
    const appId = await createAppNaming(clients, deployer, admin.address);
    await waitForIndexer(clients);

    const exposure = await analyzeAccount(clients, deployer.address);
    expect(exposure.createdApps).toContain(appId);
    // Its own global state was read, and it is not the named address.
    expect(exposure.roleScan.appsExamined).toBe(1);
    expect(exposure.appAdminRoles).toEqual([]);
    expect(exposure.findings.some((f) => f.kind === 'app-admin')).toBe(false);
    const creator = exposure.findings.find((f) => f.kind === 'app-creator');
    expect(creator).toBeDefined();
    // Creating the app is a reference; its program decides everything.
    expect(creator!.title).toContain('permissions unverified');
    expect(creator!.fixedByRekey).toBe(false);
    expect(exposure.coverage.apps.status).toBe('complete');
    expect(exposure.coverage.appPermissions).toBe('unverified');
  }, 120_000);

  it('claims no privilege for the creator of an app that grants it none', async () => {
    // CORE-03: this program refuses every update and deletion, from anyone.
    // The creator can do nothing to it, and the ledger confirms that below,
    // so a report calling the creator able to update or delete it would be
    // false. Falconer does not read programs, so it claims nothing either
    // way: a reference, no points, and an incomplete verdict.
    const deployer = await fundedAccount(clients, funder, 10_000_000n);
    const appId = await createAppNaming(
      clients,
      deployer,
      deployer.address,
      'admin',
      IMMUTABLE_APPROVAL,
    );
    const sp = await clients.algod.getTransactionParams().do();
    const del = algosdk.makeApplicationDeleteTxnFromObject({
      sender: deployer.address,
      appIndex: appId,
      suggestedParams: sp,
    });
    await expect(
      clients.algod.sendRawTransaction(del.signTxn(deployer.sk)).do(),
    ).rejects.toThrow();
    await waitForIndexer(clients);

    const exposure = await analyzeAccount(clients, deployer.address);
    expect(exposure.createdApps).toContain(appId);
    const creator = exposure.findings.find((f) => f.kind === 'app-creator');
    expect(creator).toBeDefined();
    expect(creator!.detail).not.toMatch(/can (delete|update)/);
    expect(creator!.thirdParty).toBe(false);
    expect(creator!.fixedByRekey).toBe(false);
    // Named in its own app's state too: still a reference, not a role.
    expect(exposure.appAdminRoles).toEqual([
      { appId, key: 'admin', createdByThisAccount: true, permission: 'unverified' },
    ]);
    expect(exposure.risk.complete).toBe(false);
    expect(exposure.risk.uncertainties).toContain(
      '1 application reference with unverified permissions',
    );
    // Nothing is scored for it: the same account without the app scores the same.
    const withoutApp = assessRisk({
      alreadyPq: false,
      microAlgos: exposure.microAlgos,
      controlledValue: 0n,
      assetsHeld: exposure.assetsHeld,
      appCount: 0,
      seizable: 0,
      freezable: 0,
      controlsCount: 0,
    });
    expect(exposure.risk.score).toBe(withoutApp.score);
  }, 120_000);

  it('says so when it could not check, rather than implying safety', async () => {
    // With no indexer, the tool must not present silence as safety.
    const { createClients, NETWORKS } = await import('../src/networks.js');
    const noIndexer = createClients({
      ...NETWORKS.localnet,
      indexerUrl: undefined,
    });
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const identity = generatePqIdentity();
    await rekeyToPq(clients, account, identity.address);

    const exposure = await analyzeAccount(noIndexer, account.address);
    expect(exposure.authority.evidenceUnavailable).toBe(true);
    expect(exposure.authority.quantumSafe).toBe(false);
    expect(exposure.isPostQuantum).toBe(false);
    expect(exposure.authority.detail).toContain('not evidence of safety');
  });

  it('does not claim safety for an unproven hash-derived authority', async () => {
    // Rekeyed to an application address and never used since: off-curve, but
    // nothing on chain says what it is.
    let appAddress = '';
    for (let id = 1; id < 500; id++) {
      const candidate = algosdk.getApplicationAddress(id).toString();
      if (isHashDerivedAddress(candidate)) {
        appAddress = candidate;
        break;
      }
    }
    expect(appAddress).toBeTruthy();

    const account = await fundedAccount(clients, funder, 5_000_000n);
    await rekey(clients, account, appAddress);

    // The account has never transacted under this authority, so there is
    // nothing to find no matter how caught up the indexer is.
    const exposure = await analyzeAccount(clients, account.address);
    expect(exposure.authority.authorityClass).toBe('unknown-hash-derived');
    expect(exposure.authority.proven).toBe(false);
    expect(exposure.isPostQuantum).toBe(false);
    expect(exposure.findings.map((f) => f.kind)).toContain('authority-unproven');
  });

  it('refuses to rekey to a classical address', async () => {
    const account = await fundedAccount(clients, funder, 5_000_000n);
    const classical = algosdk.generateAccount().addr.toString();
    expect(isHashDerivedAddress(classical)).toBe(false);

    await expect(rekeyToPq(clients, account, classical)).rejects.toThrow(
      /not a post-quantum address/,
    );

    const exposure = await analyzeAccount(clients, account.address);
    const plan = planMigration(exposure, classical);
    expect(plan.blockers.join(' ')).toContain('Ed25519 curve');
  });

  it('blocks a migration the account cannot afford', async () => {
    const poor = await fundedAccount(clients, funder, 150_000n);
    const exposure = await analyzeAccount(clients, poor.address);
    const target = generatePqIdentity().address;
    const budget = await quoteMigration(clients, {
      sender: poor.address,
      authorizer: poor.address,
      target,
      signer: signerFromAuthority(exposure.authority, poor.address),
    });
    const plan = planMigration(exposure, target, { drill: true, budget });
    expect(plan.budget.status).toBe('blocked');
    expect(plan.blockers.join(' ')).toMatch(/minimum balance|needs/);
  });
});
