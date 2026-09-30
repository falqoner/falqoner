/**
 * Migration engine.
 *
 * Migrating an Algorand account to post-quantum authority is a single rekey
 * transaction, which makes it deceptively easy to get catastrophically wrong:
 * if the Falcon key behind the target address is not recoverable, the account
 * is bricked permanently and there is no appeal.
 *
 * Planning and preflight here are read-only. Everything below them that
 * prepares, signs or sends is a low-level primitive: each handles one
 * transaction, and none of them makes a migration safe, because none knows
 * whether the steps before it ran or confirmed. A migration is executed
 * through the guarded ceremony (ceremony.ts), which puts the rekey after a
 * confirmed proof and checks everything else each step needs. The product's
 * own execution uses only that.
 */
import algosdk from 'algosdk';
import type {
  AccountExposure,
  MigrationPlan,
  MigrationStep,
  PqIdentity,
} from './types.js';
import {
  isHashDerivedAddress,
  makeFalconSigner,
  pqIdentityFromMnemonic,
  selfTestIdentity,
} from './falcon.js';
import { formatAlgos } from './exposure.js';
import type { FalconerClients } from './networks.js';
import {
  prepareAttempt,
  readAuthority,
  signAttempt,
  submitAndConfirm,
  type PrepareOptions,
  type PreparedTransaction,
  type SubmissionStage,
} from './submission.js';
import {
  preparedMismatch,
  quoteMigration,
  quoteStage,
  signedMismatch,
  signerFromAuthority,
  stageOf,
  unavailableBudget,
  type MigrationBudget,
  type SignatureScheme,
  type StageBudget,
} from './budget.js';

export interface PlanOptions {
  /** Run the on-chain proof-of-control drill before rekeying. */
  drill?: boolean;
  /**
   * What the migration costs, computed from live inputs (see budget.ts).
   * Without it the plan describes the steps and states no costs.
   */
  budget?: MigrationBudget;
}

/** Why a plan cannot be approved as it stands, or null. */
export function planProblem(plan: MigrationPlan): string | null {
  if (plan.blockers.length) return plan.blockers[0]!;
  if (plan.budget.status !== 'available') {
    return `The budget is ${plan.budget.status}: ${plan.budget.problems.join(' ') || 'nothing was read.'}`;
  }
  return null;
}

/**
 * Describe what migrating this account will take, what it will cost, and what
 * could go wrong, without sending anything.
 */
export function planMigration(
  exposure: AccountExposure,
  targetAuthAddr: string,
  options: PlanOptions = {},
): MigrationPlan {
  const drill = options.drill ?? true;
  const steps: MigrationStep[] = [];
  const warnings: string[] = [];
  const blockers: string[] = [];

  const authorizer = exposure.authAddr ?? exposure.address;
  const spec = {
    sender: exposure.address,
    authorizer,
    target: targetAuthAddr,
    signer: signerFromAuthority(exposure.authority, authorizer),
    drill,
  };
  let budget =
    options.budget ??
    unavailableBudget(spec, [
      'No live network parameters, balances or minimum balances were read, so no costs are stated.',
    ]);
  const b = budget.spec;
  if (b.sender !== spec.sender || b.authorizer !== spec.authorizer || b.target !== spec.target || b.drill !== drill) {
    budget = unavailableBudget(spec, ['The budget given is for a different migration.']);
  }
  const priced = (stage: SubmissionStage): StageBudget | null =>
    budget.status === 'unavailable' ? null : budget.stages.find((s) => s.stage === stage) ?? null;

  if (!algosdk.isValidAddress(targetAuthAddr)) {
    blockers.push(`Target address ${targetAuthAddr} is not a valid Algorand address.`);
  } else if (!isHashDerivedAddress(targetAuthAddr)) {
    // A Falcon address is always off-curve. An on-curve target means someone
    // pasted a classical address, which would migrate to no added safety.
    blockers.push(
      'The target address is a point on the Ed25519 curve, so it is not a ' +
        'post-quantum address. Rekeying to it would leave the account exactly ' +
        'as exposed as it is now.',
    );
  }

  if (targetAuthAddr === exposure.address) {
    blockers.push('An account cannot be rekeyed to itself.');
  }

  if (exposure.authAddr && targetAuthAddr === exposure.authAddr) {
    blockers.push(
      "The target address is already this account's authority. Rekeying to " +
        'it would change nothing, and would still spend the drill funding ' +
        'and the migration fees.',
    );
  } else if (exposure.authAddr) {
    // Fires for any existing authority, not only a proven post-quantum one.
    // An account sitting on an unproven hash-derived authority is exactly
    // the case where replacing it silently would be worst.
    warnings.push(
      exposure.isPostQuantum
        ? 'This account is already under post-quantum authority, on a ' +
          'provider-confirmed record. ' +
          'Migrating again replaces it, and the existing Falcon key stops ' +
          'being able to sign for this account.'
        : `This account is already rekeyed to ${exposure.authAddr}. That ` +
          "authority has to sign the rekey, not the account's own key, and " +
          'it stops being able to sign for this account afterwards.',
    );
  }

  let index = 1;
  if (drill) {
    const funding = priced('funding');
    const proof = priced('proof');
    steps.push({
      index: index++,
      kind: 'fund',
      title: 'Fund the post-quantum address',
      detail: !funding
        ? `Send ${targetAuthAddr} what it lacks to exist and to pay for its own ` +
          'proof-of-control transaction. The amount is worked out from live balances, ' +
          'and none were read for this plan.'
        : funding.amount === 0n
          ? `Send nothing to ${targetAuthAddr}: it already holds enough to pay for its ` +
            'own proof-of-control transaction. The payment keeps the steps in order, ' +
            'and only its fee is spent.'
          : `Send ${formatAlgos(funding.amount)} ALGO to ${targetAuthAddr}: what it lacks ` +
            'to keep its minimum balance and pay for its own proof-of-control transaction' +
            (budget.totals && budget.totals.reserve > 0n
              ? `, including a reserve of ${formatAlgos(budget.totals.reserve)} ALGO.`
              : '.') +
            ' It stays at that address, movable only with its 25 words.',
      feeMicroAlgos: funding?.fee ?? null,
    });
    steps.push({
      index: index++,
      kind: 'verify',
      title: 'Prove the Falcon key works on-chain',
      detail:
        'The new address sends a zero-value payment to itself, signed with ' +
        'the Falcon-1024 key, and pays its fee from what it holds. If this ' +
        'confirms, the network accepts the key and the phrase behind it is ' +
        'known to work. Nothing is at stake yet, because the account has not ' +
        'been rekeyed.',
      feeMicroAlgos: proof?.fee ?? null,
    });
  }

  const incomingCount = exposure.controlsAccounts.length;
  // When the search for them did not finish, the count found is a floor.
  const incomingSearch = exposure.coverage?.incoming;
  const atLeast = incomingSearch && !incomingSearch.exhausted ? 'at least ' : '';
  steps.push({
    index: index++,
    kind: 'rekey',
    title: 'Rekey the account',
    detail:
      `Transfer signing authority for ${exposure.address} to ${targetAuthAddr}. ` +
      'The address does not change. Balances, asset opt-ins, application ' +
      'state and every role this address holds carry over untouched.' +
      (incomingCount
        ? ` It does not move the ${atLeast}${incomingCount} account` +
          `${incomingCount === 1 ? '' : 's'} rekeyed to this address; see ` +
          'the note below.'
        : ''),
    feeMicroAlgos: priced('rekey')?.fee ?? null,
  });

  steps.push({
    index: index++,
    kind: 'verify',
    title: 'Confirm the new authority',
    detail:
      'Re-read the account and check auth-addr, then send one Falcon-signed ' +
      'zero-value payment from the migrated account to prove control. The ' +
      'account pays its fee.',
    feeMicroAlgos: priced('verification')?.fee ?? null,
  });

  // Affordability is the budget's to say, from live balances and minimums.
  if (budget.status === 'blocked') blockers.push(...budget.problems);

  const roleCount =
    exposure.createdAssets.length + exposure.foreignRoles.length;
  if (roleCount > 0) {
    warnings.push(
      `This address holds roles on ${roleCount} asset${roleCount === 1 ? '' : 's'}. ` +
        'Those roles reference the address, not the key, so the rekey carries ' +
        'them over automatically. No asset reconfiguration is required.',
    );
  }

  if (incomingCount) {
    // They do not follow. Algorand checks a signature against the sender's
    // auth-addr and never follows that address's own auth-addr, so after this
    // rekey they are still authorised by the key behind this address. Saying
    // otherwise invites someone to discard the one key that can still sign
    // for them. Their migration is theirs to plan: nothing here automates it.
    const exposed =
      exposure.incoming?.filter((i) => !i.authority.quantumSafe).length ??
      incomingCount;
    const plural = incomingCount === 1 ? '' : 's';
    warnings.push(
      `${atLeast ? 'At least ' : ''}${incomingCount} other account${plural} ` +
        `${incomingCount === 1 ? 'is' : 'are'} rekeyed to this address and ` +
        `will not follow this migration. Algorand checks their signatures ` +
        `against ${exposure.address} itself and never follows that ` +
        'address’s own rekey, so after this rekey they are still ' +
        `authorised by the key behind ${exposure.address}` +
        (exposed
          ? `, and ${exposed} of them ${exposed === 1 ? 'remains' : 'remain'} ` +
            'exposed'
          : '') +
        '. Each needs its own rekey, signed by that key, so keep it: it is ' +
        'the only thing that can sign for them.',
    );
  }

  if (incomingSearch && incomingSearch.status !== 'complete') {
    warnings.push(
      'The search for accounts rekeyed to this address did not finish. ' +
        `${incomingSearch.detail} Any it missed are not in this plan: each is ` +
        'still signed for by the key behind this address, and needs its own ' +
        'rekey.',
    );
  }

  // Application relationships are references. What they permit is up to
  // each program, which is not analysed, so the plan promises nothing about
  // them either way.
  const appReferences = exposure.reach?.appReferences ?? 0;
  if (appReferences) {
    warnings.push(
      `This address created, or is named in the state of, ${appReferences} ` +
        `application${appReferences === 1 ? '' : 's'}. Falconer does not ` +
        'analyse application programs, so it has not established what they ' +
        'allow this address to do, or whether any of it depends on more than ' +
        'the address, which the rekey keeps. Check each program before ' +
        'relying on it after the migration.',
    );
  }

  warnings.push(
    'A rekey lives in the account ledger record, not in the address. If ' +
      'this account is ever closed out, the record is deleted and funding ' +
      'the address again recreates it under the original Ed25519 key. ' +
      'Migrating does not make a close-out safe.',
  );

  const verification = priced('verification');
  warnings.push(
    budget.observed && budget.postMigrationFee !== null
      ? 'After migration every transaction from this account is Falcon-signed. ' +
          `At the parameters read in round ${budget.observed.round}, a zero-value payment ` +
          `from it needs ${formatAlgos(budget.postMigrationFee)} ALGO, where an ` +
          `Ed25519-signed one needs ${formatAlgos(budget.observed.minFee)} ALGO: consensus ` +
          `${budget.observed.rules} adds twice the minimum fee for a Falcon-1024 signature, ` +
          'and a congested network charges each transaction by its signed length' +
          (verification ? `, up to ${verification.feeQuote.maxSignedBytes} bytes for that payment.` : '.') +
          ' Larger transactions cost more, and tools that assume the classical minimum are refused.'
      : 'After migration every transaction from this account is Falcon-signed, which ' +
          'Algorand charges three times the minimum fee, and more by its signed length ' +
          'when the network is congested. No live parameters were read, so no figure is given.',
  );

  return {
    address: exposure.address,
    targetAuthAddr,
    steps,
    estimatedFeeMicroAlgos: budget.totals?.feeExpense ?? null,
    postMigrationFeeMicroAlgos: budget.postMigrationFee,
    budget,
    warnings,
    blockers,
  };
}

/* ------------------------------------------------------------------ */
/* Pre-flight checks that run entirely offline                         */
/* ------------------------------------------------------------------ */

export interface PreflightResult {
  /** Every check that was actually performed passed. */
  ok: boolean;
  /**
   * A phrase the operator typed back was re-derived and matched the
   * identity. False also means "not checked" - callers about to rekey must
   * require this, because `ok` alone says nothing about what was written
   * down.
   */
  transcriptionConfirmed: boolean;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
}

/**
 * Verify, without touching the network, that an identity is sound and that
 * its written-down phrase really does reproduce it.
 *
 * `transcribedMnemonic` must be what the operator typed back from what they
 * wrote down, never `identity.mnemonic`. The phrase is re-derived from
 * scratch, so a mis-transcription fails here rather than after the funds are
 * already behind it - but only if the caller supplies the transcription.
 * Omit it and the check is reported as not performed, never as passed.
 */
export function preflight(
  identity: PqIdentity,
  transcribedMnemonic?: string,
): PreflightResult {
  const checks: PreflightResult['checks'] = [];

  const signs = selfTestIdentity(identity);
  checks.push({
    name: 'Falcon key signs and verifies',
    passed: signs,
    detail: signs
      ? 'The key produced a valid Falcon-1024 signature.'
      : 'The key could not produce a verifiable signature.',
  });

  const offCurve = isHashDerivedAddress(identity.address);
  checks.push({
    name: 'Address is off-curve',
    passed: offCurve,
    detail: offCurve
      ? 'No Ed25519 private key can ever authorise this address.'
      : 'The address is on the Ed25519 curve, which must never happen.',
  });

  // Passing the identity's own in-memory phrase here would make this check
  // a tautology: it re-derives the exact string that was just displayed and
  // can never fail. It only means anything when the operator types the
  // phrase back from what they wrote down, so an absent transcription is
  // reported as not performed rather than quietly passed.
  const transcription = transcribedMnemonic?.trim();
  if (!transcription) {
    checks.push({
      name: 'Recovery phrase reproduces the key',
      passed: false,
      detail:
        'Not checked. Type the written-down phrase back to confirm it ' +
        'before anything depends on this key.',
    });
    return {
      ok: checks.slice(0, -1).every((c) => c.passed),
      transcriptionConfirmed: false,
      checks,
    };
  }

  let restores = false;
  let restoredAddress = '';
  try {
    restoredAddress = pqIdentityFromMnemonic(transcription).address;
    restores = restoredAddress === identity.address;
  } catch {
    restores = false;
  }
  checks.push({
    name: 'Recovery phrase reproduces the key',
    passed: restores,
    detail: restores
      ? 'Re-deriving from the phrase produced the same address.'
      : restoredAddress
        ? `The phrase derives ${restoredAddress}, not ${identity.address}.`
        : 'The phrase could not be decoded.',
  });

  return {
    ok: checks.every((c) => c.passed),
    transcriptionConfirmed: restores,
    checks,
  };
}

/* ------------------------------------------------------------------ */
/* Preparing each step                                                 */
/* ------------------------------------------------------------------ */

/*
 * Each step is prepared before anything is signed or sent, so its id and
 * validity window are known first (see submission.ts). A step is prepared
 * from its budget (budget.ts): the budget says its fee and amount, and the
 * prepared transaction is checked against it before anything is signed.
 *
 * The `prepare*` helpers below price a single step from the network's current
 * parameters, for callers that keep no approved budget; the helpers further
 * down sign, send and wait on them. All of them are low-level primitives: the
 * ceremony (ceremony.ts) uses `prepareStage` and `signStage` with the budget
 * the operator approved, after its own checks.
 */

function refuseRekeyTarget(address: string, targetAuthAddr: string): void {
  if (!isHashDerivedAddress(targetAuthAddr)) {
    throw new Error(
      'Refusing to rekey: the target address is a point on the Ed25519 ' +
        'curve and therefore is not a post-quantum address.',
    );
  }
  if (targetAuthAddr === address) {
    throw new Error('Refusing to rekey: an account cannot be rekeyed to itself.');
  }
}

/**
 * The transaction `stage` budgets for, built from the node's parameters.
 * Refused, with nothing signed, unless it is exactly what the budget allows
 * on the network it was read on.
 */
export async function prepareStage(
  clients: FalconerClients,
  stage: StageBudget,
  options: PrepareOptions = {},
): Promise<PreparedTransaction> {
  if (stage.stage === 'rekey') refuseRekeyTarget(stage.sender, stage.rekeyTo ?? '');
  const prepared = await prepareAttempt(
    clients,
    {
      stage: stage.stage,
      sender: stage.sender,
      authorizer: stage.authorizer,
      receiver: stage.receiver,
      amount: stage.amount,
      fee: stage.fee,
      rekeyTo: stage.rekeyTo,
    },
    { ...options, genesis: options.genesis ?? stage.genesis },
  );
  const why = preparedMismatch(prepared.attempt, stage);
  if (why) throw new Error(`${why} Nothing was signed.`);
  return prepared;
}

/**
 * `signer`, refusing to hand back a signature that `stage`'s budget does not
 * cover: another scheme, another fee, or a signed length its fee does not pay
 * for. The refusal is thrown before anything can be sent.
 */
export function budgetedSigner(
  signer: algosdk.TransactionSigner,
  stage: StageBudget,
): algosdk.TransactionSigner {
  return async (group, indexes) => {
    const out = await signer(group, indexes);
    for (const signed of out) {
      const why = signedMismatch(signed, stage);
      if (why) throw new Error(`${why} Nothing was sent.`);
    }
    return out;
  };
}

/** Sign a prepared step, holding the signature to its budget. */
export function signStage(
  prepared: PreparedTransaction,
  signer: algosdk.TransactionSigner,
  stage: StageBudget,
  options: { bindAuthorizer?: boolean } = {},
): Promise<Uint8Array> {
  return signAttempt(prepared, budgetedSigner(signer, stage), options);
}

/** The account being migrated, and whose key signs for it now. */
export interface MigratingAccount {
  address: string;
  /** Whose key signs. When not given, the authority the node reports now. */
  authorizer?: string;
  /** What that key is. When not given, Ed25519 for an on-curve address; anything else is refused. */
  scheme?: SignatureScheme;
}

/** Who signs for `from`, and with what: as given, or as the node and the address shape say. */
async function signerOf(
  clients: FalconerClients,
  from: MigratingAccount,
  options?: PrepareOptions,
): Promise<{ authorizer: string; scheme: SignatureScheme }> {
  const authorizer =
    from.authorizer ??
    (await readAuthority(clients, from.address, { requestTimeoutMs: options?.requestTimeoutMs })).authority;
  if (from.scheme) return { authorizer, scheme: from.scheme };
  const support = signerFromAuthority(undefined, authorizer);
  if (!support.supported) throw new Error(`${support.reason} Nothing was prepared.`);
  return { authorizer, scheme: support.scheme };
}

async function fundingStage(
  clients: FalconerClients,
  from: MigratingAccount,
  pqAddress: string,
  amount: bigint | undefined,
  options?: PrepareOptions,
): Promise<StageBudget> {
  const { authorizer, scheme } = await signerOf(clients, from, options);
  if (amount !== undefined) {
    return quoteStage(
      clients,
      { stage: 'funding', sender: from.address, authorizer, receiver: pqAddress, rekeyTo: null, scheme, amount },
      options,
    );
  }
  // What the target lacks, from the whole budget: refused unless affordable.
  const budget = await quoteMigration(
    clients,
    {
      sender: from.address,
      authorizer,
      target: pqAddress,
      signer: { supported: true, scheme, basis: 'As the caller says.' },
    },
    { requestTimeoutMs: options?.requestTimeoutMs },
  );
  return stageOf(budget, 'funding');
}

/**
 * The funding payment to the post-quantum address, signed by the account's
 * authority. Without an amount, it sends what the budget says the address
 * lacks, and is refused unless the whole migration is affordable.
 */
export async function prepareFunding(
  clients: FalconerClients,
  from: MigratingAccount,
  pqAddress: string,
  amount?: bigint,
  options?: PrepareOptions,
): Promise<PreparedTransaction> {
  return prepareStage(clients, await fundingStage(clients, from, pqAddress, amount, options), options);
}

const proofStage = (clients: FalconerClients, pqAddress: string, options?: PrepareOptions) =>
  quoteStage(
    clients,
    { stage: 'proof', sender: pqAddress, authorizer: pqAddress, receiver: pqAddress, rekeyTo: null, scheme: 'falcon-1024', amount: 0n },
    options,
  );

/** The drill: a zero-value self-payment from the post-quantum address, signed by its Falcon key. */
export async function prepareProof(
  clients: FalconerClients,
  pqAddress: string,
  options?: PrepareOptions,
): Promise<PreparedTransaction> {
  return prepareStage(clients, await proofStage(clients, pqAddress, options), options);
}

async function rekeyStage(
  clients: FalconerClients,
  account: MigratingAccount,
  targetAuthAddr: string,
  options?: PrepareOptions,
): Promise<StageBudget> {
  refuseRekeyTarget(account.address, targetAuthAddr);
  const { authorizer, scheme } = await signerOf(clients, account, options);
  return quoteStage(
    clients,
    { stage: 'rekey', sender: account.address, authorizer, receiver: account.address, rekeyTo: targetAuthAddr, scheme, amount: 0n },
    options,
  );
}

/** The rekey, signed by the account's current authority. */
export async function prepareRekey(
  clients: FalconerClients,
  account: MigratingAccount,
  targetAuthAddr: string,
  options?: PrepareOptions,
): Promise<PreparedTransaction> {
  return prepareStage(clients, await rekeyStage(clients, account, targetAuthAddr, options), options);
}

const controlProofStage = (clients: FalconerClients, address: string, pqAddress: string, options?: PrepareOptions) =>
  quoteStage(
    clients,
    { stage: 'verification', sender: address, authorizer: pqAddress, receiver: address, rekeyTo: null, scheme: 'falcon-1024', amount: 0n },
    options,
  );

/**
 * Verification's proof: a zero-value self-payment from the migrated account,
 * signed by the Falcon key it is now rekeyed to.
 */
export async function prepareControlProof(
  clients: FalconerClients,
  address: string,
  pqAddress: string,
  options?: PrepareOptions,
): Promise<PreparedTransaction> {
  return prepareStage(clients, await controlProofStage(clients, address, pqAddress, options), options);
}

/* ------------------------------------------------------------------ */
/* On-chain operations                                                 */
/* ------------------------------------------------------------------ */

/*
 * Low-level primitives, kept for tests and tooling. Each signs and sends one
 * step with no knowledge of the others: `rekeyToPq` does not check that any
 * proof ran, and none of them records an attempt before sending. They do not
 * establish a safe migration; `openCeremony` does.
 */

/**
 * Fund the post-quantum address so it can pay for its own drill transaction.
 * Without an amount, it sends what the budget says the address lacks.
 */
export async function fundPqAddress(
  clients: FalconerClients,
  from: MigratingAccount & { signer: algosdk.TransactionSigner },
  pqAddress: string,
  amount?: bigint,
) {
  const stage = await fundingStage(clients, from, pqAddress, amount);
  const prepared = await prepareStage(clients, stage);
  // The signer is the authority the node reported, or the one the caller
  // named; it is not bound to the attempt here, but its signature is held
  // to the budget.
  return submitAndConfirm(clients, prepared, budgetedSigner(from.signer, stage), { bindAuthorizer: false });
}

/**
 * Prove on-chain that the Falcon key can authorise transactions, before any
 * account depends on it.
 *
 * The post-quantum address sends a zero-value payment to itself. It is a real
 * transaction validated by real consensus, so a pass here means the key,
 * the address derivation and the signature encoding are all correct.
 */
export async function proveControl(
  clients: FalconerClients,
  identity: PqIdentity,
): Promise<{ txId: string; confirmedRound: bigint }> {
  const stage = await proofStage(clients, identity.address);
  const prepared = await prepareStage(clients, stage);
  return submitAndConfirm(clients, prepared, budgetedSigner(makeFalconSigner(identity), stage));
}

/**
 * Hand signing authority for `address` to a post-quantum address.
 *
 * This is the irreversible step. It is signed by the account's current
 * authority, which is the last time that key signs for this account. It is
 * not necessarily the last time that key is needed: any account rekeyed to
 * this address is still authorised by the key behind the address, and moves
 * only with its own rekey.
 */
export async function rekeyToPq(
  clients: FalconerClients,
  account: MigratingAccount & { signer: algosdk.TransactionSigner },
  targetAuthAddr: string,
): Promise<{ txId: string; confirmedRound: bigint }> {
  const stage = await rekeyStage(clients, account, targetAuthAddr);
  const prepared = await prepareStage(clients, stage);
  return submitAndConfirm(clients, prepared, budgetedSigner(account.signer, stage), { bindAuthorizer: false });
}

export interface VerificationResult {
  authAddrMatches: boolean;
  observedAuthAddr?: string;
  controlProven: boolean;
  proofTxId?: string;
  detail: string;
}

/**
 * Confirm a migration landed: the ledger reports the new authority, and the
 * Falcon key can actually move the migrated account.
 *
 * Not read-only: when the authority matches, this sends a Falcon-signed
 * proof from the account. Recovery and status checks use `readAuthority`
 * and `reconcileAttempt` instead.
 */
export async function verifyMigration(
  clients: FalconerClients,
  address: string,
  identity: PqIdentity,
): Promise<VerificationResult> {
  const info: any = await clients.algod.accountInformation(address).do();
  const observed = info.authAddr?.toString?.() ?? info.authAddr;
  const authAddrMatches = observed === identity.address;

  if (!authAddrMatches) {
    return {
      authAddrMatches: false,
      observedAuthAddr: observed,
      controlProven: false,
      detail: observed
        ? `Account authority is ${observed}, not ${identity.address}.`
        : 'Account still has no auth-addr; the rekey did not take effect.',
    };
  }

  try {
    const stage = await controlProofStage(clients, address, identity.address);
    const prepared = await prepareStage(clients, stage);
    const signer = budgetedSigner(makeFalconSigner(identity, address), stage);
    const { txId } = await submitAndConfirm(clients, prepared, signer);
    return {
      authAddrMatches: true,
      observedAuthAddr: observed,
      controlProven: true,
      proofTxId: txId,
      detail:
        'Ledger reports the post-quantum authority, and a Falcon-signed ' +
        'transaction from the account was accepted.',
    };
  } catch (err: any) {
    return {
      authAddrMatches: true,
      observedAuthAddr: observed,
      controlProven: false,
      detail:
        'auth-addr is correct but the Falcon key could not move the ' +
        `account: ${String(err?.message ?? err).slice(0, 200)}`,
    };
  }
}
