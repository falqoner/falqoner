/**
 * The guarded migration ceremony (SAFE-03b): the one supported way to execute
 * a migration.
 *
 * The helpers in migrate.ts and submission.ts are low-level primitives. Each
 * prepares, signs or sends one transaction, and none knows what came before
 * it: called directly, nothing puts a confirmed proof before the rekey. A
 * `Ceremony` does. It pins the account, the authority that signs for it now,
 * the new address and the network, and sends the four stages in order, each
 * only when all of this holds at that moment:
 *
 * - The node is on a network execution is allowed on - TestNet exactly, or a
 *   private LocalNet, never MainNet whatever the label or endpoint - and on
 *   the one the ceremony was pinned to.
 * - The new key was admitted: its public key derives the target, its phrase
 *   typed back re-derives it, and it signs and verifies (`preflight`).
 * - Every attempt the ceremony knows of has been settled by its own reading
 *   of the ledger, and the stage is the next one those readings allow. A
 *   stage that confirmed is never sent again, a stage runs only after the one
 *   before it confirmed, and an attempt is replaced only once shown never to
 *   have landed. So the rekey runs only after a confirmed proof, signed by
 *   the new key, for this target on this network. A transaction id does not
 *   cover who signed it, so a proof or verification counts as confirmed only
 *   once the ledger's copy carries a Falcon-1024 signature, from a key that
 *   derives the target, that verifies over it here.
 * - The account answers to the pinned authority - to the new key, for
 *   verification - read now. Before the proof and the rekey, the target
 *   answers to its own key, read now: a proof shows the key worked then, not
 *   that it still controls the target.
 * - The funding and the rekey are signed by a single Ed25519 key whose
 *   25-word phrase derives the pinned authority. Multisig, logic-signature
 *   and post-quantum authorities are refused by name.
 * - The budget read now (budget.ts) is within the one approved. An available
 *   budget also means the node runs a consensus protocol whose Falcon-1024
 *   rules are encoded in `PROTOCOL_RULES`, with no upgrade due and no
 *   catch-up in progress: anything else blocks before signing.
 *
 * Each attempt is handed to the caller's `record` before it is sent, and a
 * `record` that throws means it is not sent (submission.ts). What the ledger
 * says is read by the ceremony itself: it takes no caller's evidence, flag or
 * label. A recovered ceremony is given public attempts only, as the
 * transactions to ask about, and each must be exactly the transaction its
 * stage sends.
 *
 * The stages are four separate transactions sent one after another, not an
 * atomic group: a run can stop between any two. This guards the product's own
 * execution; it is not a sandbox, and code holding a key can still call the
 * primitives.
 */
import algosdk from 'algosdk';
import { verifyCompressed } from 'falcon-1024';
import type { PqIdentity } from './types.js';
import { checkPqAddressBinding } from './authority.js';
import { derivePqAddress, isHashDerivedAddress, makeFalconSigner } from './falcon.js';
import type { FalconerClients } from './networks.js';
import { exceedsApproved, quoteMigration, stageOf, type MigrationBudget, type SignerSupport } from './budget.js';
import { preflight, prepareStage, signStage } from './migrate.js';
import {
  CONFIRMATION_TIMEOUT_MS,
  RECONCILE_TIMEOUT_MS,
  REQUEST_TIMEOUT_MS,
  VALIDITY_ROUNDS,
  attemptTransaction,
  awaitAttempt,
  genesisOfParams,
  publicMessage,
  readAuthority,
  reconcileAttempt,
  sendAttempt,
  withTimeout,
  type AttemptEvidence,
  type AuthorityObservation,
  type NetworkGenesis,
  type SendResult,
  type SubmissionStage,
  type TransactionAttempt,
} from './submission.js';

/** The stages, in the order they run. */
export const STAGE_ORDER: readonly SubmissionStage[] = Object.freeze(['funding', 'proof', 'rekey', 'verification']);

/* ------------------------------------------------------------------ */
/* Networks                                                            */
/* ------------------------------------------------------------------ */

const MAINNET = { id: 'mainnet-v1.0', hash: 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=' };
const TESTNET = { id: 'testnet-v1.0', hash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=' };
const PUBLIC_IDS = ['mainnet-v1.0', 'testnet-v1.0', 'betanet-v1.0'];
const PUBLIC_HASHES = [MAINNET.hash, TESTNET.hash];

/**
 * Why a node reporting `g` may not be executed on as `network`, or null.
 * TestNet must be TestNet exactly. LocalNet may be any private network, never
 * a public one: a local port can be a tunnel to MainNet. Anything else,
 * MainNet included, is refused whatever the node reports.
 */
export function genesisRefusal(network: string, g: NetworkGenesis): string | null {
  const named = `The node reports ${g.id} (${g.hash})`;
  if (network === 'testnet') {
    return g.id === TESTNET.id && g.hash === TESTNET.hash ? null : `${named}, not TestNet.`;
  }
  if (network === 'localnet') {
    return PUBLIC_IDS.includes(g.id) || PUBLIC_HASHES.includes(g.hash)
      ? `${named}, a public network, behind the LocalNet endpoint.`
      : null;
  }
  return 'Execution is limited to TestNet and LocalNet.';
}

/**
 * Clients whose transaction parameters must come from `genesis`. Every
 * transaction is prepared, and every budget read, from `getTransactionParams`,
 * so a node that changes network part-way fails before anything is signed
 * for it. Everything else is the original client.
 */
export function pinClients(clients: FalconerClients, genesis: NetworkGenesis): FalconerClients {
  const base = clients.algod;
  const algod: typeof base = Object.create(base);
  algod.getTransactionParams = () => {
    const request = base.getTransactionParams();
    return {
      do: async () => {
        const params = await request.do();
        const seen = genesisOfParams(params);
        if (seen.id !== genesis.id || seen.hash !== genesis.hash) {
          throw new Error(
            `The node now reports ${seen.id}, not ${genesis.id} as when this ` +
              'migration started. Nothing was signed for it.',
          );
        }
        return params;
      },
    } as ReturnType<typeof base.getTransactionParams>;
  };
  return Object.freeze({ ...clients, algod });
}

/* ------------------------------------------------------------------ */
/* Evidence                                                            */
/* ------------------------------------------------------------------ */

/** Whether a reading settles its attempt: a confirmation, or a full read of a passed window. */
export const isFinalEvidence = (e: AttemptEvidence): boolean =>
  e.outcome === 'confirmed' || (e.outcome === 'expired' && e.nonInclusion);

const settledAs = (e: AttemptEvidence) => (e.outcome === 'confirmed' ? 'confirmed' : 'not-included');

/**
 * `held` with `readings` added. A settling reading already held is a fact: a
 * later, weaker reading does not replace it, and a later settling reading
 * that says otherwise is a conflict.
 */
export function mergeEvidence(
  held: Readonly<Record<string, AttemptEvidence>>,
  readings: readonly AttemptEvidence[],
): { evidence: Record<string, AttemptEvidence>; conflict: string | null } {
  const evidence = { ...held };
  let conflict: string | null = null;
  for (const e of readings) {
    const prev = evidence[e.txId];
    if (prev && isFinalEvidence(prev)) {
      if (isFinalEvidence(e) && settledAs(e) !== settledAs(prev)) {
        conflict ??= `Transaction ${e.txId} was read as ${settledAs(prev)}, and later as ${settledAs(e)}.`;
      }
      continue;
    }
    evidence[e.txId] = e;
  }
  return { evidence, conflict };
}

const unknownReading = (txId: string, detail: string): AttemptEvidence =>
  Object.freeze({ txId, outcome: 'unknown', confirmedRound: null, observedRound: null, source: 'none', nonInclusion: false, detail });

/* ------------------------------------------------------------------ */
/* What each stage sends                                               */
/* ------------------------------------------------------------------ */

export interface CeremonyPin {
  /** The account being migrated. */
  readonly sender: string;
  /** Whose key signs the funding and the rekey: the account's direct authority. */
  readonly authorizer: string;
  /** The new post-quantum address. */
  readonly target: string;
}

/** Who each stage's transaction is from, to and signed by. */
export function stageShape(pin: CeremonyPin, stage: SubmissionStage) {
  switch (stage) {
    case 'funding':
      return { sender: pin.sender, authorizer: pin.authorizer, receiver: pin.target, rekeyTo: null };
    case 'proof':
      return { sender: pin.target, authorizer: pin.target, receiver: pin.target, rekeyTo: null };
    case 'rekey':
      return { sender: pin.sender, authorizer: pin.authorizer, receiver: pin.sender, rekeyTo: pin.target };
    case 'verification':
      return { sender: pin.sender, authorizer: pin.target, receiver: pin.sender, rekeyTo: null };
  }
}

/** Why `a` is not a transaction this ceremony's `stage` sends on `genesis`, or null. */
function attemptProblem(pin: CeremonyPin, genesis: NetworkGenesis, a: TransactionAttempt): string | null {
  if (!STAGE_ORDER.includes(a.stage)) return `An attempt names an unknown stage.`;
  if (a.genesisId !== genesis.id || a.genesisHash !== genesis.hash) return `${a.txId} was built for another network.`;
  const want = stageShape(pin, a.stage);
  for (const k of ['sender', 'authorizer', 'receiver', 'rekeyTo'] as const) {
    if (a[k] !== want[k]) return `${a.txId} is not the transaction its stage sends for this migration.`;
  }
  if (a.stage !== 'funding' && a.amount !== 0n) return `${a.txId} sends an amount its stage never sends.`;
  if (a.firstValid < 1n || a.lastValid < a.firstValid || a.lastValid - a.firstValid > VALIDITY_ROUNDS) {
    return `${a.txId} has an invalid validity window.`;
  }
  let id: string;
  try {
    id = attemptTransaction(a).txID();
  } catch {
    return `${a.txId} does not describe a transaction.`;
  }
  return id === a.txId ? null : `${a.txId} is not the id of the transaction its fields describe.`;
}

/* ------------------------------------------------------------------ */
/* Signed by the new key                                               */
/* ------------------------------------------------------------------ */

const FALCON = 'a post-quantum signature';
const ALGOD_KINDS = { sig: 'an Ed25519 signature', msig: 'a multisignature', lsig: 'a logic signature', pqsig: FALCON };
const INDEXER_KINDS = { sig: 'an Ed25519 signature', multisig: 'a multisignature', logicsig: 'a logic signature', pqsig: FALCON };
const kindsOf = (o: unknown, names: Record<string, string>) =>
  Object.keys(names).filter((k) => (o as Record<string, unknown> | undefined)?.[k] != null).map((k) => names[k]!);

/** How a confirmed transaction was signed, as the node's lookup or the indexer reports it. */
interface Envelope {
  readonly authorizer: string;
  readonly kinds: readonly string[];
  readonly pqsig?: { scheme?: unknown; publicKey?: unknown; salt?: unknown; signature?: unknown };
}

/**
 * Why the ledger does not show `a` signed by `target`'s own Falcon key, or
 * null. Read-only, and it does not throw.
 *
 * A confirmed id shows which transaction landed, not who signed it: the id
 * covers the unsigned transaction only. An Ed25519 key the target was once
 * rekeyed to can sign the very transaction a proof would be. So the signed
 * copy is read, from the node's lookup or else the indexer, and must carry
 * one Falcon-1024 signature, authorised by the target, from a key that
 * derives the target, that verifies over this transaction here. A copy that
 * cannot be read is `unknown`; one that shows anything else is a `conflict`.
 */
async function falconSignatureDoubt(
  clients: FalconerClients,
  a: TransactionAttempt,
  target: string,
  requestMs: number,
): Promise<{ outcome: 'unknown' | 'conflict'; detail: string } | null> {
  let envelope: Envelope | null = null;
  try {
    const p = (await withTimeout(
      clients.algod.pendingTransactionInformation(a.txId).do(),
      requestMs,
      'reading how the transaction was signed',
    )) as { confirmedRound?: unknown; txn?: algosdk.SignedTransaction };
    const s = p?.txn;
    // Confirmed, so this is the copy that landed, not one still in the pool.
    if (s?.txn?.txID?.() === a.txId && Number(p.confirmedRound) > 0) {
      const q = s.pqsig;
      envelope = {
        authorizer: (s.sgnr ?? s.txn.sender).toString(),
        kinds: kindsOf(s, ALGOD_KINDS),
        pqsig: q && { scheme: q.sch, publicKey: q.pk, salt: q.slt, signature: q.sig },
      };
    }
  } catch {
    // Not held by the node: the indexer, below.
  }
  if (!envelope && clients.indexer) {
    try {
      const t = ((await withTimeout(
        clients.indexer.lookupTransactionByID(a.txId).do(),
        requestMs,
        'asking the indexer how the transaction was signed',
      )) as { transaction?: { id?: unknown; confirmedRound?: unknown; sender?: unknown; authAddr?: unknown; signature?: { pqsig?: Envelope['pqsig'] } } })
        ?.transaction;
      if (t?.id === a.txId && t.confirmedRound) {
        envelope = {
          authorizer: String(t.authAddr ?? t.sender),
          kinds: kindsOf(t.signature, INDEXER_KINDS),
          pqsig: t.signature?.pqsig,
        };
      }
    } catch {
      // Not found while it lags, or unavailable: no evidence either way.
    }
  }
  if (!envelope) {
    return {
      outcome: 'unknown',
      detail: `${a.txId} is in the ledger, but neither the node nor the indexer showed how it was signed, so it does not show that the new key signed it.`,
    };
  }
  const { authorizer, kinds, pqsig } = envelope;
  let why: string | null = null;
  if (kinds.length !== 1 || kinds[0] !== FALCON) {
    why = `it was signed by ${authorizer} with ${kinds.join(' and ') || 'no signature'}`;
  } else if (authorizer !== target) {
    why = `it was authorised by ${authorizer}`;
  } else {
    try {
      const { publicKey, signature } = pqsig!;
      const binding = checkPqAddressBinding(pqsig, target);
      if (!binding.bound || !(publicKey instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
        why = `its Falcon-1024 key does not derive ${target} (${binding.reason ?? 'unreadable'})`;
      } else if (!verifyCompressed(publicKey, signature, attemptTransaction(a).bytesToSign())) {
        why = 'its Falcon-1024 signature does not verify over it';
      }
    } catch {
      why = 'its Falcon-1024 signature does not verify over it';
    }
  }
  return why
    ? { outcome: 'conflict', detail: `${a.txId} is in the ledger, but ${why}: it does not show that ${target}'s own Falcon key signed it.` }
    : null;
}

/* ------------------------------------------------------------------ */
/* Signers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Why the funding and the rekey cannot be signed for a budget priced for
 * `signer`, or null. This ceremony signs them with a single Ed25519 key only.
 */
export function signerRefusal(signer: SignerSupport | undefined): string | null {
  if (signer?.supported && signer.scheme === 'ed25519') return null;
  return (
    'The funding and the rekey are signed only with a single Ed25519 key, from its 25-word phrase. ' +
    (signer?.supported
      ? `This account's authority is a ${signer.scheme} key: the budget prices it, but it cannot sign with it here.`
      : (signer?.reason ?? 'Nothing established what signs for this account.'))
  );
}

/** The Ed25519 key a phrase derives, if it is the pinned authority; otherwise why not. */
function signingAccount(pin: CeremonyPin, phrase: string): algosdk.Account | string {
  if (isHashDerivedAddress(pin.authorizer)) {
    return (
      `${pin.authorizer} is not an Ed25519 key: it is a multisig, a logic signature or a ` +
      'post-quantum key. The funding and the rekey are signed only with a single Ed25519 key.'
    );
  }
  let account: algosdk.Account;
  try {
    account = algosdk.mnemonicToSecretKey(phrase.trim().split(/\s+/).join(' '));
  } catch {
    // The decoder's own message is not repeated: it is about the phrase.
    return 'The signing phrase is not a valid 25-word Algorand phrase.';
  }
  const typed = account.addr.toString();
  if (typed === pin.authorizer) return account;
  return pin.authorizer !== pin.sender
    ? `${pin.sender} is rekeyed to ${pin.authorizer}, so that key has to sign the migration. ` +
        `The phrase you entered controls ${typed}.`
    : `That phrase controls ${typed}, not the account being migrated.`;
}

/* ------------------------------------------------------------------ */
/* The ceremony                                                        */
/* ------------------------------------------------------------------ */

export interface CeremonyInit extends CeremonyPin {
  /** The network meant. Only `testnet` and `localnet` may execute, and only on a node that reports it. */
  readonly network: string;
  /** For a recovered migration: the network it was pinned to when it started. */
  readonly genesis?: NetworkGenesis;
  /**
   * For a recovered migration: its attempts, in the order they were recorded.
   * Public, and only which transactions to ask the ledger about.
   */
  readonly attempts?: readonly TransactionAttempt[];
}

export interface CeremonyTiming {
  /** The longest one request may take. */
  requestMs: number;
  /** How long a sent attempt is waited for. */
  confirmMs: number;
  pollMs: number;
  /** The longest one reconciliation may take. */
  reconcileMs: number;
}

export const CEREMONY_TIMING: Readonly<CeremonyTiming> = Object.freeze({
  requestMs: REQUEST_TIMEOUT_MS,
  confirmMs: CONFIRMATION_TIMEOUT_MS,
  pollMs: 1000,
  reconcileMs: RECONCILE_TIMEOUT_MS,
});

export interface RunOptions {
  /** The budget the operator approved for this run. Nothing is sent beyond it. */
  approved: MigrationBudget | null;
  /** The 25-word phrase of the account's current authority, for the funding and the rekey. */
  signingPhrase?: string;
  /** Awaited with the attempt before it is sent. If it throws, nothing is sent. */
  record: (attempt: TransactionAttempt) => void | Promise<void>;
  timing?: Partial<CeremonyTiming>;
}

export type StageRun =
  /** Nothing was recorded or sent for this stage. */
  | {
      readonly sent: false;
      readonly reason: string;
      /** The budget read for this stage, if it got that far. */
      readonly quote: MigrationBudget | null;
      readonly authority: AuthorityObservation | null;
    }
  /** Recorded, then sent. `evidence` is what the ledger said after. */
  | {
      readonly sent: true;
      readonly attempt: TransactionAttempt;
      readonly send: SendResult;
      readonly evidence: AttemptEvidence;
      readonly quote: MigrationBudget;
      readonly authority: AuthorityObservation;
    };

export type Position =
  | { readonly stage: SubmissionStage; readonly blockedBy: null }
  | { readonly stage: null; readonly blockedBy: string };

export interface Ceremony extends CeremonyPin {
  readonly network: string;
  /** The network pinned, or null before the first pin of a new migration. */
  genesis(): NetworkGenesis | null;
  attempts(): readonly TransactionAttempt[];
  /** What this ceremony has read from the ledger, by transaction id. */
  evidence(): Readonly<Record<string, AttemptEvidence>>;
  /** Two settled readings of one attempt that disagree. Nothing runs while it stands. */
  conflict(): string | null;
  /** The stage the ledger readings allow next, or why none may run. */
  next(): Position;
  /** Admit the new key: offline checks, including its phrase typed back. Returns why not, or null. */
  admitKey(identity: PqIdentity, transcription: string): string | null;
  hasKey(): boolean;
  /** Why this phrase cannot sign the funding and the rekey, or null. Offline. */
  signingRefusal(signingPhrase: string): string | null;
  /**
   * Take up attempts recorded since, by this ceremony or another holder of
   * the same record. What it already knows must be where the list starts.
   * Returns why not, or null.
   */
  include(attempts: readonly TransactionAttempt[]): string | null;
  /** Establish the node's network and pin it. Read-only. */
  pin(timing?: Partial<CeremonyTiming>): Promise<{ genesis: NetworkGenesis; clients: FalconerClients } | { refused: string }>;
  /**
   * Read what the ledger says about every attempt not yet settled. Read-only.
   * `hints` names rounds attempts are claimed to be in: only a block's own
   * answer counts.
   */
  reconcile(options?: {
    hints?: Readonly<Record<string, bigint | null>>;
    timing?: Partial<CeremonyTiming>;
  }): Promise<{ readings: AttemptEvidence[]; conflict: string | null }>;
  /** Run `stage`, if it is the next one and everything above holds now. */
  run(stage: SubmissionStage, options: RunOptions): Promise<StageRun>;
}

/**
 * A ceremony for one account, authority, target and network. Throws, with
 * nothing read or sent, when these cannot be executed: another network, a
 * target that is not a new post-quantum address for this account, or
 * recovered attempts that are not this migration's.
 */
export function openCeremony(clients: FalconerClients, init: CeremonyInit): Ceremony {
  const { network, sender, authorizer, target } = init;
  if (network !== 'testnet' && network !== 'localnet') {
    throw new Error('Execution is limited to TestNet and LocalNet.');
  }
  for (const [what, a] of [['account', sender], ['authority', authorizer], ['target', target]] as const) {
    if (!algosdk.isValidAddress(a)) throw new Error(`The ${what} is not a valid address.`);
  }
  if (!isHashDerivedAddress(target)) {
    throw new Error('The target address is a point on the Ed25519 curve, so it is not a post-quantum address.');
  }
  if (target === sender) throw new Error('An account cannot be rekeyed to itself.');
  if (target === authorizer) throw new Error("The target address is already this account's authority.");
  const pin: CeremonyPin = Object.freeze({ sender, authorizer, target });
  const refused = init.genesis && genesisRefusal(network, init.genesis);
  if (refused) throw new Error(refused);

  let genesis: NetworkGenesis | null = init.genesis ? Object.freeze({ ...init.genesis }) : null;
  let pinned: FalconerClients | null = null;
  const attempts: TransactionAttempt[] = [];
  let evidence: Record<string, AttemptEvidence> = {};
  let conflict: string | null = null;
  let identity: PqIdentity | null = null;
  let busy = false;

  /** `e`, unless it confirms a transaction only the target's key signs and the ledger does not show that key's signature. */
  const vetted = async (a: TransactionAttempt, e: AttemptEvidence, requestMs: number): Promise<AttemptEvidence> => {
    if (e.outcome !== 'confirmed' || a.authorizer !== target) return e;
    const doubt = await falconSignatureDoubt(clients, a, target, requestMs);
    return doubt ? Object.freeze({ ...e, ...doubt, confirmedRound: null }) : e;
  };

  const observe = (readings: readonly AttemptEvidence[]) => {
    const merged = mergeEvidence(evidence, readings);
    evidence = merged.evidence;
    conflict ??= merged.conflict;
  };

  const include = (list: readonly TransactionAttempt[]): string | null => {
    if (list.length < attempts.length || attempts.some((a, i) => list[i]!.txId !== a.txId)) {
      return 'The recorded attempts are not the ones this migration sent.';
    }
    const added = list.slice(attempts.length);
    if (added.length && !genesis) return 'Attempts were recorded without the network they were built for.';
    for (const a of added) {
      const why = attemptProblem(pin, genesis!, a);
      if (why) return why;
      if (attempts.some((b) => b.txId === a.txId)) return `${a.txId} is recorded twice.`;
      // The transaction only: a stored label is not taken in with it.
      const { txId, stage, genesisId, genesisHash, amount, fee, firstValid, lastValid } = a;
      attempts.push(Object.freeze({ txId, stage, genesisId, genesisHash, ...stageShape(pin, stage), amount, fee, firstValid, lastValid }));
    }
    return null;
  };

  const confirmed = (stage: SubmissionStage) =>
    attempts.filter((a) => a.stage === stage && evidence[a.txId]?.outcome === 'confirmed');

  const next = (): Position => {
    const no = (blockedBy: string): Position => ({ stage: null, blockedBy });
    if (conflict) return no(`The ledger contradicts this migration: ${conflict}`);
    for (const a of attempts) {
      const e = evidence[a.txId];
      if (!e || !isFinalEvidence(e)) {
        return no(`Attempt ${a.txId} (${a.stage}) is not settled by the ledger yet. Check the ledger first.`);
      }
    }
    // Every attempt is settled. The next stage is the first without a
    // confirmation, and only if nothing was ever attempted beyond it.
    for (const [i, stage] of STAGE_ORDER.entries()) {
      const done = confirmed(stage).length;
      if (done > 1) return no(`Two attempts of "${stage}" confirmed. Nothing more is sent.`);
      if (done === 1) continue;
      if (attempts.some((a) => STAGE_ORDER.indexOf(a.stage) > i)) {
        return no(`An attempt went beyond "${stage}", which never confirmed. Nothing more is sent.`);
      }
      return { stage, blockedBy: null };
    }
    return no('Every stage has confirmed.');
  };

  const initial = include(init.attempts ?? []);
  if (initial) throw new Error(initial);

  const ceremony: Ceremony = {
    network,
    sender,
    authorizer,
    target,
    genesis: () => genesis,
    attempts: () => Object.freeze([...attempts]),
    evidence: () => Object.freeze({ ...evidence }),
    conflict: () => conflict,
    next,
    include,
    hasKey: () => identity !== null,

    admitKey(candidate, transcription) {
      if (candidate.address !== target) return 'That key is not the one this migration rekeys to.';
      let derives = false;
      try {
        derives = derivePqAddress(candidate.publicKey).address === target;
      } catch {
        derives = false;
      }
      if (!derives) return 'That key does not derive the address this migration rekeys to.';
      const checks = preflight(candidate, transcription);
      if (!checks.transcriptionConfirmed) return 'The phrase typed back does not re-derive the new address.';
      if (!checks.ok) {
        const failed = checks.checks.filter((c) => !c.passed).map((c) => c.name);
        return `A preflight check failed: ${failed.join(', ')}.`;
      }
      // A copy, so nothing the caller changes later reaches what signs.
      identity = Object.freeze({
        ...candidate,
        publicKey: candidate.publicKey.slice(),
        privateKey: candidate.privateKey.slice(),
      });
      return null;
    },

    signingRefusal(phrase) {
      const account = signingAccount(pin, phrase);
      return typeof account === 'string' ? account : null;
    },

    async pin(timing) {
      if (busy) return { refused: 'A step or check of this migration is already in progress.' };
      const t = { ...CEREMONY_TIMING, ...timing };
      let seen: NetworkGenesis;
      try {
        seen = genesisOfParams(
          await withTimeout(clients.algod.getTransactionParams().do(), t.requestMs, 'establishing which network the node is on'),
        );
      } catch (err) {
        return { refused: `Could not establish which network the node is on: ${publicMessage(err)}` };
      }
      const wrong = genesisRefusal(network, seen);
      if (wrong) return { refused: wrong };
      // Once anything was recorded on a network, it is the only one.
      if (genesis && (attempts.length || init.genesis) && (seen.id !== genesis.id || seen.hash !== genesis.hash)) {
        return { refused: `The node reports ${seen.id}, not ${genesis.id} as when this migration started.` };
      }
      genesis = Object.freeze(seen);
      pinned = pinClients(clients, genesis);
      return { genesis, clients: pinned };
    },

    async reconcile(options = {}) {
      if (busy) throw new Error('A step or check of this migration is already in progress.');
      busy = true;
      try {
        const t = { ...CEREMONY_TIMING, ...options.timing };
        const readings: AttemptEvidence[] = [];
        for (const a of attempts) {
          const held = evidence[a.txId];
          if (held && isFinalEvidence(held)) continue;
          let e: AttemptEvidence;
          try {
            e = await withTimeout(
              reconcileAttempt(clients, a, {
                requestTimeoutMs: t.requestMs,
                totalTimeoutMs: t.reconcileMs,
                hintRound: options.hints?.[a.txId] ?? null,
              }),
              t.reconcileMs + t.requestMs,
              'checking the ledger',
            );
          } catch (err) {
            e = unknownReading(a.txId, publicMessage(err));
          }
          readings.push(await vetted(a, e, t.requestMs));
        }
        observe(readings);
        return { readings, conflict };
      } finally {
        busy = false;
      }
    },

    async run(stage, options) {
      const no = (reason: string, quote: MigrationBudget | null = null, authority: AuthorityObservation | null = null): StageRun =>
        Object.freeze({ sent: false, reason, quote, authority });
      if (busy) return no('A step or check of this migration is already in progress.');
      busy = true;
      try {
        const at = next();
        if (at.stage === null) return no(at.blockedBy);
        if (at.stage !== stage) return no(`"${stage}" cannot run now: the ledger puts this migration at "${at.stage}".`);
        if (!pinned || !genesis) return no('The network has not been established for this migration.');
        if (!identity) return no('The new key has not been admitted: type its phrase back first.');
        if (stage === 'rekey' && confirmed('proof').length !== 1) {
          return no('The new key has not proved itself on this network: there is no confirmed proof for this target.');
        }
        const t = { ...CEREMONY_TIMING, ...options.timing };
        const { approved } = options;
        if (!approved) return no('No budget was approved for this run.');

        let signer: algosdk.TransactionSigner;
        if (stage === 'funding' || stage === 'rekey') {
          const unsupported = signerRefusal(approved.spec.signer);
          if (unsupported) return no(unsupported);
          const account = signingAccount(pin, options.signingPhrase ?? '');
          if (typeof account === 'string') return no(account);
          signer = algosdk.makeBasicAccountTransactionSigner(account);
        } else {
          signer = makeFalconSigner(identity, stage === 'verification' ? sender : undefined);
        }

        // Who signs for each address now: a scan or an earlier proof says
        // nothing about after an authority changed.
        let authority: AuthorityObservation;
        try {
          authority = await readAuthority(clients, sender, { requestTimeoutMs: t.requestMs });
          const expected = stage === 'verification' ? target : authorizer;
          if (authority.authority !== expected) {
            return no(
              stage === 'verification'
                ? authority.rekeyed
                  ? `Account authority is ${authority.authority}, not ${target}.`
                  : 'Account still has no auth-addr; the rekey did not take effect.'
                : `The account's authority is ${authority.authority}, not ${expected} as this step needs. ` +
                    'Check the ledger before going on.',
              null,
              authority,
            );
          }
          if (stage === 'proof' || stage === 'rekey') {
            const own = await readAuthority(clients, target, { requestTimeoutMs: t.requestMs });
            if (own.authority !== target) {
              return no(
                `${target} answers to ${own.authority}, not to its own Falcon key, so it cannot ` +
                  `${stage === 'proof' ? 'prove the key' : 'be trusted with this account'}.`,
                null,
                authority,
              );
            }
          }
        } catch (err) {
          return no(`The account could not be read: ${publicMessage(err)}`);
        }

        // The budget read now, held to what was approved.
        const quote = await quoteMigration(
          pinned,
          { sender, authorizer, target, signer: approved.spec.signer, from: stage },
          { requestTimeoutMs: t.requestMs },
        );
        const beyond = exceedsApproved(approved, quote);
        if (beyond) return no(`The budget changed since it was approved. ${beyond}`, quote, authority);

        let prepared;
        let signed: Uint8Array;
        try {
          const budget = stageOf(quote, stage);
          prepared = await prepareStage(pinned, budget, { genesis, requestTimeoutMs: t.requestMs });
          // The signature is held to the budget too: its scheme, its fee, and
          // the length that fee has to pay for.
          signed = await signStage(prepared, signer, budget);
        } catch (err) {
          return no(publicMessage(err, 600), quote, authority);
        }

        let send: SendResult;
        try {
          send = await sendAttempt(pinned, prepared, signed, {
            requestTimeoutMs: t.requestMs,
            record: async (a) => {
              await options.record(a);
              attempts.push(a);
            },
          });
        } catch (err) {
          return no(publicMessage(err), quote, authority);
        }

        // Read through the unpinned clients, so another network shows as a
        // conflict rather than an error.
        const wait = { requestTimeoutMs: t.requestMs, totalTimeoutMs: t.reconcileMs };
        const { attempt } = prepared;
        let reading: AttemptEvidence;
        try {
          reading =
            send.status === 'conflict'
              ? Object.freeze({ ...unknownReading(attempt.txId, send.reason), outcome: 'conflict' as const })
              : send.status === 'rejected'
                ? await withTimeout(reconcileAttempt(clients, attempt, wait), t.reconcileMs + t.requestMs, 'checking the ledger')
                : await withTimeout(
                    awaitAttempt(clients, attempt, { ...wait, timeoutMs: t.confirmMs, pollMs: t.pollMs }),
                    t.confirmMs + t.reconcileMs,
                    'waiting for confirmation',
                  );
        } catch (err) {
          reading = unknownReading(attempt.txId, publicMessage(err));
        }
        reading = await vetted(attempt, reading, t.requestMs);
        observe([reading]);
        return Object.freeze({ sent: true, attempt, send, evidence: reading, quote, authority });
      } finally {
        busy = false;
      }
    },
  };
  return Object.freeze(ceremony);
}
