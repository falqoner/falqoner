/**
 * Transaction submission and reconciliation (SAFE-02b).
 *
 * A send that times out, answers with an error or loses its response does not
 * show whether the transaction reached the ledger. A transaction the node
 * refused can already be in a block ("already in ledger" is a refusal), and one
 * whose response never arrived may have confirmed. Everything here is built so
 * that no such failure is read as "it did not happen".
 *
 * An attempt goes through four steps, and each one leaves evidence:
 *
 * 1. **Prepare.** The transaction is built locally from the node's parameters
 *    with a short validity window, and its id is derived before anything is
 *    signed or sent. Everything that identifies it is public and is held in a
 *    `TransactionAttempt`, which rebuilds the exact same transaction.
 * 2. **Sign.** The signed bytes must decode to that same id, authorised by the
 *    address the attempt names.
 * 3. **Record, then send.** The caller's `record` is awaited before the send.
 *    If it throws, nothing is sent. The id the node answers with must be the
 *    one derived locally.
 * 4. **Reconcile.** Read-only and bounded: which network the node is on, how
 *    far it has got, what its pool and recent ledger say, and, once the
 *    validity window has passed, every round the transaction could have
 *    landed in. Only that last read can show that it never landed.
 *
 * Preparing, signing and sending here are low-level primitives for one
 * transaction. They do not order a migration's steps or require a proof
 * before a rekey; the guarded ceremony (ceremony.ts) does, and the product
 * sends only through it. Reading and reconciling are read-only.
 */
import algosdk from 'algosdk';
import type { FalconerClients } from './networks.js';

export type SubmissionStage = 'funding' | 'proof' | 'rekey' | 'verification';

/**
 * How many rounds after its first valid round an attempt stays valid. Short,
 * so an attempt that did not land can be settled by reading every round it
 * could have landed in, soon after it could last have landed.
 */
export const VALIDITY_ROUNDS = 50n;
/** The longest any single request to a provider may take. */
export const REQUEST_TIMEOUT_MS = 15_000;
/** The longest a caller waits for a sent attempt to confirm. */
export const CONFIRMATION_TIMEOUT_MS = 60_000;
/** The longest one reconciliation may take, all its requests together. */
export const RECONCILE_TIMEOUT_MS = 90_000;

/** The network a node reports. The hash is base64. */
export interface NetworkGenesis {
  readonly id: string;
  readonly hash: string;
}

/**
 * One transaction the migration may send, described by public fields only.
 * `attemptTransaction` rebuilds the exact transaction from them, so the id
 * can always be checked against the rest.
 */
export interface TransactionAttempt {
  readonly txId: string;
  readonly stage: SubmissionStage;
  readonly genesisId: string;
  readonly genesisHash: string;
  readonly sender: string;
  /** Whose key authorises it: the sender itself, or the sender's authority. */
  readonly authorizer: string;
  readonly receiver: string;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly firstValid: bigint;
  readonly lastValid: bigint;
  readonly rekeyTo: string | null;
}

export interface PreparedTransaction {
  readonly attempt: TransactionAttempt;
  readonly txn: algosdk.Transaction;
}

/* ------------------------------------------------------------------ */
/* Bounded requests and public messages                                */
/* ------------------------------------------------------------------ */

export class TimeoutError extends Error {
  constructor(what: string, ms: number) {
    super(`No answer after ${ms} ms while ${what}.`);
    this.name = 'TimeoutError';
  }
}

/**
 * `work`, or a `TimeoutError` after `ms`. A late answer is dropped: nothing
 * awaiting this sees it.
 */
export function withTimeout<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError(what, ms)), ms);
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/** The HTTP status an algosdk request error carries, if any. */
export function httpStatus(err: unknown): number | undefined {
  const status = (err as { response?: { status?: unknown } } | null)?.response?.status;
  return typeof status === 'number' ? status : undefined;
}

/**
 * An error's message, bounded, and with anything shaped like a run of
 * recovery-phrase words removed. Provider errors do not carry phrases, but a
 * message that reaches the page or a log must not be able to.
 */
export function publicMessage(err: unknown, max = 240): string {
  const raw = String((err as { message?: unknown } | null)?.message ?? err);
  const cleaned = raw.replace(/\b(?:[a-z]{3,8}\s+){11,}[a-z]{3,8}\b/g, '[redacted]');
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

/* ------------------------------------------------------------------ */
/* Preparation                                                         */
/* ------------------------------------------------------------------ */

const isBytes = (x: unknown): x is Uint8Array =>
  ArrayBuffer.isView(x) && (x as Uint8Array).BYTES_PER_ELEMENT === 1;

/** The genesis in a suggested-params answer, or an error if it has none. */
export function genesisOfParams(params: {
  genesisID?: unknown;
  genesisHash?: unknown;
}): NetworkGenesis {
  const id = params?.genesisID;
  const raw = params?.genesisHash;
  const hash = isBytes(raw) ? algosdk.bytesToBase64(raw) : raw;
  if (typeof id !== 'string' || !id || typeof hash !== 'string' || !hash) {
    throw new Error('The node did not say which network it is on.');
  }
  return { id, hash };
}

/**
 * The unsigned transaction an attempt describes. The same fields always
 * build the same bytes, and so the same id.
 */
export function attemptTransaction(a: Omit<TransactionAttempt, 'txId'>): algosdk.Transaction {
  return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: a.sender,
    receiver: a.receiver,
    amount: a.amount,
    ...(a.rekeyTo ? { rekeyTo: a.rekeyTo } : {}),
    suggestedParams: {
      flatFee: true,
      fee: a.fee,
      minFee: a.fee,
      firstValid: a.firstValid,
      lastValid: a.lastValid,
      genesisID: a.genesisId,
      genesisHash: algosdk.base64ToBytes(a.genesisHash),
    },
  });
}

export interface AttemptSpec {
  readonly stage: SubmissionStage;
  readonly sender: string;
  readonly authorizer: string;
  readonly receiver: string;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly rekeyTo?: string | null;
}

export interface PrepareOptions {
  /** Refuse unless the node reports exactly this network. */
  genesis?: NetworkGenesis;
  validityRounds?: bigint;
  requestTimeoutMs?: number;
}

/**
 * Build an attempt from the node's current parameters. Nothing is signed or
 * sent. The id is derived here, before either.
 */
export async function prepareAttempt(
  clients: FalconerClients,
  spec: AttemptSpec,
  options: PrepareOptions = {},
): Promise<PreparedTransaction> {
  for (const [name, address] of [
    ['sender', spec.sender],
    ['authorizer', spec.authorizer],
    ['receiver', spec.receiver],
    ...(spec.rekeyTo ? [['rekey target', spec.rekeyTo]] : []),
  ] as const) {
    if (!algosdk.isValidAddress(address)) throw new Error(`The ${name} is not a valid address.`);
  }
  if (spec.amount < 0n || spec.fee <= 0n) throw new Error('The amount or fee is out of range.');
  const window = options.validityRounds ?? VALIDITY_ROUNDS;
  if (window < 1n) throw new Error('The validity window must be at least one round.');

  const sp = await withTimeout(
    clients.algod.getTransactionParams().do(),
    options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
    'reading transaction parameters',
  );
  const genesis = genesisOfParams(sp);
  if (options.genesis && (genesis.id !== options.genesis.id || genesis.hash !== options.genesis.hash)) {
    throw new Error(
      `The node reports ${genesis.id}, not ${options.genesis.id}. Nothing was signed for it.`,
    );
  }
  const firstValid = BigInt(sp.firstValid);
  const nodeLast = BigInt(sp.lastValid);
  const lastValid = firstValid + window < nodeLast ? firstValid + window : nodeLast;
  if (firstValid < 1n || lastValid < firstValid) {
    throw new Error('The node answered with an unusable validity window.');
  }
  const fields = {
    stage: spec.stage,
    genesisId: genesis.id,
    genesisHash: genesis.hash,
    sender: spec.sender,
    authorizer: spec.authorizer,
    receiver: spec.receiver,
    amount: spec.amount,
    fee: spec.fee,
    firstValid,
    lastValid,
    rekeyTo: spec.rekeyTo ?? null,
  };
  const txn = attemptTransaction(fields);
  return Object.freeze({ attempt: Object.freeze({ txId: txn.txID(), ...fields }), txn });
}

/* ------------------------------------------------------------------ */
/* Signing and sending                                                 */
/* ------------------------------------------------------------------ */

/** Decode signed bytes, and require them to carry `attempt`. */
function checkSigned(attempt: TransactionAttempt, signed: unknown, bindAuthorizer: boolean): Uint8Array {
  if (!isBytes(signed)) throw new Error('The signer did not return a signed transaction. Nothing was sent.');
  let decoded: algosdk.SignedTransaction;
  try {
    decoded = algosdk.decodeSignedTransaction(signed);
  } catch {
    throw new Error('The signer returned bytes that are not a signed transaction. Nothing was sent.');
  }
  const id = decoded.txn.txID();
  if (id !== attempt.txId) {
    throw new Error(`The signer signed ${id}, not the prepared ${attempt.txId}. Nothing was sent.`);
  }
  if (bindAuthorizer) {
    const signedFor = decoded.sgnr?.toString() ?? attempt.sender;
    if (signedFor !== attempt.authorizer) {
      throw new Error(
        `The transaction was authorised by ${signedFor}, not ${attempt.authorizer}. Nothing was sent.`,
      );
    }
  }
  return signed;
}

/**
 * Sign a prepared attempt. The result must decode to the prepared id and,
 * unless `bindAuthorizer` is false, be authorised by the attempt's
 * authorizer.
 */
export async function signAttempt(
  prepared: PreparedTransaction,
  signer: algosdk.TransactionSigner,
  options: { bindAuthorizer?: boolean } = {},
): Promise<Uint8Array> {
  const out = await signer([prepared.txn], [0]);
  if (!Array.isArray(out) || out.length !== 1) {
    throw new Error('The signer did not return exactly one signed transaction. Nothing was sent.');
  }
  return checkSigned(prepared.attempt, out[0], options.bindAuthorizer !== false);
}

/** `record` threw, so the attempt was not sent. */
export class RecordError extends Error {
  constructor(reason: string) {
    super(`The attempt could not be recorded, so it was not sent: ${reason}`);
    this.name = 'RecordError';
  }
}

export type SendResult =
  /** The node took it into its pool and answered with the same id. */
  | { readonly status: 'accepted' }
  /** The node answered with an error. It may already be in the ledger. */
  | { readonly status: 'rejected'; readonly httpStatus: number; readonly reason: string; readonly error: unknown }
  /** No usable answer. It may or may not have reached the node. */
  | { readonly status: 'unknown'; readonly reason: string; readonly error: unknown }
  /** The node answered with another id. Its answer cannot be trusted. */
  | { readonly status: 'conflict'; readonly reason: string };

export interface SendOptions {
  /**
   * Awaited before the send. If it throws, nothing is sent and a
   * `RecordError` is thrown.
   */
  record?: (attempt: TransactionAttempt) => void | Promise<void>;
  requestTimeoutMs?: number;
  bindAuthorizer?: boolean;
}

/**
 * Record, then send. Only the send can have reached the network, and no
 * outcome of it is read as "not sent".
 */
export async function sendAttempt(
  clients: FalconerClients,
  prepared: PreparedTransaction,
  signed: Uint8Array,
  options: SendOptions = {},
): Promise<SendResult> {
  const { attempt } = prepared;
  checkSigned(attempt, signed, options.bindAuthorizer !== false);
  if (options.record) {
    try {
      await options.record(attempt);
    } catch (err) {
      throw new RecordError(publicMessage(err));
    }
  }
  let answer: { txid?: unknown };
  try {
    answer = await withTimeout(
      clients.algod.sendRawTransaction(signed).do(),
      options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
      'sending the transaction',
    );
  } catch (err) {
    const status = httpStatus(err);
    if (status !== undefined && status >= 400 && status < 500) {
      return { status: 'rejected', httpStatus: status, reason: publicMessage(err), error: err };
    }
    return { status: 'unknown', reason: publicMessage(err), error: err };
  }
  if (answer?.txid !== attempt.txId) {
    return {
      status: 'conflict',
      reason:
        `The node answered with transaction id ${String(answer?.txid).slice(0, 60)}, ` +
        `not ${attempt.txId}, which was derived before sending.`,
    };
  }
  return { status: 'accepted' };
}

/* ------------------------------------------------------------------ */
/* Read-only observation                                               */
/* ------------------------------------------------------------------ */

export interface NetworkObservation {
  readonly genesis: NetworkGenesis;
  /** The node's last committed round. */
  readonly round: bigint;
  /** The node is catching up, so its view of the ledger is behind. */
  readonly catchingUp: boolean;
}

const toRound = (x: unknown, what: string): bigint => {
  if (typeof x === 'bigint' && x >= 0n) return x;
  if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x);
  throw new Error(`The node answered with a malformed ${what}.`);
};

/** Which network the node is on, and how far it has got. Read-only. */
export async function readNetwork(
  clients: FalconerClients,
  options: { requestTimeoutMs?: number } = {},
): Promise<NetworkObservation> {
  const ms = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const [params, status] = await Promise.all([
    withTimeout(clients.algod.getTransactionParams().do(), ms, 'reading the network'),
    withTimeout(clients.algod.status().do(), ms, 'reading the node status'),
  ]);
  const catchup = (status as { catchupTime?: unknown })?.catchupTime;
  return {
    genesis: genesisOfParams(params),
    round: toRound((status as { lastRound?: unknown })?.lastRound, 'round'),
    catchingUp: catchup !== undefined && toRound(catchup, 'catch-up time') > 0n,
  };
}

export interface AuthorityObservation {
  readonly address: string;
  /** Who can sign for the account now: its auth-addr, or the account itself. */
  readonly authority: string;
  readonly rekeyed: boolean;
  /** The round the node read it at. */
  readonly round: bigint;
}

/** The account's current authority, from algod. Read-only. */
export async function readAuthority(
  clients: FalconerClients,
  address: string,
  options: { requestTimeoutMs?: number } = {},
): Promise<AuthorityObservation> {
  const info = (await withTimeout(
    clients.algod.accountInformation(address).do(),
    options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
    'reading the account',
  )) as { address?: unknown; authAddr?: unknown; round?: unknown } | null;
  const reported = info?.address === undefined ? address : String(info.address);
  if (reported !== address) throw new Error('The node answered for a different account.');
  const raw = info?.authAddr;
  const auth = raw === undefined || raw === null ? null : String(raw);
  if (auth !== null && !algosdk.isValidAddress(auth)) {
    throw new Error('The node reported a malformed authority for the account.');
  }
  return {
    address,
    authority: auth ?? address,
    rekeyed: auth !== null && auth !== address,
    round: toRound(info?.round, 'account round'),
  };
}

/* ------------------------------------------------------------------ */
/* Reconciliation                                                      */
/* ------------------------------------------------------------------ */

export type AttemptOutcome =
  /** It is in a block, within its validity window. */
  | 'confirmed'
  /** The node holds it in its pool. It can still land. */
  | 'pending'
  /** The node dropped it with an error. It can still land, so this proves nothing. */
  | 'rejected'
  /** Its validity window has passed, so it can no longer land. See `nonInclusion`. */
  | 'expired'
  /** Nothing establishes whether it landed. */
  | 'unknown'
  /** Something read contradicts the attempt or its network. Stop. */
  | 'conflict';

export type EvidenceSource = 'algod-pending' | 'algod-block' | 'indexer' | 'none';

export interface AttemptEvidence {
  readonly txId: string;
  readonly outcome: AttemptOutcome;
  readonly confirmedRound: bigint | null;
  /** The node's last round when this was read, if it was read. */
  readonly observedRound: bigint | null;
  readonly source: EvidenceSource;
  /**
   * Every round of the passed validity window was read and none holds the
   * transaction. The only evidence that it never landed.
   */
  readonly nonInclusion: boolean;
  readonly detail: string;
}

/** Whether a new attempt may replace this one: it never landed, and never can. */
export const replaceable = (e: AttemptEvidence): boolean =>
  e.outcome === 'expired' && e.nonInclusion;

export interface ReconcileOptions {
  requestTimeoutMs?: number;
  /** The whole reconciliation, every request together. */
  totalTimeoutMs?: number;
  /** The widest validity window read round by round. */
  maxScanRounds?: bigint;
  /**
   * Also ask the indexer, for a confirmation algod no longer holds. Its
   * silence is never evidence: an indexer can lag.
   */
  indexer?: boolean;
  /**
   * A round the transaction is claimed to be in, such as a stored label's.
   * Only a hint: that block is read, and only what it holds counts.
   */
  hintRound?: bigint | null;
}

/**
 * A well-formed transaction id: the unpadded base32 of 32 bytes, so 52
 * characters whose last one carries a single bit and four zero bits.
 */
export function isTransactionId(x: unknown): x is string {
  return typeof x === 'string' && /^[A-Z2-7]{51}[AQ]$/.test(x);
}

const SOURCE_LABEL: Record<EvidenceSource, string> = {
  'algod-pending': "the node's transaction lookup",
  'algod-block': 'the block itself',
  indexer: 'the indexer',
  none: 'nothing',
};

/**
 * What the ledger says about one attempt. Read-only: nothing is signed or
 * sent, whatever it finds.
 */
export async function reconcileAttempt(
  clients: FalconerClients,
  attempt: TransactionAttempt,
  options: ReconcileOptions = {},
): Promise<AttemptEvidence> {
  const deadline = Date.now() + (options.totalTimeoutMs ?? RECONCILE_TIMEOUT_MS);
  const perRequest = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const budget = (what: string): number => {
    const left = deadline - Date.now();
    if (left <= 0) throw new TimeoutError(what, options.totalTimeoutMs ?? RECONCILE_TIMEOUT_MS);
    return Math.min(perRequest, left);
  };
  // The budget is taken before the request starts, so a request is never
  // left running with nothing awaiting it.
  const bounded = <T>(work: () => Promise<T>, what: string): Promise<T> => {
    const ms = budget(what);
    return withTimeout(work(), ms, what);
  };

  const evidence = (outcome: AttemptOutcome, patch: Partial<AttemptEvidence>): AttemptEvidence =>
    Object.freeze({
      txId: attempt.txId,
      outcome,
      confirmedRound: null,
      observedRound: null,
      source: 'none' as EvidenceSource,
      nonInclusion: false,
      detail: '',
      ...patch,
    });

  let network: NetworkObservation;
  try {
    network = await readNetwork(clients, { requestTimeoutMs: budget('reading the network') });
  } catch (err) {
    return evidence('unknown', { detail: `The node could not be read: ${publicMessage(err)}` });
  }
  const round = network.round;
  if (network.genesis.id !== attempt.genesisId || network.genesis.hash !== attempt.genesisHash) {
    return evidence('conflict', {
      observedRound: round,
      detail:
        `The node reports ${network.genesis.id} (${network.genesis.hash}), but this ` +
        `attempt was built for ${attempt.genesisId} (${attempt.genesisHash}).`,
    });
  }
  if (network.catchingUp) {
    return evidence('unknown', {
      observedRound: round,
      detail: 'The node is catching up, so its view of the ledger is behind.',
    });
  }

  const confirmedAt = (at: bigint, source: EvidenceSource): AttemptEvidence =>
    at < attempt.firstValid || at > attempt.lastValid
      ? evidence('conflict', {
          observedRound: round,
          source,
          detail:
            `${SOURCE_LABEL[source]} reports it in round ${at}, outside its validity ` +
            `window ${attempt.firstValid}–${attempt.lastValid}.`,
        })
      : evidence('confirmed', {
          confirmedRound: at,
          observedRound: round,
          source,
          detail: `Confirmed in round ${at}, according to ${SOURCE_LABEL[source]}.`,
        });

  // The pool, and the node's recent ledger.
  let pooled = false;
  let poolError = '';
  let lookup = '';
  try {
    const p = (await bounded(
      () => clients.algod.pendingTransactionInformation(attempt.txId).do(),
      'looking the transaction up',
    )) as { confirmedRound?: unknown; poolError?: unknown; txn?: { txn?: { txID?: () => string } } };
    const seen = p?.txn?.txn?.txID?.();
    if (seen !== attempt.txId) {
      return evidence('conflict', {
        observedRound: round,
        source: 'algod-pending',
        detail: 'The node answered the lookup with a different transaction.',
      });
    }
    const confirmed = p.confirmedRound === undefined ? 0n : toRound(p.confirmedRound, 'confirmed round');
    if (confirmed > 0n) return confirmedAt(confirmed, 'algod-pending');
    if (typeof p.poolError === 'string' && p.poolError) poolError = publicMessage(p.poolError);
    else pooled = true;
  } catch (err) {
    lookup =
      httpStatus(err) === 404
        ? 'the node does not hold it in its pool or its recent ledger'
        : `its lookup failed (${publicMessage(err)})`;
  }

  const fromIndexer = async (): Promise<AttemptEvidence | null> => {
    if (options.indexer === false || !clients.indexer) return null;
    let t: { id?: unknown; confirmedRound?: unknown; genesisId?: unknown; genesisHash?: unknown } | undefined;
    try {
      const res = (await bounded(
        () => clients.indexer!.lookupTransactionByID(attempt.txId).do(),
        'asking the indexer',
      )) as { transaction?: typeof t };
      t = res?.transaction;
    } catch {
      // Not found while it lags, or unavailable: no evidence either way.
      return null;
    }
    if (!t || t.confirmedRound === undefined) return null;
    const hash = isBytes(t.genesisHash) ? algosdk.bytesToBase64(t.genesisHash) : t.genesisHash;
    if (t.id !== attempt.txId || t.genesisId !== attempt.genesisId || hash !== attempt.genesisHash) {
      return evidence('conflict', {
        observedRound: round,
        source: 'indexer',
        detail: 'The indexer answered with a transaction from another network, or another transaction.',
      });
    }
    try {
      return confirmedAt(toRound(t.confirmedRound, 'indexer round'), 'indexer');
    } catch {
      return null;
    }
  };

  /**
   * What one block says about the attempt. A valid entry naming it is
   * positive evidence whatever else the list holds; the round counts as
   * showing it absent only if every entry is a well-formed transaction id,
   * because a malformed entry could stand for anything, this one included.
   */
  const readRound = async (r: bigint): Promise<'found' | 'absent' | 'gap'> => {
    const res = (await bounded(
      () => clients.algod.getBlockTxids(r).do(),
      `reading round ${r}`,
    )) as { blocktxids?: unknown };
    const ids = res?.blocktxids;
    if (!Array.isArray(ids)) return 'gap';
    const valid = ids.filter(isTransactionId);
    if (valid.includes(attempt.txId)) return 'found';
    return valid.length === ids.length ? 'absent' : 'gap';
  };

  // A claimed round is read first; only the block's own answer counts.
  const hint = options.hintRound ?? null;
  if (hint !== null && hint >= attempt.firstValid && hint <= attempt.lastValid && hint <= round) {
    try {
      if ((await readRound(hint)) === 'found') return confirmedAt(hint, 'algod-block');
    } catch {
      // Unreadable: the scan below, or nothing, decides.
    }
  }

  if (round > attempt.lastValid) {
    // It can no longer land. Whether it ever did is settled only by reading
    // every round it could have landed in.
    const width = attempt.lastValid - attempt.firstValid + 1n;
    const max = options.maxScanRounds ?? VALIDITY_ROUNDS + 1n;
    let unread = width > max ? width : 0n;
    if (unread === 0n) {
      for (let r = attempt.firstValid; r <= attempt.lastValid; r++) {
        try {
          const seen = await readRound(r);
          if (seen === 'found') return confirmedAt(r, 'algod-block');
          if (seen === 'gap') unread++;
        } catch (err) {
          unread++;
          if (err instanceof TimeoutError && Date.now() >= deadline) {
            unread += attempt.lastValid - r;
            break;
          }
        }
      }
    }
    if (unread === 0n && !pooled) {
      return evidence('expired', {
        observedRound: round,
        nonInclusion: true,
        source: 'algod-block',
        detail:
          `Its validity ended at round ${attempt.lastValid}, and none of rounds ` +
          `${attempt.firstValid}–${attempt.lastValid} holds it: it never landed, and ` +
          'can no longer land.',
      });
    }
    const indexed = await fromIndexer();
    if (indexed) return indexed;
    return evidence('expired', {
      observedRound: round,
      detail:
        `Its validity ended at round ${attempt.lastValid}, so it can no longer land. ` +
        (pooled
          ? 'The node still reports it as pending, which contradicts that, so whether it landed is not established.'
          : `${unread} of the ${width} rounds it could have landed in could not be read in full, so whether it landed is not established.`),
    });
  }

  // Still inside its validity window: it can still land.
  if (pooled) {
    return evidence('pending', {
      observedRound: round,
      source: 'algod-pending',
      detail: `The node holds it in its pool. It can land until round ${attempt.lastValid}.`,
    });
  }
  const indexed = await fromIndexer();
  if (indexed) return indexed;
  if (poolError) {
    return evidence('rejected', {
      observedRound: round,
      source: 'algod-pending',
      detail:
        `The node dropped it from its pool (${poolError}). It can still land until ` +
        `round ${attempt.lastValid}, so this does not show that it failed.`,
    });
  }
  return evidence('unknown', {
    observedRound: round,
    detail:
      `At round ${round}, ${lookup}. It may still land until round ${attempt.lastValid}, ` +
      'so this does not show that it was never sent.',
  });
}

export interface AwaitOptions extends ReconcileOptions {
  timeoutMs?: number;
  pollMs?: number;
  /** For tests. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Wait, bounded, for a sent attempt to settle. Returns `confirmed`,
 * `conflict`, `expired` or `rejected` as soon as one is seen, and otherwise
 * the latest reading the node actually answered: a poll that could not read
 * the node does not replace what an earlier one read.
 *
 * The deadline decides whether another poll starts. Each poll keeps its own
 * bounds, so the wait can run over by at most one bounded poll, and a poll
 * started just before the deadline is not starved into reading nothing.
 */
export async function awaitAttempt(
  clients: FalconerClients,
  attempt: TransactionAttempt,
  options: AwaitOptions = {},
): Promise<AttemptEvidence> {
  const deadline = Date.now() + (options.timeoutMs ?? CONFIRMATION_TIMEOUT_MS);
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let answered: AttemptEvidence | null = null;
  for (;;) {
    const last = await reconcileAttempt(clients, attempt, { ...options, indexer: false });
    if (last.outcome !== 'pending' && last.outcome !== 'unknown') return last;
    if (last.observedRound !== null) answered = last;
    if (Date.now() + (options.pollMs ?? 1000) >= deadline) return answered ?? last;
    await sleep(options.pollMs ?? 1000);
  }
}

/**
 * Sign, send and wait, for callers that need a confirmed transaction or an
 * error and keep no record. Every failure is thrown, including ones where
 * the transaction may have landed.
 */
export async function submitAndConfirm(
  clients: FalconerClients,
  prepared: PreparedTransaction,
  signer: algosdk.TransactionSigner,
  options: SendOptions & AwaitOptions = {},
): Promise<{ txId: string; confirmedRound: bigint }> {
  const signed = await signAttempt(prepared, signer, options);
  const sent = await sendAttempt(clients, prepared, signed, options);
  if (sent.status === 'rejected' || sent.status === 'unknown') throw sent.error;
  if (sent.status === 'conflict') throw new Error(sent.reason);
  const e = await awaitAttempt(clients, prepared.attempt, options);
  if (e.outcome !== 'confirmed') throw new Error(`Transaction ${e.txId}: ${e.detail}`);
  return { txId: e.txId, confirmedRound: e.confirmedRound! };
}
