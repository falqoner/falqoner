/**
 * The migration budget (SAFE-03a).
 *
 * One calculation says what each step of a migration costs, who pays it, and
 * what every address holds after it, from values read off the network. The
 * plan, the CLI and the page's execution all use it, and nothing is prepared
 * against a figure it did not produce.
 *
 * **Fee rules.** Encoded for one consensus protocol, v42 - the one algod
 * 5.0.2 reports on MainNet, TestNet and LocalNet as of 2026-09-28 - and
 * refused for any other:
 *
 * - Consensus: a group pays at least `minFee` times the sum of its fee
 *   factors. A transaction's factor is one, plus its signature scheme's
 *   contribution: two for Falcon-1024, none for Ed25519 (go-algorand
 *   `PQSchemeFeeContribution`; the developer portal's fee table). Every step
 *   here is sent alone, so each fee covers its own factor.
 * - Pool: each transaction pays at least the node's current fee per byte
 *   times the length of the *signed* transaction, signature envelope included
 *   (go-algorand `checkSufficientFee`). The per-byte fee is zero until the
 *   pool is congested.
 *
 * A step's fee is the larger of the two. Neither rule knows the other, so the
 * larger satisfies both.
 *
 * **Size.** The signed length is bounded before anything is signed: the
 * transaction is encoded with every value that is not yet known - the fee,
 * the validity rounds, a nonzero amount - at its widest encoding, and with
 * the largest envelope its signer can produce. A Falcon-1024 envelope carries
 * the 1,793-byte public key and a compressed signature of at most 1,423
 * bytes, whose length varies from one signature to the next; an Ed25519 size
 * estimate says nothing about it. Because the fee field is already priced at
 * its widest, the fee chosen can never make the transaction longer than the
 * length it was priced for, so there is nothing to iterate. The bound is
 * never signed: its fee and rounds make it invalid by construction.
 *
 * **Balances.** The source pays its own fees - including the verification
 * after the rekey - and the transfer. The target pays the proof from what it
 * holds, so that fee is part of the transfer when the transfer is needed and
 * is never charged to the source a second time. The transfer is only the
 * target's shortfall, plus an explicitly labelled reserve. Both addresses are
 * checked against their minimum balances after every step.
 *
 * **Inputs.** Read by a bounded, read-only adapter: parameters and status
 * from algod, and both accounts. Missing, malformed, stale or unsupported
 * inputs produce an unavailable budget, never an affordable one. Nothing here
 * loads a key or signs.
 */
import algosdk from 'algosdk';
import type { AuthorityAssessment } from './authority.js';
import { MAX_SIGNATURE_BYTES } from './falcon-binding.js';
import { FALCON_PUBKEY_BYTES, FALCON_SCHEME, isHashDerivedAddress } from './falcon.js';
import { formatAlgos } from './exposure.js';
import type { FalconerClients } from './networks.js';
import {
  REQUEST_TIMEOUT_MS,
  VALIDITY_ROUNDS,
  attemptTransaction,
  genesisOfParams,
  publicMessage,
  withTimeout,
  type NetworkGenesis,
  type SubmissionStage,
  type TransactionAttempt,
} from './submission.js';

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

export type SignatureScheme = 'ed25519' | 'falcon-1024';

/** What one consensus protocol charges and requires, as far as a migration meets it. */
export interface ProtocolRules {
  readonly name: string;
  /** The minimum balance of an account that holds nothing but Algos. */
  readonly baseMinBalance: bigint;
  /** Each scheme's addition to a transaction's fee factor, in millionths of the minimum fee. */
  readonly contribution: Readonly<Record<SignatureScheme, bigint>>;
}

/** The protocol algod 5.0.2 reports on MainNet, TestNet and LocalNet: consensus v42. */
export const V42_PROTOCOL =
  'https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f';

/**
 * Protocols whose rules this model encodes. Anything else, `future`
 * included, leaves the budget unavailable: its rules are not known here.
 */
export const PROTOCOL_RULES: Readonly<Record<string, ProtocolRules>> = Object.freeze({
  [V42_PROTOCOL]: Object.freeze({
    name: 'v42',
    baseMinBalance: 100_000n,
    contribution: Object.freeze({ ed25519: 0n, 'falcon-1024': 2_000_000n }),
  }),
});

/** A fee factor of one: one minimum fee. */
const FACTOR_ONE = 1_000_000n;
/** The largest compressed deterministic Falcon-1024 signature. */
export const FALCON_MAX_SIGNATURE_BYTES = MAX_SIGNATURE_BYTES;
/** No step is quoted, prepared or recorded with a fee above this. */
export const MAX_STAGE_FEE_MICROALGOS = 1_000_000n;
/** How many rounds after it was read a quote may still be used to prepare a step. */
export const QUOTE_LIFETIME_ROUNDS = VALIDITY_ROUNDS;
/** How far apart, in rounds, the readings behind one quote may be. */
export const MAX_READING_SPREAD_ROUNDS = 10n;

const U64 = (1n << 64n) - 1n;

/* ------------------------------------------------------------------ */
/* Signers                                                             */
/* ------------------------------------------------------------------ */

/** What signs for the account now, and whether this model can price it. */
export type SignerSupport =
  | { readonly supported: true; readonly scheme: SignatureScheme; readonly basis: string }
  | { readonly supported: false; readonly reason: string };

/**
 * What signs the funding and the rekey, from what the scan established about
 * the account's authority. Multisig, logic signatures and anything unknown
 * are refused by name: their envelopes are not priced here.
 */
export function signerFromAuthority(
  authority: Pick<AuthorityAssessment, 'authorityClass'> | undefined,
  authorizer: string,
): SignerSupport {
  switch (authority?.authorityClass) {
    case 'post-quantum':
      return {
        supported: true,
        scheme: 'falcon-1024',
        basis: `${authorizer} is a Falcon-1024 key, on a provider-confirmed record.`,
      };
    case 'classical-multisig':
      return {
        supported: false,
        reason: `${authorizer} is a multisig. Multisig signing is not priced by this budget.`,
      };
    case 'logicsig':
      return {
        supported: false,
        reason: `${authorizer} is a logic signature. Logic-signature signing is not priced by this budget.`,
      };
    case 'unknown-hash-derived':
      return {
        supported: false,
        reason: `Nothing establishes what signs for ${authorizer}, so its signature cannot be priced.`,
      };
    case 'classical-key':
      return ed25519ByShape(authorizer);
    default:
      return isHashDerivedAddress(authorizer)
        ? { supported: false, reason: `Nothing establishes what signs for ${authorizer}, so its signature cannot be priced.` }
        : ed25519ByShape(authorizer);
  }
}

function ed25519ByShape(authorizer: string): SignerSupport {
  if (isHashDerivedAddress(authorizer) || !algosdk.isValidAddress(authorizer)) {
    return { supported: false, reason: `${authorizer} is not an Ed25519 public key.` };
  }
  return {
    supported: true,
    scheme: 'ed25519',
    basis:
      `${authorizer} is on the Ed25519 curve, so it is priced as a single Ed25519 key. ` +
      'An on-curve multisig or logic signature is not ruled out by the address alone, and ' +
      'would carry a different envelope.',
  };
}

/** The signer when a 25-word phrase was checked to derive the authorizer: a single Ed25519 key. */
export const ED25519_BY_PHRASE: SignerSupport = Object.freeze({
  supported: true,
  scheme: 'ed25519',
  basis: 'A 25-word phrase derives this key, so it is a single Ed25519 key.',
});

/* ------------------------------------------------------------------ */
/* Fees                                                                */
/* ------------------------------------------------------------------ */

/** What a fee is computed from. */
export interface FeeParams {
  readonly genesis: NetworkGenesis;
  /** The consensus protocol the node reports. */
  readonly protocol: string;
  /** The minimum fee, per transaction. */
  readonly minFee: bigint;
  /** The pool's current fee per signed byte; zero when not congested. */
  readonly feePerByte: bigint;
  /** The older of the node's last rounds when the parameters and status were read. */
  readonly round: bigint;
  /** A different protocol the node will switch to, and when; null if none. */
  readonly upgrade: { readonly protocol: string; readonly round: bigint } | null;
}

/** One transaction a step sends, as far as its price depends on it. */
export interface StageShape {
  readonly stage: SubmissionStage;
  readonly sender: string;
  /** Whose key signs it. When it is not the sender, the envelope names it. */
  readonly authorizer: string;
  readonly receiver: string;
  readonly rekeyTo: string | null;
  readonly scheme: SignatureScheme;
  /** It carries a nonzero amount, priced at the widest encoding. */
  readonly transfers: boolean;
}

export interface FeeQuote {
  /** The fee the transaction carries. */
  readonly fee: bigint;
  /** `minFee` times the fee factor. */
  readonly consensusMinimum: bigint;
  /** The per-byte fee times the bound on the signed length. */
  readonly congestionCharge: bigint;
  /** The longest the signed transaction can be. */
  readonly maxSignedBytes: number;
  /** In millionths of the minimum fee. */
  readonly factorMicros: bigint;
  readonly minFee: bigint;
  readonly feePerByte: bigint;
}

const PLACEHOLDER = 0xff;
const bytes = (n: number) => new Uint8Array(n).fill(PLACEHOLDER);

/**
 * The longest `shape` can be once signed, on the network `genesis` names.
 * Every value not yet known is at its widest encoding, and the envelope is
 * the largest its scheme produces, so no real signing of this shape is longer.
 */
export function signedSizeBound(shape: StageShape, genesis: NetworkGenesis): number {
  const txn = attemptTransaction({
    stage: shape.stage,
    genesisId: genesis.id,
    genesisHash: genesis.hash,
    sender: shape.sender,
    authorizer: shape.authorizer,
    receiver: shape.receiver,
    amount: shape.transfers ? U64 : 0n,
    fee: U64,
    firstValid: U64,
    lastValid: U64,
    rekeyTo: shape.rekeyTo,
  });
  const sgnr = shape.authorizer === shape.sender ? undefined : algosdk.Address.fromString(shape.authorizer);
  const stxn =
    shape.scheme === 'ed25519'
      ? new algosdk.SignedTransaction({ txn, sig: bytes(64), sgnr })
      : new algosdk.SignedTransaction({
          txn,
          // The widest salt; zero would be omitted, and 128-255 take two bytes.
          pqsig: { sch: FALCON_SCHEME, slt: algosdk.PQ_SALT_MAX, pk: bytes(FALCON_PUBKEY_BYTES), sig: bytes(FALCON_MAX_SIGNATURE_BYTES) },
          sgnr,
        });
  return algosdk.encodeMsgpack(stxn).length;
}

const ceilDiv = (a: bigint, b: bigint) => (a + b - 1n) / b;

/** The fee `shape` must carry under `params`. */
export function quoteFee(params: FeeParams, rules: ProtocolRules, shape: StageShape): FeeQuote {
  const factorMicros = FACTOR_ONE + rules.contribution[shape.scheme];
  const consensusMinimum = ceilDiv(params.minFee * factorMicros, FACTOR_ONE);
  const maxSignedBytes = signedSizeBound(shape, params.genesis);
  const congestionCharge = params.feePerByte * BigInt(maxSignedBytes);
  const fee = consensusMinimum > congestionCharge ? consensusMinimum : congestionCharge;
  return Object.freeze({
    fee,
    consensusMinimum,
    congestionCharge,
    maxSignedBytes,
    factorMicros,
    minFee: params.minFee,
    feePerByte: params.feePerByte,
  });
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

/** An account as algod reported it. */
export interface AccountReading {
  readonly address: string;
  /** Algod keeps no record of an account holding nothing: a zero balance means it does not exist. */
  readonly exists: boolean;
  readonly balance: bigint;
  /** As algod reports it; for an absent account, what creating it would require. */
  readonly minBalance: bigint;
  readonly authAddr: string | null;
  readonly round: bigint;
}

export interface BudgetInputs {
  readonly params: FeeParams;
  readonly source: AccountReading;
  readonly target: AccountReading;
}

/** An input could not be read, or was not usable. Never evidence of anything. */
export class BudgetInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BudgetInputError';
  }
}

const bad = (what: string): never => {
  throw new BudgetInputError(`The node answered with a malformed ${what}.`);
};

/** A microAlgo amount or round: a bigint, or a number only while it is exact. */
function uint(x: unknown, what: string): bigint {
  if (typeof x === 'bigint') return x >= 0n && x <= U64 ? x : bad(what);
  if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x);
  return bad(what);
}

const text = (x: unknown): string | null => (typeof x === 'string' && x ? x : null);

export interface ReadOptions {
  requestTimeoutMs?: number;
}

/** The fee parameters, and whether a protocol change is scheduled. Read-only. */
export async function readFeeParams(
  clients: FalconerClients,
  options: ReadOptions = {},
): Promise<FeeParams> {
  const ms = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const [sp, st] = (await Promise.all([
    withTimeout(clients.algod.getTransactionParams().do(), ms, 'reading transaction parameters'),
    withTimeout(clients.algod.status().do(), ms, 'reading the node status'),
  ])) as unknown as [Record<string, unknown>, Record<string, unknown>];
  let genesis: NetworkGenesis;
  try {
    genesis = genesisOfParams(sp as { genesisID?: unknown; genesisHash?: unknown });
  } catch (err) {
    throw new BudgetInputError(publicMessage(err));
  }
  const protocol = text(sp?.consensusVersion);
  if (!protocol) throw new BudgetInputError('The node did not say which consensus protocol it runs.');
  const catchup = st?.catchupTime === undefined ? 0n : uint(st.catchupTime, 'catch-up time');
  if (catchup > 0n) throw new BudgetInputError('The node is catching up, so its parameters and balances are behind.');
  const round = uint(sp?.firstValid, 'parameter round');
  const statusRound = uint(st?.lastRound, 'round');
  if ((round > statusRound ? round - statusRound : statusRound - round) > MAX_READING_SPREAD_ROUNDS) {
    throw new BudgetInputError('The parameters and the node status were read too many rounds apart to be used together.');
  }
  const next = text(st?.nextVersion);
  const nextRound = st?.nextVersionRound === undefined ? null : uint(st.nextVersionRound, 'upgrade round');
  return Object.freeze({
    genesis,
    protocol,
    minFee: uint(sp?.minFee, 'minimum fee'),
    feePerByte: uint(sp?.fee, 'fee per byte'),
    // The older reading: a quote is as old as its oldest input.
    round: round < statusRound ? round : statusRound,
    upgrade: next && next !== protocol && nextRound !== null ? Object.freeze({ protocol: next, round: nextRound }) : null,
  });
}

/**
 * An account's balance, minimum balance and authority. Read-only. A lookup
 * that fails is thrown, never read as an absent account.
 */
export async function readAccountForBudget(
  clients: FalconerClients,
  address: string,
  options: ReadOptions = {},
): Promise<AccountReading> {
  const info = (await withTimeout(
    clients.algod.accountInformation(address).do(),
    options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
    'reading an account',
  )) as unknown as Record<string, unknown> | null;
  if (typeof info !== 'object' || info === null) bad('account');
  const reported = info!.address === undefined ? address : String(info!.address);
  if (reported !== address) throw new BudgetInputError('The node answered for a different account.');
  const balance = uint(info!.amount, 'balance');
  const minBalance = uint(info!.minBalance, 'minimum balance');
  const raw = info!.authAddr;
  const authAddr = raw === undefined || raw === null ? null : String(raw);
  if (authAddr !== null && !algosdk.isValidAddress(authAddr)) bad('authority');
  return Object.freeze({
    address,
    exists: balance > 0n,
    balance,
    minBalance,
    authAddr: authAddr === address ? null : authAddr,
    round: uint(info!.round, 'account round'),
  });
}

/** Everything a budget is computed from. Read-only; throws when anything is unusable. */
export async function readBudgetInputs(
  clients: FalconerClients,
  accounts: { source: string; target: string },
  options: ReadOptions = {},
): Promise<BudgetInputs> {
  const [params, source, target] = await Promise.all([
    readFeeParams(clients, options),
    readAccountForBudget(clients, accounts.source, options),
    readAccountForBudget(clients, accounts.target, options),
  ]);
  return Object.freeze({ params, source, target });
}

/* ------------------------------------------------------------------ */
/* The budget                                                          */
/* ------------------------------------------------------------------ */

export interface BudgetSpec {
  /** The account being migrated. */
  readonly sender: string;
  /** Whose key signs the funding and the rekey now. */
  readonly authorizer: string;
  /** The new post-quantum address. */
  readonly target: string;
  /** What that key is. */
  readonly signer: SignerSupport;
  /** Fund the target and prove its key before the rekey. Defaults to true. */
  readonly drill?: boolean;
  /** The first step still to run; the ones before it confirmed. Defaults to the first. */
  readonly from?: SubmissionStage;
  /** Funding beyond the target's shortfall, shown as a reserve. Defaults to none. */
  readonly reserve?: bigint;
}

export interface StageBudget {
  readonly stage: SubmissionStage;
  /** Pays the fee, and any amount. */
  readonly sender: string;
  readonly authorizer: string;
  readonly receiver: string;
  readonly rekeyTo: string | null;
  readonly scheme: SignatureScheme;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly feeQuote: FeeQuote;
  /** The network the budget was read on. */
  readonly genesis: NetworkGenesis;
  /** The last round a transaction for this step may start in under this quote. */
  readonly validThroughRound: bigint;
  /** What each address holds once this step confirms; null for a step priced on its own. */
  readonly after: { readonly source: bigint; readonly target: bigint } | null;
}

export interface BudgetTotals {
  /** Every fee, whoever pays it. */
  readonly feeExpense: bigint;
  /** Fees the source pays: funding, rekey and verification. */
  readonly sourceFees: bigint;
  /** The proof's fee, paid by the target from what it holds. */
  readonly targetProofExpense: bigint;
  /** What the source sends the target. Not a fee: it stays at the target. */
  readonly transfer: bigint;
  /** Of the transfer, the part beyond what the target needs. */
  readonly reserve: bigint;
  /** Transfer plus the source's own fees. */
  readonly sourceDebit: bigint;
  /** The balance the source needs now: its minimum plus its debit. */
  readonly sourceRequired: bigint;
  readonly sourceRetained: bigint;
  /** What the target keeps once every step has run: movable only with its 25 words. */
  readonly targetRetained: bigint;
}

export type BudgetStatus =
  /** Every remaining step is priced and affordable, on inputs read from the network. */
  | 'available'
  /** Priced, but it cannot go ahead as it stands: see `problems`. */
  | 'blocked'
  /** Not priced: its inputs are missing, malformed, stale or unsupported. */
  | 'unavailable';

export interface MigrationBudget {
  readonly status: BudgetStatus;
  /** Why it is blocked or unavailable. Empty when available. */
  readonly problems: readonly string[];
  /** What the figures assume, in plain words. */
  readonly assumptions: readonly string[];
  readonly spec: {
    readonly sender: string;
    readonly authorizer: string;
    readonly target: string;
    readonly drill: boolean;
    readonly from: SubmissionStage;
    readonly signer: SignerSupport;
  };
  /** What was read, and until when it may be used. Null when nothing usable was read. */
  readonly observed: {
    readonly genesis: NetworkGenesis;
    readonly protocol: string;
    readonly rules: string;
    readonly minFee: bigint;
    readonly feePerByte: bigint;
    readonly round: bigint;
    readonly validThroughRound: bigint;
  } | null;
  readonly source: { readonly balance: bigint; readonly minBalance: bigint; readonly round: bigint } | null;
  readonly target: {
    readonly exists: boolean;
    readonly balance: bigint;
    /** Its minimum once it exists: its own, or what creating it requires. */
    readonly minBalance: bigint;
    readonly round: bigint;
  } | null;
  /** The remaining steps, in order. */
  readonly stages: readonly StageBudget[];
  readonly totals: BudgetTotals | null;
  /** One Falcon-signed zero-value payment from the migrated account, at these parameters. */
  readonly postMigrationFee: bigint | null;
}

const DRILL_ORDER: readonly SubmissionStage[] = ['funding', 'proof', 'rekey', 'verification'];
const NO_DRILL_ORDER: readonly SubmissionStage[] = ['rekey', 'verification'];

function freezeBudget(b: MigrationBudget): MigrationBudget {
  return Object.freeze({
    ...b,
    problems: Object.freeze([...b.problems]),
    assumptions: Object.freeze([...b.assumptions]),
    spec: Object.freeze({ ...b.spec }),
    stages: Object.freeze(b.stages.map((s) => Object.freeze({ ...s, after: s.after && Object.freeze({ ...s.after }) }))),
  });
}

/** The rules for `params`, or why the parameters cannot be priced from. */
function rulesFor(params: FeeParams, validThroughRound: bigint): ProtocolRules | string {
  const rules = PROTOCOL_RULES[params.protocol];
  if (!rules) {
    return (
      `The node runs consensus protocol ${params.protocol.slice(0, 120)}, whose fee and ` +
      'minimum-balance rules this tool does not encode.'
    );
  }
  if (params.minFee < 1n) return 'The node reports a zero minimum fee, which no encoded protocol has.';
  if (params.upgrade && params.upgrade.round <= validThroughRound + VALIDITY_ROUNDS) {
    return (
      `The node switches to consensus protocol ${params.upgrade.protocol.slice(0, 120)} at round ` +
      `${params.upgrade.round}, before these figures could be used. Read them again after it.`
    );
  }
  return rules;
}

/**
 * One step priced on its own, from the network's current parameters: its fee,
 * and nothing about balances. For callers outside a migration budget, who
 * learn nothing here about whether the step is affordable. Throws when the
 * parameters cannot be read or priced from.
 */
export async function quoteStage(
  clients: FalconerClients,
  step: Omit<StageShape, 'transfers'> & { readonly amount: bigint },
  options: ReadOptions = {},
): Promise<StageBudget> {
  const params = await readFeeParams(clients, options);
  const validThroughRound = params.round + QUOTE_LIFETIME_ROUNDS;
  const rules = rulesFor(params, validThroughRound);
  if (typeof rules === 'string') throw new BudgetInputError(rules);
  const feeQuote = quoteFee(params, rules, { ...step, transfers: step.amount > 0n });
  if (feeQuote.fee > MAX_STAGE_FEE_MICROALGOS) {
    throw new BudgetInputError(
      `"${step.stage}" would need a fee of ${formatAlgos(feeQuote.fee)} ALGO, above the ` +
        `${formatAlgos(MAX_STAGE_FEE_MICROALGOS)} ALGO this tool will pay for one step.`,
    );
  }
  return Object.freeze({
    stage: step.stage,
    sender: step.sender,
    authorizer: step.authorizer,
    receiver: step.receiver,
    rekeyTo: step.rekeyTo,
    scheme: step.scheme,
    amount: step.amount,
    fee: feeQuote.fee,
    feeQuote,
    genesis: params.genesis,
    validThroughRound,
    after: null,
  });
}

function specOf(spec: BudgetSpec) {
  const drill = spec.drill ?? true;
  return {
    sender: spec.sender,
    authorizer: spec.authorizer,
    target: spec.target,
    drill,
    from: spec.from ?? (drill ? DRILL_ORDER : NO_DRILL_ORDER)[0]!,
    signer: spec.signer,
  };
}

/** A budget that states no figures, and why. */
export function unavailableBudget(spec: BudgetSpec, problems: readonly string[]): MigrationBudget {
  return freezeBudget({
    status: 'unavailable',
    problems,
    assumptions: [],
    spec: specOf(spec),
    observed: null,
    source: null,
    target: null,
    stages: [],
    totals: null,
    postMigrationFee: null,
  });
}

/**
 * What the remaining steps of a migration cost, who pays each, and what every
 * address holds after it. Pure: everything comes from `inputs`, so the same
 * inputs always give the same budget.
 */
export function computeBudget(inputs: BudgetInputs | null, spec: BudgetSpec): MigrationBudget {
  const s = specOf(spec);
  const order = s.drill ? DRILL_ORDER : NO_DRILL_ORDER;
  const unavailable = (...why: string[]) => unavailableBudget(spec, why);
  if (!order.includes(s.from)) return unavailable(`"${s.from}" is not a step of this migration.`);
  const reserve = spec.reserve ?? 0n;
  if (reserve < 0n || reserve > U64) return unavailable('The reserve is out of range.');
  for (const [what, a] of [['account', s.sender], ['authority', s.authorizer], ['target', s.target]] as const) {
    if (!algosdk.isValidAddress(a)) return unavailable(`The ${what} is not a valid address.`);
  }
  if (!inputs) {
    return unavailable(
      'No live network parameters, balances or minimum balances were read, so no costs are stated.',
    );
  }

  const { params, source, target } = inputs;
  if (source.address !== s.sender || target.address !== s.target) {
    return unavailable('The readings are for different accounts than this migration.');
  }
  const validThroughRound = params.round + QUOTE_LIFETIME_ROUNDS;
  const rules = rulesFor(params, validThroughRound);
  if (typeof rules === 'string') return unavailable(rules);
  for (const r of [source.round, target.round]) {
    const spread = r > params.round ? r - params.round : params.round - r;
    if (spread > MAX_READING_SPREAD_ROUNDS) {
      return unavailable('The parameters and balances were read too many rounds apart to be used together.');
    }
  }

  const remaining = order.slice(order.indexOf(s.from));
  const sourceSigns = remaining.some((st) => st === 'funding' || st === 'rekey');
  if (sourceSigns && !s.signer.supported) {
    return freezeBudget({ ...unavailable(), status: 'blocked', problems: [s.signer.reason] });
  }
  const sourceScheme = s.signer.supported ? s.signer.scheme : 'ed25519';

  const problems: string[] = [];
  const assumptions: string[] = [];

  // Who signs for the account must be who the remaining steps expect.
  const expected = remaining.includes('rekey') ? s.authorizer : s.target;
  const answersTo = source.authAddr ?? s.sender;
  if (answersTo !== expected) {
    problems.push(
      `${s.sender} answers to ${answersTo}, not ${expected} as the remaining steps need. ` +
        'Nothing can be signed for it as planned.',
    );
  }
  if (remaining.includes('proof') && target.authAddr !== null) {
    problems.push(
      `${s.target} is rekeyed to ${target.authAddr}, so its own Falcon key cannot sign the proof.`,
    );
  }

  // What each step's transaction is, and so what it costs.
  const shapes: Record<SubmissionStage, StageShape> = {
    funding: { stage: 'funding', sender: s.sender, authorizer: s.authorizer, receiver: s.target, rekeyTo: null, scheme: sourceScheme, transfers: true },
    proof: { stage: 'proof', sender: s.target, authorizer: s.target, receiver: s.target, rekeyTo: null, scheme: 'falcon-1024', transfers: false },
    rekey: { stage: 'rekey', sender: s.sender, authorizer: s.authorizer, receiver: s.sender, rekeyTo: s.target, scheme: sourceScheme, transfers: false },
    verification: { stage: 'verification', sender: s.sender, authorizer: s.target, receiver: s.sender, rekeyTo: null, scheme: 'falcon-1024', transfers: false },
  };
  const quotes = {} as Record<SubmissionStage, FeeQuote>;
  for (const st of remaining) {
    quotes[st] = quoteFee(params, rules, shapes[st]);
    if (quotes[st].fee > MAX_STAGE_FEE_MICROALGOS) {
      problems.push(
        `"${st}" would need a fee of ${formatAlgos(quotes[st].fee)} ALGO, above the ` +
          `${formatAlgos(MAX_STAGE_FEE_MICROALGOS)} ALGO this tool will pay for one step.`,
      );
    }
  }

  // The target's minimum once it exists: its own, or what creating it takes.
  const targetMin = target.exists
    ? target.minBalance
    : target.minBalance > rules.baseMinBalance
      ? target.minBalance
      : rules.baseMinBalance;
  if (!target.exists) {
    assumptions.push(
      `${s.target} does not exist yet. Funding creates it, and from then on it must keep ` +
        `${formatAlgos(targetMin)} ALGO (consensus ${rules.name} minimum balance).`,
    );
  }

  // The transfer: only what the target lacks for its minimum and its proof.
  let transfer = 0n;
  if (remaining.includes('funding')) {
    const need = targetMin + (s.drill ? quotes.proof.fee : 0n) - target.balance;
    transfer = (need > 0n ? need : 0n) + reserve;
    if (need <= 0n) {
      assumptions.push(
        `${s.target} already holds enough for its minimum balance and its proof, so the ` +
          'funding step sends nothing and only its fee is spent. It is kept so the steps stay in order.',
      );
    }
    if (reserve > 0n) {
      assumptions.push(`The funding includes a reserve of ${formatAlgos(reserve)} ALGO beyond what the target needs.`);
    }
  }

  // Walk the steps, checking both addresses after each.
  let sBal = source.balance;
  let tBal = target.balance;
  let tMin = target.exists ? targetMin : 0n;
  let sourceShort: string | null = null;
  let targetShort: string | null = null;
  const stages: StageBudget[] = [];
  for (const st of remaining) {
    const shape = shapes[st];
    const fee = quotes[st].fee;
    const amount = st === 'funding' ? transfer : 0n;
    if (shape.sender === s.sender) sBal -= amount + fee;
    else tBal -= fee;
    if (st === 'funding') tBal += amount;
    if (tBal > 0n) tMin = targetMin;
    if (sourceShort === null && sBal < source.minBalance) {
      sourceShort = st;
    }
    if (targetShort === null && tBal < tMin) {
      targetShort = st;
    }
    stages.push({
      stage: st,
      sender: shape.sender,
      authorizer: shape.authorizer,
      receiver: shape.receiver,
      rekeyTo: shape.rekeyTo,
      scheme: shape.scheme,
      amount,
      fee,
      feeQuote: quotes[st],
      genesis: params.genesis,
      validThroughRound,
      after: { source: sBal, target: tBal },
    });
  }

  const sourceFees = stages.filter((x) => x.sender === s.sender).reduce((n, x) => n + x.fee, 0n);
  const targetProofExpense = stages.filter((x) => x.sender !== s.sender).reduce((n, x) => n + x.fee, 0n);
  const sourceDebit = transfer + sourceFees;
  const sourceRequired = source.minBalance + sourceDebit;
  if (sourceShort !== null) {
    const spendable = source.balance - source.minBalance;
    problems.push(
      `Account has ${formatAlgos(spendable)} ALGO above its minimum balance but the migration ` +
        `needs ${formatAlgos(sourceDebit)} ALGO: it would fall below its minimum at "${sourceShort}", ` +
        `short by ${formatAlgos(sourceRequired - source.balance)} ALGO.`,
    );
  }
  if (targetShort !== null) {
    problems.push(
      `${s.target} would fall below its minimum balance of ${formatAlgos(targetMin)} ALGO at ` +
        `"${targetShort}". Nothing tops it up automatically: fund it, then read the budget again.`,
    );
  }
  if (sourceRequired > U64 || transfer > U64) problems.push('The amounts are out of range.');

  assumptions.unshift(
    `Consensus ${rules.name} fee rules, read at round ${params.round}: a minimum fee of ` +
      `${formatAlgos(params.minFee)} ALGO per transaction, three times that for a Falcon-1024 ` +
      `signature, and ${params.feePerByte} microAlgo per signed byte from the node's pool` +
      (params.feePerByte === 0n ? ' (no congestion charge at this reading).' : ' (a congestion charge is in effect).'),
    'Sizes are priced at the largest envelope each signer can produce: a Falcon-1024 signature of up to ' +
      `${FALCON_MAX_SIGNATURE_BYTES} bytes with its ${FALCON_PUBKEY_BYTES}-byte public key.`,
  );
  if (sourceSigns && s.signer.supported) assumptions.push(s.signer.basis);
  assumptions.push(
    `These figures may be used to prepare a step until round ${validThroughRound}, and are read ` +
      'again before every step. A step that would cost more than was approved is not sent.',
  );

  const post = quoteFee(params, rules, shapes.verification);
  return freezeBudget({
    status: problems.length ? 'blocked' : 'available',
    problems,
    assumptions,
    spec: s,
    observed: {
      genesis: params.genesis,
      protocol: params.protocol,
      rules: rules.name,
      minFee: params.minFee,
      feePerByte: params.feePerByte,
      round: params.round,
      validThroughRound,
    },
    source: { balance: source.balance, minBalance: source.minBalance, round: source.round },
    target: { exists: target.exists, balance: target.balance, minBalance: targetMin, round: target.round },
    stages,
    totals: {
      feeExpense: sourceFees + targetProofExpense,
      sourceFees,
      targetProofExpense,
      transfer,
      reserve: remaining.includes('funding') ? reserve : 0n,
      sourceDebit,
      sourceRequired,
      sourceRetained: sBal,
      targetRetained: tBal,
    },
    postMigrationFee: post.fee,
  });
}

/**
 * Read the inputs and compute the budget. Never throws: inputs that cannot be
 * read or used give an unavailable budget that says why.
 */
export async function quoteMigration(
  clients: FalconerClients,
  spec: BudgetSpec,
  options: ReadOptions = {},
): Promise<MigrationBudget> {
  let inputs: BudgetInputs;
  try {
    inputs = await readBudgetInputs(clients, { source: spec.sender, target: spec.target }, options);
  } catch (err) {
    return unavailableBudget(spec, [`The budget's inputs could not be read: ${publicMessage(err)}`]);
  }
  return computeBudget(inputs, spec);
}

/** A remaining step's budget, or an error saying why there is none to prepare from. */
export function stageOf(budget: MigrationBudget, stage: SubmissionStage): StageBudget {
  if (budget.status !== 'available') {
    throw new Error(`The budget is ${budget.status}: ${budget.problems.join(' ') || 'nothing was read.'}`);
  }
  const found = budget.stages.find((x) => x.stage === stage);
  if (!found) throw new Error(`The budget has no figure for "${stage}".`);
  return found;
}

/* ------------------------------------------------------------------ */
/* Holding a run to what was approved                                  */
/* ------------------------------------------------------------------ */

/**
 * Why `fresh` goes beyond `approved`, or null if every remaining step costs
 * no more than was approved, sends no more, and is signed and paid the same
 * way. A lower figure is fine; a higher one needs a new approval.
 */
export function exceedsApproved(approved: MigrationBudget, fresh: MigrationBudget): string | null {
  if (approved.status !== 'available') return 'No available budget was approved.';
  if (fresh.status !== 'available') {
    return `The budget read now is ${fresh.status}: ${fresh.problems.join(' ') || 'nothing usable was read.'}`;
  }
  const a = approved.spec;
  const f = fresh.spec;
  if (a.sender !== f.sender || a.authorizer !== f.authorizer || a.target !== f.target || a.drill !== f.drill) {
    return 'The budget read now is for a different migration.';
  }
  const ga = approved.observed!.genesis;
  const gf = fresh.observed!.genesis;
  if (ga.id !== gf.id || ga.hash !== gf.hash) return `The budget read now is for ${gf.id}, not ${ga.id}.`;
  for (const st of fresh.stages) {
    const was = approved.stages.find((x) => x.stage === st.stage);
    if (!was) return `No budget was approved for "${st.stage}".`;
    if (was.scheme !== st.scheme || was.sender !== st.sender || was.authorizer !== st.authorizer) {
      return `"${st.stage}" would now be signed or paid differently than was approved.`;
    }
    if (st.fee > was.fee) {
      return `"${st.stage}" now needs a fee of ${formatAlgos(st.fee)} ALGO; ${formatAlgos(was.fee)} ALGO was approved.`;
    }
    if (st.amount > was.amount) {
      return `"${st.stage}" now needs to send ${formatAlgos(st.amount)} ALGO; ${formatAlgos(was.amount)} ALGO was approved.`;
    }
  }
  return null;
}

/**
 * Why a prepared attempt is not the transaction `stage` budgets for, or null.
 * Checked before signing, so a mismatch is never signed.
 */
export function preparedMismatch(attempt: TransactionAttempt, stage: StageBudget): string | null {
  if (attempt.stage !== stage.stage) return `The attempt is for "${attempt.stage}", not "${stage.stage}".`;
  if (attempt.genesisId !== stage.genesis.id || attempt.genesisHash !== stage.genesis.hash) {
    return `The attempt was prepared on ${attempt.genesisId}, not ${stage.genesis.id} as budgeted.`;
  }
  for (const k of ['sender', 'authorizer', 'receiver', 'amount', 'fee', 'rekeyTo'] as const) {
    if (attempt[k] !== stage[k]) return `The attempt's ${k} is not what the budget allows.`;
  }
  if (attempt.firstValid > stage.validThroughRound) {
    return `The budget was read too long ago: it may be used until round ${stage.validThroughRound}, and this attempt starts at ${attempt.firstValid}.`;
  }
  return null;
}

/** The scheme of a signed transaction's envelope, or why it is not one this model prices. */
function schemeOf(stxn: algosdk.SignedTransaction): SignatureScheme | string {
  if (stxn.sig && !stxn.msig && !stxn.lsig && !stxn.pqsig) return 'ed25519';
  const pq = stxn.pqsig;
  if (pq && !stxn.sig && !stxn.msig && !stxn.lsig) {
    return algosdk.bytesToBase64(pq.sch) === algosdk.bytesToBase64(FALCON_SCHEME)
      ? 'falcon-1024'
      : 'a post-quantum scheme other than Falcon-1024';
  }
  if (stxn.msig) return 'a multisig';
  if (stxn.lsig) return 'a logic signature';
  return 'no signature';
}

/**
 * Why signed bytes may not be sent under `stage`'s budget, or null. The fee
 * must be the budgeted one, and must cover what the network requires of
 * *this* signed transaction: its actual scheme, at its actual length.
 */
export function signedMismatch(signed: Uint8Array, stage: StageBudget): string | null {
  let stxn: algosdk.SignedTransaction;
  try {
    stxn = algosdk.decodeSignedTransaction(signed);
  } catch {
    return 'The signed bytes do not decode.';
  }
  const scheme = schemeOf(stxn);
  if (scheme !== stage.scheme) return `It was signed with ${scheme}, not the ${stage.scheme} the budget priced.`;
  const q = stage.feeQuote;
  if (stxn.txn.fee !== stage.fee) return `It carries a fee of ${stxn.txn.fee}, not the budgeted ${stage.fee}.`;
  if (signed.length > q.maxSignedBytes) {
    return `It is ${signed.length} bytes signed, longer than the ${q.maxSignedBytes} the budget priced.`;
  }
  const congestion = q.feePerByte * BigInt(signed.length);
  const required = q.consensusMinimum > congestion ? q.consensusMinimum : congestion;
  if (stxn.txn.fee < required) {
    return `Its fee of ${stxn.txn.fee} is below the ${required} this signed transaction requires.`;
  }
  return null;
}
