/**
 * Authority classification.
 *
 * Whether an account is actually protected from a quantum adversary is a
 * question about which *kind* of key authorises it, and that cannot be read
 * off the address.
 *
 * An address that is off the Ed25519 curve is hash-derived, which rules out a
 * bare classical key. It does not rule out a multisignature account or a
 * delegated logic signature, both of which are built from Ed25519 keys and
 * are just as exposed. Treating "off-curve" as "safe" is the most dangerous
 * mistake this tool could make, so nothing is reported as post-quantum
 * without a record of the authority signing.
 *
 * Trust model (RC01). The configured indexer is trusted as a source of
 * confirmed ledger records. The evidence is a transaction it reports as
 * confirmed, sent by the account and authorised by a Falcon-1024 `pqsig`.
 * Falconer then does one thing locally: it re-derives the address that the
 * record's scheme, public key and salt bind to, and requires it to be the
 * account's authority exactly. That address binding is a real check, but it
 * is not signature verification - Falconer never checks the signature bytes
 * or the transaction payload. A provider that fabricates a coherent record is
 * outside this boundary, and every verdict states which guarantees it rests
 * on rather than implying more.
 */
import algosdk from 'algosdk';
import {
  isHashDerivedAddress,
  derivePqAddressAtSalt,
  FALCON_PUBKEY_BYTES,
} from './falcon.js';
import type { FalconerClients } from './networks.js';

export type AuthorityClass =
  /**
   * The authority address is on the Ed25519 curve, so a classical Ed25519
   * key can authorise it. That exposure follows from the address alone; the
   * account *type* behind it (a single key, or an on-curve multisig or
   * logic-signature hash) is not established by shape.
   */
  | 'classical-key'
  /** A confirmed record shows a multisig signature: N Ed25519 keys. */
  | 'classical-multisig'
  /** A confirmed record shows a logic signature: program-controlled. */
  | 'logicsig'
  /**
   * A confirmed Falcon-1024 record whose scheme, public key and salt bind
   * exactly to this authority address.
   */
  | 'post-quantum'
  /** Off-curve, but nothing establishes which kind of authority it is. */
  | 'unknown-hash-derived';

/** What a classification rests on. */
export type EvidenceBasis =
  /**
   * The address is on the Ed25519 curve. That alone establishes classical
   * exposure, but says nothing about the account type behind it.
   */
  | 'address-shape'
  /** A confirmed, well-formed record from the trusted provider. */
  | 'provider-record'
  /** Nothing establishes the class. */
  | 'none';

/** Why a provider record was not accepted as evidence. */
export type EvidenceRejection =
  /** Not a transaction record at all (null, or not an object). */
  | 'malformed-record'
  /** No transaction id, or a blank one: the record cannot be named. */
  | 'missing-id'
  /** An id that is not a 52-character base32 Algorand transaction id. */
  | 'malformed-id'
  /** Returned for a sender-role query, but sent by another account. */
  | 'wrong-sender'
  /** Not reported as confirmed in a round. */
  | 'unconfirmed'
  /** Confirmed in a round later than the provider's own current round. */
  | 'confirmed-after-current-round'
  /** No signature of any kind. */
  | 'missing-signature'
  /** More than one kind of signature, or one the authority cannot have made. */
  | 'contradictory-record'
  /** A scheme field that is absent or not a string or bytes. */
  | 'malformed-scheme'
  /** A well-formed scheme Falconer does not support (only `f1` is defined). */
  | 'unsupported-scheme'
  /** Not a 1793-byte Falcon-1024 public key. */
  | 'malformed-public-key'
  /** A salt that is not an integer in range. */
  | 'malformed-salt'
  /** The record's scheme, public key and salt bind to a different address. */
  | 'address-mismatch'
  /** They bind to an on-curve address, which a classical key could claim. */
  | 'on-curve-binding'
  | 'malformed-multisig'
  | 'malformed-logicsig';

/**
 * Why a provider's search response as a whole could not be used. Distinct
 * from a rejected record, and from a valid search that found nothing.
 */
export type ResponseFault =
  /** The response was not an object. */
  | 'malformed-response'
  /** No transaction list at all. */
  | 'missing-transaction-list'
  /** A transaction list that is not a list. */
  | 'malformed-transaction-list'
  /** No current round, so confirmation cannot be checked against it. */
  | 'missing-provider-round'
  /** A current round that is not a round. */
  | 'malformed-provider-round';

/**
 * Where a classification came from, and exactly which guarantees back it.
 *
 * The three guarantees are separate on purpose. A confirmed record and a
 * local address binding are what RC01 checks; independent verification of
 * the signature bytes is not performed, and the type says so.
 */
export interface AuthorityEvidence {
  basis: EvidenceBasis;
  /**
   * How the evidence search ended. `unavailable` means the provider could
   * not be asked; `invalid-response` means it answered with something that
   * is not a usable search result. Neither is the same as `none-found`, a
   * valid search that returned nothing.
   */
  lookup:
    | 'not-needed'
    | 'found'
    | 'none-found'
    | 'history-limited'
    | 'unavailable'
    | 'invalid-response';
  /** Set with `invalid-response`: what was wrong with the response. */
  responseFault?: ResponseFault;
  /** The trusted provider the records came from. */
  provider?: { network: string; indexer?: string };
  /** The record the classification rests on. */
  txId?: string;
  /** Round the provider reported that record confirmed in. */
  confirmedRound?: bigint;
  /** The provider's current round when it was asked, for freshness. */
  providerRound?: bigint;
  /** Records examined, and the most that were requested. */
  examined: number;
  lookback?: number;
  guarantees: {
    /** The trusted provider reported a confirmed record of this authority signing. */
    providerConfirmedRecord: boolean;
    /** Falconer re-derived the authority address from the record and it matched. */
    localAddressBinding: boolean;
    /** Falconer verified the signature bytes itself. Never performed in RC01. */
    independentSignatureVerification: false;
  };
  /** Records that were not accepted as evidence, and why (bounded). */
  rejected: Array<{ txId?: string; reason: EvidenceRejection }>;
}

export interface AuthorityAssessment {
  authAddr?: string;
  authorityClass: AuthorityClass;
  /** True only when post-quantum authority is established by a record. */
  quantumSafe: boolean;
  /**
   * True only when the class rests on a confirmed, well-formed record from
   * the trusted provider (`evidence.basis === 'provider-record'`) - that is,
   * when the account type was observed. An on-curve address establishes
   * classical exposure without proving the type, so it is never `proven`.
   */
  proven: boolean;
  /**
   * True when the evidence lookup could not run at all (no indexer
   * configured, it errored, or it returned a malformed response). "We could
   * not check" is a different answer from "we checked and found nothing",
   * and callers must not present the first as if it were the second.
   */
  evidenceUnavailable?: boolean;
  evidenceTxId?: string;
  /** Basis, provenance, freshness and guarantees behind this assessment. */
  evidence: AuthorityEvidence;
  detail: string;
}

/** Most rejected records kept on an assessment. */
const REJECTED_KEPT = 10;

/**
 * Decode base64 without depending on Node's Buffer, so the same analysis code
 * runs in the browser where keys are generated and never leave the page.
 */
function b64(s: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(s);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  // Node before atob was global.
  return Uint8Array.from(
    (globalThis as any).Buffer.from(s, 'base64') as Uint8Array,
  );
}

/** Pull a field that may arrive kebab-cased or camel-cased. */
function field(obj: any, ...names: string[]): any {
  for (const n of names) {
    if (obj?.[n] !== undefined) return obj[n];
  }
  return undefined;
}

/**
 * Bytes from the two encodings a provider uses: raw bytes from algosdk's
 * models, base64 text from the REST API. Anything else is not bytes.
 */
function bytesOf(v: unknown): Uint8Array | undefined {
  if (v instanceof Uint8Array) return v;
  if (typeof v !== 'string' || v.length === 0) return undefined;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(v) || v.length % 4 !== 0) return undefined;
  try {
    return b64(v);
  } catch {
    return undefined;
  }
}

/** A confirmed round, or undefined when absent or not a real round. */
function roundOf(v: unknown): bigint | undefined {
  if (typeof v === 'bigint') return v > 0n ? v : undefined;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v > 0) {
    return BigInt(v);
  }
  return undefined;
}

/**
 * A provider's current round: any non-negative integer, since a chain can be
 * at round 0. Undefined when it is not one.
 */
function providerRoundOf(v: unknown): bigint | undefined {
  if (typeof v === 'bigint') return v >= 0n ? v : undefined;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) {
    return BigInt(v);
  }
  return undefined;
}

/** An Algorand transaction id: base32 of a 32-byte hash, no padding. */
const TXID = /^[A-Z2-7]{52}$/;

/** Longest raw id kept for tracing a malformed one. */
const TRACE_CHARS = 64;

/**
 * A usable transaction id, or why the record has none. A record that cannot
 * be named cannot be looked up, so it is not evidence of anything. A
 * malformed id is kept, truncated, so the record can still be traced.
 */
function txIdOf(
  v: unknown,
):
  | { ok: true; id: string }
  | { ok: false; reason: 'missing-id' | 'malformed-id'; trace?: string } {
  if (v === undefined || v === null) return { ok: false, reason: 'missing-id' };
  if (typeof v !== 'string') {
    return {
      ok: false,
      reason: 'malformed-id',
      trace: String(v).slice(0, TRACE_CHARS),
    };
  }
  if (v.trim() === '') return { ok: false, reason: 'missing-id' };
  return TXID.test(v)
    ? { ok: true, id: v }
    : { ok: false, reason: 'malformed-id', trace: v.slice(0, TRACE_CHARS) };
}

/** A provider field as text: algosdk returns addresses as objects. */
function asText(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  const s = typeof v === 'string' ? v : String((v as any)?.toString?.() ?? v);
  return s.length ? s : undefined;
}

export type AddressBindingFailure = Extract<
  EvidenceRejection,
  | 'malformed-scheme'
  | 'unsupported-scheme'
  | 'malformed-public-key'
  | 'malformed-salt'
  | 'address-mismatch'
  | 'on-curve-binding'
>;

export interface AddressBinding {
  /** The record's scheme, public key and salt bind to the expected address. */
  bound: boolean;
  reason?: AddressBindingFailure;
}

/**
 * Check that a `pqsig` record binds to an authority address.
 *
 * This validates the record's scheme, public-key length and salt, re-derives
 * the address they bind to, and requires it to be `expectedAuthAddr` and to
 * be off the curve. It is a local check on what the provider reported, and it
 * is *only* an address binding: the signature bytes are not examined, so a
 * pass does not show that this key signed anything.
 */
export function checkPqAddressBinding(
  pqsig: unknown,
  expectedAuthAddr: string,
): AddressBinding {
  const fail = (reason: AddressBindingFailure): AddressBinding => ({
    bound: false,
    reason,
  });
  if (!pqsig || typeof pqsig !== 'object') return fail('malformed-public-key');

  const scheme = field(pqsig, 'scheme');
  let schemeText: string;
  if (typeof scheme === 'string') {
    schemeText = scheme;
  } else if (scheme instanceof Uint8Array) {
    schemeText = new TextDecoder().decode(scheme);
  } else {
    return fail('malformed-scheme');
  }
  // Falcon-1024 is the only scheme currently defined.
  if (schemeText !== 'f1') return fail('unsupported-scheme');

  const publicKey = bytesOf(field(pqsig, 'public-key', 'publicKey'));
  if (!publicKey || publicKey.length !== FALCON_PUBKEY_BYTES) {
    return fail('malformed-public-key');
  }

  // Algorand's canonical encoding omits zero-valued fields, so a salt of 0
  // arrives as an absent field rather than a literal 0. Reading it as NaN
  // would reject roughly half of all genuine post-quantum signatures,
  // because salt 0 is the most common canonical salt. Absent is the only
  // spelling of zero accepted: null, text and fractions are malformed.
  const rawSalt = field(pqsig, 'salt');
  let salt: number;
  if (rawSalt === undefined) {
    salt = 0;
  } else if (typeof rawSalt === 'number' && Number.isInteger(rawSalt)) {
    salt = rawSalt;
  } else if (typeof rawSalt === 'bigint') {
    salt = Number(rawSalt);
  } else {
    return fail('malformed-salt');
  }
  if (salt < 0 || salt > algosdk.PQ_SALT_MAX) return fail('malformed-salt');

  // Derive at the salt the record actually carries. Re-deriving the
  // canonical salt and demanding a match would reject any account rekeyed to
  // one of the other addresses the same key can control.
  const derived = derivePqAddressAtSalt(publicKey, salt);
  if (derived !== expectedAuthAddr) return fail('address-mismatch');
  // A Falcon record over an on-curve address is not post-quantum authority:
  // an Ed25519 key pair can claim that address too, which is the whole
  // reason the salt search exists.
  if (!isHashDerivedAddress(derived)) return fail('on-curve-binding');
  return { bound: true };
}

/**
 * Whether a `pqsig` record's scheme, public key and salt bind to
 * `expectedAuthAddr`.
 *
 * @deprecated The name overstates the check. This does not verify a
 * signature: it is `checkPqAddressBinding(...).bound`, kept so existing
 * callers keep working.
 */
export function verifyPqSignatureAuthorises(
  pqsig: any,
  expectedAuthAddr: string,
): boolean {
  try {
    return checkPqAddressBinding(pqsig, expectedAuthAddr).bound;
  } catch {
    return false;
  }
}

/**
 * One line stating what an assessment rests on, for every presentation.
 *
 * Kept next to the model so the CLI and web cannot drift into claiming more
 * than was checked: a provider record is always stated as the provider's,
 * the local address binding is named for what it is, and the signature bytes
 * are always stated as not verified by Falconer.
 */
export function describeEvidence(a: AuthorityAssessment): string {
  const e = a.evidence;
  const rejected = e.rejected.length
    ? `; ${e.rejected.length} record${e.rejected.length === 1 ? '' : 's'} ` +
      `rejected (${[...new Set(e.rejected.map((r) => r.reason))].join(', ')})`
    : '';
  switch (e.basis) {
    case 'provider-record': {
      const where =
        `confirmed record ${e.txId ?? '(no id)'} in round ${e.confirmedRound}, ` +
        `reported by the ${e.provider?.network ?? 'configured'} indexer`;
      return e.guarantees.localAddressBinding
        ? `${where}; address binding checked locally; signature bytes not ` +
            'verified by Falconer'
        : `${where}; signature bytes not verified by Falconer`;
    }
    case 'address-shape':
      return (
        'address shape: on the Ed25519 curve, so a classical key can ' +
        'authorise it; the account type was not observed'
      );
    case 'none':
      switch (e.lookup) {
        case 'unavailable':
          return `no evidence: transaction history could not be read${rejected}`;
        case 'invalid-response':
          return (
            'no evidence: the provider returned a malformed response ' +
            `(${e.responseFault ?? 'unknown fault'})`
          );
        case 'history-limited':
          return (
            `no acceptable record in the ${e.lookback} most recent ` +
            `transactions, and older ones were not read${rejected}`
          );
        default:
          return `no acceptable record found${rejected}`;
      }
  }
}

/**
 * What this account's own authority was established to be, in the words
 * every presentation uses. The CLI and web style it their own way; the
 * meaning stays here.
 *
 * `exposed` is established classical exposure, `unproven` is neither
 * exposure nor safety. Only a record can name a multisig, and an unknown
 * authority is never labelled classical.
 */
export interface AuthorityVerdict {
  tone: 'post-quantum' | 'exposed' | 'unproven';
  label: string;
}

export function authorityVerdict(a: AuthorityAssessment): AuthorityVerdict {
  switch (a.authorityClass) {
    case 'post-quantum':
      return { tone: 'post-quantum', label: 'post-quantum, on a provider-confirmed record' };
    case 'classical-key':
      // The shape establishes the exposure, not a single key: an on-curve
      // multisig or logic-signature hash reads the same.
      return { tone: 'exposed', label: 'classical, by address shape: on the Ed25519 curve' };
    case 'classical-multisig':
      return { tone: 'exposed', label: 'classical multisignature, on a provider-confirmed record' };
    case 'logicsig':
      return { tone: 'unproven', label: 'logic signature, safety unproven' };
    case 'unknown-hash-derived':
      return {
        tone: 'unproven',
        label: a.evidenceUnavailable
          ? 'could not be checked'
          : a.evidence.rejected.length
            ? 'hash-derived, a record rejected'
            : 'hash-derived, type unconfirmed',
      };
  }
}

/** The evidence record for an assessment that needed no lookup. */
const NO_GUARANTEES = {
  providerConfirmedRecord: false,
  localAddressBinding: false,
  independentSignatureVerification: false,
} as const;

const REJECTION_TEXT: Record<EvidenceRejection, string> = {
  'malformed-record': 'is not a transaction record at all',
  'missing-id': 'has no transaction id',
  'malformed-id': 'has an id that is not a 52-character Algorand transaction id',
  'wrong-sender': 'was returned for this account but was sent by another one',
  unconfirmed: 'is not reported as confirmed in any round',
  'confirmed-after-current-round':
    'claims to be confirmed in a round later than the provider’s own current round',
  'missing-signature': 'carries no signature',
  'contradictory-record': 'carries contradictory signature data',
  'malformed-scheme': 'carries no readable signature scheme',
  'unsupported-scheme': 'uses a signature scheme Falconer does not support',
  'malformed-public-key':
    'carries a public key that is not a 1793-byte Falcon-1024 key',
  'malformed-salt': 'carries an invalid salt',
  'address-mismatch':
    'claims a Falcon-1024 signature, but the public key it carries does not ' +
    're-derive this authority address',
  'on-curve-binding':
    'binds to an address on the Ed25519 curve, which a classical key could ' +
    'also claim',
  'malformed-multisig': 'carries an unreadable multisignature',
  'malformed-logicsig': 'carries an unreadable logic signature',
};

const FAULT_TEXT: Record<ResponseFault, string> = {
  'malformed-response': 'it was not a search result',
  'missing-transaction-list': 'it had no transaction list',
  'malformed-transaction-list': 'its transaction list was not a list',
  'missing-provider-round': 'it did not report the provider’s current round',
  'malformed-provider-round': 'its current round was not a valid round',
};

/**
 * Determine what really controls an account.
 *
 * The authority is a separate address when the account has been rekeyed, and
 * the account's own address otherwise. Either way the same question applies:
 * an on-curve authority is exposed to a classical key, and an off-curve one
 * is hash-derived and needs evidence before its kind can be named. Reading
 * "classical" off the *absence* of a rekey is the same category error as
 * reading "post-quantum" off an off-curve address, so neither is done here.
 *
 * Reads recent transactions the account sent, as reported by the trusted
 * provider, and inspects how each was authorised. Falls back to a
 * conservative "unknown" when no acceptable record exists, because absence of
 * evidence is not proof of safety.
 */
export async function assessAuthority(
  clients: FalconerClients,
  address: string,
  authAddr: string | undefined,
  options: { lookback?: number } = {},
): Promise<AuthorityAssessment> {
  // Whatever signs for this account: a separate authority once the account
  // has been rekeyed, otherwise the account's own address.
  const authorityAddress = authAddr ?? address;
  const selfAuthorised = !authAddr;
  const lookback = options.lookback ?? 50;
  const provider = {
    network: clients.network.name,
    indexer: clients.network.indexerUrl,
  };

  if (!isHashDerivedAddress(authorityAddress)) {
    return {
      authAddr,
      authorityClass: 'classical-key',
      quantumSafe: false,
      // Exposure is certain; the account type is not observed.
      proven: false,
      evidence: {
        basis: 'address-shape',
        lookup: 'not-needed',
        examined: 0,
        guarantees: NO_GUARANTEES,
        rejected: [],
      },
      // An on-curve address is usually a bare Ed25519 key, but a multisig or
      // logicsig address is a plain hash and lands on the curve about half
      // the time, so it cannot be named as *the* public key. Either way a
      // classical key can authorise it, which is the part that matters here.
      detail:
        (selfAuthorised
          ? 'The account signs for itself, and its address is a point on the ' +
            'Ed25519 curve, so whatever controls it is classical. On Algorand ' +
            'an address is published from the moment the account exists, so ' +
            'that key material is already in a harvester’s hands.'
          : `Authority belongs to ${authAddr}, which is a point on the Ed25519 ` +
            'curve and is therefore classical.') +
        ' This follows from the shape of the address alone: it establishes ' +
        'the exposure, not which kind of account this is.',
    };
  }

  // Off-curve. Could be post-quantum, multisig, logicsig or an application.
  const base = selfAuthorised
    ? `This account signs for itself, and ${address} is hash-derived, so no ` +
      'bare Ed25519 key can produce it. That alone does not make it quantum ' +
      'safe: multisignature, logic-signature and application addresses are ' +
      'also hash-derived and are built from classical keys. '
    : `Authority belongs to ${authAddr}, which is hash-derived, so no bare ` +
      'Ed25519 key can produce it. That alone does not make it quantum ' +
      'safe: multisignature and logic-signature addresses are also ' +
      'hash-derived and are built from classical keys. ';

  const unchecked: AuthorityAssessment = {
    authAddr,
    authorityClass: 'unknown-hash-derived',
    quantumSafe: false,
    proven: false,
    evidenceUnavailable: true,
    evidence: {
      basis: 'none',
      lookup: 'unavailable',
      provider,
      examined: 0,
      lookback,
      guarantees: NO_GUARANTEES,
      rejected: [],
    },
    detail:
      base +
      'Transaction history could not be read, so no conclusion about the ' +
      'authority type is possible. This is not evidence of safety.',
  };

  if (!clients.indexer) return unchecked;

  const rejected: AuthorityEvidence['rejected'] = [];
  const reject = (txId: string | undefined, reason: EvidenceRejection) => {
    if (rejected.length < REJECTED_KEPT) rejected.push({ txId, reason });
  };

  let res: any;
  try {
    // Ask the ledger for the sender role rather than filtering after the
    // fact. lookupAccountTransactions returns every transaction the address
    // took part in, newest first, so inbound traffic evicts the very
    // transactions the authority signed: 60 received payments are enough to
    // push a post-quantum account back to "unconfirmed", and any account
    // that receives anything at all accumulates them.
    res = await clients.indexer
      .searchForTransactions()
      .address(address)
      .addressRole('sender')
      .limit(lookback)
      .do();
  } catch {
    return unchecked;
  }

  // The response as a whole, before any record in it. A malformed response
  // is not a search that found nothing: reading it as one would turn a
  // provider fault into an ordinary "unconfirmed" account.
  const invalid = (fault: ResponseFault): AuthorityAssessment => ({
    ...unchecked,
    evidence: {
      ...unchecked.evidence,
      lookup: 'invalid-response',
      responseFault: fault,
    },
    detail:
      base +
      `The provider’s response could not be used: ${FAULT_TEXT[fault]}. No ` +
      'conclusion about the authority type is possible, and this is neither ' +
      'evidence of safety nor an empty history.',
  });

  if (!res || typeof res !== 'object') return invalid('malformed-response');
  const list = field(res, 'transactions');
  if (list === undefined) return invalid('missing-transaction-list');
  if (!Array.isArray(list)) return invalid('malformed-transaction-list');
  const rawProviderRound = field(res, 'current-round', 'currentRound');
  if (rawProviderRound === undefined) return invalid('missing-provider-round');
  const providerRound = providerRoundOf(rawProviderRound);
  if (providerRound === undefined) return invalid('malformed-provider-round');

  const transactions: unknown[] = list;
  let examined = 0;

  const found = (
    authorityClass: 'post-quantum' | 'classical-multisig' | 'logicsig',
    txId: string,
    confirmedRound: bigint,
    localAddressBinding: boolean,
    detail: string,
  ): AuthorityAssessment => ({
    authAddr,
    authorityClass,
    quantumSafe: authorityClass === 'post-quantum',
    proven: true,
    evidenceTxId: txId,
    evidence: {
      basis: 'provider-record',
      lookup: 'found',
      provider,
      txId,
      confirmedRound,
      providerRound,
      examined,
      lookback,
      guarantees: {
        providerConfirmedRecord: true,
        localAddressBinding,
        independentSignatureVerification: false,
      },
      rejected: [...rejected],
    },
    detail,
  });

  const source = (txId: string, round: bigint) =>
    `The ${provider.network} indexer reported confirmed transaction ` +
    `${txId} in round ${round}, sent by this account`;

  for (const txn of transactions) {
    examined++;

    // Well-formedness first, for every record the provider returns: an
    // object, with a usable id, confirmed no later than the provider's own
    // current round. A record failing any of these is not a confirmed
    // ledger record, whichever authority it claims.
    if (!txn || typeof txn !== 'object') {
      reject(undefined, 'malformed-record');
      continue;
    }
    const id = txIdOf(field(txn, 'id'));
    if (!id.ok) {
      reject(id.trace, id.reason);
      continue;
    }
    const txId = id.id;
    const confirmedRound = roundOf(
      field(txn, 'confirmed-round', 'confirmedRound'),
    );
    if (confirmedRound === undefined) {
      reject(txId, 'unconfirmed');
      continue;
    }
    if (confirmedRound > providerRound) {
      reject(txId, 'confirmed-after-current-round');
      continue;
    }

    const sender = asText(field(txn, 'sender'));
    if (sender !== address) {
      // The query asked for this sender. A record for another one is a
      // provider inconsistency, never evidence.
      reject(txId, 'wrong-sender');
      continue;
    }

    // A transaction with no auth-addr was authorised by its sender, so the
    // self-authorised case and the rekeyed case share one comparison.
    const txnAuthority = asText(field(txn, 'auth-addr', 'authAddr')) ?? sender;
    // Only transactions authorised by the *current* authority say anything
    // about it. Earlier ones are genuine history about a previous
    // authority, so they are passed over rather than rejected.
    if (txnAuthority !== authorityAddress) continue;

    const sig = field(txn, 'signature');
    const kinds = (['sig', 'multisig', 'logicsig', 'pqsig'] as const).filter(
      (k) => {
        const v = field(sig, k);
        return v !== undefined && v !== null;
      },
    );
    if (kinds.length === 0) {
      reject(txId, 'missing-signature');
      continue;
    }
    if (kinds.length > 1) {
      reject(txId, 'contradictory-record');
      continue;
    }
    const kind = kinds[0]!;
    const body = field(sig, kind);

    if (kind === 'pqsig') {
      const signature = bytesOf(field(body, 'signature'));
      if (!signature || signature.length === 0) {
        reject(txId, 'missing-signature');
        continue;
      }
      let binding: AddressBinding;
      try {
        binding = checkPqAddressBinding(body, authorityAddress);
      } catch {
        binding = { bound: false, reason: 'malformed-public-key' };
      }
      if (!binding.bound) {
        reject(txId, binding.reason ?? 'address-mismatch');
        continue;
      }
      return found(
        'post-quantum',
        txId,
        confirmedRound,
        true,
        `${source(txId, confirmedRound)} and authorised by a Falcon-1024 ` +
          'signature. Falconer re-derived the authority address from the ' +
          'scheme, public key and salt in that record, and it matches ' +
          `${authorityAddress} exactly. Falconer did not verify the signature ` +
          'bytes or the transaction payload itself: this verdict rests on ' +
          'trusting that provider’s confirmed record.',
      );
    }

    if (kind === 'multisig') {
      const threshold = field(body, 'threshold');
      const subs = field(body, 'subsignature');
      const t = typeof threshold === 'bigint' ? Number(threshold) : threshold;
      if (
        typeof t !== 'number' ||
        !Number.isInteger(t) ||
        t < 1 ||
        !Array.isArray(subs) ||
        subs.length < t
      ) {
        reject(txId, 'malformed-multisig');
        continue;
      }
      return found(
        'classical-multisig',
        txId,
        confirmedRound,
        false,
        `${source(txId, confirmedRound)} and authorised by a ${t}-of-` +
          `${subs.length} multisignature. Algorand has no post-quantum ` +
          'multisignature: multisig is Ed25519-only by design, so every member ' +
          'key is classical and this account can never be made quantum-safe ' +
          'while a multisig controls it. Threshold control of a post-quantum ' +
          'account is done with a logic signature instead.',
      );
    }

    if (kind === 'logicsig') {
      const logic = bytesOf(field(body, 'logic'));
      if (!logic || logic.length === 0) {
        reject(txId, 'malformed-logicsig');
        continue;
      }
      return found(
        'logicsig',
        txId,
        confirmedRound,
        false,
        `${source(txId, confirmedRound)} and authorised by a logic ` +
          'signature, so its safety depends on the program. A delegated ' +
          'program can be signed either by an Ed25519 key or, since consensus ' +
          'v42, by a Falcon key, and a logic signature is the only way to get ' +
          'threshold control of a post-quantum account. Falconer does not yet ' +
          'tell those cases apart, so this is reported as unproven rather than ' +
          'exposed.',
      );
    }

    // An Ed25519 signature cannot authorise a hash-derived address, so a
    // record claiming one is inconsistent with the authority it names.
    reject(txId, 'contradictory-record');
  }

  const historyLimited = transactions.length >= lookback;
  const evidence: AuthorityEvidence = {
    basis: 'none',
    lookup: historyLimited ? 'history-limited' : 'none-found',
    provider,
    providerRound,
    examined,
    lookback,
    guarantees: NO_GUARANTEES,
    rejected,
  };

  /**
   * A record that claims to be evidence but fails validation is the single
   * most suspicious thing this lookup can find. It must never be folded into
   * "nothing was found", which is what a caller reads as an ordinary
   * unconfirmed account.
   */
  const suspicious = rejected[0];
  if (suspicious) {
    return {
      authAddr,
      authorityClass: 'unknown-hash-derived',
      quantumSafe: false,
      proven: false,
      evidenceUnavailable: false,
      evidenceTxId: suspicious.txId,
      evidence,
      detail:
        base +
        `A provider record ${REJECTION_TEXT[suspicious.reason]}` +
        (rejected.length > 1
          ? `, and ${rejected.length - 1} more record(s) were also rejected`
          : '') +
        '. That is not proof of anything except that something is wrong: ' +
        'treat the authority as unverified and investigate the transaction ' +
        'named as evidence.',
    };
  }

  return {
    authAddr,
    authorityClass: 'unknown-hash-derived',
    quantumSafe: false,
    proven: false,
    evidenceUnavailable: false,
    evidence,
    detail:
      base +
      (historyLimited
        ? `No transaction signed by this authority was found in the ${lookback} ` +
          'most recent this account sent, and older ones were not read, so its ' +
          'type is unconfirmed.'
        : 'No transaction signed by this authority was found, so its type is ' +
          'unconfirmed.'),
  };
}
