/**
 * Falcon-1024 identity handling.
 *
 * The derivation chain Algorand uses for a native post-quantum account is:
 *
 *   25-word phrase
 *     -> pq25WordMnemonicToSeed(phrase, "f1")      (32-byte, domain-separated)
 *     -> Falcon-1024 deterministic keygen           (1793-byte public key)
 *     -> addressFromPQKey("f1", publicKey)          (32-byte address + salt)
 *
 * The salt is the lowest byte value whose resulting address is *off* the
 * Edwards25519 curve, which is what guarantees a post-quantum address can
 * never collide with a classical Ed25519 public key.
 */
import algosdk from 'algosdk';
import { generateKey, signCompressed, verifyCompressed } from 'falcon-1024';
import jsSha512 from 'js-sha512';
import type { PqIdentity } from './types.js';

export const FALCON_SCHEME = algosdk.FALCON_1024_SCHEME;
export const FALCON_PUBKEY_BYTES = 1793;
export const FALCON_PRIVKEY_BYTES = 2305;

// What a Falcon signature adds to a fee is a consensus rule, not a constant:
// see budget.ts, which prices every step from the network's own parameters.

/* -------------------------------------------------------------------------
 * Edwards25519 point test
 *
 * algosdk keeps its curve check private, so we implement the standard
 * decompression test. A 32-byte value that is *not* a curve point cannot be
 * an Ed25519 public key, which makes it a hash-derived address: a
 * post-quantum account, an application account, or a logic signature.
 * ---------------------------------------------------------------------- */

const P = (1n << 255n) - 19n;
const D =
  37095705934669439343138083508754565189542113879843219016388785533085940283555n;
/** sqrt(-1) mod p */
const SQRT_M1 =
  19681161376707505956807079304988542015446066515923890162744021073123829784752n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

/**
 * Report whether 32 bytes could decode to an Edwards25519 curve point.
 *
 * Returns true for anything that might be a classical public key. A false
 * result is a hard guarantee that the value is hash-derived.
 */
export function couldBeCurvePoint(keyBytes: Uint8Array): boolean {
  if (keyBytes.length !== 32) return false;
  const withoutSign = new Uint8Array(keyBytes);
  withoutSign[31] = withoutSign[31]! & 0x7f;
  const y = leToBigInt(withoutSign);
  // Non-canonical encodings are still accepted by some verifiers, so treat
  // anything at or above p as "could be a point" rather than risk a false
  // negative on a real account.
  if (y >= P) return true;

  const y2 = (y * y) % P;
  const u = (y2 - 1n + P) % P;
  const v = (D * y2 + 1n) % P;
  if (v === 0n) return false;

  // x = u * v^3 * (u * v^7)^((p-5)/8)
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  const pow = modPow((u * v7) % P, (P - 5n) / 8n, P);
  let x = (((u * v3) % P) * pow) % P;

  const vx2 = (((x * x) % P) * v) % P;
  if (vx2 === u) return true;
  if (vx2 === (P - u) % P) {
    x = (x * SQRT_M1) % P;
    return (((x * x) % P) * v) % P === u;
  }
  return false;
}

/**
 * Whether an address is hash-derived and therefore cannot be controlled by a
 * bare Ed25519 key.
 *
 * This is a necessary but not sufficient condition for a post-quantum
 * account: application and logic-signature addresses are also hash-derived.
 * Use {@link confirmPostQuantum} for proof.
 */
export function isHashDerivedAddress(address: string): boolean {
  return classifyAddressShape(address) === 'off-curve';
}

/**
 * What an address string is, as far as its shape can say.
 *
 * `isHashDerivedAddress` answers a yes/no question and has to report
 * "no" for input it could not decode at all, which reads as "on-curve" to
 * a caller that only sees the boolean. Anything presenting a verdict to a
 * person needs the three-way answer so it never describes a malformed
 * string as a valid Ed25519 point.
 */
export function classifyAddressShape(
  address: string,
): 'invalid' | 'on-curve' | 'off-curve' {
  let publicKey: Uint8Array;
  try {
    if (!algosdk.isValidAddress(address)) return 'invalid';
    publicKey = algosdk.decodeAddress(address).publicKey;
  } catch {
    return 'invalid';
  }
  return couldBeCurvePoint(publicKey) ? 'on-curve' : 'off-curve';
}

/* -------------------------------------------------------------------------
 * Identity derivation
 * ---------------------------------------------------------------------- */

/** Derive the post-quantum address authorised by a Falcon-1024 public key. */
export function derivePqAddress(publicKey: Uint8Array): {
  address: string;
  salt: number;
} {
  const { address, salt } = algosdk.addressFromPQKey(FALCON_SCHEME, publicKey);
  return { address: address.toString(), salt };
}

/** Domain separation prefix for post-quantum address derivation. */
const PQ_ADDRESS_PREFIX = new TextEncoder().encode('PQA');

/**
 * Derive the address a Falcon key controls **at a specific salt**.
 *
 *   address = SHA-512/256("PQA" || scheme || salt || publicKey)
 *
 * The canonical salt is the lowest one producing an off-curve address, and
 * it is what every piece of Algorand tooling emits. It is not a consensus
 * rule: the protocol verifies a pqsig at any salt, so one Falcon key can
 * control up to 256 distinct addresses, and an account may legitimately be
 * rekeyed to a non-canonical one.
 *
 * `algosdk.addressFromPQKey` only ever returns the canonical salt, and
 * `addressFromPQSig` throws outright on anything else, so verifying against
 * either would report a genuine post-quantum account as unconfirmed.
 */
export function derivePqAddressAtSalt(
  publicKey: Uint8Array,
  salt: number,
): string {
  if (!Number.isInteger(salt) || salt < 0 || salt > algosdk.PQ_SALT_MAX) {
    throw new Error(`salt out of range: ${salt}`);
  }
  const buf = new Uint8Array(
    PQ_ADDRESS_PREFIX.length + FALCON_SCHEME.length + 1 + publicKey.length,
  );
  let at = 0;
  buf.set(PQ_ADDRESS_PREFIX, at);
  at += PQ_ADDRESS_PREFIX.length;
  buf.set(FALCON_SCHEME, at);
  at += FALCON_SCHEME.length;
  buf[at++] = salt;
  buf.set(publicKey, at);
  const digest = Uint8Array.from(jsSha512.sha512_256.array(buf));
  return new algosdk.Address(digest).toString();
}

/** Rebuild a Falcon-1024 identity from its 25-word recovery phrase. */
export function pqIdentityFromMnemonic(mnemonic: string): PqIdentity {
  const normalised = mnemonic.trim().replace(/\s+/g, ' ');
  const seed = algosdk.pq25WordMnemonicToSeed(normalised, FALCON_SCHEME);
  const { publicKey, privateKey } = generateKey(seed);
  const { address, salt } = derivePqAddress(publicKey);
  return {
    scheme: FALCON_SCHEME,
    publicKey,
    privateKey,
    address,
    salt,
    mnemonic: normalised,
  };
}

/**
 * Create a fresh Falcon-1024 identity backed by a 25-word phrase.
 *
 * Entropy comes from the platform CSPRNG. The phrase is the only backup that
 * matters: the 2305-byte private key is fully recoverable from it.
 */
export function generatePqIdentity(): PqIdentity {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(seed));
}

/** Round-trip check that a phrase really does reproduce an identity. */
export function verifyMnemonicRestores(
  identity: PqIdentity,
  mnemonic: string,
): boolean {
  try {
    return pqIdentityFromMnemonic(mnemonic).address === identity.address;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------
 * Signing
 * ---------------------------------------------------------------------- */

/**
 * Build a transaction signer for `sendingAddress` backed by a Falcon key.
 *
 * When `sendingAddress` differs from the identity's own address, this signs
 * on behalf of a rekeyed account: the classical address stays the sender,
 * and the Falcon key is the authority.
 */
export function makeFalconSigner(
  identity: PqIdentity,
  sendingAddress?: string,
): algosdk.TransactionSigner {
  const signingKey = {
    falcon1024PublicKey: identity.publicKey,
    falcon1024Signer: async (bytes: Uint8Array) =>
      signCompressed(identity.privateKey, bytes),
  };
  const addressable = algosdk.addressWithSignersFromRawFalcon1024Signer(
    signingKey,
    sendingAddress ? algosdk.decodeAddress(sendingAddress) : undefined,
  );
  return addressable.txnSigner;
}

/**
 * Local self-test that a Falcon identity can sign and verify. False, not an
 * exception, when it cannot: the library throws on a signature it rejects.
 */
export function selfTestIdentity(identity: PqIdentity): boolean {
  const probe = new TextEncoder().encode('falconer-self-test');
  try {
    return verifyCompressed(identity.publicKey, signCompressed(identity.privateKey, probe), probe);
  } catch {
    return false;
  }
}
