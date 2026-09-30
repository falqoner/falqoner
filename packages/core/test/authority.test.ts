import { describe, it, expect } from 'vitest';
import algosdk from 'algosdk';
import { verifyPqSignatureAuthorises } from '../src/authority.js';
import { generatePqIdentity, derivePqAddress } from '../src/falcon.js';

/** Find an identity whose canonical salt is exactly `want`. */
function identityWithSalt(want: number, attempts = 400) {
  for (let i = 0; i < attempts; i++) {
    const id = generatePqIdentity();
    if (id.salt === want) return id;
  }
  throw new Error(`no identity with salt ${want} after ${attempts} tries`);
}

describe('post-quantum signature verification', () => {
  it('accepts a signature whose salt field is omitted, meaning zero', () => {
    // Algorand's canonical encoding drops zero-valued fields, so a pqsig with
    // salt 0 arrives with no salt field at all. Salt 0 is the most common
    // canonical salt, so treating the absence as NaN would silently fail to
    // recognise about half of all real post-quantum accounts.
    const id = identityWithSalt(0);
    const pqsig = { publicKey: id.publicKey, scheme: 'f1' }; // no salt key
    expect(verifyPqSignatureAuthorises(pqsig, id.address)).toBe(true);
  });

  it('accepts an explicit zero salt', () => {
    const id = identityWithSalt(0);
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: id.publicKey, scheme: 'f1', salt: 0 },
        id.address,
      ),
    ).toBe(true);
  });

  it('accepts a non-zero salt', () => {
    const id = identityWithSalt(1);
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: id.publicKey, scheme: 'f1', salt: 1 },
        id.address,
      ),
    ).toBe(true);
  });

  it('rejects a salt that is not the canonical one', () => {
    const id = identityWithSalt(1);
    // Claiming salt 0 for a key whose canonical salt is 1 is exactly the
    // inconsistency the network rejects.
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: id.publicKey, scheme: 'f1', salt: 0 },
        id.address,
      ),
    ).toBe(false);
  });

  it('rejects a signature that authorises a different address', () => {
    const a = generatePqIdentity();
    const b = generatePqIdentity();
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: a.publicKey, scheme: 'f1', salt: a.salt },
        b.address,
      ),
    ).toBe(false);
  });

  it('rejects an unknown scheme', () => {
    const id = generatePqIdentity();
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: id.publicKey, scheme: 'zz', salt: id.salt },
        id.address,
      ),
    ).toBe(false);
  });

  it('accepts the kebab-cased, base64 form the REST API returns', () => {
    const id = identityWithSalt(0);
    expect(
      verifyPqSignatureAuthorises(
        {
          'public-key': Buffer.from(id.publicKey).toString('base64'),
          scheme: 'f1',
        },
        id.address,
      ),
    ).toBe(true);
  });

  it('rejects malformed input instead of throwing', () => {
    expect(verifyPqSignatureAuthorises({}, 'x')).toBe(false);
    expect(verifyPqSignatureAuthorises(null, 'x')).toBe(false);
    expect(
      verifyPqSignatureAuthorises(
        { publicKey: new Uint8Array(10), scheme: 'f1' },
        algosdk.ALGORAND_ZERO_ADDRESS_STRING,
      ),
    ).toBe(false);
  });

  it('derives salt 0 for a meaningful share of keys', () => {
    // Guards the assumption behind the omitted-field case: salt 0 is common,
    // so this path is the norm rather than an edge case.
    let zeros = 0;
    for (let i = 0; i < 40; i++) {
      if (derivePqAddress(generatePqIdentity().publicKey).salt === 0) zeros++;
    }
    expect(zeros).toBeGreaterThan(8);
  });
});
