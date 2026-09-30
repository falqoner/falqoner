import { describe, it, expect } from 'vitest';
import algosdk from 'algosdk';
import {
  couldBeCurvePoint,
  isHashDerivedAddress,
  generatePqIdentity,
  pqIdentityFromMnemonic,
  verifyMnemonicRestores,
  selfTestIdentity,
  derivePqAddress,
  FALCON_PUBKEY_BYTES,
  FALCON_PRIVKEY_BYTES,
} from '../src/falcon.js';

/**
 * algosdk keeps its curve check private, so the reference implementation is
 * resolved from disk at runtime: the package exports map blocks a deep
 * import, and a bundler would refuse to statically analyse one. This lets us
 * differential-test our own implementation against the SDK's.
 *
 * A failure to resolve it is recorded rather than swallowed. The comparison is
 * the only external check on our curve arithmetic, so if the SDK's internal
 * path moves the test below fails and asks for the path to be re-pointed; it
 * does not quietly stop comparing.
 */
let reference: ((b: Uint8Array) => boolean) | undefined;
let referenceError: string | undefined;
{
  const { createRequire } = await import('node:module');
  const { pathToFileURL } = await import('node:url');
  const path = await import('node:path');
  const fs = await import('node:fs');
  let candidate = '<unresolved>';
  try {
    const require = createRequire(import.meta.url);
    // The exports map blocks 'algosdk/package.json', so walk up from the
    // main entry point until we find the package root.
    let root = path.dirname(require.resolve('algosdk'));
    while (root !== path.dirname(root) && path.basename(root) !== 'algosdk') {
      root = path.dirname(root);
    }
    candidate = path.join(root, 'dist/esm/utils/ed25519-check.js');
    if (!fs.existsSync(candidate)) {
      referenceError = `no file at ${candidate}`;
    } else {
      const mod = await import(/* @vite-ignore */ pathToFileURL(candidate).href);
      if (typeof mod.couldBeCurvePoint === 'function') {
        reference = mod.couldBeCurvePoint;
      } else {
        referenceError = `${candidate} no longer exports couldBeCurvePoint`;
      }
    }
  } catch (err) {
    referenceError = `${candidate}: ${(err as Error).message}`;
  }
}

describe('Edwards25519 point test', () => {
  it('accepts every real Ed25519 public key', () => {
    for (let i = 0; i < 300; i++) {
      const pk = algosdk.decodeAddress(
        algosdk.generateAccount().addr.toString(),
      ).publicKey;
      expect(couldBeCurvePoint(pk)).toBe(true);
    }
  });

  it('splits uniformly random values roughly in half', () => {
    let onCurve = 0;
    const n = 600;
    for (let i = 0; i < n; i++) {
      if (couldBeCurvePoint(crypto.getRandomValues(new Uint8Array(32)))) onCurve++;
    }
    // Binomial(600, 0.5); this window is ~7 sigma wide.
    expect(onCurve).toBeGreaterThan(220);
    expect(onCurve).toBeLessThan(380);
  });

  it('agrees with the algosdk reference implementation', () => {
    // Without the reference this test proves nothing, so a missing reference
    // is a failure. Re-point the path above; never relax the comparison.
    expect(
      reference,
      `algosdk reference implementation unavailable (${referenceError}) - ` +
        'the differential check cannot run',
    ).toBeTypeOf('function');

    for (let i = 0; i < 500; i++) {
      const b = crypto.getRandomValues(new Uint8Array(32));
      expect(couldBeCurvePoint(b)).toBe(reference!(b));
    }
    for (let i = 0; i < 100; i++) {
      const pk = algosdk.decodeAddress(
        algosdk.generateAccount().addr.toString(),
      ).publicKey;
      expect(couldBeCurvePoint(pk)).toBe(reference!(pk));
    }
  });

  it('rejects inputs that are not 32 bytes', () => {
    expect(couldBeCurvePoint(new Uint8Array(31))).toBe(false);
    expect(couldBeCurvePoint(new Uint8Array(33))).toBe(false);
  });

  it('classifies the zero address as on-curve, because it is', () => {
    // y = 0 solves to x^2 = -1, which has a root mod p, so the zero address
    // is a real (order-4 torsion) curve point. It is therefore NOT provably
    // hash-derived, and Falconer must never present it as post-quantum.
    expect(isHashDerivedAddress(algosdk.ALGORAND_ZERO_ADDRESS_STRING)).toBe(
      false,
    );
  });

  it('returns false for malformed addresses instead of throwing', () => {
    expect(isHashDerivedAddress('not-an-address')).toBe(false);
    expect(isHashDerivedAddress('')).toBe(false);
  });
});

describe('Falcon-1024 identity', () => {
  it('produces keys of the sizes the protocol expects', () => {
    const id = generatePqIdentity();
    expect(id.publicKey.length).toBe(FALCON_PUBKEY_BYTES);
    expect(id.privateKey.length).toBe(FALCON_PRIVKEY_BYTES);
    expect(algosdk.isValidAddress(id.address)).toBe(true);
  });

  it('always derives an off-curve address, which is the anti-collision guarantee', () => {
    for (let i = 0; i < 20; i++) {
      const id = generatePqIdentity();
      expect(isHashDerivedAddress(id.address)).toBe(true);
    }
  });

  it('restores exactly from its 25-word phrase', () => {
    const id = generatePqIdentity();
    const restored = pqIdentityFromMnemonic(id.mnemonic!);
    expect(restored.address).toBe(id.address);
    expect(restored.salt).toBe(id.salt);
    expect(Buffer.from(restored.publicKey)).toEqual(Buffer.from(id.publicKey));
    expect(Buffer.from(restored.privateKey)).toEqual(Buffer.from(id.privateKey));
    expect(verifyMnemonicRestores(id, id.mnemonic!)).toBe(true);
  });

  it('tolerates whitespace and casing noise in a typed phrase', () => {
    const id = generatePqIdentity();
    const messy = `  ${id.mnemonic!.replace(/ /g, '   ')}  \n`;
    expect(pqIdentityFromMnemonic(messy).address).toBe(id.address);
  });

  it('rejects a phrase that does not belong to the identity', () => {
    const a = generatePqIdentity();
    const b = generatePqIdentity();
    expect(verifyMnemonicRestores(a, b.mnemonic!)).toBe(false);
  });

  it('generates distinct identities across calls', () => {
    const seen = new Set(
      Array.from({ length: 10 }, () => generatePqIdentity().address),
    );
    expect(seen.size).toBe(10);
  });

  it('signs and verifies', () => {
    expect(selfTestIdentity(generatePqIdentity())).toBe(true);
  });

  it('reports a key whose halves do not match as failing, rather than throwing', () => {
    const [a, b] = [generatePqIdentity(), generatePqIdentity()];
    expect(selfTestIdentity({ ...a, privateKey: b.privateKey })).toBe(false);
  });

  it('derives the same address as algosdk for a given public key', () => {
    const id = generatePqIdentity();
    const direct = algosdk.addressFromPQKey(
      algosdk.FALCON_1024_SCHEME,
      id.publicKey,
    );
    const ours = derivePqAddress(id.publicKey);
    expect(ours.address).toBe(direct.address.toString());
    expect(ours.salt).toBe(direct.salt);
  });
});
