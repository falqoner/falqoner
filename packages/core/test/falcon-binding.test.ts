/**
 * The owned Falcon-1024 binding (src/falcon-binding.ts) against fixed results
 * of the `falcon-1024` 0.2.0 package it replaced (falcon-vectors.json, from
 * fixed synthetic seeds), and its failure handling, with failures injected
 * into the real module's exports.
 */
import { createHash } from 'node:crypto';
import algosdk from 'algosdk';
import { describe, expect, it } from 'vitest';
import { MAX_SIGNATURE_BYTES, bindFalcon, falcon, instantiateFalcon } from '../src/falcon-binding.js';
import { pqIdentityFromMnemonic } from '../src/falcon.js';
import vectors from './falcon-vectors.json';

const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));
const message = (n: number, k = 0) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + k) & 255);
const flip = (b: Uint8Array, i: number) => {
  const c = b.slice();
  c[i] = c[i]! ^ 1;
  return c;
};
const ZERO = bytes(vectors.seeds[0]!.seed);

/** Calls each binding must refuse, by name, around a key pair and its signature of `m`. */
function negatives(f: typeof falcon) {
  const key = f.generateKey(ZERO);
  const other = f.generateKey(bytes(vectors.seeds[1]!.seed)).publicKey;
  const m = message(137);
  const sig = f.signCompressed(key.privateKey, m);
  const loose = (v: unknown) => v as Uint8Array;
  return {
    'seed of 0 bytes': () => f.generateKey(new Uint8Array(0)),
    'seed of 31 bytes': () => f.generateKey(new Uint8Array(31)),
    'seed of 33 bytes': () => f.generateKey(new Uint8Array(33)),
    'no seed': () => f.generateKey(loose(undefined)),
    'seed as a plain array': () => f.generateKey(loose([...ZERO])),
    'private key of 2304 bytes': () => f.signCompressed(key.privateKey.subarray(1), m),
    'private key of 2306 bytes': () => f.signCompressed(new Uint8Array(2306), m),
    'private key with a changed header': () => f.signCompressed(flip(key.privateKey, 0), m),
    'message as a string': () => f.signCompressed(key.privateKey, loose('falcon')),
    'public key of 1792 bytes': () => f.verifyCompressed(key.publicKey.subarray(1), sig, m),
    'public key with a changed header': () => f.verifyCompressed(flip(key.publicKey, 0), sig, m),
    "another key's public key": () => f.verifyCompressed(other, sig, m),
    'empty signature': () => f.verifyCompressed(key.publicKey, new Uint8Array(0), m),
    'one-byte signature': () => f.verifyCompressed(key.publicKey, sig.subarray(0, 1), m),
    'signature of 1424 bytes': () => f.verifyCompressed(key.publicKey, new Uint8Array(1424), m),
    'truncated signature': () => f.verifyCompressed(key.publicKey, sig.subarray(0, sig.length - 1), m),
    'signature with its last byte changed': () => f.verifyCompressed(key.publicKey, flip(sig, sig.length - 1), m),
    'signature with a changed header': () => f.verifyCompressed(key.publicKey, flip(sig, 0), m),
    'signature with a middle byte changed': () => f.verifyCompressed(key.publicKey, flip(sig, sig.length >> 1), m),
    'message with one bit changed': () => f.verifyCompressed(key.publicKey, sig, flip(m, 5)),
    'message one byte shorter': () => f.verifyCompressed(key.publicKey, sig, m.subarray(1)),
  };
}

describe('owned Falcon-1024 binding, against the package it replaced', () => {
  it('derives the same key pairs and signatures from every fixture seed', () => {
    for (const s of vectors.seeds) {
      const key = falcon.generateKey(bytes(s.seed));
      expect([sha(key.publicKey), sha(key.privateKey)], s.name).toEqual([s.publicKey, s.privateKey]);
      const sigs = vectors.lengths.map((n) => falcon.signCompressed(key.privateKey, message(n)));
      expect(sigs.map(sha), s.name).toEqual(s.signatures);
      expect(sigs.every((sig) => sig.length <= MAX_SIGNATURE_BYTES), s.name).toBe(true);
    }
  });

  it('restores the same keys, address and salt from each fixture seed\'s 25 words', () => {
    for (const s of vectors.seeds) {
      const id = pqIdentityFromMnemonic(algosdk.mnemonicFromSeed(bytes(s.seed)));
      expect({ publicKey: sha(id.publicKey), privateKey: sha(id.privateKey), address: id.address, salt: id.salt }, s.name)
        .toEqual(s.restored);
    }
  });

  it('verifies its signatures, and refuses them altered', () => {
    const key = falcon.generateKey(ZERO);
    vectors.zeroSignatures.forEach((hex, j) => {
      const sig = bytes(hex);
      const m = message(vectors.lengths[j]!);
      expect(sha(sig)).toBe(vectors.seeds[0]!.signatures[j]);
      expect(falcon.verifyCompressed(key.publicKey, sig, m)).toBe(true);
      expect(() => falcon.verifyCompressed(key.publicKey, flip(sig, sig.length - 1), m)).toThrow();
    });
  });

  it('grows its memory for a long message and signs it as the package did', () => {
    const f = bindFalcon(instantiateFalcon);
    const key = f.generateKey(ZERO);
    const before = f.memoryBytes();
    const big = message(vectors.large.length, vectors.large.k);
    const sig = f.signCompressed(key.privateKey, big);
    expect(f.memoryBytes()).toBeGreaterThan(before);
    expect(sha(sig)).toBe(vectors.large.signature);
    expect(f.verifyCompressed(key.publicKey, sig, big)).toBe(true);
  });

  it('refuses every malformed call', () => {
    const accepted = Object.entries(negatives(falcon)).filter(([, call]) => {
      try {
        call();
        return true;
      } catch {
        return false;
      }
    });
    expect(accepted.map(([name]) => name)).toEqual([]);
  });

  it('gives the same results over repeated calls, failing ones included, without growing', () => {
    const f = bindFalcon(instantiateFalcon);
    const key = f.generateKey(ZERO);
    const m = message(137);
    const sig = sha(f.signCompressed(key.privateKey, m));
    const bad = Object.values(negatives(f));
    const before = f.memoryBytes();
    // 100 rounds of 21 refused calls: a leak of even a private key's size per call would grow memory.
    for (let i = 0; i < 100; i++) {
      const s = vectors.seeds[i % vectors.seeds.length]!;
      expect(sha(f.generateKey(bytes(s.seed)).publicKey)).toBe(s.publicKey);
      expect(sha(f.signCompressed(key.privateKey, m))).toBe(sig);
      for (const call of bad) expect(call).toThrow();
    }
    expect(f.memoryBytes()).toBe(before);
  });
});

/* -------------------------------------------------------------------------
 * Failures injected into the real module
 * ---------------------------------------------------------------------- */

type Exports = Record<string, any>;

/**
 * A binding over real instances, each with some exports replaced, recording
 * every allocation, whether all were cleared when the first free came, and
 * which are still outstanding.
 */
function instrumented(replace: (real: Exports, wrapped: Exports) => Exports = () => ({})) {
  const log = { instances: 0, outstanding: new Map<number, number>(), clearedBeforeFree: [] as boolean[] };
  const instantiate = () => {
    log.instances++;
    const real: Exports = instantiateFalcon();
    const cleared = () => [...log.outstanding].every(([p, n]) => new Uint8Array(real.memory.buffer, p, n).every((b) => b === 0));
    const wrapped: Exports = {
      ...real,
      malloc: (n: number) => {
        const p = real.malloc(n);
        if (p) log.outstanding.set(p, n);
        return p;
      },
      free: (p: number) => {
        log.clearedBeforeFree.push(cleared());
        log.outstanding.delete(p);
        real.free(p);
      },
    };
    return { ...wrapped, ...replace(real, wrapped) };
  };
  return { log, f: bindFalcon(instantiate) };
}
const trap = () => new WebAssembly.RuntimeError('unreachable');

describe('owned Falcon-1024 binding, under injected failures', () => {
  const key = falcon.generateKey(ZERO);
  const m = message(137);

  it('frees what it allocated when an allocation fails', () => {
    let calls = 0;
    const { log, f } = instrumented((_, w) => ({ malloc: (n: number) => (++calls === 3 ? 0 : w.malloc(n)) }));
    expect(() => f.signCompressed(key.privateKey, m)).toThrow('out of WebAssembly memory');
    expect([log.outstanding.size, log.clearedBeforeFree]).toEqual([0, [true, true]]);
    expect(f.verifyCompressed(key.publicKey, falcon.signCompressed(key.privateKey, m), m)).toBe(true);
    expect(log.instances).toBe(1);
  });

  it('clears and frees every copy when the C call traps, then uses a new instance', () => {
    const { log, f } = instrumented((real) => ({
      falcon_det1024_sign_compressed: (sig: number) => {
        new Uint8Array(real.memory.buffer).fill(0xa5, sig, sig + 100);
        throw trap();
      },
    }));
    expect(() => f.signCompressed(key.privateKey, m)).toThrow(WebAssembly.RuntimeError);
    expect([log.outstanding.size, log.clearedBeforeFree]).toEqual([0, [true, true, true, true]]);
    expect(sha(f.generateKey(ZERO).publicKey)).toBe(vectors.seeds[0]!.publicKey);
    expect(log.instances).toBe(2);
  });

  it('returns no signature whose reported length is out of bounds', () => {
    for (const length of [0, MAX_SIGNATURE_BYTES + 1, 2 ** 32 - 1]) {
      const { log, f } = instrumented((real) => ({
        falcon_det1024_sign_compressed: (...args: number[]) => {
          const r = real.falcon_det1024_sign_compressed(...args);
          new DataView(real.memory.buffer).setUint32(args[1]!, length, true);
          return r;
        },
      }));
      expect(() => f.signCompressed(key.privateKey, m)).toThrow(RangeError);
      expect([log.outstanding.size, log.clearedBeforeFree.every(Boolean)]).toEqual([0, true]);
    }
  });

  it('reads memory afresh when it grows during a call', () => {
    const { log, f } = instrumented((real, w) => ({
      malloc: (n: number) => {
        real.memory.grow(1);
        return w.malloc(n);
      },
    }));
    const k = f.generateKey(ZERO);
    expect([sha(k.publicKey), sha(k.privateKey)]).toEqual([vectors.seeds[0]!.publicKey, vectors.seeds[0]!.privateKey]);
    const sig = f.signCompressed(k.privateKey, message(4096));
    expect(sha(sig)).toBe(vectors.seeds[0]!.signatures[6]);
    expect(f.verifyCompressed(k.publicKey, sig, message(4096))).toBe(true);
    expect(log.outstanding.size).toBe(0);
  });

  it('clears every copy before freeing any, even when a free traps', () => {
    const { log, f } = instrumented((_, w) => ({
      free: (p: number) => {
        w.free(p);
        throw trap();
      },
    }));
    expect(() => f.signCompressed(key.privateKey, m)).toThrow(WebAssembly.RuntimeError);
    expect(log.clearedBeforeFree).toEqual([true]);
    expect(f.memoryBytes()).toBe(0);
  });

  it('refuses a module whose exports or sizes differ', () => {
    for (const [replace, error] of [
      [(real: Exports) => ({ falqoner_size: (i: number) => (i === 0 ? 1792 : real.falqoner_size(i)) }), /sizes are 1792\/2305\/1423/],
      [() => ({ falcon_det1024_verify_compressed: undefined }), /lacks an expected export/],
      [() => ({ memory: new ArrayBuffer(65536) }), /lacks an expected export/],
    ] as const) {
      const { log, f } = instrumented(replace);
      expect(() => f.generateKey(ZERO)).toThrow(error);
      expect([log.instances, log.outstanding.size, f.memoryBytes()]).toEqual([1, 0, 0]);
    }
  });

  it('refuses a length a 32-bit call cannot carry, before allocating', () => {
    const huge = new Proxy(new Uint8Array(1), { get: (t, k) => (k === 'length' ? 2 ** 31 : Reflect.get(t, k)) });
    const { log, f } = instrumented();
    expect(() => f.signCompressed(key.privateKey, huge)).toThrow(/longer than 2147483647 bytes/);
    expect(log.instances).toBe(0);
  });
});
