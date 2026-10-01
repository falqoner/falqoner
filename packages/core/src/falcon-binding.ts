/**
 * Falcon-1024 through Falqoner's own WebAssembly build of Algorand's
 * deterministic Falcon C code: `falcon/binding.c` compiled with it by
 * `falcon/build.sh`, embedded in `falcon-wasm.ts` by
 * `scripts/wasm-provenance.mjs`, which also checks it.
 *
 * The module is standalone WebAssembly: no Emscripten JavaScript, nothing
 * fetched, and nothing imported but a growth notice it does not need. It is
 * compiled and instantiated synchronously when a call first needs it, so
 * every function here is synchronous.
 *
 * Each call checks its inputs, copies them into fresh allocations, and clears
 * and frees those before it returns, thrown or not. An output is copied out
 * only after the C call reports success. Clearing is best effort: the C
 * code's stack temporaries are not cleared, and the keys returned are
 * ordinary JavaScript arrays. An instance that traps is not used again.
 */
import { FALCON_WASM } from './falcon-wasm.js';

export const PUBLIC_KEY_BYTES = 1793;
export const PRIVATE_KEY_BYTES = 2305;
/** The largest compressed deterministic Falcon-1024 signature. */
export const MAX_SIGNATURE_BYTES = 1423;
const SEED_BYTES = 32;
/** Lengths reach WebAssembly as 32-bit integers; its memory is smaller still. */
const MAX_LENGTH = 0x7fff_ffff;

/** The module's exports, as `falcon/build.sh` builds it. */
interface FalconExports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  malloc(size: number): number;
  free(pointer: number): void;
  falqoner_size(which: number): number;
  falqoner_keygen(seed: number, seedLength: number, privateKey: number, publicKey: number): number;
  falcon_det1024_sign_compressed(
    signature: number, signatureLength: number, privateKey: number, message: number, messageLength: number,
  ): number;
  falcon_det1024_verify_compressed(
    signature: number, signatureLength: number, publicKey: number, message: number, messageLength: number,
  ): number;
}
const FUNCTIONS = [
  '_initialize', 'malloc', 'free', 'falqoner_size', 'falqoner_keygen',
  'falcon_det1024_sign_compressed', 'falcon_det1024_verify_compressed',
] as const;

/** A new instance of the embedded module. */
export function instantiateFalcon(): WebAssembly.Exports {
  const bytes = Uint8Array.from(atob(FALCON_WASM), (c) => c.charCodeAt(0));
  // Called after memory grows. Every access below takes a fresh view instead.
  const imports = { env: { emscripten_notify_memory_growth() {} } };
  return new WebAssembly.Instance(new WebAssembly.Module(bytes), imports).exports;
}

/** The exports, initialized, if they are the ones and sizes this binding was written for. */
function checked(exports: WebAssembly.Exports): FalconExports {
  const x = exports as unknown as FalconExports;
  if (!(x.memory instanceof WebAssembly.Memory) || FUNCTIONS.some((f) => typeof x[f] !== 'function')) {
    throw new Error('Falcon: the WebAssembly module lacks an expected export');
  }
  x._initialize();
  const sizes = [0, 1, 2].map((i) => x.falqoner_size(i)).join('/');
  const expected = [PUBLIC_KEY_BYTES, PRIVATE_KEY_BYTES, MAX_SIGNATURE_BYTES].join('/');
  if (sizes !== expected) throw new Error(`Falcon: the WebAssembly module's sizes are ${sizes}, not ${expected}`);
  return x;
}

function need(value: unknown, name: string, length?: number): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError(`Falcon: ${name} must be a Uint8Array`);
  if (length !== undefined && value.length !== length) {
    throw new RangeError(`Falcon: ${name} must be ${length} bytes, not ${value.length}`);
  }
  if (value.length > MAX_LENGTH) throw new RangeError(`Falcon: ${name} is longer than ${MAX_LENGTH} bytes`);
}

/**
 * Falcon-1024 over instances `instantiate` makes, one at a time: the first
 * when a call first needs it, and another after a call traps.
 */
export function bindFalcon(instantiate: () => WebAssembly.Exports) {
  let current: FalconExports | undefined;

  /** Allocate `lengths`, run `body` with their addresses, then clear and free them. */
  function call<T>(lengths: number[], body: (x: FalconExports, at: number[]) => T): T {
    const x = (current ??= checked(instantiate()));
    const at: number[] = [];
    try {
      try {
        for (const n of lengths) {
          const p = x.malloc(Math.max(n, 1)) >>> 0;
          if (!p) throw new Error('Falcon: out of WebAssembly memory');
          at.push(p);
        }
        return body(x, at);
      } finally {
        // Every copy is cleared before any is freed, so a free that traps leaves none.
        const heap = new Uint8Array(x.memory.buffer);
        at.forEach((p, i) => heap.fill(0, p, p + lengths[i]!));
        for (const p of at) x.free(p);
      }
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError && current === x) current = undefined;
      throw e;
    }
  }
  const put = (x: FalconExports, at: number, bytes: Uint8Array) => new Uint8Array(x.memory.buffer).set(bytes, at);
  const get = (x: FalconExports, at: number, length: number) => new Uint8Array(x.memory.buffer).slice(at, at + length);

  return {
    /** Diagnostics: the current instance's memory, or 0 before there is one. */
    memoryBytes: () => current?.memory.buffer.byteLength ?? 0,

    /** The key pair for a 32-byte seed. There is no seedless or random form. */
    generateKey(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
      need(seed, 'seed', SEED_BYTES);
      return call([SEED_BYTES, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES], (x, [s, priv, pub]) => {
        put(x, s!, seed);
        const r = x.falqoner_keygen(s!, SEED_BYTES, priv!, pub!);
        if (r !== 0) throw new Error(`Falcon: key generation failed (${r})`);
        return { publicKey: get(x, pub!, PUBLIC_KEY_BYTES), privateKey: get(x, priv!, PRIVATE_KEY_BYTES) };
      });
    },

    /** The deterministic compressed signature of `message`. */
    signCompressed(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
      need(privateKey, 'private key', PRIVATE_KEY_BYTES);
      need(message, 'message');
      return call([MAX_SIGNATURE_BYTES, 4, PRIVATE_KEY_BYTES, message.length], (x, [sig, len, priv, msg]) => {
        put(x, priv!, privateKey);
        put(x, msg!, message);
        const r = x.falcon_det1024_sign_compressed(sig!, len!, priv!, msg!, message.length);
        if (r !== 0) throw new Error(`Falcon: signing failed (${r})`);
        const length = new DataView(x.memory.buffer).getUint32(len!, true);
        if (length < 1 || length > MAX_SIGNATURE_BYTES) {
          throw new RangeError(`Falcon: signing reported ${length} bytes, not 1 to ${MAX_SIGNATURE_BYTES}`);
        }
        return get(x, sig!, length);
      });
    },

    /** True, or throws: a signature it rejects is an error. */
    verifyCompressed(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): true {
      need(publicKey, 'public key', PUBLIC_KEY_BYTES);
      need(signature, 'signature');
      need(message, 'message');
      if (signature.length < 1 || signature.length > MAX_SIGNATURE_BYTES) {
        throw new RangeError(`Falcon: a signature is 1 to ${MAX_SIGNATURE_BYTES} bytes, not ${signature.length}`);
      }
      return call([signature.length, PUBLIC_KEY_BYTES, message.length], (x, [sig, pub, msg]) => {
        put(x, sig!, signature);
        put(x, pub!, publicKey);
        put(x, msg!, message);
        const r = x.falcon_det1024_verify_compressed(sig!, signature.length, pub!, msg!, message.length);
        if (r !== 0) throw new Error(`Falcon: signature rejected (${r})`);
        return true;
      });
    },
  };
}

/** Core's Falcon-1024, over the embedded module. */
export const falcon = bindFalcon(instantiateFalcon);
