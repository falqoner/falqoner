import jsSha512 from 'js-sha512';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * A deterministic transaction id in the real Algorand format, for fixtures.
 *
 * A real id is the unpadded base32 of a 32-byte SHA-512/256 digest: 52
 * characters of `[A-Z2-7]`. Falconer rejects a provider record whose id is
 * not one, so fixtures need ids a genuine provider could return; hashing a
 * readable label keeps them stable and lets a test name the record it means.
 */
export function txid(label: string): string {
  const bytes = jsSha512.sha512_256.array(new TextEncoder().encode(label));
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(value >> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}
