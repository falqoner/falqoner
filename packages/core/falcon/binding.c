/*
 * Falqoner's binding to Algorand's deterministic Falcon-1024 (algorand/falcon
 * at ce15e75bceb372867daf6b8e81918ab6978686eb), compiled with it by build.sh
 * into the WebAssembly module that src/falcon-wasm.ts embeds.
 *
 * JavaScript (src/falcon-binding.ts) calls falcon_det1024_sign_compressed and
 * falcon_det1024_verify_compressed directly. This file adds only what needs
 * the C structs and macros: seeded key generation, done as the pinned
 * repository's own Go binding does it (falcon.go, GenerateKey), and the sizes.
 */
#include <stddef.h>
#include "deterministic.h"

int falqoner_keygen(const void *seed, size_t seed_len, void *privkey, void *pubkey)
{
  shake256_context rng;
  int r;

  shake256_init_prng_from_seed(&rng, seed, seed_len);
  r = falcon_det1024_keygen(&rng, privkey, pubkey);
  /* Best effort: the generator's state determines the key. */
  volatile unsigned char *p = (volatile unsigned char *)&rng;
  for (size_t i = 0; i < sizeof rng; i++) {
    p[i] = 0;
  }
  return r;
}

/* 0: public key, 1: private key, 2: largest compressed signature. */
size_t falqoner_size(int which)
{
  switch (which) {
  case 0: return FALCON_DET1024_PUBKEY_SIZE;
  case 1: return FALCON_DET1024_PRIVKEY_SIZE;
  case 2: return FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;
  default: return 0;
  }
}
