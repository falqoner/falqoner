#!/usr/bin/env bash
# Falqoner's build of Algorand's deterministic Falcon-1024 as a standalone
# WebAssembly module: the bytes src/falcon-wasm.ts embeds. Ordinary installs
# and builds use those committed bytes and never need this. Linux x86_64 (WSL2
# is fine), from checkouts made with Linux git outside this repository:
#
#   git clone https://github.com/algorand/falcon.git
#   git -C falcon checkout ce15e75bceb372867daf6b8e81918ab6978686eb
#   git clone https://github.com/emscripten-core/emsdk.git
#   git -C emsdk checkout 41190c21c662e9cc1962aea94e71cbae9fd2fc87    # tag 5.0.7
#   emsdk/emsdk install 5.0.7 && emsdk/emsdk activate 5.0.7
#   packages/core/falcon/build.sh <falcon> <emsdk> <new output directory>
#   node scripts/wasm-provenance.mjs <output directory>/falcon.wasm
#
# It refuses another or a changed Falcon checkout, another emsdk revision, and
# any compiler but that SDK's own: the emcc on PATH, the clang it runs and the
# wasm-opt it uses must be the 5.0.7 release's. It prints the SHA-256 of every
# input and output and writes falcon.wasm, the linker's record of what it took
# from Emscripten's system libraries (why-extract.txt), and upstream's
# tests/test_deterministic built with the same flags (kat.js, kat.wasm), which
# it runs. The last command compares the module with the committed one.
#
# Upstream's sources and config.h are used unmodified, so FALCON_FPEMU stays 1:
# integer-emulated floating point, which upstream requires for deterministic
# signing. -O3 is upstream's Makefile setting. Nothing is compiled with -g, so
# no path is kept. Signing keeps an 80 KB buffer on the C stack, more than
# Emscripten's 64 KB default, hence STACK_SIZE. A call needs only kilobytes of
# heap, so it starts at 1 MiB instead of the default 16 MiB and grows for long
# messages.
set -euo pipefail
FALCON=$(cd "$1" && pwd)
EMSDK=$(cd "$2" && pwd)
mkdir "$3"
OUT=$(cd "$3" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)

# The C sources, unchanged at the pinned commit.
test "$(git -C "$FALCON" rev-parse HEAD)" = ce15e75bceb372867daf6b8e81918ab6978686eb
test -z "$(git -C "$FALCON" status --porcelain --ignored)"
grep -qx '#define FALCON_FPEMU  1' "$FALCON/config.h"

# The SDK and the compiler it actually runs.
test "$(git -C "$EMSDK" rev-parse HEAD)" = 41190c21c662e9cc1962aea94e71cbae9fd2fc87
# shellcheck disable=SC1091
source "$EMSDK/emsdk_env.sh" > /dev/null 2>&1
test "$(cat "$EMSDK/upstream/.emsdk_version")" = releases-6cd98e86d7749ff98b82b7f2ae78eb4f01942788-64bit
test "$(command -v emcc)" = "$EMSDK/upstream/emscripten/emcc"
test "$(em-config LLVM_ROOT)" = "$EMSDK/upstream/bin"
test "$(em-config BINARYEN_ROOT)" = "$EMSDK/upstream"
EMCC_VERSION=$(emcc --version 2> /dev/null | head -n 1)
test "$EMCC_VERSION" = 'emcc (Emscripten gcc/clang-like replacement + linker emulating GNU ld) 5.0.7 (263db4cffa6f9fc2ec514a70abac81362ea41849)'
CLANG=$(emcc -v 2>&1)
grep -qx 'clang version 23.0.0git (https:/github.com/llvm/llvm-project 7b58716d96c3ae4c0c4e6f72e29b16137bb6224b)' <<< "$CLANG"
grep -qx "InstalledDir: $EMSDK/upstream/bin" <<< "$CLANG"
test "$("$EMSDK/upstream/bin/wasm-opt" --version)" = 'wasm-opt version 129 (version_129-64-gc6a5e65b7)'
echo "$EMCC_VERSION"
grep '^clang version' <<< "$CLANG"
"$EMSDK/upstream/bin/wasm-opt" --version

# Upstream's Makefile objects, and the inputs' hashes.
cd "$FALCON"
SOURCES=(codec.c common.c deterministic.c falcon.c fft.c fpr.c keygen.c rng.c shake.c sign.c vrfy.c)
sha256sum "${SOURCES[@]}" ./*.h tests/test_deterministic.c "$HERE/binding.c" | sed "s|$HERE/||"
emcc -O3 -I. "${SOURCES[@]}" "$HERE/binding.c" \
  --no-entry -sSTANDALONE_WASM -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=262144 -sINITIAL_HEAP=1048576 \
  -sEXPORTED_FUNCTIONS=_falqoner_keygen,_falqoner_size,_falcon_det1024_sign_compressed,_falcon_det1024_verify_compressed,_malloc,_free \
  -Wl,--why-extract="$OUT/why-extract.txt" \
  -o "$OUT/falcon.wasm"
emcc -O3 -I. "${SOURCES[@]}" tests/test_deterministic.c -sSTACK_SIZE=262144 -o "$OUT/kat.js"
node "$OUT/kat.js"
cd "$OUT"
sha256sum falcon.wasm kat.js kat.wasm
