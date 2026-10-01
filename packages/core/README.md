# @falqoner/core

The engine behind Falqoner, post-quantum readiness for Algorand. It maps what
an Ed25519 key controls and scores that exposure, reports what ledger records
establish about an account's authority, and plans and runs the rekey to a
Falcon-1024 key that the Falqoner web app performs on TestNet and LocalNet.

> **Experimental and not audited.** Version 0.1.0-beta.1 is a beta for testers.
> It is not published to any package registry, and its API may change. A rekey
> to a key you cannot reproduce cannot be undone: try any migration on TestNet
> first.

## Install

Packages named `@falconer/...` on the public npm registry are not this
project. Build a tarball from a checkout of the Falqoner repository and
install that file:

```bash
npm ci && npm run build
npm pack -w @falqoner/core
# then, in your own project:
npm install /path/to/falqoner-core-0.1.0-beta.1.tgz
```

Node 22.13+ or Node 24. The package is ESM only.

## Use

Offline, with no provider:

```js
import { classifyAddressShape, generatePqIdentity, selfTestIdentity } from '@falqoner/core';

// 'on-curve', 'off-curve' or 'invalid': a shape, never a verdict.
classifyAddressShape(address);

// A new Falcon-1024 key and its 25-word recovery phrase. Both are secret:
// keep the returned object out of logs.
const identity = generatePqIdentity();

// true when the key signs and verifies locally.
selfTestIdentity(identity);
```

Reading a network. This only reads: nothing is signed or sent.

```js
import { analyzeAccount, clientsFor, riskVerdict } from '@falqoner/core';

const exposure = await analyzeAccount(clientsFor('mainnet'), address);
riskVerdict(exposure.risk); // headline, score, and whether nothing exposed was found
exposure.authority;         // what the provider's records establish, and on what basis
exposure.coverage;          // what each check covered
```

The other exports are typed in the bundled `.d.ts` files. The `falqoner` CLI
(`@falqoner/cli`) and the web app in the Falqoner repository are the
reference callers.

The web app migrates through `openCeremony`, the one supported way to run a
migration. It executes only on TestNet or a private LocalNet, sends the four
steps in order, sends the rekey only after a confirmed proof whose Falcon
signature it verifies, and hands each attempt to the caller's `record` before
sending it, so that an unknown outcome can be settled later.

The other migration exports are primitives for tests and tooling, not a
supported migration path. `prepareStage`, `prepareFunding`, `prepareProof`,
`prepareRekey` and `prepareControlProof` only build a transaction, refusing
one that does not match its budget and a rekey to an on-curve address or to
the account itself. `signStage` holds a signature to its budget, and
`fundPqAddress`, `proveControl`, `rekeyToPq` and `verifyMigration` each sign
and send one transaction under that check. None of them orders the steps,
requires a confirmed proof before a rekey, limits execution to TestNet and
LocalNet, or records an attempt before sending. `prepareAttempt`,
`signAttempt`, `sendAttempt` and `submitAndConfirm`, which they build on,
check no budget.

## Limits

- The configured algod and indexer are trusted for confirmed ledger records.
  Falqoner checks that a reported Falcon record is well formed and binds to
  the authority address, but outside the migration ceremony it does not
  verify Falcon signature bytes.
- A post-quantum verdict needs a confirmed Falcon-1024 record. An off-curve
  address is hash-derived, not proof of a post-quantum key.
- Every check is bounded and says what it covered. Only a complete verdict
  can be clean, and a clean one means nothing exposed was found in what was
  checked. Scores are a heuristic, not a certification.
- Roles on assets and applications the account neither created, holds,
  opted into nor named are outside a scan unless sampled, and application
  permissions are reported as unverified.

## License

Falqoner's own code is MIT licensed: see `LICENSE`. This package does not
include its dependencies. npm installs `algosdk`, `js-sha512` and
`falcon-1024` from the registry under their own terms. `falcon-1024` 0.2.0,
which provides the Falcon-1024 WebAssembly, declares no license in its
package or its source repository. Its build compiles, with Emscripten 5.0.7,
the Falcon Project's C code, published under the MIT license, and Algorand's
deterministic-signing extension to it, whose terms are unresolved: its files
have no license header, and an upstream issue asking whether the MIT license
covers them is unanswered.
Falqoner rebuilt the WebAssembly from the package's source commit and got a
byte-identical module. That shows where the code came from; it is not a
license.
