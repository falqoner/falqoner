# Local testing

Falqoner has four test suites with deliberately different requirements.

| Suite | What it covers | Needs a node? |
| --- | --- | --- |
| **Core offline** | Unit, regression, coverage and cryptographic tests, including the differential check against `algosdk`'s own Edwards25519 implementation, and scan coverage against a scripted provider: paging, caps, failures and malformed responses. Submission and reconciliation against a scripted ledger (`test/scripted-ledger.ts`) with faults injected where a test wants them: lost requests and responses, hangs, pool errors, pruned rounds, malformed block entries, a lagging indexer, another network | No. Passes with Docker stopped and no services running. |
| **CLI offline** | Command dispatch and option parsing, in-process against a deterministic fake ledger, with traps on recovery-phrase access, identity recovery, signing and submission, including coverage rendering and `--fail-on` exits. Also the built `falqoner` executable as a subprocess, with network and environment traps preloaded, run against a fixed ledger (`fixture-ledger.mjs`) that answers its provider reads as REST JSON for every authority class, and a check that the committed demo recording is what the fixture demo prints. | No. The fixed ledger answers inside the process; any other request to a node, public or local, is recorded and refused, and fails the suite. |
| **Web offline** | The web app's components rendered to static markup in Node, from exposures the core model produces against a scripted provider: verdict, coverage, reach and graph labels. The migration operation's transitions, eligibility, network pin and record-driven recovery rules. The migration journal's strict format, compare-and-swap storage and one-tab lock. The whole app mounted in a jsdom document (the only added test environment; files opt in with `@vitest-environment jsdom`), with the scan, key generation and the phrase check replaced, and every transaction prepared, signed, recorded, sent and reconciled by the real code against a scripted ledger per network: repeated clicks, controls during every step, late scan results and late answers, refusals before submission, lost requests and responses at every step, reloads, delayed and expired confirmations, wrong phrases and networks, changed authority, stored state labels altered to claim what the ledger does not show, partial or stale readings, unusable storage and competing tabs | No. No browser and no network: `fetch` and `XMLHttpRequest` are trapped and fail the test. |
| **LocalNet** | End-to-end migration against a real Algorand node: asset creation, rekeying, Falcon-1024 signing, indexer-proven authority. Submission reconciliation with the loss injected in the client and the outcome read from the real node: lost send responses, lookups hidden during a wait, a lagging indexer, an expired window read round by round, a lost proof after a rekey | Yes, and it **fails** rather than skips when the node is missing. |

The offline and LocalNet suites are separated at discovery, not at runtime. The
core offline configuration excludes `*.localnet.test.ts`, so those files are
never even imported — which matters, because a skipped integration suite used to
report a green run that had asserted nothing about the chain. The CLI and web
suites have their own configurations, in `packages/cli` and `apps/web`, and
import no LocalNet test.

The CLI suite builds core and the CLI before it runs (the same `tsc` builds as
`npm run build`), so its executable checks always run the current source, never
a stale `dist`. A failed build fails the suite.

## Toolchain

Node 22.13 or later on the 22 line, or Node 24, each with the npm it ships
(npm 10.9 or later, or npm 11). `devEngines` in the root `package.json` makes
`npm ci`, `npm install` and `npm run` stop on anything else, and every
workspace's `engines` states the same range. The 22.13 floor is jsdom's, the
web suite's test environment; Vitest and Vite accept it too. No newer line is
declared, because nothing has been run on one.

On Linux x64 the lockfile also lists `@napi-rs/lzma-linux-x64-gnu`, which
asks for Node 22.20 or 24.12. It is an optional dependency Rollup declares and
nothing loads, and npm skips an optional package whose engines do not match,
so it does not raise the floor. Hosted CI installs on both sides of it.

Install from the lockfile, then check:

```bash
npm ci
npm run format:check   # whitespace and line endings
npm run typecheck      # types and lint rules
npm run build          # core, the CLI, then the web app
npm test
```

**Lint** is TypeScript's own: unused locals and parameters, implicit returns,
a missing `override`, switch fallthrough, unreachable code and unused labels,
set once in `tsconfig.base.json`. `npm run typecheck` and every build enforce
them on what they compile: each workspace's sources, tests and vitest
configs, and the scripts listed in `scripts/tsconfig.json`. Other scripts,
such as the demo, recording and web smoke check, are not type-checked.

**Formatting** is whitespace only; nothing reflows code. `.editorconfig` states
the conventions: UTF-8, LF, two-space indentation, a final newline and no
trailing whitespace except a Markdown line break. `npm run format:check` runs
`git diff --check` against the empty tree, so every tracked text file is checked
as it stands in the working tree, using the rules `.gitattributes` sets: no
trailing whitespace, tab indentation, space before a tab or blank line at the
end of a file, and no conflict markers. A new file is checked once it is added.
A missing final newline is not detected.

**Line endings** are LF in the repository and in every checkout;
`.gitattributes` overrides `core.autocrlf`. A checkout made before that rule may
still hold CRLF files; Git stores them as LF either way.

**Generated files.** Build output is ignored: `dist/`, `*.tsbuildinfo` (the
web build's `tsc -b` cache), `coverage/` and `.vite/`. Three tracked files are
generated and exempt from the whitespace rules: `package-lock.json`, which only
npm writes, and `docs/terminal.cast` and `docs/terminal.svg`, which
`npm run record` writes and `npm test` checks. `docs/demo.svg` is exported
artwork and exempt for the same reason.

## Entry points

The root entry points run every suite of their kind. A workspace entry point
runs that workspace's own suites, except `test:all`, which always runs
everything:

| Command | From the root | In `packages/core` | In `packages/cli` | In `apps/web` | Exit code |
| --- | --- | --- | --- | --- | --- |
| `npm test` | Core offline, CLI offline, then web offline. **Never** LocalNet. | Core offline | CLI offline | Web offline | non-zero on any offline failure |
| `npm run test:unit` | Identical to `npm test` | Core offline | CLI offline | Web offline | non-zero on any offline failure |
| `npm run test:localnet` | LocalNet only. Requires a healthy node. | LocalNet only | — | — | non-zero if the node is missing, incapable, or any test fails |
| `npm run test:all` | Core, CLI and web offline, then LocalNet. Stops at the first failing stage. | Same as the root | — | — | the failing stage's exit code |
| `npm run localnet:status` | Read-only readiness and version report. Starts nothing. | Same as the root | — | — | non-zero if anything is missing |
| `npm run test:web-smoke` | The built web app in Google Chrome against the fixed ledger. Run `npm run build` first. | — | — | — | non-zero on a failed check or any request the ledger does not answer |
| `npm run typecheck` | Types and lint rules for the runner scripts, then core, the CLI and the web app: sources, tests, vitest configs | Core only | CLI only | Web only | non-zero on any type or lint error |
| `npm run format:check` | Whitespace rules on every tracked text file | — | — | — | non-zero on any violation |

The root `test`, `test:unit`, `test:localnet` and `test:all` scripts, and core's
`test:all`, route through `scripts/run-tests.mjs`, which runs each suite in its
own workspace and stops at the first stage that exits non-zero, exiting with
that stage's code. To run a workspace's scripts from the root, add
`-w @falqoner/core`, `-w @falqoner/cli` or `-w @falqoner/web`
(`npm test -w @falqoner/cli`), or run the script directly in that directory.

No suite reports success on an empty match: every configuration sets
`passWithNoTests: false`, so a discovery glob that stops matching fails the run
instead of quietly passing. Nor on a skip: Vitest exits 0 with skipped or todo
tests, so the runner reads each stage's JSON report, fails the run unless every
collected test passed, and prints how many each stage ran.

`npm run test:web-smoke` serves the built app with `vite preview` and drives
the installed Google Chrome through `playwright-core`, which downloads no
browser. Every request that leaves the page is answered by the CLI's fixed
ledger or refused and reported. It checks that the page loads, that a scan
shows a post-quantum authority with its evidence, that a history the provider
cannot serve is shown as unproven, and that an invalid address is refused on
screen: that the bundle works in a browser, not the behaviour the web suite
covers.

## Running the LocalNet suite

### 1. Start the services, explicitly

```bash
npm run localnet:start   # python -m algokit localnet start
```

Nothing in this repository starts, stops or resets LocalNet on your behalf, and
nothing falls back to TestNet or MainNet when a local node is missing. Starting
the node is always a command you run.

`localnet start` starts the existing containers and preserves their chain state.
It is not a reset.

### 2. Check readiness

```bash
npm run localnet:status
```

```
LocalNet preflight (read-only; nothing is started or reset)
  algod       OK   build 5.0.2 genesis dockernet-v1 round 8143
  network     OK   genesis dockernet-v1 is a verified AlgoKit LocalNet
  falcon-1024 OK   algod 5.0.2 on verified protocol https://github.com/.../268b6343...
  indexer     OK   version 3.10.0 round 8143 lag 0
  kmd         OK   api v1 wallet unencrypted-default-wallet present
  => ready (node v22.15.0)
```

Five things are checked, and each is a real prerequisite of the suite:

- **algod** — the node the tests submit transactions to. Reachability is not
  enough: the probe requires a well-formed round, an active protocol, a genesis
  id and a complete build version. An algod that answers `200` with empty
  metadata is not ready.
- **network** — which chain is actually behind the port. A loopback address
  proves nothing; a tunnel or proxy can serve MainNet on `localhost:4001`, and
  this suite creates assets, rekeys accounts and signs transactions. The genesis
  id algod reports must be on the supported list, public networks are refused by
  name, and anything unrecognised is refused as unverified.
- **falcon-1024** — the capability, which needs two things. A build major of 5
  or higher means the binary *contains* native Falcon-1024 accounts; the active
  consensus protocol determines whether the chain has them switched on. Both are
  required, and a pending upgrade to an unverified protocol is refused too.
- **indexer** — authority proofs are read from the indexer, so its health is
  checked (`db-available`, not migrating, no reported errors, a valid round) and
  its lag behind algod is held to a bound.
- **kmd** — the tests fund accounts from the `unencrypted-default-wallet`
  keystore.

Every check fails closed, and every check always appears in the report. Absent
or malformed readiness metadata is a failure, never a pass: the alternative is a
green run against a node that cannot do what the suite assumes. A check that
could not be evaluated is reported as failed rather than omitted.

The same probe runs automatically before the LocalNet suite
(`packages/core/test/localnet.globalSetup.ts`), so a missing prerequisite is
named once, up front, and the run exits non-zero without importing any test
file. The probe only ever issues HTTP GETs.

### Supported network and protocol policy

This is a narrow, tested allowlist in `scripts/localnet-preflight.mjs`, not
universal network or capability detection:

| Policy | Value | Why |
| --- | --- | --- |
| `SUPPORTED_GENESIS_IDS` | `dockernet-v1` | The genesis AlgoKit 2.10.2 LocalNet reports, verified by the integration suite passing against it. |
| `SUPPORTED_PROTOCOLS` | `future`, and the pinned `specs/tree/268b6343…` revision | The two active-protocol identifiers observed on a verified LocalNet. The pinned revision is what algod 5.0.2's image reports; `future` is the name reported for unreleased consensus in dev mode. |
| `MIN_ALGOD_MAJOR` | `5` | Native Falcon-1024 accounts first ship in algod 5.0. |
| `MAX_INDEXER_LAG_ROUNDS` | `5` | Bounded catch-up allowance — see below. |
| `MAX_INDEXER_LEAD_ROUNDS` | `2` | The probe reads algod's round first, so the indexer can legitimately look a round or two ahead of that snapshot. |

Rejection is deliberately the default. Upgrading the LocalNet image will fail
the protocol check with a diagnostic asking for re-verification, rather than
assuming a protocol nobody has run the suite against is capable. Extending
either list means verifying a healthy run on that network or protocol first and
recording it.

### Bounded indexer catch-up policy

Not every round difference is a problem. The indexer trails algod by design, so
a lag within `MAX_INDEXER_LAG_ROUNDS` is accepted and printed. Past that bound
the authority proofs the suite asserts on would time out, so the run fails
immediately with a retryable diagnostic instead of after twenty slow timeouts —
re-run `npm run localnet:status` once conduit catches up. An indexer more than
`MAX_INDEXER_LEAD_ROUNDS` *ahead* of algod is never waited out: that means a
stale algod or a different chain, and it will not resolve on its own.

### 3. Run the suite

```bash
npm run test:localnet   # prints how many ran; a skip fails the run
npm run test:all        # offline suite first, then LocalNet
```

### 4. Stop the services when you are done

```bash
npm run localnet:stop
```

## Version evidence

`npm run localnet:status` prints the versions any run should be recorded
against: algod build and genesis id, the consensus version, the indexer
version, the KMD API version and the Node version. For the rest of the
toolchain:

```bash
node --version
npm --version
docker version --format '{{.Server.Version}}'
python -m algokit --version
```

The most recent local run, on 2026-09-29, used Windows 11 with Node v22.15.0,
npm 10.9.2, Docker 28.5.2, AlgoKit 2.10.2, algod 5.0.2 and indexer 3.10.0.

## Troubleshooting

Ordered from safest to most destructive. Work down the list, not up it.

**`=> NOT ready: algod, indexer, kmd`, all `ECONNREFUSED`**
Nothing is listening. Docker is probably not running — start Docker, then
`npm run localnet:start`.

**One service failing while the others pass**
That service's container is down or still starting. Check it:

```bash
docker ps -a --filter name=algokit
docker logs --tail 50 algokit_sandbox_indexer
docker start algokit_sandbox_indexer
```

Indexer and conduit take the longest to become healthy after a cold start, so
re-run `npm run localnet:status` a few seconds later before concluding anything.

**`indexer unhealthy: lag N exceeds the 5-round bound`**
The indexer is behind algod, not wrong, and this clears on its own. Wait a
moment and re-run `npm run localnet:status`. If the lag keeps growing, conduit
is not consuming blocks — check `docker logs --tail 50 algokit_sandbox_conduit`.

**`indexer unhealthy: db-available false` / `is-migrating true` / `errors ...`**
The indexer answered but is not serving queries. This does not clear by
waiting on rounds; read its logs.

**`indexer unhealthy: indexer is N rounds ahead of algod`**
The indexer holds data algod does not, which means they are not looking at the
same chain — usually a partially reset LocalNet. Inspect both containers before
doing anything destructive.

**`network ... is not a verified local network` / `refusing to run against the
public network ...`**
The chain behind `localhost:4001` is not a LocalNet this harness has been
verified against. If it is genuinely a local AlgoKit network, see the supported
network and protocol policy above: extending the list is deliberate and
requires a verified run.

**`falcon-1024 capability unverified: active protocol ... is not a verified one`**
The node is new enough but is running a consensus protocol nobody has run this
suite against — typically after a LocalNet image upgrade. Verify a healthy run
and add the protocol to the policy; do not widen the check to make the message
go away.

**`kmd ... unencrypted-default-wallet is missing`**
The node is not an AlgoKit-created LocalNet, or the wallet was renamed. Check
which wallets exist before changing anything:

```bash
curl -s -H "X-KMD-API-Token: $(python -c "print('a'*64)")" http://localhost:4002/v1/wallets
```

**`No un-rekeyed funded LocalNet account in the default wallet`**
Every funder account in the wallet has been rekeyed away by an earlier run. The
suite never rekeys the funder, so this usually means an interrupted run or
manual experimentation. Inspect first — this is the point where the only
remaining options are destructive.

**`algod ... predates native Falcon-1024 accounts`**
The LocalNet image is too old. Upgrading it **replaces local chain state**:

```bash
python -m algokit localnet reset --update
```

> **Destructive.** `algokit localnet reset` deletes the local chain, including
> every account, asset and application on it, and the accounts in the KMD
> wallet. Nothing in this repository runs it for you, and no test or script will
> ever reset LocalNet automatically. Run it yourself, deliberately, when you
> have accepted losing local state.

## Offline suites without Docker

The offline suites are the ones to reach for when Docker is unavailable:

```bash
npm test   # core, CLI, then web offline: no services, no network
```

If any of them reaches for a node, that is a bug in the harness, not a missing
prerequisite. `packages/core/test/preflight.test.ts` keeps the core suite
honest: the readiness probe must target the same endpoints the library uses,
every one of them must be on `localhost`, and the probe's whole verdict is
exercised against controlled responses — a healthy node, and each way a service
can answer while not actually being ready. The CLI suite replaces the provider
with a fake ledger in-process and preloads `packages/cli/test/offline-trap.mjs`
into every subprocess, so a request to any node, MainNet, TestNet or LocalNet,
is recorded, refused, and fails the test that made it. The web suite renders
from exposures built against `packages/core/test/fake-provider.ts`, a scripted
provider with no transport at all, and its mounted tests transact against
`packages/core/test/scripted-ledger.ts`, which has none either.

Under jsdom a test file gets its own `Uint8Array`, while `TextEncoder`, `Buffer`
and WebAssembly still make Node's, and algosdk's `instanceof` checks fail across
the two. `apps/web/test/realm.ts` makes the web suite use Node's everywhere, as a
browser uses its own; without it a Falcon signature cannot be encoded in jsdom.

## Hosted CI

`.github/workflows/ci.yml` is configured for every push to the default branch
and every pull request against it. Application/test and dependency jobs have read-only
repository permissions and use no repository secrets. Pull requests run on
`pull_request`, never `pull_request_target`, and checkout does not keep its
token for later steps. The conditional CodeQL job additionally requests
`security-events: write` to upload analysis; it runs only while the repository
is public. Every action is pinned to a commit SHA, with its release
in a comment. Configuration alone is not evidence of a successful hosted run.

| Job | Runs | Where |
| --- | --- | --- |
| Offline | `npm ci`, `format:check`, `typecheck`, `build`, `npm test` | Ubuntu 24.04, Windows Server 2025 and macOS 26, each on Node 22.13.0 and 24.0.0, the floors of the supported lines |
| Built-page smoke | `npm run test:web-smoke` | The Ubuntu, Node 22.13.0 offline job, with the runner's Google Chrome |
| LocalNet integration | `npm ci`, the pinned LocalNet, readiness, `npm run test:localnet` | Ubuntu 24.04, Node 24.21.0 |
| Dependency audit | `npm audit`, where any advisory fails, then `npm audit signatures` | Ubuntu 24.04, Node 24.21.0 |
| CodeQL | JavaScript and TypeScript, uploaded to code scanning | Only while the repository is public |

The offline jobs start no services and need no Docker, secret or public
provider.

**LocalNet.** `.github/localnet/` is the definition AlgoKit 2.10.2 writes,
with every image pinned by digest to the build the suite passed against:
algod 5.0.2-stable, indexer 3.10.0, conduit-localnet 1.1.0 and PostgreSQL
16.15. It is its own Compose project, `falconer_ci_localnet`, so it cannot
touch a developer's `algokit_sandbox`. The job waits at most five minutes for
the unchanged preflight to pass and writes its report, every version included,
to the job summary. It resets and removes nothing: the hosted runner is
discarded. Upgrading an image means verifying the suite against it first, as
for the genesis and protocol allowlists.

To run the same LocalNet on your machine, stop your own first, since the ports
are the same:

```bash
npm run localnet:stop
docker compose -f .github/localnet/docker-compose.yml up --detach
npm run localnet:status          # repeat until ready
npm run test:localnet
docker compose -f .github/localnet/docker-compose.yml down --volumes   # falconer_ci_localnet only
npm run localnet:start
```

**CodeQL** has not run yet. The job runs only on a public repository; in a
private one it is skipped, and a skipped CodeQL job is not a passing one.
