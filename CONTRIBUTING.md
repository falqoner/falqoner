# Contributing to Falqoner

This guide is for testers and contributors. It covers getting the right source,
running it, checking a change, reporting a problem and how the public
repository is updated, and it links to the [README](README.md) and
[Local testing](docs/LOCAL_TESTING.md) guide rather than repeating them.

Falqoner is experimental prerelease software. It has not been externally
audited, and a migration it performs cannot be undone by anyone if the new key
is lost; see [Limitations](README.md#limitations) and [SECURITY.md](SECURITY.md).

## Get the source

The public repository is
[`falqoner/falqoner`](https://github.com/falqoner/falqoner). Released versions
are tagged, with their downloads on its
[Releases page](https://github.com/falqoner/falqoner/releases); none is
published on a package registry. If you were invited to test a revision that
is not public yet, use the repository and exact commit or branch your
invitation names instead.

```bash
git clone https://github.com/falqoner/falqoner.git
cd falqoner
git checkout <revision you were asked to test>   # or stay on the default branch
git rev-parse HEAD   # quote this commit in every report
```

The command is `falqoner` and the packages are `@falqoner/*`. Some text, the
demo and a few stored names still use the development name, Falconer; see
[Try It](README.md#try-it).

## Set up and run it

1. Use Node 22.13 or later on the 22 line, or Node 24, with the npm it ships
   ([toolchain](docs/LOCAL_TESTING.md#toolchain)).
2. Install exactly what the lockfile pins: `npm ci`.
3. Try it as the README describes: the
   [web app](README.md#option-a-the-visual-web-app-recommended-for-quick-evaluation)
   with `npm run dev`, or the
   [offline terminal demo](README.md#option-b-the-2-minute-terminal-demo) with
   `npm run build` then `npm run demo`, which needs no network, keys or Docker.

**Check the network before you act.** The web app's network selector starts on
MainNet, and the CLI reads MainNet unless given `--network`. Scans and plans
only read public data on any network. Migration runs only in the web app, only
on TestNet or LocalNet, with accounts made for testing that hold nothing of
value. Never type a MainNet recovery phrase into a web page: a phrase is the
same key on every network. Before a LocalNet run, `npm run localnet:status`
reports which network the local node is on and whether it is supported.

Running a local node needs Docker and AlgoKit; start, check and stop it as
[Running the LocalNet suite](docs/LOCAL_TESTING.md#running-the-localnet-suite)
describes, and see [Troubleshooting](docs/LOCAL_TESTING.md#troubleshooting) when
something is not ready.

## How the code is laid out

| Path | What it is |
| --- | --- |
| `packages/core` | The engine the CLI and web app share: account and authority reading, exposure and coverage, Falcon-1024 keys, migration plans, budgets and the guarded migration ceremony |
| `packages/cli` | The `falqoner` command: read-only `scan`, `plan`, `verify` and `inspect`, and `keygen`, whose output is a secret |
| `apps/web` | The browser app: the audit, and the experimental TestNet/LocalNet migration |
| `scripts` | The test runner, demo and recording, built-page smoke check and LocalNet readiness probe |

[Architecture & Philosophy](README.md#architecture--philosophy) and the
[Technical Deep Dive](README.md#technical-deep-dive-for-engineers--auditors)
explain the design.

## Check a change

For code changes, run the checks CI's offline job runs: `npm run format:check`,
`npm run typecheck`, `npm run build`, `node scripts/wasm-provenance.mjs
packages/core/dist/falcon-wasm.js apps/web/dist/assets` and `npm test`, which
runs the offline suites and needs no Docker. Then add what the change touches:

| You changed | Also run |
| --- | --- |
| `packages/core` | `npm run test:localnet` when submission, the migration ceremony, budgets or ledger reading changed. It needs a healthy LocalNet and fails rather than skips without one. |
| `packages/core/falcon` | Rebuild the Falcon-1024 WebAssembly as `packages/core/falcon/build.sh` describes and compare it: `node scripts/wasm-provenance.mjs <output>/falcon.wasm`. A module that should change also changes the pinned hash in that script, then `--write` regenerates `src/falcon-wasm.ts`. |
| `packages/cli` | Nothing more: `npm test` builds the CLI and checks the committed demo recording. If the demo's output changed on purpose, `npm run record` rewrites the recording. |
| `apps/web` | `npm run test:web-smoke` after `npm run build`. It needs Google Chrome, and a fixed ledger answers every request the page makes. |
| Documentation only | `npm run format:check` |

[Entry points](docs/LOCAL_TESTING.md#entry-points) lists every command and what
it runs.

## Branches and commits

- Work on a short-lived branch from the revision you were given, named for the
  change: `fix/graph-labels`, `docs/tester-guide`.
- Write [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): summary`, such as `fix(web): keep focus when a step starts`.
  Use `feat`, `fix`, `docs`, `test` or `chore`, with the area as the scope. Keep
  one logical change per commit, and say why in the body.
- In a pull request, say what changed, why, and which checks you ran, with
  their results.
- Never commit a recovery phrase, key, token or `keygen` output. Build output
  is ignored.

## Report a problem

Report ordinary bugs and suggestions as
[issues](https://github.com/falqoner/falqoner/issues), or where your invitation
says for a revision that is not public yet. A useful issue includes:

- the commit (`git rev-parse HEAD`)
- your operating system, `node --version`, and the browser and its version for
  the web app
- the network: MainNet, TestNet or LocalNet
- what you did, what you expected and what happened, as the smallest
  reproduction you can find
- public diagnostics: the command and its output, public addresses, transaction
  ids and rounds, browser console errors

**Never include a recovery phrase, private key, seed, token or funds**, in an
issue or anywhere else. No report needs them, and no maintainer will ask for
them. If a phrase was exposed, treat that key as compromised and move what it
controls.

**Security vulnerabilities and other sensitive details do not belong in
issues.** Report them privately, as
[SECURITY.md](SECURITY.md#reporting-a-vulnerability) describes, and do not post
them in issues, pull requests or anywhere public. A code of conduct, with a way
to raise conduct concerns, is not in place yet; conduct concerns do not belong
in issues.

## How the public repository is updated

The `falqoner` GitHub organization owns
[`falqoner/falqoner`](https://github.com/falqoner/falqoner). Falqoner is
developed in a separate repository and published here by a one-way export:
each update is one new commit holding a snapshot of an allowlisted set of
files. Before it is pushed, the export and its history are checked for files
and references that must stay out, such as internal planning and review
records. Published history is never rewritten.

Pull requests are reviewed here. Because this repository changes only by
export, an accepted change is applied in the development repository and
arrives in a later export commit rather than by merging the pull request.
