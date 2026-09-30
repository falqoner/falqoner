# @falconer/cli

`falconer`, post-quantum readiness checks for Algorand accounts in a terminal
or a CI pipeline: what a key controls, whether an account's authority is
established as post-quantum, and what migrating it would take.

> **Experimental and not audited.** Version 0.1.0 is a pre-release that has
> not been published to any package registry.

## Install

Packages named `@falconer/...` or `falconer` on the public npm registry are
other projects, and `@falconer/cli` there also installs a `falconer` command.
Build both tarballs from a checkout of the Falqoner repository and install the
two files together, because this package depends on `@falconer/core`:

```bash
npm ci && npm run build
npm pack -w @falconer/core -w @falconer/cli
# then, in your own project:
npm install /path/to/falconer-core-0.1.0.tgz /path/to/falconer-cli-0.1.0.tgz
npx --no falconer help
```

`--no` stops npx from downloading a different package if `falconer` is not
installed. Node 22.13+ or Node 24.

## Commands

`scan`, `plan`, `verify` and `inspect` only read, on every network, MainNet
(the default) included. They never load a key or recovery phrase, sign, or
submit a transaction. There is no migrate command.

```bash
falconer scan <address> [-n network] [--assets ids] [--apps ids] [--deep] [--json] [--fail-on band]
falconer plan <address> --to <pq-address> [-n network] [--json]
falconer verify <address> [-n network] [--json]
falconer inspect <address>
falconer keygen [--json]
```

- `scan` maps what a key controls, scores the exposure and states what each
  check covered. `--fail-on` exits 2 at the band, or when an incomplete check
  means it cannot be evaluated.
- `plan` shows the migration steps, blockers and a budget priced from the
  network. It sends nothing, and nothing it prints can be signed by a wallet.
- `verify` exits 0 only when a confirmed Falcon-1024 record establishes
  post-quantum authority, and 2 for anything else.
- `inspect` reports whether an address is on the Ed25519 curve, offline. That
  is a shape, never a verdict.
- `keygen` prints a new Falcon-1024 account and its recovery phrase. **Its
  output is secret**: anyone who reads it controls the account. Keep it out of
  logs, CI and shared terminals.

`falconer help` lists every option and exit code. `--json` prints JSON alone
on stdout. Usage errors and failed reads exit 1.

## Limits

Verdicts rest on the provider's confirmed records and are bounded by what
each check read; a clean scan means nothing exposed was found in what was
checked, not that nothing is exposed. Scores are a heuristic, not a
certification. MainNet signing belongs in a wallet you trust: the CLI accepts
no signing key.

## License

Falqoner's own code is MIT licensed: see `LICENSE`. This package does not
include its dependencies, which npm installs under their own terms; see the
`@falconer/core` README for the Falcon-1024 dependency.
