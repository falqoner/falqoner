# @falqoner/cli

`falqoner`, post-quantum readiness checks for Algorand accounts in a terminal
or a CI pipeline: what a key controls, whether an account's authority is
established as post-quantum, and what migrating it would take.

> **Experimental and not audited.** Version 0.1.0-beta.1 is a beta for testers.
> It is not published to any package registry.

## Install

Packages named `@falconer/...` or `falconer` on the public npm registry are
other projects. Build both tarballs from a checkout of the Falqoner repository
and install the two files together, because this package depends on
`@falqoner/core`:

```bash
npm ci && npm run build
npm pack -w @falqoner/core -w @falqoner/cli
# then, in your own project:
npm install /path/to/falqoner-core-0.1.0-beta.1.tgz /path/to/falqoner-cli-0.1.0-beta.1.tgz
npx --no falqoner help
```

`--no` stops npx from downloading a different package if `falqoner` is not
installed. Node 22.13+ or Node 24.

## Commands

`scan`, `plan`, `verify` and `inspect` only read, on every network, MainNet
(the default) included. They never load a key or recovery phrase, sign, or
submit a transaction. There is no migrate command.

```bash
falqoner scan <address> [-n network] [--assets ids] [--apps ids] [--deep] [--json] [--fail-on band]
falqoner plan <address> --to <pq-address> [-n network] [--json]
falqoner verify <address> [-n network] [--json]
falqoner inspect <address>
falqoner keygen [--json]
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

`falqoner help` lists every option and exit code. `--json` prints JSON alone
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
`@falqoner/core` README for the Falcon-1024 WebAssembly core embeds.
