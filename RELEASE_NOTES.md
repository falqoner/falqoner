# Release notes

Falqoner is experimental prerelease software and has not been externally
audited. A version is released only once its tag and downloads are on the
[Releases page](https://github.com/falqoner/falqoner/releases); a version named
here alone is not a release. No package is published on any registry.

## 0.1.0-beta.1 (beta, prepared 2026-10-01)

A beta for testers. It covers the `@falqoner/core` and `@falqoner/cli`
packages, with the `falqoner` command, and the web app. The project owner
has directed beta preparation on the assumption that the Algorand extension
may be redistributed. This is an owner assumption, not upstream confirmation;
the licensing questions under [Limits](#limits) remain unresolved.

### Reading an account

- `scan`, the web audit and the CLI's other read-only commands show what an
  account's key controls: its balance, roles on assets it created or holds or
  that you name, the applications it created, joined or appears in, and other
  accounts rekeyed to it. Every result says what each check covered and what it could not
  reach.
- An account counts as post-quantum only on a provider-confirmed transaction
  signed with Falcon-1024 whose key and salt match the account's authority
  address. The audit does not verify that signature's bytes itself.
- A failed or unusable account read ends with an error, never a result.
- `scan`, `plan`, `verify`, `inspect` and the web audit never ask for a key or
  recovery phrase, sign or submit, on any network. `keygen` prints a new
  secret phrase.

### Migrating an account (web app, TestNet and LocalNet only)

- The MainNet page is read-only: key generation and migration are disabled.
  Use TestNet or LocalNet to try the browser key-generation flow.

- Funding, proof, rekey and verification are four separate transactions, never
  sent on MainNet. The rekey waits until the proof's Falcon-1024 signature has
  been read back and verified locally.
- The budget is shown before you approve and checked again before each step.
- A public record in browser storage lets you resume after a reload. It never
  holds a recovery phrase or key, and resuming needs the phrase typed again.

### Limits

- The command is `falqoner` and the packages are `@falqoner/*`, but the web
  app, some messages and the demo still use the development name, Falconer;
  see [Try It](README.md#try-it).
- The terms of Algorand's extension to the Falcon C code, which Falqoner
  compiles into its Falcon-1024 WebAssembly, are unresolved. See
  [third-party notices](packages/core/THIRD_PARTY_NOTICES.md).
- Searches are bounded, and application and logic-signature programs are not
  analysed. See [Limitations](README.md#limitations) and
  [SECURITY.md](SECURITY.md), which also explains how to report a
  vulnerability privately.
- These notes report no hosted CI or CodeQL result. See the repository's
  [Actions page](https://github.com/falqoner/falqoner/actions) for the commit
  you use.
