# Release notes

Falqoner is experimental prerelease software and has not been externally
audited. Nothing has been released: there is no tagged version and no package
on any registry, although the manifests say `0.1.0`.

## Unreleased: first public source (2026-09-30)

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
- `falcon-1024`, which supplies the Falcon-1024 WebAssembly, declares no
  license. See
  [third-party notices](apps/web/public/THIRD_PARTY_NOTICES.md).
- Searches are bounded, and application and logic-signature programs are not
  analysed. See [Limitations](README.md#limitations) and
  [SECURITY.md](SECURITY.md), which also explains how to report a
  vulnerability privately.
- The CI workflow and CodeQL analysis have not run on this repository yet.
