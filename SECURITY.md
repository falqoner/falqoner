# Security Policy

Falqoner is experimental prerelease software. It has not been externally audited, and nothing in it guarantees that an account is safe from a quantum adversary. Automated tests, CI and dependency checks have run, and they are described below with their limits. None of them is a security audit.

## Supported versions

| Version | Receives security fixes |
| :--- | :--- |
| Current source on the default branch | Yes. Fixes are made here. |
| Tagged prereleases, such as `0.1.0-beta.1` | Not separately. Fixes are made on the default branch. |

A version is released only once its tag and downloads are on the [Releases page](https://github.com/falqoner/falqoner/releases). A version named in the manifests alone is not a release.

## Reporting a vulnerability

Report a vulnerability privately by email to [security@falqoner.com](mailto:security@falqoner.com), spelled with a *q*. Do not post vulnerability details in public issues, discussions or pull requests. The address is monitored, but no response time has been committed.

A useful report includes:

- the Falqoner commit or version, and the command or page involved
- the network (MainNet, TestNet or LocalNet), and any public addresses, transaction ids and rounds involved
- steps to reproduce, and what happened compared with what you expected
- your operating system, Node version and browser, where relevant

**Never send a recovery phrase, private key, seed or funds**, in a report or anywhere else. A report never needs them, and no Falqoner maintainer will ask for them. If a phrase was exposed while you reproduced a problem, treat that key as compromised and move what it controls.

Problems in the Algorand protocol, node software, public API providers, wallets or the Falcon C code in `algorand/falcon` belong with their own maintainers. Please also tell us if one affects Falqoner.

## What Falqoner checks, and what it trusts

| Area | Falqoner checks | Trusted, or outside Falqoner |
| :--- | :--- | :--- |
| Ledger providers | Reads fixed endpoints: `mainnet-api.algonode.cloud` and `mainnet-idx.algonode.cloud`, their `testnet-` equivalents, and `localhost:4001` and `localhost:8980` for LocalNet. Records it searched for or read by id (authority history, rekeyed accounts, held or named assets, applications) must have the expected shape; anything else is reported as `invalid-response` or `unavailable`, not as "nothing found". The account record itself must be for the address asked about, with a usable balance and authority, and must list as many holdings, created assets and apps, and opt-ins as its own totals report. A failed or unusable account read, a "not found" answer included, stops `scan`, `plan`, `verify` and the web audit with an error instead of producing a result. | The provider is trusted to report confirmed ledger records truthfully. Falqoner does not check ledger inclusion. A well-formed record that is false, for example one that leaves out a real rekey or asset role, is taken as the ledger's answer. A provider that fabricates a coherent record is outside this boundary. |
| Post-quantum verdict | Requires a provider-confirmed transaction signed with Falcon-1024 whose scheme, public key and salt derive the account's authority address exactly. | In the audit, Falqoner does not verify the Falcon signature bytes or the transaction payload. The migration ceremony does verify its own proof signature locally (see below). |
| Scores and coverage | Every scan reports what each check covered, and an incomplete check keeps a verdict from being clean. | Searches are bounded, and roles on assets or apps the account did not create, hold, join or name are not searched for. Application and logic-signature programs are not analysed. An off-curve address, a logic signature and a score of zero are not safety certificates. See [Coverage](README.md#4-coverage-what-a-scan-checked) and [Limitations](README.md#limitations). |
| Your device | The CLI's `scan`, `plan`, `verify` and `inspect` never load a key or phrase, sign, or submit, on any network. | A compromised operating system, browser, extension, terminal or dependency can read anything typed into or shown by Falqoner. |

Public providers see the addresses and ids you look up, and your IP address.

## The quantum risk is forgery, not decryption

Algorand accounts are controlled by signatures. The risk from a large enough quantum computer is that it could derive an Ed25519 private key from its public key and then **forge signatures**: spend from the account, rekey it, or use any asset role it holds. Nothing is decrypted. An Ed25519 address is its public key, so it stays visible after a migration. What a migration changes is which key must sign the account's future transactions.

Falqoner makes no prediction about when such a computer might exist. Moving authority to Falcon-1024 is only as strong as the Falcon implementation Falqoner uses and the authority an old key still holds.

## Rekeying: what can be changed, and what can be lost

- **A rekey can be changed by whoever holds the current authority key.** That key can sign another rekey, including one back to the account's own address.
- **Authority is lost with the key.** Algorand does not check that anyone controls the address an account is rekeyed to ([Algorand: rekeying](https://dev.algorand.co/concepts/accounts/rekeying/), read 2026-09-29). Rekey to a key you cannot reproduce, or lose every copy of the current authority key, and the account, with everything it controls, cannot be recovered by anyone, Falqoner included.
- **After a Falcon rekey, only the new key signs.** Falqoner is not a wallet: apart from the migration itself, it never signs for an account. Before relying on a migrated account, confirm on TestNet that a tool you trust can sign with a Falcon key restored from its phrase.
- **Closing out an account undoes a migration.** This is protocol behavior: closing an account removes its rekey, so if the address is funded again, its original Ed25519 key controls it ([same source](https://dev.algorand.co/concepts/accounts/rekeying/)). Falqoner warns about this but cannot prevent it.
- **Old authority remains elsewhere.** Accounts rekeyed *to* a migrated address still accept that address's original Ed25519 key, because Algorand does not follow a chain of rekeys. Each needs its own rekey. Programs that reference the address are not analysed.

## Browser migration: limits and failure handling

Migration runs only in the web app, only on TestNet (checked by its exact genesis) or a private LocalNet, and never on MainNet, whatever the endpoint or label. The funding and the rekey must be signed by a single Ed25519 key; multisig, logic-signature and post-quantum authorities are refused.

- **Four steps, not one atomic operation.** Funding, proof, rekey and verification are separate transactions. A run can stop between any two. Fees for confirmed steps are spent even if a later step never runs, and funding sent to the new address stays there, controlled by the new key.
- **Checked before every step.** The page checks the node's network, re-reads the account's authority and re-reads the budget. A step that would cost more than you approved, or that the account can no longer afford, is not sent. When the network runs a consensus protocol whose Falcon-1024 rules Falqoner does not encode, or an upgrade is pending, no budget is offered and nothing is signed.
- **The rekey waits for a verified proof.** The rekey is sent only after the proof transaction has confirmed and its signed copy, read back from the node or indexer, carries a Falcon-1024 signature from the new key that Falqoner verifies locally. If that copy cannot be read, the rekey waits; it is never sent on a transaction id alone.
- **Unknown outcomes are not treated as failures.** A send that times out or errors may still have landed. Before each send, the page saves a public record of the transaction in browser storage. After a reload it reads the ledger to settle what happened, and replaces an attempt only once the ledger shows it can no longer land. Continuing needs the new key's phrase typed in again.
- **The record is not a backup.** It holds only public data and never a phrase or key. Clearing browser storage loses the ability to resume from this page, not what happened on the ledger. Control of the account depends only on the phrases you kept.
- Only one browser tab may run a migration. A browser without Web Locks is refused.

Core's lower-level functions are for tests and tooling, not a supported migration path. The `prepare*` helpers only build a transaction, refusing one that does not match its budget and a rekey to an on-curve address or to the account itself. `fundPqAddress`, `proveControl`, `rekeyToPq` and `verifyMigration` each sign and send one transaction, holding its signature to the budget. None of them orders the steps, requires a confirmed proof before a rekey, limits execution to TestNet and LocalNet, or records an attempt before sending so that an unknown outcome can be recovered.

## Secrets

- **Read-only paths.** The CLI's `scan`, `plan`, `verify` and `inspect`, and the web app's audit and plan, never ask for a phrase or key and never sign or submit, on any network.
- **`falqoner keygen` prints a secret.** Its output, JSON included, contains a recovery phrase. Do not run it where output is logged, such as CI, a shared terminal or a recording.
- **The web migration handles secrets.** It shows a newly generated phrase on screen and asks for the 25-word phrase of the key that signs the rekey. Both stay in the page's memory and are not sent or saved by Falqoner; only signed transactions are sent. Never type a MainNet phrase into a web page.
- **Local handling is not zero-knowledge.** Phrases and keys are held as ordinary data in page memory, and JavaScript cannot guarantee they are erased. They are also wherever you write them down or save them.

## Dependencies and the Falcon WebAssembly

- `package-lock.json` pins every third-party package to an exact version from the npm registry with an integrity hash, and `npm ci` installs exactly those.
- Falcon-1024 runs in Falqoner's own WebAssembly build of Algorand's deterministic Falcon C code, `algorand/falcon` at a pinned commit, compiled with Emscripten 5.0.7 and embedded in `@falqoner/core` with Falqoner's own loader. `packages/core/falcon/build.sh` builds it and refuses any other source revision or compiler; two builds from clean checkouts on 2026-10-01 gave identical bytes, and `scripts/wasm-provenance.mjs` checks that the embedded module is that build. On fixed test inputs its keys and signatures match those of the `falcon-1024` npm package Falqoner used before. Falqoner has not checked which Falcon revision go-algorand uses, and a reproducible build and matching test results do not show that the cryptography is correct.
- The loader checks every input's type and size and copies inputs into the module's memory. After each call it clears those copies before attempting to free them; if WebAssembly traps, it discards the instance. That clearing is best effort: it does not reach the C code's own temporary memory or the keys returned to JavaScript.
- Falqoner's LocalNet tests submit Falcon signatures made with this build to a real algod node, which accepts them. A dependency audit on 2026-09-29 reported no known vulnerabilities and verified npm registry signatures. These checks show compatibility and where packages came from, not that the cryptography is correct. CodeQL static analysis has not yet run on Falqoner's code.
