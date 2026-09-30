<!--
Which checks each kind of change needs is in CONTRIBUTING.md, under "Check a
change". Never put a recovery phrase, private key, seed, token or `keygen`
output in a pull request or commit. Security vulnerabilities do not belong
here; see SECURITY.md.
-->

## What changed and why

<!-- The behavior or text that changed, why, and any issue it addresses. -->

## Checks

<!--
Each command you ran and its result, for example "`npm test`: exit 0". Name
any check the change needs that you skipped, and why, for example
`npm run test:localnet` without Docker. A documentation-only change needs only
`npm run format:check`.
-->

## Trust and safety impact

<!-- Tick what the change touches, and say how you checked each one. -->

- [ ] None: it changes nothing Falqoner reads, reports, signs or submits
- [ ] Reading accounts and authority, coverage or verdicts (`scan`, `plan`, `verify`, the web audit)
- [ ] Keys or recovery phrases: generation, derivation, display or storage
- [ ] Transactions: Falcon signing or verification, salts, fees or migration budgets
- [ ] The migration ceremony: step order, network limits, the proof before the rekey, or what happens after a failed step
- [ ] Dependencies, CI or the build

<!--
If you ticked keys, transactions or the ceremony, also name the test or
LocalNet run that exercises the change, and say what happens to the account
if a step fails or the new key is lost.
-->

## Review

<!--
For the reviewer, not the author: the commit you reviewed, what you checked
yourself rather than took from the results above, and your decision. Authors
do not review or approve their own changes.
-->
