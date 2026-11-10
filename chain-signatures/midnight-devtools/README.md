# Midnight devtools

TypeScript test tooling for the MPC node's Midnight integration. Nothing here ships in the node image: the node builds, proves and posts its responses in Rust ([doc/midnight-publisher.md](../../doc/midnight-publisher.md)).

## What it holds

- `devtools/real-stack/driver.ts`: the fixture driver the `integration-tests` Midnight cases spawn. It funds the role wallets from the local genesis wallet (or checks the funded wallets it is given on a deployed network), deploys the singleton, the responder and the Compact caller contracts, submits requests as a client would, and reads the responses from the responder.
- `devtools/real-stack/generate-api-parity-vectors.ts`: compiles `api-parity-oracle.compact` against the pinned `@sig-net/midnight` and writes `chain-midnight/fixtures/api-parity-vectors.json`.
- `devtools/generate-midnight-respond-vectors.ts`: writes the `midnight-respond-codec` test vectors.
- `devtools/gen-initial-state.ts`: writes `chain-midnight/fixtures/initial-responder-state.mn`, the responder's initial state with the installed package's verifier keys.
- `devtools/bootstrap-live.ts`: funds a deployer wallet and deploys a fresh responder on a live network.
- `devtools/real-stack/vault.ts` and its `vault-*.ts` helpers: drive `erc20-vault.compact`, a copy of the example vault; `provenance.json` records its source commit, compiler, the Signet library it was written against, and SHA-256. The copy differs from that source only in `completeDeposit` and `completeWithdraw`, which read the attested Boolean byte directly because compactc 0.36.0 fails with an internal error on their `deserialize`. Here it is compiled against the pinned `@sig-net/midnight`, like the caller.
- `devtools/real-stack/fallible.ts` and `adversarial.ts`: build the transactions that place singleton notifications in guaranteed and fallible transcripts, and the partially successful shapes from the partial-success review; `placement.ts` reads where the ledger will run each call.

The installed `@sig-net/midnight-responder` package is also where local runs and the real-stack tests read the responder's proving artifacts from (`node_modules/@sig-net/midnight-responder/dist/managed`).

## Development

Run commands from this directory with Node.js 22.13 or newer:

```sh
npm ci
npm run format:check
npm run lint
npm run typecheck
```

`npm run compile:real-stack-caller` compiles the real-stack caller and the API parity oracle, and `npm run compile:real-stack-vault` the vault; run both before `npm run typecheck:real-stack`. `npm run gen:api-parity-vectors`, `npm run gen:midnight-respond-vectors` and `npm run gen:initial-state` regenerate the fixtures above.
