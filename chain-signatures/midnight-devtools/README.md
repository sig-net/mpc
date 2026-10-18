# Midnight devtools

TypeScript test tooling for the MPC node's Midnight integration. Nothing here ships in the node image: the node builds, proves and posts its responses in Rust ([doc/midnight-publisher.md](../../doc/midnight-publisher.md)).

## What it holds

- `devtools/real-stack/driver.ts`: the fixture driver the `integration-tests` Midnight cases spawn. It funds the role wallets from the local genesis wallet, deploys the singleton and the Compact caller contracts, and submits requests as a client would.
- `devtools/real-stack/generate-api-parity-vectors.ts`: compiles `api-parity-oracle.compact` against the pinned `@sig-net/midnight` and writes `chain-midnight/fixtures/api-parity-vectors.json`.
- `devtools/generate-midnight-respond-vectors.ts`: writes the `midnight-respond-codec` test vectors.
- `devtools/gen-initial-state.ts`: writes `chain-midnight/fixtures/initial-singleton-state.mn`, the singleton's initial state with the installed package's verifier keys.
- `devtools/bootstrap-live.ts`: funds a deployer wallet and deploys a fresh singleton on a live network.

The installed `@sig-net/midnight-contract` package is also where local runs and the real-stack tests read the contract's proving artifacts from (`node_modules/@sig-net/midnight-contract/dist/managed`).

## Development

Run commands from this directory with Node.js 22.13 or newer:

```sh
npm ci
npm run format:check
npm run lint
npm run typecheck
```

`npm run compile:real-stack-caller` compiles the real-stack caller and the API parity oracle; run it before `npm run typecheck:real-stack`. `npm run gen:api-parity-vectors`, `npm run gen:midnight-respond-vectors` and `npm run gen:initial-state` regenerate the fixtures above.
