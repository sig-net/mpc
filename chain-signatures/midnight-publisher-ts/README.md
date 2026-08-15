# Midnight publisher

`midnight-publisher` is a private, persistent Node.js 22.13+ stdio child process or sidecar for the Rust MPC node. It is a publishing mechanism, not an authority: Rust and the MPC flow decide what to publish and supply the contract state, ledger parameters, request, threshold signature, and absolute TTL. The TypeScript process only runs the Compact circuit and, when asked, funds and submits the resulting Midnight transaction.

## Process and protocol

The process speaks newline-delimited JSON (NDJSON) over stdio, with exactly one JSON object per line in each direction. `stdout` is reserved for protocol replies; startup and failure diagnostics go to `stderr`. Every usable request `id` is echoed in its reply, and requests are handled sequentially so replies cannot overtake one another.

Protocol generation 1 uses an explicit readiness handshake. Rust must send `{"id":0,"op":"ready","protocolVersion":1}` and require an `ok` reply that echoes the same `id` and contains `"ready":true` and the exact same `"protocolVersion":1`. A missing, differently typed, older, or newer version is rejected rather than negotiated.

Operations are:

- `ready`: validates protocol compatibility, starts background construction and synchronization of the memoized funding wallet, and returns without waiting for wallet readiness. The reply also advertises `submitTimeoutMs` and `recipeTtlMs`.
- `build`: runs the selected `respond` circuit and returns a serialized ledger intent. It does not open, synchronize, or use the funding wallet. Callers must send `"op":"build"` explicitly.
- `submit`: deserializes and proves the intent, DUST-balances it with the funding wallet, finalizes it, posts it, and returns the transaction ID.

The process memoizes one wallet facade, including while it is starting. A single submit gate protects that facade and its DUST UTXO; submissions are never processed concurrently.

## Deadlines and retry policy

Each submit gets one absolute 360-second budget. Wallet startup, DUST readiness, base-transaction proof, DUST balancing, balancing-transaction proof/finalization, and submission all consume that same deadline rather than starting phase-specific clocks. Readiness and base proof still own cancellation at their respective boundaries; wallet-critical work does not.

Three errors have especially important retry semantics:

- `wallet_unsynced`: wallet startup or DUST readiness exhausted the submit deadline. Nothing was posted, so retrying is safe; the background startup launched by `ready` continues.
- `proving_timeout`: base proving exhausted the remaining submit deadline. No wallet operation started, so retrying is safe.
- `ambiguous_submit`: the absolute deadline expired after wallet-critical work may have started. The transaction can still land in the background; check the chain for the request before retrying to avoid paying or posting twice.

## Configuration

All six variables are required when the process starts, even if a caller initially uses only `build`:

- `MIDNIGHT_PUB_NETWORK_ID`: one of `undeployed`, `stagenet`, `preview`, `preprod`, or `mainnet`.
- `MIDNIGHT_PUB_NODE_URL`: absolute Midnight node HTTP(S) or WebSocket URL.
- `MIDNIGHT_PUB_PROOF_SERVER_URL`: absolute proof-server HTTP(S) URL.
- `MIDNIGHT_PUB_INDEXER_URL`: absolute indexer HTTP(S) URL.
- `MIDNIGHT_PUB_INDEXER_WS_URL`: absolute indexer WebSocket URL.
- `MIDNIGHT_PUB_FUNDING_SEED`: raw hexadecimal seed containing 16 to 64 bytes. A mnemonic is not accepted, and rejected seed input is not echoed in errors.

## Development

Run commands from this directory with Node.js 22.13 or newer:

```sh
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
```

`npm run start` runs the TypeScript entry point during development. `npm run format` and `npm run lint:fix` apply the local formatting and lint fixes. `npm test` builds first because the process tests execute `dist/main.js`; `npm run build` emits that runtime entry point without opening or synchronizing a wallet.

## Deployment seam

The runtime image for this sidecar must include the built `dist/` tree, production Node.js dependencies, and the managed contract proving assets (`keys/` and `zkir/`) shipped by `@sig-net/midnight-contract`; proving resolves those assets through the installed package at runtime.

This branch does not yet contain the dependent Rust child-process integration or Docker packaging seam. Its current Rust `MidnightPublisher` is still an unimplemented stub, and the repository Dockerfile neither builds this package nor installs Node.js 22 in the runtime image. When that seam lands, Rust must send and require protocol version 1 in the `ready` handshake before normal build/submit traffic.
