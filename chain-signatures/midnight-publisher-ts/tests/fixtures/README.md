# Fixtures

The `.mn` files here are captured by [`regenerate.ts`](./regenerate.ts) against the running midnight-integration stack (`npx tsx tests/fixtures/regenerate.ts`); that script is the single source of provenance for the raw bytes. It refuses to run against any chain but the capture chain: genesis `0xbbb72bbb…4ac4e6cbb`, with the singleton `aa5d96c2…06ff3f47` deployed at block 1352, the caller `dcd470fb…b0a6f0d2` at 1358, and the notify cross-contract call landing at block 1366.

| file | content |
|---|---|
| `singleton-pre-state-1365.mn`, `singleton-post-state-1366.mn` | the singleton's raw `contract-state[v8]` blobs either side of the notify block, read over `midnight_contractState` |
| `notify-tx.mn` | the notify block's `midnight.sendMnTransaction` bytes, in the `{"tx":{"Midnight":"<hex>"}}` wrapper |
| `golden-*.json` | decoder output for those bytes, frozen as regression pins and byte-compared by the `chain-midnight` tests |
| `respond-singleton-state-37571.mn` | the write-path harness state: a singleton of the CURRENT contract build (`d7b3c45d…6391f169`, deployed via `devtools/bootstrap-live.ts`) captured at the block a respond post landed in. Its embedded verifier keys must match `dist/managed`, so it is redeployed and recaptured on every contract change |

Only `respond-singleton-state-37571.mn` is read by a test in this package. Everything else above is the read path's material: it is consumed by the Rust `chain-midnight` crate, which lands with the indexer, so expect no reader for it here.

The goldens were produced by TypeScript decoders that used to live in this package. Those decoders are gone: state and transactions are decoded in Rust now, against Midnight's own ledger crates. The checked-in goldens therefore remain a record that two separately written implementations agreed, and the Rust tests assert against them byte for byte.

Nothing regenerates a golden today. Whatever regenerates them next will be the Rust decoder, which makes them regression pins rather than cross-implementation evidence: they will catch a change in our own output or in a ledger-crate bump, but can no longer establish that the output is right. Treat any golden minted from that point as unverified, and never re-freeze one to green a failing test. If the capture chain is ever gone, the checked-in files remain the record: recapturing means a fresh deploy, new heights and addresses in `regenerate.ts`, and a review of every pinned value in the tests.
