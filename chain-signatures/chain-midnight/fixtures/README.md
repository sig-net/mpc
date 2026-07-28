# Fixtures

The `.mn` files are raw chain data captured against the midnight-integration stack, from one capture chain: genesis `0xbbb72bbb…4ac4e6cbb`, with the singleton `aa5d96c2…06ff3f47` deployed at block 1352, the caller `dcd470fb…b0a6f0d2` at 1358, and the notify cross-contract call landing at block 1366.

| file | content |
|---|---|
| `singleton-pre-state-1365.mn`, `singleton-post-state-1366.mn` | the singleton's raw `contract-state[v8]` blobs either side of the notify block, read over `midnight_contractState` |
| `notify-tx.mn` | the notify block's `midnight.sendMnTransaction` bytes, in the `{"tx":{"Midnight":"<hex>"}}` wrapper |
| `golden-*.json` | decoder output for those bytes, byte-compared by the `state` and `tx_decode` tests |

The goldens were produced by a TypeScript decoder written independently of this crate, so matching them is evidence the Rust decode is right rather than merely self-consistent. That decoder no longer exists: state and transactions are decoded here, against Midnight's own ledger crates.

Nothing regenerates a golden today. Whatever regenerates one next will be the Rust decoder, which turns it into a regression pin rather than cross-implementation evidence: it will catch a change in our own output or a ledger-crate bump, but can no longer establish that the output is right. Treat any golden minted from that point as unverified, and never re-freeze one to green a failing test. If the capture chain is gone, these files remain the record, and recapturing means a fresh deploy, new heights and addresses, and a review of every pinned value in the tests.
