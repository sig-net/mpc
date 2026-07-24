# Fixtures

Every file here is produced by [`regenerate.ts`](./regenerate.ts) against the running midnight-integration stack (`npx tsx tests/fixtures/regenerate.ts`); that script is the single source of provenance. It refuses to run against any chain but the capture chain: genesis `0xbbb72bbb…4ac4e6cbb`, with the singleton `aa5d96c2…06ff3f47` deployed at block 1352, the caller `dcd470fb…b0a6f0d2` at 1358, and the notify cross-contract call landing at block 1366.

| file | content |
|---|---|
| `singleton-pre-state-1365.mn`, `singleton-post-state-1366.mn` | the singleton's raw `contract-state[v8]` blobs either side of the notify block, read over `midnight_contractState` |
| `caller-state-1366.mn` | the caller's blob at the notify block: hub address, attestation point, null nodes, trimmed atoms, the request map |
| `notify-tx.mn`, `deploy-tx-1352.mn` | the `midnight.sendMnTransaction` bytes of the notify and of the singleton deploy, in the `{"tx":{"Midnight":"<hex>"}}` wrapper |
| `golden-*.json` | the decoders' output for those bytes, frozen as regression pins and byte-compared by the tests |

The goldens pin the wire, so a golden that comes out `CHANGED` under `regenerate.ts` is a wire change and needs review; never re-freeze one to green a failing test. If the capture chain is ever gone, the checked-in files remain the record: recapturing means a fresh deploy, new heights and addresses in `regenerate.ts`, and a review of every pinned value in the tests.
