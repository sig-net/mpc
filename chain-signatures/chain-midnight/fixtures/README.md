# Fixtures

The `.mn` files are raw chain data captured against the midnight-integration stack (branch `feat/notification-field-path`, commit `bccaad0`), from one capture chain: the signet singleton `d0219905…7d5d86d3` deployed at block 47, the test caller `34f84063…353a2987` at block 56, and the caller's `submitSignatureRequest` landing its record plus the notify cross-contract call at block 64, filed under request id `aadca83b…2ace84d7`. The dev node's genesis hash is fixed by the node image, so a capture chain is identified by its deploys and heights, never by genesis.

| file | content |
|---|---|
| `singleton-pre-state-63.mn`, `singleton-post-state-64.mn` | the singleton's raw `contract-state[v8]` blobs either side of the notify block, read over `midnight_contractState` |
| `caller-post-state-64.mn` | the test caller's blob at the notify block, holding the filed record under its request id at ledger field 4 |
| `golden-*.json` | decoder output for those bytes, byte-compared by the `state` tests |

The goldens are minted by this crate's own decoder at capture time, so the byte comparison is a regression pin: it catches a change in our own output or a ledger-crate bump, but cannot by itself establish that the output is right. That evidence comes from the capture-backed indexer test, which asserts the decoded notification and record against values fixed outside this crate: the deployed caller's address, the ledger path its contract source pins, and the request fields `submitSignatureRequest` hardcodes. Never re-freeze a golden to green a failing test.

If the capture chain is gone, these files remain the record. Recapturing means running the stack's generic e2e suite to a landed submit, scanning `midnight_contractState` for the singleton's first post-deploy change to find the notify block, saving the hex-decoded blobs either side of it plus the caller's, and then re-reviewing every pinned value in the tests: the golden files, the heights in these file names, and the capture constants (addresses, request id, record fields) in the indexer tests.
