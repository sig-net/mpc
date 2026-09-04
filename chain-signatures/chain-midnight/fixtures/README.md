# Fixtures

The fixtures come from one local `midnight-integration` capture chain at `c171225731f5ca07028fcd6caa6ced853ed139ef`, running `@sig-net/midnight-contract@0.20.0-rc.1`. Its singleton address was `b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e`, its caller address was `e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6`, and all three captured events carry request id `1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b`.

`caller-post-state-156.mn` is the caller's raw `contract-state[v8]` blob at the notify block, with its request index at ledger field 4. `golden-state-caller-156.json` is this crate's native decode of those bytes. The golden is a regression snapshot of our decoder and pinned ledger crates, not independent evidence that the decode is correct; the raw transaction fixtures are the producer evidence for the event names and payloads.

## Capture provenance

`ContractCall` addresses below render the pallet bytes as the ASCII tag `midnight:contract-address[v2]:` followed by the hex-encoded 32-byte address suffix; the suffixes and event order are exact.

| Fixture | Recorded finalized block | Extrinsic | Midnight status and ledger transaction hash | `ContractCall` addresses in event order | Decoded event locator |
|---|---:|---:|---|---|---|
| `notify-tx-156.mn` | `dc5fcc9c954d8e65937cdb3c6904809cde15bfce3f11a2a2ab4b4bb379a59a3e` at 156 | 4 | `TxApplied`, `f3dbadf75d4deab3a944c5493658cf35ee80dbb7cd928777dc528b149ae582d2` | `midnight:contract-address[v2]:e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6`, then `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 1, emission 0, `SignBidirectionalEvent` |
| `respond-tx-161.mn` | `4fcf501af455ebbde39bb70e6d06245a3c581239c47185cefad0f034ce4adc25` at 161 | 4 | `TxApplied`, `9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745` | `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 0, emission 0, `SignatureRespondedEvent` |
| `respond-bidirectional-tx-181.mn` | `b375f617cf94b19c0f75703dfa943da5dd9c64f97aaa5568517df57d4c8e675f` at 181 | 4 | `TxApplied`, `5291b70cbdfe7a095828a2c6c94cf5b89f7eb2a94e22c2c4953d7706067ef17a` | `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 0, emission 0, `RespondBidirectionalEvent` |

These files are not inclusion proofs. They pin the transcript and payload half of a future audit. The live reader's proof seed additionally carries the node-reported genesis hash, block number and hash, SCALE header, complete ordered block body, and complete `System::Events` bytes. A later auditor can corroborate those objects against another node, verify the body against the header's extrinsics root, and rerun the transcript decoder without changing the V1 locator. Proving `System::Events` against the header's state root additionally requires a storage read proof, which the V1 seed does not carry.

The indexer was used only as a capture aid to locate the three transaction heights. The production Rust read path does not query or trust the indexer.

## Recapture procedure

1. In `midnight-integration`, install Compact `0.33.0-rc.2`, compile the contracts, start the stack with `docker compose up -d`, and run `yarn test:integration-tests:signet-caller-evm-e2e` to exercise notify, respond, and respond-bidirectional against the 0.20 singleton.
2. Record `MIDNIGHT_SIGNET_CONTRACT_ADDRESS`, `MIDNIGHT_CALLER_CONTRACT_ADDRESS`, and the request id from the e2e output. Use the indexer transaction query only to locate the three block heights; it is not part of the captured data's production read path.
3. Before each capture, confirm through the node's finalized-head RPC that the chosen height is finalized; `capture_block_fixtures` does not enforce this. Then run that ignored test with `MIDNIGHT_NODE_URL`, `MIDNIGHT_CAPTURE_BLOCK`, `MIDNIGHT_CAPTURE_SINGLETON`, and a fresh `MIDNIGHT_CAPTURE_OUT_DIR`. Set `MIDNIGHT_CAPTURE_CALLER` on the notify height so the same run also captures caller state. The tool refuses to replace an existing output and prints the block hash, extrinsic index, status, ledger transaction hash, and ordered `ContractCall` addresses.
4. Rename the three `tx-<height>-<extrinsic-index>.mn` files to the event-specific names in the table. The crate currently has no checked-in golden-generation entry point: add and review an explicit generator around `as_golden_json` before replacing the caller golden. Review every recorded height, hash, address, request id, call index, event kind, payload offset, status, and `ContractCall` row before committing a replacement capture.
