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

## Applied fallible vault captures

The three `fallible-*.mn` fixtures are unchanged proven transaction bytes extracted from extrinsic 4 of a local real-MPC vault suite using `midnight-examples` revision `028c6acd780af40cf8128ddfbffa36744ed9981c`, published Signet packages `0.21.0-rc.9`, ledger WASM `1.0.0-rc.3`, and node runtime `2.0.0-d9729c13`. The singleton is `4daa9701226222a9db302dfb6f347f48c947278a4dc93812a79494f4086a0172`; the vault caller is `ea86c03175c6ad122b76f865946e91ee6d778b9fafa8b35e0a6528e6d7964556`. Each captured node event sequence reports the vault call, singleton call, and `TxApplied` for that extrinsic. These fixtures establish successful fallible-only singleton notifications, not partial-success handling or inclusion-proof verification.

| Fixture | Block hash | Physical segment | Request ID | Ledger transaction hash / SHA-256 of bytes |
|---|---|---:|---|---|
| `fallible-deposit-tx-432.mn` | `e2395173ce6b3d52da2570a675818fa1af31d9df4c4ebe8a5ff5594ed480b945` | 49592 | `ee3385dda706877d30e802a0df57c228310016889104b8fb361c830a58d1e500` | `ba41ac43f2cfa97e32357877b85210a7f2105f4930b60515e19aa9ec00bb0f5d` |
| `fallible-withdraw-tx-458.mn` | `6599956fe7f15db082cae342d790338db4dd9b881e90cebceeaec2c1f2d32526` | 18314 | `2b39323a4680ccb0b379e61e4887375190e2d5e14f8f2c0ac81d7df4ca6ba400` | `c776ab2b5696e61e16e01f1ca53aad654a0e1dadd031337f5a6ce68dcf16a9bc` |
| `fallible-supply-tx-368.mn` | `1b0e6b6282cdb4d3a6032173f69af771c502987e400dcd02753f41413636a224` | 10005 | `32aeb17a73a84173bce929c0225a50b2c6ffcc55a97d2c6787204fcc7cba9600` | `03112b9982c9593952e2f14a477fae05f0cfc5b3dac6ae3bf05105ee1f54e910` |

All three events have native call index 1, fallible phase, emission index 0, and kind `SignBidirectionalEvent`. The corresponding vault entrypoints are `startDeposit`, `startWithdraw`, and `startSupply`.

`fallible-block-432-metadata.scale` and `fallible-block-432-events.scale` are the captured node's raw `state_getMetadata` and `System.Events` storage bytes for block 432. They allow the reader tests to decode the actual `TxApplied` association at extrinsic 4. Tests that replace the terminal event with `TxPartialSuccess`, `TxDiscarded`, or another hash are explicitly synthetic status-selection cases; they are not claimed to be accepted chain transactions.

To recapture, run the real vault integration suite, record the node block hash, block body, metadata and `System.Events` at the selected hash, decode `Midnight.send_mn_transaction` using that metadata, and save the argument bytes without reserialization. Confirm the node event status, ledger transaction hash, singleton address, native call ordinal, physical segment and payload against the same capture. These files contain neither GRANDPA finality proofs nor storage read proofs.
