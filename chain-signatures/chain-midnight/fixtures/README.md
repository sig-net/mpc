# Fixtures

The active fixtures come from one local `midnight-integration` capture chain at `c171225731f5ca07028fcd6caa6ced853ed139ef`, running `@sig-net/midnight-contract@0.20.0-rc.1`. Its singleton address was `b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e`, its caller address was `e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6`, and all three captured events carry request id `1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b`.

## Active files

| File | Content and regression coverage |
|---|---|
| `notify-tx-156.mn` | Raw tagged ledger transaction from block 156, extrinsic 4. `emissions::tests::captured_transactions_decode_the_three_singleton_emissions` executes the singleton transcript and pins call index 1, the `SignBidirectional` kind, and the request id at payload offset 1. `reader::tests::decode_notification_reads_the_captured_emission` then pins notification version 1, the caller address, and requests path `[4]`. |
| `respond-tx-161.mn` | Raw tagged ledger transaction from block 161, extrinsic 4. The emissions test pins call index 0, `SignatureResponded`, and the request id at payload offset 0; the reader test requires the emitted point, scalar, and recovery id to decode as a valid signature. |
| `respond-bidirectional-tx-181.mn` | Raw tagged ledger transaction from block 181, extrinsic 4. The emissions test pins call index 0, `RespondBidirectional`, and the request id at payload offset 0; the reader test requires a valid signature. |
| `caller-post-state-156.mn` | The caller's raw `contract-state[v8]` blob at the notify block, holding the request record under the captured request id at ledger field 4. |
| `golden-state-caller-156.json` | Native decoder output for `caller-post-state-156.mn`, byte-compared by `state::tests::native_decode_matches_the_committed_golden`. |
| `singleton-state-156.mn` | The singleton's raw `contract-state[v8]` blob at the notify block. The first migration does not read singleton state; this capture is retained for the deferred read-side deployment guard. |

The golden is minted by this crate's own state decoder, so it catches changes in our output or the pinned ledger crates but does not independently establish that the decoded value is correct. The captured transaction tests provide separate evidence from the actual producer by executing the real transcript bytes and comparing the resulting names and payload fields with addresses, request id, and ledger path fixed by the capture chain.

## Source-block facts

`ContractCall` addresses below render the pallet bytes as the ASCII tag `midnight:contract-address[v2]:` followed by the hex-encoded 32-byte address suffix; the suffixes and event order are exact.

| Event | Finalized block | Extrinsic | Midnight status and ledger transaction hash | `ContractCall` addresses in event order | Decoded event locator |
|---|---:|---:|---|---|---|
| Notify | `dc5fcc9c954d8e65937cdb3c6904809cde15bfce3f11a2a2ab4b4bb379a59a3e` at 156 | 4 | `TxApplied`, `f3dbadf75d4deab3a944c5493658cf35ee80dbb7cd928777dc528b149ae582d2` | `midnight:contract-address[v2]:e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6`, then `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 1, emission 0, `SignBidirectionalEvent` |
| Respond | `4fcf501af455ebbde39bb70e6d06245a3c581239c47185cefad0f034ce4adc25` at 161 | 4 | `TxApplied`, `9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745` | `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 0, emission 0, `SignatureRespondedEvent` |
| Respond bidirectional | `b375f617cf94b19c0f75703dfa943da5dd9c64f97aaa5568517df57d4c8e675f` at 181 | 4 | `TxApplied`, `5291b70cbdfe7a095828a2c6c94cf5b89f7eb2a94e22c2c4953d7706067ef17a` | `midnight:contract-address[v2]:b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e` | call 0, emission 0, `RespondBidirectionalEvent` |

These files are not inclusion proofs. They pin the transcript and payload half of a future audit. The live reader's proof seed additionally carries the node-reported genesis hash, block number and hash, SCALE header, complete ordered block body, and complete `System::Events` bytes. Together with extrinsic, call, and emission indices recorded above, those objects let a later auditor ask another node for the same finalized height, verify the body and event commitments against the header, and rerun this same transcript decoder without changing the V1 locator.

The indexer was used only as a capture aid to locate the three transaction heights. The production Rust read path does not query or trust the indexer.

## Recapture procedure

1. In `midnight-integration`, install Compact `0.33.0-rc.2`, compile the contracts, start the stack with `docker compose up -d`, and run `yarn test:integration-tests:signet-caller-evm-e2e`. The captured run completed one test file with all 15 tests passing and exercised notify, respond, and respond-bidirectional against the 0.20 singleton.
2. Record `MIDNIGHT_SIGNET_CONTRACT_ADDRESS`, `MIDNIGHT_CALLER_CONTRACT_ADDRESS`, and the request id from the e2e output. Use the indexer transaction query only to locate the three block heights; it is not part of the captured data's production read path.
3. For each height, run the ignored `rpc::tests::capture_block_fixtures` test with `MIDNIGHT_NODE_WS_URL`, `MIDNIGHT_CAPTURE_BLOCK`, `MIDNIGHT_CAPTURE_SINGLETON`, and a fresh `MIDNIGHT_CAPTURE_OUT_DIR`. Set `MIDNIGHT_CAPTURE_CALLER` on the notify height so the same run also captures caller and singleton state. The tool refuses to replace an existing output and prints the finalized block hash, extrinsic index, status, ledger transaction hash, and ordered `ContractCall` addresses.
4. Rename the three `tx-<height>-<extrinsic-index>.mn` files to the event-specific names in the table. Regenerate the caller golden through `as_golden_json`, then review every pinned height, hash, address, request id, call index, event kind, payload offset, status, and `ContractCall` row before replacing the committed capture.

`caller-post-state-64.mn` and `golden-state-caller-64.json` are the retained caller-side pair from the previous capture chain. The superseded singleton-map captures were removed when the event-contract fixtures above replaced them.
