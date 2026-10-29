# Midnight publisher

The node posts every finished Midnight response itself: one transaction per signature, built, proven, paid for and submitted in process by `chain-midnight`. The publisher is a mechanism, not an authority. The MPC flow decides what to publish; the publisher turns that decision into a transaction the node accepts.

## One publish

`MidnightPublisher::publish_signature` holds one flow lock for the whole publish, because one funding wallet pays every fee. Under it, it reads the finalized head once and pins the singleton's contract state and the ledger parameters to that hash, then hands both to the intent client.

**Build.** `minocrab-publisher` writes the `respond` or `respondBidirectional` call: the arguments, the singleton's `Push`/`Log` program, and the transcript the ledger partitions against the pinned state and parameters. The build first checks that the deployed operation's verifier key hashes to the packaged `<circuit>.verifier`; a contract with another key is refused before anything is proven. The intent's TTL is the publish's build and submit budgets summed.

**Prove.** The call is proven in process under the packaged prover key, with zkir v3. Nothing runs out of process and no proof server is involved.

**Pay.** The fee is a second intent, at the first segment the respond leaves free, whose DUST actions spend the funding wallet's UTXOs. The fee is priced the way the Midnight wallet SDK prices it, `fees_with_margin(parameters, 5)` at the parameters of the finalized head read once the respond is proven, but over the real respond proof: each pass merges a mock-proven fee intent, which the ledger documents as fee-accurate, and adds the remaining deficit, until the merged transaction balances. The fee intent is then proven with the ledger's zkir v2 prover, both halves are sealed separately and merged, and the merged transaction must still cover its fee before it is posted.

**Post.** The transaction goes to the node through `author_submitExtrinsic` as an unsigned `Midnight::send_mn_transaction`. The publisher then scans every finalized block after that head for the transaction's ledger hash:

- `TxApplied` answers the publish with the ledger transaction hash.
- `TxPartialSuccess` fails it: readers skip every event of a partially successful transaction.
- A finalized block past the fee intent's TTL without the transaction means it can never land.

## The funding wallet

The wallet's DUST key is account 0, index 0 of the funding seed, derived the way the Midnight wallet SDK derives it: BIP-32 `m/44'/2400'/0'/2/0`, then the ledger's `DustSecretKey::derive_secret_key`. Spendable DUST is derived by replaying every DUST ledger event into a `DustLocalState`, and only the indexer serves those events (`dustLedgerEvents` over `graphql-transport-ws`). The state is in memory: the node replays from the first event when the publisher starts, resubscribes from the newest applied event after a dropped connection, and starts over from the first event if an event does not apply. The wallet is ready once it has applied the newest event the indexer reports.

A DUST spend proves against the DUST commitment and generation roots, which the chain looks up by the spend's `ctime`, so the fee names a time the replay has fully seen: the earlier of the finalized head's and the indexer's newest block's time, or the newest replayed event's time when that is later.

A submitted transaction reserves the UTXOs it spends. The reservation ends when the chain spends them, when the node refuses or never receives the transaction, or one minute after the fee intent's TTL (three minutes, less when the budget is short), when the transaction can no longer land. A publish whose fee needs reserved UTXOs fails as `wallet_busy` and the publish loop retries it.

The indexer is trusted for liveness only. A replay that disagrees with the chain produces spends whose proofs or nullifiers the node rejects, so a lying indexer can stop the node from paying, not make it post something else.

## Budget and failures

A submit has one budget, `PublisherConfig::submit_timeout` (420 s): waiting for the wallet may use all but the last 120 s, and everything after that, proving, pricing and the landing, shares what is left. The publish loop retries every failure. The class in the error message says what the retry may assume:

| Class | Meaning |
|---|---|
| `bad_request` | The request or intent is malformed. |
| `contract_mismatch` | The deployed contract or the packaged artifacts are not the ones this node proves for. |
| `wallet_unsynced` | The DUST replay has not caught up. Nothing was posted. |
| `wallet_busy` | The fee needs UTXOs held by a submit that may still land. Nothing was posted. |
| `wallet_unfunded` | The wallet cannot pay the fee. Nothing was posted. |
| `proving_timeout` | Proving outlasted the budget. Nothing was posted. |
| `state_conflict` | The node refused the transaction, it expired unlanded, or it landed partially. The retry rebuilds against fresh state. |
| `ambiguous_submit` | The transaction was not seen finalized within the budget and may still land. A retry may post the response again; duplicate responses are harmless. |
| `internal` | Anything else. |

The node counts each failure by its class in `multichain_publish_refusals`. A landed publish sets `multichain_funding_wallet_balance` to the spendable DUST its fee was planned from.

## Configuration and artifacts

The operator configures the node URL, the singleton address, the funding seed and the indexer subscription URL (`--midnight-indexer-ws-url`). The node image carries what proving reads, at the paths `PublisherConfig` defaults to:

- `/usr/local/share/midnight/signet-contract`: the `respond` and `respondBidirectional` keys and IR from `@sig-net/midnight-contract`'s `dist/managed`.
- `/usr/local/share/midnight/zk-params`: the KZG parameters for k = 13 and k = 16 and the DUST spend keys, laid out as the ledger's parameter cache. A missing file is fetched from `srs.midnight.network` and checked against the hash the ledger pins.

Every download in the image is pinned by its SHA-256. Test builds take `--midnight-contract-artifacts-dir` and `--midnight-zk-params-dir` instead.

## Events the reader supports

The MPC reader processes events from finalized transactions with one unambiguous `TxApplied` (full success) status and a matching transaction hash. It reads both guaranteed and fallible transcripts of calls to the configured Signet singleton, processing all guaranteed phases before fallible phases in ledger execution order.

A `TxPartialSuccess` result causes the reader to skip every event from that transaction, including guaranteed events and events from successful fallible segments. This does not undo any effects committed by Midnight. Other candidates without `TxApplied` are also logged and skipped. Malformed status data, duplicate `TxApplied` or `TxPartialSuccess` events, conflicting statuses, and transaction hash mismatches stop processing at that block.

Supported singleton programs consist of literal, non-storage `Push`/`Log` pairs: `Push` places the encoded event on the execution stack, and `Log` emits it. `Noop` (no-op) and `Ckpt` (checkpoint) instructions may appear before, between or after those instructions. During VM execution, they only charge gas and do not change the recovered events. The reader ignores them when checking the instruction pattern, but replays the original program.

The node validates the transaction structure; the reader checks whether it can reconstruct events without the original contract state. Declared effects must be empty, and events must use a supported Signet schema. Unsupported instructions or event schemas stop processing at that block. A fallible transcript alone is not a reason to reject a call: it is supported when the whole transaction succeeds. Caller record and signature validation still apply after decoding.

## Attestations

Every protocol hash input starts with its SDK `HashDomain` tag. Request identity commits to `(keyVersion, sender, path, algo, txParamType, txParamsDigest, executionDest)`. The transaction digest includes only used calldata words, access-list entries, and storage keys; unused capacity and absent calldata contents do not affect it. Reserved signature destination, extra MPC parameters, and serialization schemas remain outside the identity. The EVM account nonce remains part of the transaction.

Final attestations bind `(requestId, blockHeight, outputKind, serializedOutputLength, outputHash)` using the SDK's Compact transient hash, where `outputHash` is the `attestedOutput`-tagged hash of the serialized output. Output kinds are `executed = 0`, `failed = 1`, and `unviable = 2`. The published `respondBidirectional` response carries the request ID, height, kind, output length, output hash, digest and signature, so a node checks it without the output; the serialized output travels separately through the raw output cache at `<prefix>/<network>/<central>/<requestId>.bin`.
