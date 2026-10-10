# Backlog

The backlog is the node's per-source-chain record of signing work that has been indexed but is not yet terminal. It makes indexing, signing, publishing, and restart recovery converge on the same ordered chain history.

## Scope And Invariants

- A request is identified by `SignId` and belongs to one source chain.
- Index a request before signing it. Do not start signing before the indexer completes catchup and the request meets that chain's finality policy.
- Store a request before enqueueing it. Duplicate observations must not create duplicate active signing work.
- A completed source-chain response removes ordinary work. A bidirectional response first moves work to target-execution watching.
- Never reuse MPC triples or pre-signatures after a protocol attempt has begun; recoverable signing failures retry in a later round.
- The backlog is recoverable from durable checkpoints. Live stream state and target-chain watchers are reconstructed after recovery.

## Request Lifecycle

1. The source signing contract emits a request. The indexer converts it to a normalized chain event.
2. During catchup, requests enter the backlog but are not sent to signing. `CatchupCompleted` re-enqueues pending-generation requests in a stable order and resumes pending publications.
3. The signing protocol deduplicates active `SignId`s. On success, only the proposer publishes the response and the request becomes pending publication.
4. Publication is deduplicated and retried with backoff. A validated source response completes ordinary requests.
5. A bidirectional request instead progresses through: `PendingGeneration -> PendingPublish -> PendingExecution -> PendingGenerationBidirectional -> PendingPublishBidirectional -> complete`. Target execution creates the final response-signing request.

An empty bidirectional serialized transaction is rejected before storage. Target-chain decoding and transaction validation happen later, while processing the source response. Duplicate target execution confirmations are intended to be idempotent.

## Checkpoints

A checkpoint contains the chain, processed height, pending request recovery data, and a digest of the consensus-relevant request IDs and coarse phases. The serialized recovery data is local state and is intentionally not part of the consensus digest.

- Create checkpoints only after catchup, when an observed height crosses a configured interval bucket. Sparse block/slot/offset observations are valid.
- Persist the checkpoint as pending, then vote for its digest through governance.
- After threshold confirmation, atomically promote it to the latest checkpoint and prune older pending checkpoints.
- Retain at most 32 unconfirmed checkpoints per chain. At the limit, stop consuming stream events for that chain so bounded backpressure reaches the indexer rather than losing work.
- On restart, restore the newest durable pending checkpoint when present, otherwise the latest confirmed checkpoint, then align it with governance.

If pending-checkpoint storage fails, the in-memory processed height has already advanced and the current implementation does not retry that interval. A later interval crossing can checkpoint again; a crash before then replays from the last durable checkpoint. This is an accepted current behavior, not a settled durability policy.

Default intervals are Ethereum 20 blocks, Solana 120 slots, Hydration 240 blocks, and Canton 50 offsets. NEAR and Bitcoin currently are not implemented.

## Regression And Recovery

A regression is a local checkpoint that does not match governance consensus.

The intended recovery is:

1. Abort source-chain signing tasks and checkpoint voting.
2. Stop the indexer and obtain the consensus checkpoint from a peer by digest.
3. Replace local durable and in-memory backlog state, rebuild execution watchers, and catch up from the restored height.

The supervisor also restarts an indexer after an error or chain-specific stream stall. When governance has no checkpoint, no alignment occurs. When governance does have a checkpoint that is absent locally, including fresh bootstrap, the node fetches a digest-matching checkpoint from a peer and regresses to it.

## Chains And Indexers

| Chain | Current behavior | Backlog status |
| --- | --- | --- |
| Ethereum | Finalized-head indexing by default; optimistic mode is development/test only. Ordinary requests and responses are indexed. | Supervised, checkpointed. First catchup without a checkpoint starts at the startup anchor, not a deployment/genesis height. |
| Solana | Historical catchup plus a pre-started websocket live stream; uses `confirmed` commitment. Ordinary and bidirectional requests are indexed. | Supervised, checkpointed. Live buffering can overflow during slow catchup. |
| Canton | Resumes from ledger offset, catches up to an anchor, then streams; source requests are bidirectional. | Supervised, checkpointed. Finality semantics and lifecycle tests are incomplete. |
| Hydration | Subscribes to finalized blocks and verifies event-storage proofs before parsing requests and responses. | Does not use the common stream/checkpoint event pipeline. Disconnect-window backfill and checkpoint advancement are open. |
| NEAR | Polls contract pending requests with an in-memory, one-hour seen cache. | Integration-test-only path; bypasses backlog, checkpoint, and regression supervision. |
| Bitcoin, Midnight | Chain identifiers/configuration exist. | TBD |

Ethereum is the only implemented target-execution watcher found. Bidirectional
execution monitoring for Solana, Canton, and Hydration is open.

## Failure Rules

- Indexer and transient RPC failures retry or cause supervised restart; Recognized terminal HTTP client errors (400, 401, 403, 404, 405) are not retried; 408, 429, timeouts, and other errors are retried according to the RPC policy.
- Publication must survive restart while a request is pending publication.
- A stalled checkpoint consensus intentionally backpressures that chain. Its operational behavior must be monitored because it can also trigger watchdog restart loops.
- Do not treat provider data as cryptographically verified unless the indexer verifies it. Hydration currently verifies a state proof; the other indexers rely on their providers.
