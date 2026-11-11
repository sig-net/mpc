# Delta Derivation

Requirements for the per-request re-randomization of presignatures.

Every participant re-randomizes the presignature with a public scalar `delta`:

```
delta  = H(request_id || big_r || entropy)
big_r' = big_r * delta,  k' = k / delta,  sigma' = (sigma + epsilon * k) / delta
```

## Requirements

1. **Requester-relative unpredictability.** Before the containing block is published, the requester must not be able to freely choose or reliably predict `entropy`. It is public after publication, not secret randomness. Nodes read it from a final block so every node derives the same `delta`. Values derived solely from the transaction or request do not qualify: the requester knows them before broadcast and can vary them. A block producer may know or influence a chain's entropy source; that influence and the threat-model assumption must be documented for that chain.

2. **Per-request binding.** `delta` is different for every request. Binding `delta` to `request_id`, the hash of the request fields (payload, key, epsilon), gives this, also when requests share `entropy`, such as all requests in one block.

3. **Uniqueness.** `big_r` gives uniqueness. One `delta` must map to exactly one presignature, so the presignature's public nonce is part of the derivation. Uniqueness does not imply unpredictability; the two are separate requirements served by separate inputs.

Operators choose which presignature they propose and so control `big_r`. That is acceptable: `delta` still depends on the request and on `entropy`, so choosing `big_r` gives no advantage toward forging. `entropy` is not there to counter presignature choice.

Which block field satisfies requirement 1 depends on the chain and is decided per chain.

## Solana

Use the containing finalized block's `blockhash` from the `getBlock` response,
decoded from base58 to 32 bytes. Do not use the transaction signature or the
transaction message's `recentBlockhash`: the requester knows both before
broadcast, chooses the `recentBlockhash`, and can vary the signature by
changing the signed transaction. The indexer already fetches the containing
block to process its transactions, so this requires no additional RPC call or
delay to a later slot.

Solana's blockhash is a leader-produced block identifier, not a randomness
beacon. The requester's transaction is part of the ledger, so varying its
contents or timing can indirectly affect the result; this source does not
promise zero requester influence or a formal bound on grinding. The slot leader
controls block construction and can influence the resulting hash; it can also
censor or withhold a block. This source hardens against direct requester choice,
but does not provide bias resistance against a malicious or colluding leader.
The assumption is that the requester cannot collude with the leader or reliably
predict/grind the finalized blockhash in advance. Historical values exposed
through `recentBlockhash` or `SlotHashes` are not a stronger source of fresh
entropy.

### Deployment compatibility

Changing this source changes the `SignArgs::entropy` for Solana requests. Mixed-
version nodes can derive different deltas and proposer schedules for the same
request. Coordinate the rollout so no request is signed under mixed rules:
pause new Solana requests, drain pending requests and align the finalized
indexer cutoff, then deploy to all nodes before resuming. Alternatively, gate
the change at a fixed slot and retain the old derivation below that slot.
