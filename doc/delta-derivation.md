# Delta Derivation

Requirements for the per-request re-randomization of presignatures.

Every participant re-randomizes the presignature with a public scalar `delta`:

```
delta  = H(request_id || big_r || entropy)
big_r' = big_r * delta,  k' = k / delta,  sigma' = (sigma + epsilon * k) / delta
```

## Requirements

1. **Unpredictability.** Under the chain's threat model, the requester must not be able to freely choose or reliably predict `entropy` before the request's containing block is published. Entropy is public once that block is published; it is not secret randomness. It must depend on a chain-provided block value that nodes read from a final block, so every node derives the same `delta`. Request or transaction data alone does not qualify, since the requester computes it before broadcast; it may be mixed with the block value. This property is chain-specific; malicious or colluding block producers are outside the threat model.

2. **Per-request binding.** `delta` is different for every request. Binding `delta` to `request_id`, the hash of the request fields (payload, key, epsilon), gives this, also when requests share a block. Ethereum additionally mixes `request_id` into its block-hash-based entropy so requests in one block get different proposer seeds.

3. **Uniqueness.** `big_r` gives uniqueness. One `delta` must map to exactly one presignature, so the presignature's public nonce is part of the derivation. Uniqueness does not imply unpredictability; the two are separate requirements served by separate inputs.

Operators choose which presignature they propose and so control `big_r`. That is acceptable: `delta` still depends on the request and on `entropy`, so choosing `big_r` gives no advantage toward forging. `entropy` is not there to counter presignature choice.

Which block value satisfies requirement 1 depends on the chain and is decided per chain.
On Ethereum, each request's `entropy` is
`keccak256(block_hash || request_id)`, where `block_hash` is the containing
finalized block's hash. The request ID is
public before inclusion, but the containing block hash is not available to the
requester until the block is produced. By contrast, after the Merge,
[EIP-4399](https://eips.ethereum.org/EIPS/eip-4399) defines `PREVRANDAO` in
`mixHash` as the latest RANDAO mix from the previous beacon state, so it is
known before the containing block is produced and does not meet this requirement.
An Ethereum proposer can know and influence its block hash by choosing block
contents, or censor a request into a later block; these producer-level powers
are outside the threat model. Requester-proposer collusion is not covered.
Production nodes derive entropy only from finalized blocks.

## Deployment compatibility

Changing Ethereum's entropy source changes `SignArgs::entropy` without changing
the request ID. Every node signing a request must use the same entropy value.
A lagging indexer that replays a pre-upgrade request after the change can derive
block-hash/request-ID entropy while peers retain the old transaction-hash entropy.
Backlog checkpoints identify requests by ID and status, not by entropy, so they do not
necessarily expose this mismatch.

Before switching sources, either prevent new Ethereum sign requests from being
submitted, let every indexer catch up through the last request's finalized
block, drain pending Ethereum requests, and deploy to all nodes before
submissions resume; or implement a fixed activation height and retain the old
derivation for requests in earlier blocks. Do not let nodes sign the same
request under mixed entropy rules.
