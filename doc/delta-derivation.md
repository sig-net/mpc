# Delta Derivation

Requirements for the per-request re-randomization of presignatures.

Every participant re-randomizes the presignature with a public scalar `delta`:

```
delta  = H(request_id || big_r || entropy)
big_r' = big_r * delta,  k' = k / delta,  sigma' = (sigma + epsilon * k) / delta
```

## Requirements

1. **Unpredictability.** `delta` is unpredictable until the request is committed on-chain. Nobody may know which `delta` will apply to a request before the request is posted. `entropy` gives this. It must include a value the requester cannot know or influence before the block containing the request is validated, read from a final block so every node derives the same `delta`. Nothing derived solely from the transaction or the request qualifies, since the requester computes those before broadcast. A malicious block producer is out of scope.

2. **Per-request binding.** `delta` is different for every request. Binding `delta` to `request_id`, the hash of the request fields (payload, key, epsilon), gives this, also when requests share `entropy`, such as all requests in one block.

3. **Uniqueness.** `big_r` gives uniqueness. One `delta` must map to exactly one presignature, so the presignature's public nonce is part of the derivation. Uniqueness does not imply unpredictability; the two are separate requirements served by separate inputs.

Operators choose which presignature they propose and so control `big_r`. That is acceptable: `delta` still depends on the request and on `entropy`, so choosing `big_r` gives no advantage toward forging. `entropy` is not there to counter presignature choice.

Which block field satisfies requirement 1 depends on the chain and is decided per chain.
On Midnight, `entropy = Keccak256(block_hash || request_id)`, where `block_hash`
is the finalized block containing the request. Both inputs are 32 bytes. The
block hash supplies unpredictability; including the request ID gives requests
in the same block distinct proposer-election seeds.

On Ethereum, `entropy = Keccak256(block_hash || request_id)`, where `block_hash`
is the containing finalized block's hash. The request ID is public before
inclusion, but the containing block hash is not available to the requester until
the block is produced. By contrast, after the Merge,
[EIP-4399](https://eips.ethereum.org/EIPS/eip-4399) defines `PREVRANDAO` in
`mixHash` as the latest RANDAO mix from the previous beacon state, so it is
known before the containing block is produced and does not meet this requirement.
An Ethereum proposer can know and influence its block hash by choosing block
contents, or censor a request into a later block; these producer-level powers
are outside the threat model. Requester-proposer collusion is not covered.
Production nodes derive entropy only from finalized blocks.

## Upgrade safety

Changing the entropy source changes `SignArgs::entropy` without changing the
request ID, so nodes on different rules derive different values for the same
request. Since [#1595](https://github.com/sig-net/mpc/pull/1595) the checkpoint
digest covers `request.args` (entropy included), such a split shows up as
diverging digests: it heals by rebase while one rule still has `t` nodes, and
otherwise Ethereum checkpoints stall.

## Entropy of a response

For a response to a bidirectional request ([bidirectional-calls.md](bidirectional-calls.md), Section 4.3) its `entropy` is `H(first_leg_entropy || payload || epsilon)`, the hash of the first leg's `entropy`, the message being signed and its key's tweak, so `delta` moves with the first leg's `entropy` and binds the other two. Every node signing that message under that key derives the same `entropy`, whichever way it learned the outcome.
