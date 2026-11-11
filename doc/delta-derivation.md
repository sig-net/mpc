# Delta Derivation

Requirements for the per-request re-randomization of presignatures.

Every participant re-randomizes the presignature with a public scalar `delta`:

```
delta  = H(request_id || big_r || entropy)
big_r' = big_r * delta,  k' = k / delta,  sigma' = (sigma + epsilon * k) / delta
```

## Requirements

1. **Unpredictability.** Under the chain's threat model, the requester must not be able to freely choose or reliably predict `entropy` before the request's containing block is published. Entropy is public once that block is published; it is not secret randomness. It should come from a chain-provided block value that nodes read from a final block, so every node derives the same `delta`. Nothing derived from the transaction or request itself qualifies, since the requester computes those before broadcast. This property is chain-specific; malicious or colluding block producers are outside the threat model.

2. **Per-request binding.** `delta` is different for every request. Binding `delta` to `request_id`, the hash of the request fields (payload, key, epsilon), gives this, also when requests share `entropy`, such as all requests in one block.

3. **Uniqueness.** `big_r` gives uniqueness. One `delta` must map to exactly one presignature, so the presignature's public nonce is part of the derivation. Uniqueness does not imply unpredictability; the two are separate requirements served by separate inputs.

Operators choose which presignature they propose and so control `big_r`. That is acceptable: `delta` still depends on the request and on `entropy`, so choosing `big_r` gives no advantage toward forging. `entropy` is not there to counter presignature choice.

Which block field satisfies requirement 1 depends on the chain and is decided per chain.
On Ethereum, `entropy` is the containing block's `mixHash` header field. After the
Merge, [EIP-4399](https://eips.ethereum.org/EIPS/eip-4399) defines this field as
`PREVRANDAO`, the beacon-chain RANDAO mix. This is not fully unpredictable or
unbiasable: a proposer knows the value when proposing its block and has limited
influence over RANDAO, including one bit of influence per slot by withholding a
proposal. Separately, a proposer can censor a request so it lands in a later
block and uses that block's `PREVRANDAO` instead. These proposer-level
predictability, bias, and censorship powers are outside the threat model;
requester-proposer collusion is therefore not covered. Production nodes derive
entropy only from finalized blocks.

## Deployment compatibility

Changing Ethereum's entropy source changes `SignArgs::entropy` without changing
the request ID. Every node signing a request must use the same entropy value.
A lagging indexer that replays a pre-upgrade request after the change can derive
`PREVRANDAO` while peers retain the old transaction-hash entropy. Backlog
checkpoints identify requests by ID and status, not by entropy, so they do not
necessarily expose this mismatch.

Before switching sources, either prevent new Ethereum sign requests from being
submitted, let every indexer catch up through the last request's finalized
block, drain pending Ethereum requests, and deploy to all nodes before
submissions resume; or implement a fixed activation height and retain the old
derivation for requests in earlier blocks. Do not let nodes sign the same
request under mixed entropy rules.
