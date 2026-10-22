# Delta Derivation

Requirements for the per-request re-randomization of presignatures.

Every participant re-randomizes the presignature with a public scalar `delta`:

```
delta  = H(request_id || big_r || entropy)
big_r' = big_r * delta,  k' = k / delta,  sigma' = (sigma + epsilon * k) / delta
```

## Requirements

1. `delta` is unpredictable until the request is committed on-chain. Nobody may know which `delta` will apply to a request before the request is posted. Binding `delta` to `request_id`, the hash of the request fields (payload, key, epsilon), gives this if `H` behaves like a random function.

2. `entropy` strengthens unpredictability. `H` is not a true random function, so an adversary might retain some control over `delta` and the payload together. `entropy` removes that by making `delta` depend on a value outside the adversary's control. It must be a value the requester cannot know or influence before the block containing the request is validated: a validator-chosen field of that block. Nothing derived from the transaction or the request qualifies, since the requester computes those before broadcast. A malicious block producer is out of scope.

3. `big_r` gives uniqueness. One `delta` must map to exactly one presignature, so the presignature's public nonce is part of the derivation. Uniqueness does not imply unpredictability; the two are separate requirements served by separate inputs.

Operators choose which presignature they propose and so control `big_r`. That is acceptable: `delta` still depends on the request and on `entropy`, so choosing `big_r` gives no advantage toward forging. `entropy` is not there to counter presignature choice.

Which block field satisfies requirement 2 depends on the chain and is decided per chain.
