# Signet on Midnight — SGN2 storage-transport protocol

Implementation plan. **Decision history, rejected alternatives, corrections, and the reasoning behind each choice live in the companion [`midnight-spec-decisions.md`](./midnight-spec-decisions.md).** This file states WHAT to build; the companion states WHY and what was rejected.

**Homes:** contracts in `sig-net/midnight-integration` (`packages/signet-contract`, `packages/signet-midnight`, `packages/caller-contract`); MPC in `chain-signatures/chain-midnight` + the `midnight-publisher` sidecar.

**Target stack:** Compact 0.33 line (language 0.25) / midnight-js 5.0.0-beta.x / node 2.0.0-rc.4 (ledger 9.1.0.0-rc.3). **Ledger 9 only** (cross-contract calls are load-bearing). No public ledger-9 network exists yet — ship local/dev-net until the roll-forward. Toolchain unpinned (latest via `compact update`); per-feature floors: cross-contract calls ≥ 0.32.105; integrator claim circuits (only) need ≥ 0.33.0-rc.2 + `--feature-zkir-v3` for secp256k1/keccak.

**Proving status:** the central contract compiles to **v2 ZKIR** (no in-circuit ECDSA) → its circuit calls prove on the current toolkit. Only integrator **claim** circuits use zkir-v3 (`secp256k1EcdsaVerify` + keccak), which no released prover yet proves for circuit *calls* — those are upstream-gated (deploys prove, calls do not).

---

## 0. Design summary

Client ("integrator"/"caller") contracts store signature requests in **their own public ledger** using standardized types from the shared `@sig-net/midnight` Compact module. The request's storage location *is* its sender authentication: Midnight has no `msg.sender` (no `kernel.caller()`), so "whose proven state the MPC read" is the only unforgeable requester attribution, and the requester contract address is the epsilon-derivation sender. A minimal **central signet contract** (singleton) exists only so both sides have one address to watch: callers register request *notifications* there, the MPC discovers work by **watching the finalized transactions that hit it** (§5.1), and clients poll its *response* stores. It is the Midnight rendering of the EVM `ChainSignatures` doctrine — *"an event bus plus a deposit sink; it performs no signature verification itself"* — with the event bus realized as append-only ledger maps (Midnight has no events) and the deposit sink deferred (payment is a V1 TODO, §8).

**The parity rule (governs every format in this spec):** mirror the EVM/Solana signet contracts — names, field sets, field order, hash shapes, verification responsibilities — and deviate **only** where the platform forces it, documenting each deviation at its site. The forced deviations: SHA-256 instead of keccak256 for values computed in-circuit as a map key (request ids); fixed-size fields instead of dynamic strings/bytes; a `requestNonce` in the record (map-keyed storage needs distinct ids for repeat requests); a decomposed EVM tx instead of `serializedTransaction` (so caller circuits enforce fields); a 32-byte opaque `path` field instead of a variable-length path string (§3.1).

## 1. Architecture decisions

- **Requests live in the caller's ledger; storage location = sender.** Copying a record into another contract changes the sender, hence the rid and the derived keys — never the victim's key space.
- **No events anywhere.** Requests and responses are ledger state (replayable, served by any node, Merkle-provable). Discovery is **finalized-transaction watching** on the central contract (§5.1); the **node-only block-walk composition is normative**, an indexer subscription is a non-normative optional source.
- **The central contract is frozen and dumb.** CoIP-2 binds callers to the callee's verifier keys at compile time, so the singleton can never change circuits without an ecosystem redeploy — everything it does is final at genesis. It holds no keys, verifies nothing, takes no payment, deletes nothing. Anything smarter (payment, new response kinds) is a *separate contract beside it*, never a change to it.
- **Nothing is verified on post; consumers verify on claim.** All response stores are unauthenticated append-only: anyone may post, nothing can be overwritten or blocked, and consumers verify signatures off-chain or in their own claim circuits against the expected derived MPC key (the EVM model exactly).
- **Nothing is ever removed.** All stores grow monotonically; the request-path insert cost carries the O(entries) growth (an operational parameter to monitor).
- **Capacities are per-integrator generics**, never a shared singleton circuit (interface circuits can't be generic; a shared circuit forces worst-case proving cost on everyone).
- **Discovery trust is two-phase.** Phase 1: storage + sender-bound rid recompute + key spacing. Phase 2 (MPC-side, non-breaking): verify notification provenance via the ledger-enforced CCC commitment (`claimedContractCalls`) as OR-evidence (§5.4 rung 2b, probe P10).

## 2. Actors and flow

1. **User → caller contract** (`requestSignBidirectional`-style circuit): validates app rules, builds/overwrites the tx decomposition it enforces (calldata above all), sets the 32-byte derivation `path` (a per-user commitment or a contract-fixed literal), computes the rid, stores the record in its request map, and cross-contract-calls the central contract to register the notification — all in ONE transaction.
2. **MPC** watches finalized transactions on the central contract (§5.1), reads each new notification by diffing the central contract's state across that block (and takes the call's cross-contract provenance from the tx body), follows it to the caller's ledger (`fieldOrdinal`, read anchored at the same finalized block), decodes the record, **recomputes the sender-bound rid and drops on mismatch**, validates routing, signs with the epsilon-derived key `f(caller_address, path)`.
3. **MPC → central contract**: posts the raw chain signature (`postSignatureResponse` → `signatureResponseMap`); after observing destination-chain execution, posts the attestation (`postRespondBidirectional` → `respondBidirectionalMap`). Both posts are blind appends.
4. **User/dapp** polls the response stores by rid, verifies off-chain, broadcasts the signed tx; for bidirectional flows, verifies the attestation in the caller contract (the reference caller's `verifyResponse` runs `secp256k1EcdsaVerify` in-circuit and removes the caller's own request record; the central contract deletes nothing).

## 3. Data formats

### 3.1 Request records

**One record kind is built today: `SignBidirectionalEvent`**, which carries the whole transaction request. Plain `SignRequest` parity (a digest-only request mirroring EVM `SignRequest {payload, path, keyVersion, algo, dest, params}`) is a planned extension, not yet in the `@sig-net/midnight` module (§4.1). The struct is generic over the transaction-param payload `TxParams` and the two schema byte-lengths, so each integrator fixes its own capacities. The field order below is the declaration order, and it is also the rid hash order (§3.2), beginning with `sender`. All integers are little-endian; all `Bytes<N>` are raw, with zero-padded ASCII for the string-like fields (`caip2Id`, `params`, and the two schemas).

`SignBidirectionalEvent<TxParams, #LenOutputDeserialization, #LenRespondSerialization>` (mirrors EVM `SignBidirectionalRequest {serializedTransaction, caip2Id, keyVersion, path, algo, dest, params, outputDeserializationSchema, respondSerializationSchema}`, with `sender` bound as the first field so the record hashes to a per-contract id):

| field | type | notes |
|---|---|---|
| sender | ContractAddress | the requesting contract, set with `kernel.self()`; first field, so it is bound into the rid (§3.2) |
| requestNonce | Uint<64> | caller-set uniqueness salt, backstopped by the caller's `!member(rid)` guard (the reference caller currently sources it from a local `Counter`; see §3.2 and §4.3) |
| keyVersion | Uint<8> | MPC root-key version; `constructSignBidirectionalEvent` asserts `>= 1` |
| path | Bytes<32> | 32 opaque key-derivation bytes of the caller's choosing (a contract-fixed literal or a per-user commitment); used verbatim as the epsilon path, no hex re-encode |
| algo | MPCSignatureAlgorithm | enum `{ ecdsa, reserved }` |
| dest | MPCDestination | enum `{ unused, reserved }`, reserved for future use |
| params | Bytes<64> | extra MPC parameters, reserved for future use |
| txParamType | TxParamType | enum `{ evmType2, reserved }`; off-chain tag for how `txParams` is decomposed |
| txParams | TxParams | the generic tx-param payload (e.g. `EVMType2TxParams<…>`), decomposed so the caller circuit can enforce fields |
| caip2Id | Bytes<32> | destination chain, CAIP-2, e.g. "eip155:11155111" |
| outputDeserializationSchema | Bytes<LenOutputDeserialization> | ABI-style schema string, sized per integrator |
| respondSerializationSchema | Bytes<LenRespondSerialization> | ABI-style schema string, sized per integrator |

The three enums each carry a `reserved` second variant only to keep the variant count `>= 2` (a proof-server requirement), so `algo`/`dest`/`txParamType` are small-int atoms in the record encoding, not `Bytes<32>` parity fields.

- `EVMCalldata<#maxWords> { selector: Bytes<4>, noWords: Uint<16>, words: Vector<maxWords, Bytes<32>> }` — words are **strict ABI-encoded big-endian 32-byte slots used verbatim**; the MPC assembles `calldata = selector ‖ words[0..noWords]` with zero interpretation. Words are built as bytes (address words as `pad-left-12 ‖ addr`), no Field helpers.
- `EVMType2TxParams<#maxCalldataWords, #maxAccessListEntries, #maxStorageKeysPerEntry> { to: Bytes<20>, chainId: Uint<64>, nonce: Uint<64>, gasLimit: Uint<64>, maxFeePerGas: Uint<128>, maxPriorityFeePerGas: Uint<128>, value: Uint<128>, accessListEntryCount: Uint<8>, accessList: Vector<maxAccessListEntries, EVMAccessListEntry<maxStorageKeysPerEntry>>, calldata: Maybe<EVMCalldata<maxCalldataWords>> }` — `calldata` is a `Maybe` (`none` is a plain ETH transfer, "0x" data); `Vector<0, _>` is legal (compiler-verified), so `<N,0,0>` tiers work.
- `EVMAccessListEntry<#maxStorageKeys> { address: Bytes<20>, storageKeyCount: Uint<8>, storageKeys: Vector<maxStorageKeys, Bytes<32>> }` — one EIP-2930 entry; storage keys are raw 32-byte values copied verbatim into the RLP.
- Capacity generics are the integrator's compile-time throttle and proving budget (tier guidance table = probe P9).
- No record-level `schemaVersion` (parity: EVM has none). Evolution rides the notification envelope `version` (§3.4) and new `TxParamType` variants (reader-side additions, never contract changes).
- **Identity note — `path`, 32 opaque bytes.** The module stores `path: Bytes<32>` directly, and the MPC uses it verbatim as the epsilon path (there is no `commitment` field and no in-circuit hex encode). On Midnight the epsilon sender is the integrator contract, shared by all its users, and users have no platform identity, so per-user key isolation, when an integrator wants it, comes from the path: the integrator derives a witness-based commitment in its own circuit and passes it as `path`. The reference caller instead uses a contract-fixed literal `pad(32, "caller-path")` (no per-user identity) and keeps a separate `deployerCommitment = persistentHash([pad(32, "signet-caller:deployer:"), sk])` only to gate its one-shot `initialise` (§4.3). (Rejected path-string form: decisions doc §B.13.)

### 3.2 Request id

The cross-chain shape (EVM/Solana use `keccak256` over `sender ‖ request-fields`, flat, no domain tag). Midnight mirrors that shape; only platform-forced substitutions differ:

```
requestId = calculateRequestId(request) = persistentHash<SignBidirectionalEvent<…>>(request)
          ≡ SHA-256( canonical-record-bytes )   // the record's first field is `sender`, so ≡ SHA-256( sender(32) ‖ rest-of-record )
```

- **One flat SHA-256 over the record itself.** There is no separate preimage wrapper: `calculateRequestId` hashes the `SignBidirectionalEvent` directly, and because `sender` is the record's first field, Compact's canonical struct serialization (fields in declaration order, LE ints, raw bytes, no length prefixes) makes the hash literally `SHA-256(sender ‖ rest-of-record-bytes)`. No domain tag, no inner `persistentHash`.
- **SHA-256 (`persistentHash`), not keccak:** the id is computed in-circuit as the caller's map key; ids are never compared across chains, so shape parity (not byte parity) is the goal.
- **Sender is bound and comes first.** Without it, any contract could byte-copy a victim's record, mint the same id, and squat response slots. The MPC recomputes the rid with the address **it actually read the record from**; mismatch = drop. Sender = `kernel.self()` in-circuit; untagged lowercase 64-hex in the epsilon string.
- **Uniqueness:** `requestNonce` is a caller-set `Uint<64>`, backstopped by the caller's `!member(rid)` insert guard. For a multi-user contract it should be a caller-supplied salt with no contract `Counter` read (reading a counter pins its value in the transcript, so concurrent users of one contract conflict; a salt has no read, decisions doc §B.6). The single-deployer reference caller currently sources it from a local `Counter` (`signetRequestNonce`), which is safe there but not the pattern for concurrent integrators. Nonce choice is safety-irrelevant: the rid also binds `path`, so no nonce lets one user mint another's rid.
- **Storage position is not bound into the id** (a wrong-ordinal read fails the recompute or resolves to an inert no-op; position stays a discovery hint).
- `calculateRequestId<TxParams, #LenOutputDeserialization, #LenRespondSerialization>` is a generic pure circuit; the TS twin (`signet-requests.ts`) and Rust twin (mpc `records.rs`) change in lockstep and are golden-pinned. **This formula invalidates every prior rid/record golden: regenerate the whole SGN2 golden tree.**

### 3.3 Ledger layout and encoding (verified facts)

- Layout is positional and path-addressed. ≤15 ledger fields = one flat `StateValue` array; ≥16 bucket into ≤15-wide child arrays (observed splits: 16 → 1+15, 27 → 12+15 — partition is compiler-internal; **never compute paths arithmetically**, recover by recursive flattening of observed state). A struct map value is a single cell with one atom per field in declaration order; `Bytes<N>`/`Uint` atoms and map keys are **trailing-zero-trimmed** (readers re-pad). A Compact `List<T>` is a recursive **cons node** `[headValue, tailList, lengthCounter]`.
- The request map may sit at **any** ordinal; the notification carries it (`fieldOrdinal`), the reader is position-agnostic. `contract-info.json` `ledger[].index` is a *build-time* reference (our test fixtures; an integrator's golden harness lints its notify literal) — the MPC never reads any integrator's json at runtime.
- **Encoding stability:** a deployed contract's state encoding is frozen at its compile version; field-position addressing holds for the contract's lifetime; new-compiler changes affect only newly compiled contracts and are absorbed reader-side (the notification `version`). Residual: a CI job watching Compact release *tags* for encoding-affecting changes (§5.2).

### 3.4 Notifications (central-contract-stored, versioned envelope)

A notification is a **pointer**: "contract X stored request Y at ledger field Z". Nothing in it is trusted; authority comes from the caller's ledger + rid recompute, and spoofed notifications are deduped noise that costs the spoofer a tx fee.

```compact
export struct SignetMapKey { count: Uint<64>; requestId: RequestId; }   // RequestId = Bytes<32>

export struct SignBidirectionalEventNotification {
    version: Uint<8>;      // payload layout tag; this spec = 1
    payload: Bytes<128>;   // V1: callerAddress(32) ‖ requestsIndexField(1) ‖ zero-padding(95)
}
```

- **Count-keyed, never overwritable.** Entries land under `SignetMapKey{count, requestId}` with a per-rid `Counter` supplying the count (an append-only array per rid). A spammer can append noise after the honest entry but never clobber it; the MPC reads all entries per rid and keeps the first that verifies. Per-rid counters keep honest cross-rid traffic conflict-free under transcript replay; same-rid same-block races are attacker-only and first-wins (P4 validates).
- The rid lives in the **key**, not the payload. Payload budget is 128 bytes as the forward-compat surface; clients never hand-serialize (the per-version pure-circuit constructor `constructSignBidirectionalEventNotificationV1(callerAddress, requestsIndexField)` packs it; a future V2 is a new constructor plus a reader-side decoder, deployed contracts untouched).
- The V1 payload carries only `callerAddress` and `requestsIndexField` (the ledger field position of the caller's `SignBidirectionalEventMap`). It does **not** carry a `txParamType` byte: the tx decomposition is selected by the record's own `txParamType` field (§3.1), read back from the caller's ledger. A plain-`SignRequest` notify path would be a separate future addition (§4.2).

### 3.5 Responses (central-contract-stored, unverified, append-only)

Same count-keyed append pattern as notifications; **the contract verifies nothing at post time** — it stores whatever args it was called with. First-valid-write semantics are enforced by *consumers* (verify each entry, take the first valid).

- `signatureResponseMap: Map<SignetMapKey, SignatureRespondedEvent>` mirrors EVM `SignatureResponded`. `SignatureRespondedEvent { bigRx: Bytes<32>, bigRy: Bytes<32>, s: Bytes<32>, recoveryId: Uint<8> }` (the MPC's canonical signature; big-endian bytes). The raw chain signature the client verifies off-chain and broadcasts. (No `responder` field: Midnight can't observe the poster, and it carried no authority on EVM either.)
- `respondBidirectionalMap: Map<SignetMapKey, RespondBidirectionalEvent>` mirrors EVM `RespondBidirectional`. `RespondBidirectionalEvent { serializedOutput: Bytes<128>, outputLen: Uint<8>, r: Bytes<32>, s: Bytes<32>, recoveryId: Uint<8> }`. Unlike the earlier plan, the store carries the **whole serialized output** (a fixed `Bytes<128>` cap plus a meaningful `outputLen`), not an `outputHash`: the first 32-byte word == 1 signals success, and a `0xdeadbeef` prefix is the MPC's error sentinel. `r`/`s` are the ECDSA scalars as **little-endian** 32-byte values (the byte order the `Secp256k1Scalar as Bytes<32>` cast produces), stored as bytes because `Secp256k1Scalar` cannot live in ledger state; `recoveryId` is for off-chain pubkey recovery only.

**Attestation.** The MPC signs the digest with the derived **response key**: epsilon sender = the requester (caller contract address), constant path = `"midnight response key"` (the `"solana response key"` pattern), same epsilon-v2 formula as request keys. The digest is **not** keccak: the built module uses `signetAttestationDigest(requestId, serializedOutput, outputLen)`, a nested `persistentHash` (the SHA-256-based hash of §3.2), `persistentHash([requestId, persistentHash([persistentHash(serializedOutput), outputLen])])`, interpreted big-endian by `secp256k1EcdsaVerify` (RFC 6979). The inner hash binds the output together with its length so neither can be swapped under a reused signature. Verification is the integrator's claim circuit (or off-chain): `verifyRespondBidirectionalEvent(requestId, event, mpcResponseKey)` recomputes that digest and runs `secp256k1EcdsaVerify` (zkir-v3, the claim-side prover gate) against the expected response pubkey. The reference caller pins that pubkey (`mpcResponseKey: Secp256k1Point`) in a set-once, deployer-gated `initialise` run right after deploy, once the contract address (and therefore the derived key) exists: this resolves P12 in favor of the requester-scoped response key, with no constant-sender fallback needed. (The keccak-parity digest of §B.5 and probe P11 remains a possible future alignment, but is not what the current module implements.)

## 4. Contract-side deliverables (`sig-net/midnight-integration`)

### 4.1 `@sig-net/midnight` Compact module (`packages/signet-midnight`)

Types per §3 as the `Signet` module: the `SignBidirectionalEvent` record, `RequestId` (a `Bytes<32>` new type), the `SignBidirectionalEventNotification` envelope, the `SignatureRespondedEvent` / `RespondBidirectionalEvent` responses, `SignetMapKey`, the `EVMType2TxParams` / `EVMAccessListEntry` / `EVMCalldata` decomposition, and the `MPCSignatureAlgorithm` / `MPCDestination` / `TxParamType` enums. Circuits: `calculateRequestId` (generic pure circuit, hashes the record directly, no wrapper struct); `constructSignBidirectionalEvent` (contract-only builder that asserts the `keyVersion >= 1` floor and takes `path: Bytes<32>` directly, no path string or hex-assert machinery); `constructSignBidirectionalEventNotificationV1(callerAddress, requestsIndexField)`; and the ECDSA-side helpers `signetAttestationDigest`, `verifyRespondBidirectionalEvent`, `signetKeyHash`. The module also declares the `SignetSigner` contract interface (the CCC entry point) and the `SignBidirectionalEventMap` map type. A separate `circuits.compact` re-exports the non-generic circuits (`signetAttestationDigest`, `verifyRespondBidirectionalEvent`, `signetKeyHash`, `constructSignBidirectionalEventNotificationV1`) as `pureCircuits` for off-chain use; `calculateRequestId` is generic so it cannot be top-level-exported and instead has the documented TS twin `signet-requests.ts`. There is no `userCommitment` circuit in the module: per-user commitments are the integrator's own concern (the reference caller defines `deployerCommitment` for deploy-gating only).

### 4.2 Central signet contract (`packages/signet-contract`) — frozen, dumb, final at genesis

No constructor (no keys). Six ledger fields, declaration order normative (the MPC reads by ordinal); every circuit is a count-keyed append, and the only assertion anywhere is the notification `version == 1` check:

```compact
export ledger signBidirectionalEventNotificationCounterMap: Map<RequestId, Counter>;                              // 0
export ledger signBidirectionalEventNotificationMap:        Map<SignetMapKey, SignBidirectionalEventNotification>; // 1  (EVM: SignBidirectional)
export ledger signatureResponseCounterMap:                  Map<RequestId, Counter>;                              // 2
export ledger signatureResponseMap:                         Map<SignetMapKey, SignatureRespondedEvent>;           // 3  (EVM: SignatureResponded)
export ledger respondBidirectionalCounterMap:               Map<RequestId, Counter>;                              // 4
export ledger respondBidirectionalMap:                      Map<SignetMapKey, RespondBidirectionalEvent>;         // 5  (EVM: RespondBidirectional)

// One shared append pattern (per-rid counter -> key -> insert). The notify circuit is
// CCC-callable so a caller registers inside its own request transaction:
export circuit signBidirectionalEvent(requestId: RequestId, notification: SignBidirectionalEventNotification): SignetMapKey {
  assert(notification.version == 1, "only version 1 notification supported");
  const rid = disclose(requestId);
  if (!signBidirectionalEventNotificationCounterMap.member(rid)) { signBidirectionalEventNotificationCounterMap.insertDefault(rid); }
  const key = SignetMapKey { count: signBidirectionalEventNotificationCounterMap.lookup(rid).read(), requestId: rid };
  signBidirectionalEventNotificationCounterMap.lookup(rid).increment(1);
  signBidirectionalEventNotificationMap.insert(key, disclose(notification));
  return key;
}
// postSignatureResponse(requestId, signatureRespondedEvent) appends over fields 2/3;
// postRespondBidirectional(requestId, respondBidirectionalEvent) appends over fields 4/5.
// A plain-`SignRequest` notify pair (an extra counter+map plus a notify circuit) is a
// planned addition, not present today.
```

- The notify circuit `signBidirectionalEvent` is CCC-callable (no witnesses, no Zswap, per-rid state only) so a caller registers its notification inside its own request transaction. The respond circuits `postSignatureResponse` and `postRespondBidirectional` are direct calls by the MPC (and, permissionlessly, by anyone; posts are unauthenticated by design).
- **The notify's state write is what makes it discoverable at all** (§5.1): discovery reads the write out of the central contract's STATE, by diffing it across the notify block. A write-nothing notify would leave only the CCC commitment hash in the tx body (preimage unrecoverable) and nothing in state, so it would be undiscoverable; the append must stay. (The tx body is still read, but only for the cross-call provenance that binds the notification to its caller.)
- No keys, no payment fields, no sweeps, no GC (§8 payment TODO).
- Compiles **without** `--feature-zkir-v3` → v2 ZKIR → all circuit calls prove on the current toolkit.

### 4.3 Reference caller (`packages/caller-contract`)

The canonical integrator shape: owns one request map (`signBidirectionalEventMap: SignBidirectionalEventMap<EVMType2TxParams<1, 0, 0>, 34, 34>` at ledger field 4, pinned into its notify literal as `requestsIndexField = 4`) and seals the central-contract reference (`sealed ledger signetSigner: SignetSigner`). In `submitSignatureRequest` it builds a contract-fixed request via `constructSignBidirectionalEvent` (which asserts `keyVersion >= 1`), stores it under its rid behind a `!member(rid)` guard, and CCC-notifies in the same transaction. It sources `requestNonce` from a local `Counter` (`signetRequestNonce`) and uses a contract-fixed `path` literal `pad(32, "caller-path")` rather than a per-user commitment. A two-step config pins the MPC response key: the constructor seals a `deployer` identity commitment, and a one-shot deployer-gated `initialise(responseKey: Secp256k1Point)` stores `mpcResponseKey` once the contract address exists. Its `verifyResponse` circuit implements §3.5 verification (`verifyRespondBidirectionalEvent`, in-circuit `secp256k1EcdsaVerify`, zkir-v3, the one part that cannot *prove* until a v3 prover ships) and removes its own request record. `packages/caller-contract-20-field` stays as the chunked-layout parsing fixture.

## 5. MPC-side deliverables (`chain-signatures/chain-midnight`)

**Component inventory — what is extra vs the per-chain pattern.** Ethereum/Solana ship as ONE in-workspace crate (stream + a plain-RPC publisher), RPC endpoint as operator config. Midnight keeps that crate slot (`chain-midnight` — discovery loop, decode twins, rid recompute, conversion) and adds:

1. **The `midnight-publisher` sidecar** — the one extra codebase component, forced because the Midnight ledger/toolkit dependency universe cannot co-resolve with the main workspace (CI keeps the main lockfile polkadot-free). Three seams need the ledger crates: **prove+submit** responds (`POST /respond`, shipped SGN1), **decode contract state** (`GET /state`, built 2026-07-18 but currently unmerged — mpc reflog `3a7705ca`/`a0cc0472`), **decode block bodies** for cross-call provenance (`GET /block`). Full detail: §5.5.
2. **The proving supply chain** — pinned toolkit images, the central contract's compiled artifacts + prover keys as fixtures, per-respond proving time/RAM budgets (SGN1 ≈39 s / ~11.5 GiB; the v3 v2-ZKIR contract is simpler — re-measure, expect less).
3. **A Midnight RPC endpoint** — a standard external dependency like the eth/sol execution RPC, third-party-able; self-run today only because no public ledger-9 RPC exists (§5.4). Capability constraint (own or third-party): finalized block bodies (`archive-canonical`, not warp/pruned), the subscription + `state_getReadProof` methods, accepts submissions.

So the MPC **deploys** exactly TWO components (the crate + the publisher sidecar) plus a Midnight RPC URL to point at. Explicitly NOT run: the Midnight GraphQL **indexer** (non-normative option only) and the HTTP **proof server** (publisher proving is toolkit-native).

### 5.1 Discovery — finalized-transaction watching

No state polling. The MPC discovers work by watching the finalized transactions that hit the central contract. The node RPC has no tx-by-address subscription (verified: the only subscriptions are chain heads, `state_subscribeStorage`, runtime version, GRANDPA/BEEFY justifications, own-tx watch), so the normative mechanism is heads-subscription + body fetch + filter — one code path for live and catch-up:

1. **Subscribe** `chain_subscribeFinalizedHeads` (ws). Finality gating is inherent — only finalized heads arrive.
2. **Per head:** `chain_getBlock(hash)`, deserialize each extrinsic's ledger transaction (via the publisher), keep transactions with a call segment on the central contract's notify entry point (`signBidirectionalEvent` today; a plain-`SignRequest` notify would add a second). A CCC ride-along and a direct call are both plain call segments — one filter catches both. The MPC's own respond posts appear on the same stream (settlement observation for free).
3. **Read what the block wrote from STATE, not from the transcript.** `midnight_contractState(central, at = that finalized hash)` minus the same read at the parent block IS the set of writes that block made to the central contract: the `{count, requestId}` key and `{version, payload}` value, exactly as the chain stores them (`GET /state?address=&at=`). A walker moving in block order already holds the parent's tree from the previous iteration, so this costs one read per block. This is deliberate: a transcript carries no insert record, so recovering writes from a tx body means re-implementing the ledger VM's stack semantics by hand, whereas the state diff is the chain's own answer and cannot drift from it.
4. **Take the cross-contract-call provenance from the tx body** (`GET /block?hash=`): per transaction, each call's address, its own `communication_commitment`, and the calls that call claims. This is the one question only a transcript can answer — *which transaction called whom* — and it is what ties a notification to a call on the caller it names (§4.2). It is grouped per transaction so two notifications in one block stay unambiguous.
5. **No discovery-side seen-set:** each finalized tx is processed once in block order; the node's rid-level sign-once idempotency absorbs restart overlap (re-walking the checkpoint block is harmless).
6. **The caller-ledger read stays — it is the execution check.** Ledger 9 pre-validates only the guaranteed segment at inclusion (#1454), so an included notify tx can still have failed its fallible segment: tx presence alone never triggers signing. Follow the notification to the caller's ledger (`midnight_contractState(caller, at = that finalized hash)` — anchored reads are supported and honored), and a missing record or rid-recompute mismatch = drop.

**Catch-up.** Restart = walk finalized blocks `[checkpoint+1 … chain_getFinalizedHead]` via `chain_getBlockHash(n)` → `chain_getBlock`, through the same filter as live (finalized blocks are immutable, so the walk is deterministic and replayable from any depth). We rely on the RPC endpoint we query having every finalized block we need; catch-up is always this block-walk, never a storage snapshot. Conditions:

- **Block-body retention:** `--blocks-pruning` defaults to `archive-canonical` (every finalized body retained indefinitely), so catch-up from arbitrary downtime works on a default node. Ops rules: never set `--blocks-pruning <NUMBER>`, never warp-sync. A finalized body the endpoint no longer has is an availability failure (alarm, switch endpoints), not something we route around by reading storage.
- **State pruning is separate:** `--state-pruning` (default 256 blocks) limits historical *state* reads, not bodies, so it never affects the walk. The step-5 anchored read targets a just-finalized block (well inside 256); historical read-proofs (§5.4) want `--state-pruning archive`.
- **Checkpoint** = last fully processed finalized height (the existing per-chain checkpoint machinery).

Non-normative alternative discovery sources (`state_subscribeStorage`; the indexer `contractActions` subscription) exist and are catalogued in decisions doc §B — optional, never the foundation.

### 5.2 Reader

- Path-aware field resolution per §3.3: recursive flattening, ordinal from the notification, structural bucket detection, trailing-zero re-pad of atoms and map keys, cons-node walking for `List` values. Validated against committed state fixtures (our compiled test contracts at 6/8/16/27 fields, each embedding its `contract-info.json` ledger array as the expected-ordinal pin). No integrator file exists at runtime.
- Count-keyed maps: walk a rid's entries `0..counter-1` with a per-rid growth watermark, per-entry decode-or-skip — a poisoned entry never blocks a later genuine one. Used by client response polling; live discovery instead diffs the contract's state across the notify block (§5.1).
- Decode by `txParamType` with capacity-split enumeration folded into the **mandatory rid recompute-and-drop** (stored key must equal `rid(sender, record)`; the recompute disambiguates capacity splits). Unknown `version`/`txParamType` → drop with telemetry.
- Pin the ledger decode lib to the deployed node's ledger version; CI job watching Compact release tags for encoding-affecting changes.

### 5.3 Validation and conversion

keyVersion ∈ [1, LATEST]; `path` = the record's 32-byte `path` field used verbatim as the epsilon path (no hex re-encode, no `commitment`); caip2 → known-chain routing; tx reassembly `selector ‖ words[0..noWords]` + access-list truncation by counts, golden-tested byte-equal against ethers; epsilon sender = the address the record was read from (notification-carried, then verified equal to the address actually read, never from record bytes). Respond-bidirectional path: the `signetAttestationDigest` (nested `persistentHash` over rid, output, and `outputLen`, not keccak), response key path `"midnight response key"`, requester-scoped sender (P12 resolved via the caller's post-deploy `initialise`).

### 5.4 The proof path

The discovery pipeline (§5.1) consumes four inputs. In V1 each is *trusted* from the operator's node; each has a specific proof that upgrades it **in place** — the pipeline shape never changes, every proof verifies bytes the pipeline already holds, nothing new enters the data path. (This in-place property is why the node-only composition is normative; reasoning in decisions doc §B/§E.)

| rung | pipeline input | proof upgrade | proof inputs | status / order |
|---|---|---|---|---|
| 2 — **inclusion** | the block body of finalized head `H` | Merkle-verify the extrinsic against `header(H).extrinsics_root` | header + body, already fetched — pure local computation | **first** (P10); implementable today |
| 3 — **execution** | contract state at `H` | `state_getReadProof(keys, H)` vs `header(H).state_root` (`read_proof_check`, as shipped for Hydration) | the raw storage key(s) behind a contract's state — open P1-proper mapping; historical heights need `--state-pruning archive` | **second** — RPCs verified live; blocked only on key mapping |
| 2b — **provenance** | caller attribution of a CCC notify | check the caller-frame `claimedContractCalls` commitment binds `callerAddress → central.notify*` | inside the rung-2 decoded body; OR-evidence only (direct calls have no CCC frame) | **rides rung 2** |
| 4 — **finality** | the finalized head `H` | verify the GRANDPA justification for `H` against the current committee | `grandpa_proveFinality` / `grandpa_subscribeJustifications` + committee tracking across Ariadne rotations (`sidechain_getEpochCommittee`) — all exposed | **last** — the committee-tracking verifier is the open upstream item |

**Inclusion proves the tx is in the block; execution proves its effects are in executed state** (distinct — ledger 9 pre-validates only the guaranteed segment, so inclusion alone never triggers signing, §5.1 step 5); **finality proves the block is canonical.** With all three, the node degrades from a *trust* dependency to an *availability* one — a compromised node can forge nothing, only go silent.

**Completeness residual (operational):** no proof exposes a withholding node from the inside. Completeness rests on following contiguous finalized heights — a gap is locally detectable; total withholding presents as head-staleness (an availability alarm). Mitigations as value grows: cross-check finalized heads against a second independent node; alert on staleness.

**Who serves the RPC:** the Midnight RPC is an external dependency like the eth execution RPC — third-party-able. Base trust model (all chains): trust-your-RPC, protected by **threshold independence** (a request signs only after cluster consensus + a signing threshold, so a single lying RPC can't forge). Hygiene: don't point the whole signing threshold at one shared endpoint. The proof ladder above is the trust-minimization enhancement (the analog of eth's optional Helios light client) and makes a *third-party* RPC progressively **more** acceptable. Self-run today is availability, not security (no public ledger-9 RPC yet). Full reasoning + the corrected framing: decisions doc §C/§E.

**Do not let real value depend on Midnight-derived keys before rung 3 (execution proofs) lands.**

### 5.5 The `midnight-publisher` — responsibilities, packaging & deployment

**Self-contained by design.** One folder, `chain-signatures/midnight-publisher/`, that builds/tests/ships on its own: nested Cargo workspace, its OWN `Cargo.lock` (always `--locked`, never `cargo update`), its OWN `Dockerfile` bundling the full toolchain, its OWN tests. Nothing leaks into the main workspace but the localhost seam. Its existence is forced (ledger/toolkit deps can't co-resolve with the main workspace; CI keeps the main lockfile polkadot-free).

**Responsibilities — exactly the operations needing the ledger crates or the toolkit:**

1. **Write path — prove & submit responses.** Encode the MPC's already-computed signature into circuit args, validate, fetch current contract state, generate the circuit-call intent, prove + fund + submit to finality. Owns: arg serialization, prover-key custody + caches, driving proving, fee/gas custody (the funding wallet), submission + finality confirmation. The proving *compute* is offloaded to a proof server (`--proof-server`), which for these contracts is mandatory rather than an optimisation: they are compiled with `--feature-zkir-v3` (the floor for in-circuit `secp256k1EcdsaVerify`, §G.9), and the ledger the toolkit links pins `midnight-zkir` 2.2.0, which accepts only `ir-source[v2]`. Local proving of a zkir-v3 contract aborts outright; the 9.x proof server handles it. The publisher still holds the prover keys — it reads them via the resolver and ships them with each proving request.
2. **Read path — decode contract state** for the anchored authority reads (versioned-binary `ContractState`/`StateValue` → the JSON tree the crate walks).
3. **Read path — decode block bodies** for cross-call provenance (finalized block → per transaction, each call's address, its own `communication_commitment`, and the calls it claims). Deliberately NOT the values a transaction wrote: those come from a state diff via seam 2, because a transcript has no insert record and reconstructing writes from one would mean hand-modelling the ledger VM.

Cross-cutting: the dependency firewall, toolkit orchestration, funding-seed custody, compiled-artifact + cache management.

**Not pure Rust.** Thin Rust glue over a Node + Compact toolchain, all bundled into the image: a native node-toolkit binary (prove+submit), Node.js + toolkit-js + a per-contract TS config (intent generation), compactc, prover keys. **Native intent mode — no docker-in-docker at serve time.**

**Circuit-arg codec — dictated by the contract, not chosen by us.** `generate-intent circuit` reflects over the Compact-generated `contract/index.d.ts` (`ImpureCircuits`) and parses each argv entry as JSON5 against the declared parameter type. Both respond circuits therefore take exactly **two** arguments: the request id, then the whole event struct as ONE JSON object keyed by the Compact field names — `postSignatureResponse` takes `{bigRx, bigRy, s, recoveryId}`, `postRespondBidirectional` takes `{serializedOutput, outputLen, r, s, recoveryId}`. `Bytes<N>` is declared `Uint8Array` and takes bare lowercase hex; `Uint<N>` is declared `bigint` and must be a JSON *number*, because struct members are re-serialized before conversion and a quoted `"1"` would reach `BigInt("'1'")` and throw. Flattening a struct into separate argv entries fails the toolkit's arity check before any proving happens, so the publisher's encoder is pinned to this shape by test.

**Work-dir contract — what the publisher consumes but does not create.** Four inputs, all supplied by the image build or the operator: `managed/`, the compiled-contract asset root (`contract/`, `compiler/`, `keys/`, `zkir/`); `signer.config.ts`, the per-contract toolkit-js binding, which names that same `managed/` in its `withCompiledFileAssets`; `.run/private-state.json` (the respond circuits take no witnesses, so `{}` is correct); and a toolkit-js build whose `COMPACTC_VERSION` variant matches the contract's compiler (0.33.0 here) — `compactc-resolver.ts` selects the variant, and a build lacking it fails before the circuit is invoked.

`managed/` serves both halves of the write path, and both resolve by convention rather than configuration: toolkit-js reflects over `contract/index.d.ts` to type the circuit args, and the toolkit's Rust-side Resolver loads `keys/<circuit>.{prover,verifier}` and `zkir/<circuit>.bzkir` to prove. A resolver root that lacks those files does not fail cleanly — proving panics inside the toolkit ("prover key not created"), which surfaces as a 502 after the state fetch has already run.

**Trust plane:** the publisher is a **mechanism, never an authority** — every security decision (rid recompute, proof verification) lives in the `chain-midnight` crate over raw bytes, never in the publisher, so a publisher decode bug is a dropped request, never a wrong signature. (Full reasoning + the honest V1 limit: decisions doc §D.)

**Transport:** a **localhost-bound sidecar** — binds `127.0.0.1` only (or a unix socket on a shared pod volume), reached by the co-located `mpc-node`; **never `0.0.0.0` / published**. A separate **sidecar container** (not an in-node `Command::new` child) is preferred so a proving OOM or a toolkit RCE is isolated to the sidecar, never the keyholding node. (Alternatives weighed: decisions doc §B.)

**Deployment — THREE containers we own, plus an external RPC dependency.** The Midnight node is not part of our deployment; it is an RPC URL both our containers point at.

```
┌─ we deploy (co-located, localhost) ──────────────────────────────┐
│  mpc-node ──http(127.0.0.1)──> midnight-publisher ──> proof-server │
│     │                                │                            │
└─────┼────────────────────────────────┼───────────────────────────┘
      │ (heads sub / raw RPC)           │ (RPC: state, send-intent)
      ▼                                 ▼
   ╔══════════════════════════════════════════════╗
   ║  Midnight RPC endpoint  — EXTERNAL dependency ║
   ║  own node today (no public ledger-9 RPC yet); ║
   ║  third-party-able later, like eth/sol RPC     ║
   ╚══════════════════════════════════════════════╝
```

- **mpc-node** — the keyholder (threshold shares); does light RPC itself (finalized-heads subscription, raw fetch), calls the publisher for decode/prove/submit.
- **midnight-publisher** — the bundled toolchain sidecar.
- **proof-server** — upstream's `midnightntwrk/proof-server`, localhost-bound beside the publisher and pointed at by `MIDNIGHT_PUB_PROOF_SERVER_URL`. Not optional: it is the only component in the deployment that can prove a zkir-v3 circuit. It receives prover key + inputs per request and returns a proof; it holds no secret of ours (the funding seed and the threshold shares never reach it), so it is a compute peer, not a trust boundary. Sizing it, not the publisher, is what absorbs proving's memory spikes.
- **Midnight RPC** — external, consumed like any chain's RPC. Self-run today keeps its own container (large stateful DB, `archive-canonical` bodies, own release cadence — never fused into the publisher); a public endpoint later is a config change, not a deployment change.

Baked into the publisher image: toolkit binary, Node/toolkit-js, compactc, prover keys (~GB, reproducible), compiled central-contract artifacts (public). Injected at runtime, NEVER baked: the `funding_seed` (a hot gas-wallet secret — k8s Secret/env) and the Midnight RPC URL. Precedent in-repo: the root `Dockerfile` is already multi-stage multi-language (a `node:20` build stage + the Rust build) and co-locates redis beside `mpc-node`.

## 6. Integrator tooling

1. `@sig-net/midnight` Compact module + TS package (§4.1) — request builders (off-chain rid, strict-ABI word encoding, capacity-tier selection), notify/response pollers (responses polled, never ws), deploy helpers, the cross-contract proof-provider registry helper.
2. Golden harness for integrators: generate-and-verify vectors for their contract (rid, record bytes, notification, `fieldOrdinal` lint against their compiled `contract-info.json`).
3. Docs: integration guide + threat model — what the caller contract MUST enforce in-circuit (calldata construction, `path` binding, request-map hygiene, keyVersion floor; `ownPublicKey()` is a witness, never an auth source; witnesses can't cross CCC).

## 7. Security invariants (review checklist)

- Requester identity = storage location, never a notification/arg field. Epsilon sender = the address the MPC read from.
- requestId = sender-bound flat hash (§3.2); recompute-and-drop on every read path; TS/Rust twins golden-pinned to the circuit.
- Nothing in the central contract is trusted or verified: notifications are hints; response entries are claims. Consumers verify (off-chain for raw signatures, in claim circuits for attestations).
- All central-contract stores are count-keyed append-only: no overwrites, no squatting, no removal. A poisoned entry can never block a genuine one (readers walk all entries per rid).
- Per-rid counters only in the central contract. A multi-user caller should avoid counter *reads* on its request path (`requestNonce` a caller-supplied salt) for cross-rid and cross-user conflict freedom under transcript replay (P4 validates); the single-deployer reference caller reads a local `Counter`, safe only because it has one user.
- Discovery signal is transactions; authority and execution-success are the caller-ledger read. Tx inclusion alone never triggers signing.
- The `midnight-publisher` is a mechanism, never an authority (§5.5): every security decision runs in the `chain-midnight` crate over raw bytes.
- The publisher binds `127.0.0.1` (or a unix socket) only — never `0.0.0.0`/published; it holds a funding (gas) wallet but no signing key shares; the funding seed is injected, never baked.
- The Midnight RPC's trust rests on threshold independence across operators, not an own-node mandate — don't point the whole signing threshold at one shared endpoint (§5.4).
- Identity/path binding and keyVersion floor live in the *caller's* proven circuit; contract-enforced calldata for anything value-bearing.
- Range/canonicality checks are explicit, never cast-implied: `Bytes<32>` casts to secp256k1 scalars reduce mod the modulus (since 0.33.0-rc.1) and are little-endian, while ECDSA `msgHash` is big-endian — claim circuits take r/s little-endian and assert any range policy (e.g. low-s) in code. Golden-pin both endiannesses (BE forms as rejected negative controls).
- Unpaid = unserviced is **not** enforceable in V1 (no payment): the MPC's only spam defenses are dedup-by-rid, per-notification tx fees paid by the spammer, and service policy. Revisit with the payment TODO.

## 8. Open items, TODOs, probes

**PAYMENT (TODO — deliberately out of V1; needs its own design round).** Midnight V1 ships free. Intake works (a CCC callee CAN take *unshielded* payment — proven live; *shielded* intake cannot ride a CCC), but egress has no `msg.sender` admin path — a withdraw must be MPC-signature-gated or wait on `kernel.caller()`, and payment evidence wants a permanent on-chain charge ledger. Because the central contract is frozen, payment lands as a **separate contract beside it** (or via P7), never as a change to the dumb store. The prior in-hub payment/sweep design and why it was dropped: decisions doc §A/§B.

**Probes (live):**
- **P4 — concurrency:** N parallel notifies across distinct rids in one block → zero transcript conflicts; same-rid race behavior; `bytes_written` per entry; costs under the ledger-9 FixedPoint fee factors.
- **P6 — multi-call txs:** batching a caller's request with other calls; guaranteed-vs-fallible segment placement (#1454).
- **P7 — maintenance-authority circuit addition:** can a `MaintenanceUpdate` (`VerifierKeyInsert` + `IrInsert`) add a circuit to the deployed central contract without breaking integrators' `expectedVk` bindings? The primary route for ever adding payment/response kinds.
- **P9 — capacity-tier proving benchmark:** compile the reference caller at tiers, publish the §3.1 guidance table.
- **P10 — proofs on the discovery stream:** inclusion-proof implementation (`extrinsics_root` Merkle verify, rung 2) and third-party verifiability of `claimedContractCalls` from the tx body. Retention resolved (`archive-canonical`).
- **P11 — in-circuit keccak256:** compile-probe `keccak256` over `rid ‖ Bytes<K>` (zkir-v3), golden-pin the parity digest. Note: the built module does not use keccak; it attests with the nested `persistentHash` `signetAttestationDigest` (§3.5), so this probe covers only a future keccak-parity alignment (§B.5), not the current design.
- **P12 — response-key pinning:** *resolved in code.* The reference caller pins the requester-scoped response key via a set-once, deployer-gated `initialise` run after deploy (the address, and therefore the derived key, exists by then), so no constant-sender fallback is needed (§3.5, §4.3).
- **Deferred until a v3 prover ships:** live prove-time/RSS for claim circuits.

**Open upstream (Midnight):** verifiable-finality/light-client roadmap and state-inclusion commitments beyond Substrate read proofs; any plan for `kernel.caller()` (would reopen payment-egress and caller-auth design space).
