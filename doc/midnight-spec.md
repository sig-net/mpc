# Signet on Midnight — SGN2 storage-transport protocol

Implementation plan. **Decision history, rejected alternatives, corrections, and the reasoning behind each choice live in the companion [`midnight-spec-decisions.md`](./midnight-spec-decisions.md).** This file states WHAT to build; the companion states WHY and what was rejected.

**Homes:** contracts in `sig-net/midnight-integration` (`packages/signet-contract`, `packages/signet-midnight`, `packages/caller-contract`); MPC in `chain-signatures/chain-midnight` + the `midnight-publisher` sidecar.

**Target stack:** Compact 0.33 line (language 0.25) / midnight-js 5.0.0-beta.x / node 2.0.0-rc.4 (ledger 9.1.0.0-rc.3). **Ledger 9 only** (cross-contract calls are load-bearing). No public ledger-9 network exists yet — ship local/dev-net until the roll-forward. Toolchain unpinned (latest via `compact update`); per-feature floors: cross-contract calls ≥ 0.32.105; integrator claim circuits (only) need ≥ 0.33.0-rc.2 + `--feature-zkir-v3` for secp256k1/keccak.

**Proving status:** the central contract compiles to **v2 ZKIR** (no in-circuit ECDSA) → its circuit calls prove on the current toolkit. Only integrator **claim** circuits use zkir-v3 (`secp256k1EcdsaVerify` + keccak), which no released prover yet proves for circuit *calls* — those are upstream-gated (deploys prove, calls do not).

---

## 0. Design summary

Client ("integrator"/"caller") contracts store signature requests in **their own public ledger** using standardized types from the shared `@sig-net/midnight` Compact module. The request's storage location *is* its sender authentication: Midnight has no `msg.sender` (no `kernel.caller()`), so "whose proven state the MPC read" is the only unforgeable requester attribution, and the requester contract address is the epsilon-derivation sender. A minimal **central signet contract** (singleton) exists only so both sides have one address to watch: callers register request *notifications* there, the MPC discovers work by **watching the finalized transactions that hit it** (§5.1), and clients poll its *response* stores. It is the Midnight rendering of the EVM `ChainSignatures` doctrine — *"an event bus plus a deposit sink; it performs no signature verification itself"* — with the event bus realized as append-only ledger maps (Midnight has no events) and the deposit sink deferred (payment is a V1 TODO, §8).

**The parity rule (governs every format in this spec):** mirror the EVM/Solana signet contracts — names, field sets, field order, hash shapes, verification responsibilities — and deviate **only** where the platform forces it, documenting each deviation at its site. The forced deviations: SHA-256 instead of keccak256 for values computed in-circuit as a map key (request ids); fixed-size fields instead of dynamic strings/bytes; a `requestNonce` in the record (map-keyed storage needs distinct ids for repeat requests); a decomposed EVM tx instead of `serializedTransaction` (so caller circuits enforce fields); a 32-byte identity `commitment` standing in for the path string (§3.1).

## 1. Architecture decisions

- **Requests live in the caller's ledger; storage location = sender.** Copying a record into another contract changes the sender, hence the rid and the derived keys — never the victim's key space.
- **No events anywhere.** Requests and responses are ledger state (replayable, served by any node, Merkle-provable). Discovery is **finalized-transaction watching** on the central contract (§5.1); the **node-only block-walk composition is normative**, an indexer subscription is a non-normative optional source.
- **The central contract is frozen and dumb.** CoIP-2 binds callers to the callee's verifier keys at compile time, so the singleton can never change circuits without an ecosystem redeploy — everything it does is final at genesis. It holds no keys, verifies nothing, takes no payment, deletes nothing. Anything smarter (payment, new response kinds) is a *separate contract beside it*, never a change to it.
- **Nothing is verified on post; consumers verify on claim.** All response stores are unauthenticated append-only: anyone may post, nothing can be overwritten or blocked, and consumers verify signatures off-chain or in their own claim circuits against the expected derived MPC key (the EVM model exactly).
- **Nothing is ever removed.** All stores grow monotonically; the request-path insert cost carries the O(entries) growth (an operational parameter to monitor). Append-only state is also the lossless catch-up fallback (§5.1).
- **Capacities are per-integrator generics**, never a shared singleton circuit (interface circuits can't be generic; a shared circuit forces worst-case proving cost on everyone).
- **Discovery trust is two-phase.** Phase 1: storage + sender-bound rid recompute + key spacing. Phase 2 (MPC-side, non-breaking): verify notification provenance via the ledger-enforced CCC commitment (`claimedContractCalls`) as OR-evidence (§5.4 rung 2b, probe P10).

## 2. Actors and flow

1. **User → caller contract** (`requestSignBidirectional`-style circuit): validates app rules, builds/overwrites the tx decomposition it enforces (calldata above all), binds the user's identity commitment in-circuit, computes the rid, stores the record in its request map, and cross-contract-calls the central contract to register the notification — all in ONE transaction.
2. **MPC** watches finalized transactions on the central contract (§5.1), extracts each notification from the notify call's transcript, follows it to the caller's ledger (`fieldOrdinal`, read anchored at the same finalized block), decodes the record, **recomputes the sender-bound rid and drops on mismatch**, validates routing, signs with the epsilon-derived key `f(caller_address, path)`.
3. **MPC → central contract**: posts the raw chain signature (`respond` → `signatureRespondedEvents`); after observing destination-chain execution, posts the attestation (`respondBidirectional` → `respondBidirectionalEvents`). Both posts are blind appends.
4. **User/dapp** polls the response stores by rid, verifies off-chain, broadcasts the signed tx; for bidirectional flows, claims against the attestation in the caller contract (`claim` verifies the ECDSA attestation in-circuit and GCs the caller's own request record — the central contract deletes nothing).

## 3. Data formats

### 3.1 Request records

Two record kinds, mirroring the EVM structs field-for-field. Field order below is normative — it is also the rid preimage order (§3.2). All integers little-endian, all `Bytes<N>` raw, zero-padded ASCII for the string-like fields (`caip2Id`, `algo`, `dest`, `params`).

`SignRequest` (mirrors EVM `SignRequest {payload, path, keyVersion, algo, dest, params}`; EVM's `block.chainid` is dropped — the source chain is implied by the platform):

| field | type | notes |
|---|---|---|
| requestNonce | Uint<64> | caller-supplied uniqueness salt (dapp-chosen counter or random); enforced only by the caller's `!member(rid)` guard — no Counter read (§3.2) |
| payload | Bytes<32> | the 32-byte digest to sign |
| commitment | Bytes<32> | stands in for `path`; MPC derives `path = hex(commitment)` (§3.1 identity note) |
| keyVersion | Uint<32> | ≥ 1 asserted in the caller circuit (0 = unsupported legacy) |
| algo | Bytes<32> | parity field, e.g. "ecdsa" |
| dest | Bytes<32> | parity field |
| params | Bytes<64> | parity field |

`SignBidirectionalRequest<#maxWords, #maxALEntries, #maxKeysPerEntry>` (mirrors EVM `SignBidirectionalRequest {serializedTransaction, caip2Id, keyVersion, path, algo, dest, params, outputDeserializationSchema, respondSerializationSchema}`):

| field | type | notes |
|---|---|---|
| requestNonce | Uint<64> | caller-supplied uniqueness salt (as above) |
| txParamType | Uint<8> | decomposition selector; `0` = evmType2. Plain `Uint<8>`, not an enum (a 1-real-variant Compact enum has a known proving pitfall) |
| tx | EVMType2TxParams<…> | stands in for `serializedTransaction` (decomposed so the caller circuit can enforce fields) |
| caip2Id | Bytes<32> | destination chain, CAIP-2 |
| keyVersion | Uint<32> | ≥ 1 |
| commitment | Bytes<32> | stands in for `path` (§3.1 identity note) |
| algo | Bytes<32> | parity field |
| dest | Bytes<32> | parity field |
| params | Bytes<64> | parity field |
| outputDeserializationSchema | Bytes<128> | |
| respondSerializationSchema | Bytes<128> | |

- `EVMCalldata<#maxWords> { selector: Bytes<4>, noWords: Uint<8>, words: Vector<maxWords, Bytes<32>> }` — words are **strict ABI-encoded big-endian 32-byte slots used verbatim**; the MPC assembles `calldata = selector ‖ words[0..noWords]` with zero interpretation. No `Maybe`: a plain transfer is `noWords = 0`. Words are built as bytes (address words as `pad-left-12 ‖ addr`), no Field helpers.
- `EVMType2TxParams<#maxWords, #maxALEntries, #maxKeysPerEntry> { evmTo: Bytes<20>, chainId: Uint<64>, nonce: Uint<64>, gasLimit: Uint<64>, maxFee: Uint<128>, priorityFee: Uint<128>, value: Uint<128>, calldata: EVMCalldata<maxWords>, noAccessListEntries: Uint<8>, accessList: Vector<maxALEntries, AccessListEntry<maxKeysPerEntry>> }` — `Vector<0, _>` is legal (compiler-verified), so `<N,0,0>` tiers work.
- Capacity generics are the integrator's compile-time throttle and proving budget (tier guidance table = probe P9).
- No record-level `schemaVersion` (parity: EVM has none). Evolution rides the notification envelope `version` (§3.4) and new `txParamType` variants — reader-side additions, never contract changes.
- **Identity note — `commitment`, not a `path` string.** On Midnight the epsilon sender is the integrator contract, shared by every user of it, and users have no platform identity — so per-user key isolation comes from the path, and the path↔user binding must be provable in the caller circuit. The provable identity is the witness-derived `commitment = SHA-256(pad(32,"signer:user:") ‖ callerSecretKey)`; the record stores its 32 raw bytes and the MPC derives `path = lowercase-hex(commitment)`. (Rationale and the rejected path-string form: decisions doc §B.)

### 3.2 Request id

The cross-chain shape (EVM/Solana use `keccak256` over `sender ‖ request-fields`, flat, no domain tag). Midnight mirrors that shape; only platform-forced substitutions differ:

```
requestId = persistentHash<RidPreimage<…>>( { sender: kernel.self().bytes, request: record } )
          ≡ SHA-256( senderContractAddress(32) ‖ canonical-record-bytes )
```

- **One flat SHA-256.** The preimage struct is `{sender, request}`; Compact's canonical struct serialization (fields in declaration order, LE ints, raw bytes, no length prefixes) makes its hash literally `SHA-256(sender ‖ record-bytes)`. No domain tag, no inner `persistentHash(record)`.
- **SHA-256, not keccak:** the id is computed in-circuit as the caller's map key; ids are never compared across chains, so shape parity (not byte parity) is the goal.
- **Sender is bound and comes first** — without it, any contract could byte-copy a victim's record, mint the same id, and squat response slots. The MPC recomputes the rid with the address **it actually read the record from**; mismatch = drop. Sender = `kernel.self().bytes` in-circuit; untagged lowercase 64-hex in the epsilon string.
- **Uniqueness:** `requestNonce` is a **caller-supplied salt**, backstopped by the caller's `!member(rid)` insert guard. NOT a contract `Counter` read (reading a counter pins its value in the transcript → concurrent users of one contract conflict; a salt has no read). Salt choice is safety-irrelevant — the rid also binds the prover's witness-derived `commitment`, so no salt lets one user mint another's rid. (Why not a Counter: decisions doc §B.)
- **Storage position is not bound into the id** (a wrong-ordinal read fails the recompute or resolves to an inert no-op; position stays a discovery hint).
- `calculateRequestId` is a generic pure circuit; the TS twin (`signet-requests.ts`) and Rust twin (mpc `records.rs`) change in lockstep and are golden-pinned. **This formula invalidates every prior rid/record golden — regenerate the whole SGN2 golden tree.**

### 3.3 Ledger layout and encoding (verified facts)

- Layout is positional and path-addressed. ≤15 ledger fields = one flat `StateValue` array; ≥16 bucket into ≤15-wide child arrays (observed splits: 16 → 1+15, 27 → 12+15 — partition is compiler-internal; **never compute paths arithmetically**, recover by recursive flattening of observed state). A struct map value is a single cell with one atom per field in declaration order; `Bytes<N>`/`Uint` atoms and map keys are **trailing-zero-trimmed** (readers re-pad). A Compact `List<T>` is a recursive **cons node** `[headValue, tailList, lengthCounter]`.
- The request map may sit at **any** ordinal; the notification carries it (`fieldOrdinal`), the reader is position-agnostic. `contract-info.json` `ledger[].index` is a *build-time* reference (our test fixtures; an integrator's golden harness lints its notify literal) — the MPC never reads any integrator's json at runtime.
- **Encoding stability:** a deployed contract's state encoding is frozen at its compile version; field-position addressing holds for the contract's lifetime; new-compiler changes affect only newly compiled contracts and are absorbed reader-side (the notification `version`). Residual: a CI job watching Compact release *tags* for encoding-affecting changes (§5.2).

### 3.4 Notifications (central-contract-stored, versioned envelope)

A notification is a **pointer**: "contract X stored request Y at ledger field Z". Nothing in it is trusted — authority comes from the caller's ledger + rid recompute; spoofed notifications are deduped noise that costs the spoofer a tx fee.

```compact
export struct SignetEventKey { count: Uint<64>; requestId: Bytes<32>; }

export struct SignetNotification {
    version: Uint<8>;      // payload decoder selector; this spec = 1
    payload: Bytes<128>;   // V1: callerAddress(32) ‖ fieldOrdinal(1) ‖ txParamType(1) ‖ reserved(94), zero-padded
}
```

- **Count-keyed, never overwritable.** Entries land under `SignetEventKey{count, rid}` with a per-rid `Counter` supplying the count — an append-only array per rid. A spammer can append noise after the honest entry but never clobber it; the MPC reads all entries per rid and keeps the first that verifies. Per-rid counters keep honest cross-rid traffic conflict-free under transcript replay; same-rid same-block races are attacker-only and first-wins (P4 validates).
- The rid lives in the **key**, not the payload. Payload budget 128 bytes as the forward-compat surface; clients never hand-serialize (per-version pure-circuit constructor `constructSignetNotificationV1(callerAddress, fieldOrdinal, txParamType)`; a future V2 = a new constructor + reader-side decoder, deployed contracts untouched).
- `txParamType`: `0` = `SignBidirectionalRequest` decode, `255` = plain `SignRequest` decode; others drop with telemetry.

### 3.5 Responses (central-contract-stored, unverified, append-only)

Same count-keyed append pattern as notifications; **the contract verifies nothing at post time** — it stores whatever args it was called with. First-valid-write semantics are enforced by *consumers* (verify each entry, take the first valid).

- `signatureRespondedEvents: Map<SignetEventKey, SignatureResponse>` — mirrors EVM `SignatureResponded`. `SignatureResponse { bigRx: Bytes<32>, bigRy: Bytes<32>, s: Bytes<32>, recoveryId: Uint<8> }` (the MPC's canonical `Signature`; big-endian bytes). The raw chain signature the client verifies off-chain and broadcasts. (No `responder` field — Midnight can't observe the poster; it carried no authority on EVM either.)
- `respondBidirectionalEvents: Map<SignetEventKey, RespondBidirectionalResponse>` — mirrors EVM `RespondBidirectional`. `RespondBidirectionalResponse { outputHash: Bytes<32>, signature: SignatureResponse }`. The store carries `outputHash = SHA-256(serializedOutput)` instead of the variable-length output (Compact has no dynamic bytes; a frozen `Bytes<N>` cap would be forever). The client fetches the output itself and the hash matches entries; the attestation signature binds the real output (below).

**Attestation (phase-2) — full cross-chain parity.** The MPC signs `digest = keccak256(requestId ‖ serializedOutput)` (whole raw output, no inner hash — `calculate_respond_bidirectional_hash_message`) with the derived **response key**: epsilon sender = the requester (caller contract address), constant path = `"midnight response key"` (the `"solana response key"` pattern), same epsilon-v2 formula as request keys. Verification is the **integrator's claim circuit** (or off-chain): recompute `keccak256(rid ‖ output)` in-circuit over the output at the integrator's compile-time size `Bytes<K>`, and `secp256k1EcdsaVerify` against the expected response pubkey (both zkir-v3 → the claim-side prover gate). Two checkpoints before freeze: **P11** (compile-probe in-circuit keccak over `rid ‖ Bytes<K>`, golden-pin the digest); **P12** (how the integrator pins its expected response pubkey — sealing at deploy may hit an address-before-constructor circularity; fallback = response key scoped to a constant sender, decided by P12).

## 4. Contract-side deliverables (`sig-net/midnight-integration`)

### 4.1 `@sig-net/midnight` Compact module (`packages/signet-midnight`)

Types per §3; `calculateRequestId` per §3.2 (generic pure circuit + wrapper preimage struct); `constructSignetNotificationV1`; request-constructor circuits enforcing the `keyVersion ≥ 1` floor and taking `commitment` directly (no path string, no `assertPathCommitment`/`assertHexOf`); `userCommitment(sk) = persistentHash([pad(32,"signer:user:"), sk])`.

### 4.2 Central signet contract (`packages/signet-contract`) — frozen, dumb, final at genesis

No constructor arguments (no keys). Eight ledger fields, declaration order normative (the MPC reads by ordinal); every circuit is a blind count-keyed append with no asserts beyond arg plumbing:

```compact
export ledger signatureRequestedEventCounters:  Map<Bytes<32>, Counter>;                      // 0
export ledger signatureRequestedEvents:         Map<SignetEventKey, SignetNotification>;      // 1  (EVM: SignatureRequested)
export ledger signBidirectionalEventCounters:   Map<Bytes<32>, Counter>;                      // 2
export ledger signBidirectionalEvents:          Map<SignetEventKey, SignetNotification>;      // 3  (EVM: SignBidirectional)
export ledger signatureRespondedEventCounters:  Map<Bytes<32>, Counter>;                      // 4
export ledger signatureRespondedEvents:         Map<SignetEventKey, SignatureResponse>;       // 5  (EVM: SignatureResponded)
export ledger respondBidirectionalEventCounters: Map<Bytes<32>, Counter>;                     // 6
export ledger respondBidirectionalEvents:       Map<SignetEventKey, RespondBidirectionalResponse>; // 7  (EVM: RespondBidirectional)

// One shared append pattern (per-rid counter -> key -> insert), e.g.:
export circuit notifySignBidirectional(requestId: Bytes<32>, notification: SignetNotification): [] {
  const rid = disclose(requestId);
  if (!signBidirectionalEventCounters.member(rid)) { signBidirectionalEventCounters.insertDefault(rid); }
  const count = signBidirectionalEventCounters.lookup(rid).read();
  signBidirectionalEventCounters.lookup(rid).increment(1);
  signBidirectionalEvents.insert(SignetEventKey { count: count, requestId: rid }, disclose(notification));
}
// notifySignatureRequested(...) identical over fields 0/1;
// respond(requestId, signature) over 4/5;             // EVM function-name parity
// respondBidirectional(requestId, outputHash, signature) over 6/7.
```

- The two notify circuits are CCC-callable (no witnesses, no Zswap, per-rid state only) so a caller registers its notification inside its own request transaction. The respond circuits are direct calls by the MPC (and, permissionlessly, by anyone — posts are unauthenticated by design).
- **The notify's state write is also its transaction-visibility** (§5.1): a call's transcript is a replayable op program, so the `insert`'s key and value appear literally in the tx body — that is what tx-watching discovery reads. A write-nothing notify would leave only the CCC commitment hash (preimage unrecoverable) and be undiscoverable; the append must stay.
- No keys, no payment fields, no sweeps, no GC (§8 payment TODO).
- Compiles **without** `--feature-zkir-v3` → v2 ZKIR → all circuit calls prove on the current toolkit.

### 4.3 Reference caller (`packages/caller-contract`)

The canonical integrator shape: owns its request maps (`signBiRequests`, `signRequests` — any ordinals, pinned into its notify literals from its compiled `contract-info.json`), seals the central-contract reference, asserts `keyVersion ≥ 1`, stores each record under its rid (`requestNonce` = caller salt + `!member(rid)` guard, no contract Counter on the request path), and CCC-notifies in the same transaction. Its `claim` circuit implements §3.5 verification (zkir-v3; the one part that cannot *prove* until a v3 prover ships) and GCs its own request record. `packages/caller-contract-20-field` stays as the chunked-layout parsing fixture.

## 5. MPC-side deliverables (`chain-signatures/chain-midnight`)

**Component inventory — what is extra vs the per-chain pattern.** Ethereum/Solana ship as ONE in-workspace crate (stream + a plain-RPC publisher), RPC endpoint as operator config. Midnight keeps that crate slot (`chain-midnight` — discovery loop, decode twins, rid recompute, conversion) and adds:

1. **The `midnight-publisher` sidecar** — the one extra codebase component, forced because the Midnight ledger/toolkit dependency universe cannot co-resolve with the main workspace (CI keeps the main lockfile polkadot-free). Three seams need the ledger crates: **prove+submit** responds (`POST /respond`, shipped SGN1), **decode contract state** (`GET /state`, built 2026-07-18 but currently unmerged — mpc reflog `3a7705ca`/`a0cc0472`), **decode block bodies** for discovery (`GET /block`, to build). Full detail: §5.5.
2. **The proving supply chain** — pinned toolkit images, the central contract's compiled artifacts + prover keys as fixtures, per-respond proving time/RAM budgets (SGN1 ≈39 s / ~11.5 GiB; the v3 v2-ZKIR contract is simpler — re-measure, expect less).
3. **A Midnight RPC endpoint** — a standard external dependency like the eth/sol execution RPC, third-party-able; self-run today only because no public ledger-9 RPC exists (§5.4). Capability constraint (own or third-party): finalized block bodies (`archive-canonical`, not warp/pruned), the subscription + `state_getReadProof` methods, accepts submissions.

So the MPC **deploys** exactly TWO components (the crate + the publisher sidecar) plus a Midnight RPC URL to point at. Explicitly NOT run: the Midnight GraphQL **indexer** (non-normative option only) and the HTTP **proof server** (publisher proving is toolkit-native).

### 5.1 Discovery — finalized-transaction watching

No state polling. The MPC discovers work by watching the finalized transactions that hit the central contract. The node RPC has no tx-by-address subscription (verified: the only subscriptions are chain heads, `state_subscribeStorage`, runtime version, GRANDPA/BEEFY justifications, own-tx watch), so the normative mechanism is heads-subscription + body fetch + filter — one code path for live and catch-up:

1. **Subscribe** `chain_subscribeFinalizedHeads` (ws). Finality gating is inherent — only finalized heads arrive.
2. **Per head:** `chain_getBlock(hash)`, deserialize each extrinsic's ledger transaction (via the publisher), keep transactions with a call segment on the central contract at one of the two notify entry points. A CCC ride-along and a direct call are both plain call segments — one filter catches both. The MPC's own respond posts appear on the same stream (settlement observation for free).
3. **Extract** the notification from the call's transcript: the `insert`'s literal key `{count, requestId}` and value `{version, payload}` are present in the tx body verbatim (why the notify circuits write state — §4.2).
4. **No discovery-side seen-set:** each finalized tx is processed once in block order; the node's rid-level sign-once idempotency absorbs restart overlap (re-walking the checkpoint block is harmless).
5. **The caller-ledger read stays — it is the execution check.** Ledger 9 pre-validates only the guaranteed segment at inclusion (#1454), so an included notify tx can still have failed its fallible segment: tx presence alone never triggers signing. Follow the notification to the caller's ledger (`midnight_contractState(caller, at = that finalized hash)` — anchored reads are supported and honored), and a missing record or rid-recompute mismatch = drop.

**Catch-up.** Restart = walk finalized blocks `[checkpoint+1 … chain_getFinalizedHead]` via `chain_getBlockHash(n)` → `chain_getBlock`, through the same filter as live (finalized blocks are immutable → deterministic, replayable from any depth). Conditions:

- **Block-body retention:** `--blocks-pruning` defaults to `archive-canonical` (every finalized body retained indefinitely) — catch-up from arbitrary downtime works on a default node. Ops rules: never set `--blocks-pruning <NUMBER>`, never warp-sync.
- **State pruning is separate:** `--state-pruning` defaults to 256 blocks and limits historical *state* reads, not bodies. The step-5 anchored read targets a just-finalized block (well inside 256) in live operation; on a deep catch-up, fall back to the caller's *latest* state (the record is still there unless already claim-GC'd, and a claimed request needs no signing). Historical read-proofs want `--state-pruning archive`.
- **Beyond-retention fallback:** because every store is append-only (§1), the *latest* contract state contains every notification ever posted — a node that outran its block window catches up with one state read + diff, then resumes the stream (degraded: loses per-tx ordering/provenance for the gap, but never permanently blinded).
- **Checkpoint** = last fully processed finalized height (the existing per-chain checkpoint machinery).

Non-normative alternative discovery sources (`state_subscribeStorage`; the indexer `contractActions` subscription) exist and are catalogued in decisions doc §B — optional, never the foundation.

### 5.2 Reader

- Path-aware field resolution per §3.3: recursive flattening, ordinal from the notification, structural bucket detection, trailing-zero re-pad of atoms and map keys, cons-node walking for `List` values. Validated against committed state fixtures (our compiled test contracts at 6/8/16/27 fields, each embedding its `contract-info.json` ledger array as the expected-ordinal pin). No integrator file exists at runtime.
- Count-keyed maps: walk a rid's entries `0..counter-1` with a per-rid growth watermark, per-entry decode-or-skip — a poisoned entry never blocks a later genuine one. Used by client response polling and the beyond-retention catch-up; live discovery reads entries out of tx transcripts instead (§5.1).
- Decode by `txParamType` with capacity-split enumeration folded into the **mandatory rid recompute-and-drop** (stored key must equal `rid(sender, record)`; the recompute disambiguates capacity splits). Unknown `version`/`txParamType` → drop with telemetry.
- Pin the ledger decode lib to the deployed node's ledger version; CI job watching Compact release tags for encoding-affecting changes.

### 5.3 Validation and conversion

keyVersion ∈ [1, LATEST]; `path` = canonical lowercase hex of the record's `commitment`; caip2 → known-chain routing; tx reassembly `selector ‖ words[0..noWords]` + access-list truncation by counts, golden-tested byte-equal against ethers; epsilon sender = the address the record was read from (notification-carried, then verified equal to the address actually read — never from record bytes). Phase-2: the **generic** respond-bidirectional path (keccak digest over rid ‖ output, `"midnight response key"`, requester sender pending P12).

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

1. **Write path — prove & submit responses.** Encode the MPC's already-computed signature into circuit args, validate, fetch current contract state, generate the circuit-call intent, prove + fund + submit to finality. Owns: arg serialization, ZK proving (compute + prover keys + caches), fee/gas custody (the funding wallet), submission + finality confirmation.
2. **Read path — decode contract state** for the anchored authority reads (versioned-binary `ContractState`/`StateValue` → the JSON tree the crate walks).
3. **Read path — decode block bodies** for discovery (finalized block → call segments + transcript entries → the notification key/value + the CCC provenance commitment).

Cross-cutting: the dependency firewall, toolkit orchestration, funding-seed custody, compiled-artifact + cache management.

**Not pure Rust.** Thin Rust glue over a Node + Compact toolchain, all bundled into the image: a native node-toolkit binary (prove+submit), Node.js + toolkit-js + a per-contract TS config (intent generation), compactc, prover keys. **Native intent mode — no docker-in-docker at serve time.**

**Trust plane:** the publisher is a **mechanism, never an authority** — every security decision (rid recompute, proof verification) lives in the `chain-midnight` crate over raw bytes, never in the publisher, so a publisher decode bug is a dropped request, never a wrong signature. (Full reasoning + the honest V1 limit: decisions doc §D.)

**Transport:** a **localhost-bound sidecar** — binds `127.0.0.1` only (or a unix socket on a shared pod volume), reached by the co-located `mpc-node`; **never `0.0.0.0` / published**. A separate **sidecar container** (not an in-node `Command::new` child) is preferred so a proving OOM or a toolkit RCE is isolated to the sidecar, never the keyholding node. (Alternatives weighed: decisions doc §B.)

**Deployment — TWO containers we own, plus an external RPC dependency.** The Midnight node is not part of our deployment; it is an RPC URL both containers point at.

```
┌─ we deploy (co-located, localhost) ──────────────┐
│  mpc-node ──http(127.0.0.1)──> midnight-publisher │
│     │                                │            │
└─────┼────────────────────────────────┼───────────┘
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
- **Midnight RPC** — external, consumed like any chain's RPC. Self-run today keeps its own container (large stateful DB, `archive-canonical` bodies, own release cadence — never fused into the publisher); a public endpoint later is a config change, not a deployment change.

Baked into the publisher image: toolkit binary, Node/toolkit-js, compactc, prover keys (~GB, reproducible), compiled central-contract artifacts (public). Injected at runtime, NEVER baked: the `funding_seed` (a hot gas-wallet secret — k8s Secret/env) and the Midnight RPC URL. Precedent in-repo: the root `Dockerfile` is already multi-stage multi-language (a `node:20` build stage + the Rust build) and co-locates redis beside `mpc-node`.

## 6. Integrator tooling

1. `@sig-net/midnight` Compact module + TS package (§4.1) — request builders (off-chain rid, strict-ABI word encoding, capacity-tier selection), notify/response pollers (responses polled, never ws), deploy helpers, the cross-contract proof-provider registry helper.
2. Golden harness for integrators: generate-and-verify vectors for their contract (rid, record bytes, notification, `fieldOrdinal` lint against their compiled `contract-info.json`).
3. Docs: integration guide + threat model — what the caller contract MUST enforce in-circuit (calldata construction, commitment binding, request-map hygiene, keyVersion floor; `ownPublicKey()` is a witness, never an auth source; witnesses can't cross CCC).

## 7. Security invariants (review checklist)

- Requester identity = storage location, never a notification/arg field. Epsilon sender = the address the MPC read from.
- requestId = sender-bound flat hash (§3.2); recompute-and-drop on every read path; TS/Rust twins golden-pinned to the circuit.
- Nothing in the central contract is trusted or verified: notifications are hints; response entries are claims. Consumers verify (off-chain for raw signatures, in claim circuits for attestations).
- All central-contract stores are count-keyed append-only: no overwrites, no squatting, no removal. A poisoned entry can never block a genuine one (readers walk all entries per rid).
- Per-rid counters only in the central contract, and no counter *reads* on caller request paths (`requestNonce` is caller-supplied) — cross-rid and cross-user conflict freedom under transcript replay (P4 validates).
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
- **P11 — in-circuit keccak256:** compile-probe `keccak256` over `rid ‖ Bytes<K>` (zkir-v3), golden-pin the parity digest.
- **P12 — response-key pinning:** can a Midnight contract's address be computed before its constructor args are fixed? Decides requester-scoped response keys (parity) vs constant-sender fallback (§3.5).
- **Deferred until a v3 prover ships:** live prove-time/RSS for claim circuits.

**Open upstream (Midnight):** verifiable-finality/light-client roadmap and state-inclusion commitments beyond Substrate read proofs; any plan for `kernel.caller()` (would reopen payment-egress and caller-auth design space).
