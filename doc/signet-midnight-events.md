# Signet Midnight event wire format (SGN1)

Normative specification of the contract-event protocol between the `signet-signer` Compact contract (source + compile pipeline: `midnight-erc20-vault`; compiled artifacts pinned at `integration-tests/fixtures/midnight/signet-signer/`) and the sig-net MPC node (`chain-signatures/chain-midnight`). Version tag: **SGN1**. A future incompatible layout must use a new tag (e.g. `SGN2`) so parsers can coexist.

Golden vectors for everything specified here live in `chain-signatures/chain-midnight/tests/goldens/*.json` — pinned copies of the vectors generated in `midnight-erc20-vault` (`signer/src/goldens.ts` executes the compiled contract). The Rust consumer must be tested against those vectors; regenerate in the vault repo and update the pinned copies when the contract changes (SGN1 is versioned — incompatible layouts need a new tag).

## Transport

Requests and responses are Midnight ledger-9 contract events (MIP-0002), emitted as the standard `Misc` event type: `Misc { name: Bytes<32>, payload: Bytes<256> }`. On-chain and via the indexer both fields are fixed-size and zero-padded. The MPC consumes them from the midnight-indexer (`contract-events-e2e` line) GraphQL v4 API:

```graphql
subscription { contractEvents(filter: { contractAddress: $addr, types: [MISC] }, id: $resume) { ... } }
```

The `contractAddress` filter is the provenance root: only events emitted by the pinned signer contract enter the stream. `MiscContractEvent` exposes `id` (monotonic, resumable), `name`, `payload`, `transactionId`, and `transaction { block { height } }`.

All request-emitting circuits keep every `emit` in the guaranteed transaction segment (the contract never calls `kernel.checkpoint()`), so "transaction succeeded ⇒ all parts of the request were emitted" holds exactly, and chunked requests are all-or-nothing on-chain.

## Event name grammar (`Misc.name`, 32 bytes, ASCII, zero-padded)

| Name | Circuit | Parts |
|---|---|---|
| `SGN1:SIGN` | `sign` | 1 |
| `SGN1:SIGNBI:<i>/5`, i = 1..5 | `sign_bidirectional` | 5 |
| `SGN1:RESP` | `respond` | 1 |
| `SGN1:RESPBI:<i>/2`, i = 1..2 | `respond_bidirectional` | 2 |

Part indices are 1-based ASCII (`1/5` … `5/5`). Parsers MUST ignore events whose name does not exactly match this grammar (after stripping trailing zero bytes).

## Payload shape (`Misc.payload`, 256 bytes)

Every payload is:

```
payload[0..32]   requestId   (32 bytes)
payload[32..256] tail        (224 bytes, part body zero-padded)
```

The tail is the canonical Compact serialization (`serialize<T, 224>`) of the part's body struct. Compact canonical serialization of these fixed-size types is plain field concatenation with **no headers**: `Bytes<N>` and `Vector<K, Bytes<N>>` are raw bytes, `Uint<8|32|64|128>` are 1/4/8/16-byte **little-endian**, then zero-padding to 224.

## Request id

For a request with parts 1..P (in part order):

```
requestId = SHA-256( tail_1 || tail_2 || … || tail_P )
```

i.e. the hash of the exact padded 224-byte tails as they appear on the wire (this equals Compact `persistentHash<Bytes<224>>` / `persistentHash<Vector<P, Bytes<224>>>`, which are plain SHA-256 of the (concatenated) bytes — verified against compact-runtime 0.18 and pinned by goldens).

Uniqueness comes from the contract's global `signetNonce` counter serialized into part 1 of every request; a caller can neither choose nor replay another request's id because their call consumes their own nonce in-circuit.

**Provenance rule (MUST):** the consumer recomputes `requestId` from the received tails and drops the request on mismatch. Combined with the `contractAddress` filter and `(transactionId, requestId)`-scoped reassembly, this prevents payload splicing and malformed chunks.

Responded events (`SGN1:RESP*`) carry the `requestId` **verbatim** from the circuit argument — it is never recomputed on-chain and refers to the request being answered.

## Reassembly rules

- Group events by `(transactionId, requestId)`; a request's parts are always emitted by one circuit call inside one transaction, in part order (monotonic indexer `id`s).
- A request is complete when all P parts (per the name grammar) are present; multi-part requests missing parts after their transaction is fully consumed are malformed — drop them.
- Progress/resume tokens are contract-event `id`s. Advance the persisted id only at request boundaries; on reconnect, over-fetch from `resume_id − (P_max − 1)` (P_max = 5) and dedupe, so a restart mid-request never loses parts.

## Part layouts

All offsets are within the 224-byte tail. "reserved" fields are zero in SGN1 but are part of the request-id preimage, so they can become real arguments later without an id-scheme change.

### `sign` — `SGN1:SIGN` (1 part)

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 8 | nonce | Uint<64> LE |
| 8 | 32 | commitment | caller identity commitment |
| 40 | 32 | payload | 32-byte hash to sign (big-endian scalar) |
| 72 | 4 | keyVersion | Uint<32> LE |
| 76 | 32 | algo | reserved (zero) |
| 108 | 32 | dest | reserved (zero) |
| 140 | 64 | params | reserved (zero) |
| 204 | 20 | — | zero padding |

### `sign_bidirectional` — `SGN1:SIGNBI:<i>/5` (5 parts)

Part 1 (core):

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 8 | nonce | Uint<64> LE |
| 8 | 32 | commitment | caller identity commitment |
| 40 | 4 | keyVersion | Uint<32> LE |
| 44 | 32 | caip2Id | ASCII, zero-padded (e.g. `eip155:11155111`) |
| 76 | 32 | dest | ASCII, zero-padded |
| 108 | 64 | params | ASCII, zero-padded |

Part 2 (EVM params):

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 20 | evmTo | raw 20-byte address |
| 20 | 8 | evmChainId | Uint<64> LE |
| 28 | 8 | evmNonce | Uint<64> LE |
| 36 | 8 | evmGasLimit | Uint<64> LE |
| 44 | 16 | evmMaxFee | Uint<128> LE (wei) |
| 60 | 16 | evmPriorityFee | Uint<128> LE (wei) |
| 76 | 16 | evmValue | Uint<128> LE (wei) |
| 92 | 1 | argCount | Uint<8> |
| 93 | 64 | funcSig | ASCII, zero-padded (e.g. `transfer(address,uint256)`) |

Part 3 (calldata args): offsets 0..128, `Vector<4, Bytes<32>>` — four 32-byte words. The first `argCount` words are **ABI-ready big-endian words** used verbatim in calldata (addresses left-padded with 12 zero bytes, uints big-endian). This deliberately differs from the old vault's little-endian `Field` encoding: no Field cast is involved, and the MPC needs no ABI type introspection.

Part 4 (output schema): offsets 0..128, ASCII, zero-padded.

Part 5 (respond schema): offsets 0..128, ASCII, zero-padded.

### `respond` — `SGN1:RESP` (1 part)

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 32 | bigRx | signature R.x, big-endian |
| 32 | 32 | bigRy | signature R.y, big-endian |
| 64 | 32 | s | signature s, big-endian |
| 96 | 1 | recoveryId | Uint<8> |

### `respond_bidirectional` — `SGN1:RESPBI:<i>/2` (2 parts)

Part 1: `serializedOutput` at 0..128 (target-chain execution output, zero-padded), `outputLen` (Uint<8>) at 128 — the meaningful byte count of `serializedOutput`.

Part 2: identical layout to `SGN1:RESP` (the phase-2 signature).

## Field conventions

- ASCII fields (`caip2Id`, `dest`, `params`, `funcSig`, `outputSchema`, `respondSchema`): consumers strip trailing zero bytes to recover the string; the empty string is all-zero.
- Binary fields (`commitment`, `payload`, arg words, signature scalars): fixed-size, never stripped.
- `serializedOutput` is sized by `outputLen`, not by zero-stripping (outputs may legitimately end in zero bytes).
- **Schema content (normative, verified in the bidirectional e2e):** for EVM contract-call requests, `outputSchema` MUST be the object form `[{"name":"<field>","type":"<solidity type>"}]` — the MPC's Ethereum execution watcher decodes call results with a strict `Vec<AbiField>` parse and drops requests whose output it cannot extract. The bare-string shorthand (`["bool"]`) is accepted only on the respond-serialization side and for plain value transfers; do not use it for contract calls.

## MPC-side interpretation (chain-midnight indexer)

- `sender` (epsilon derivation) = the signer **contract address** as untagged lowercase hex, 64 chars, no `0x` (the exact string the toolkit's `contract-address` prints untagged). As raw bytes it is carried in `SignBidirectionalEvent.sender: [u8; 32]` and hex-encoded by `sender_string` (Canton precedent).
- `path` = lowercase hex of `commitment` (64 chars), reconstructed off-chain. The commitment is `SHA-256(pad(32, "signer:user:") || callerSecretKey)`, computed in-circuit from the caller's secret-key witness, so only the key holder can produce requests under their path.
- `epsilon` = v2 scheme: `keccak256("sig.network v2.0.0 epsilon derivation:midnight:mainnet:{sender}:{path}")` as a non-biased big-endian scalar. CAIP-2 id `midnight:mainnet` is synthetic (Midnight has no registered CAIP-2 namespace). Key version MUST be ≥ 1 (there is no Midnight v1 legacy; the indexer drops `keyVersion 0` requests).
- `entropy` = `keccak256(requestId)` (Canton precedent).
- Validation before forwarding: `payload` must parse as a secp256k1 scalar (big-endian, 0 < payload ≤ n−1); `keyVersion ≤ LATEST_MPC_KEY_VERSION`; bidirectional `caip2Id` must map to a known target `Chain`. `deposit` is fixed to 1 — Midnight requests carry no deposit; economic spam gating is an acknowledged gap (see the integration plan's trust model).
- Finality gate: events are held until their block height is ≤ the node's `chain_getFinalizedHead` height, checked against the operator's own node RPC.

## Transaction building (bidirectional)

`calldata = keccak256(funcSig_ascii)[0..4] || args[0] || … || args[argCount−1]` — the words are used verbatim (golden-tested against ethers' ABI encoding). The unsigned transaction is EIP-1559: `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList=[]])`; the phase-1 signing payload is its keccak256 (`signingHash` in the goldens).

## Respond semantics

- `respond(requestId, bigRx, bigRy, s, recoveryId)` answers `sign` and phase-1 of `sign_bidirectional`. The MPC publisher submits it; the indexer maps `SGN1:RESP` to a settlement event and the node verifies the signature against the derived key (`verify_entry_signature`). The circuits verify nothing on-chain, matching the Solana/Canton signers.
- `respond_bidirectional(requestId, serializedOutput, outputLen, …sig)` posts the target-chain execution output plus the **phase-2** signature. `requestId` is the original request's id. The phase-2 signing payload is `keccak256(requestId || serializedOutput[..outputLen])`, and the phase-2 key uses the fixed derivation path `midnight response key` with the same sender (contract address).
- Duplicate responded events are legal; consumers skip responds for unknown/settled ids. Failure outputs use the `0xdeadbeef` prefix convention inside `serializedOutput`.
