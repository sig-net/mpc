# `midnight-publisher`: language decision and migration plan

**Date:** 2026-07-23. **Status:** decided, migrated, and redesigned. `chain-signatures/midnight-publisher-ts` is the implementation; the Rust crate is still in the tree pending cutover. §1 to §6 are the decision and the evidence, written before the port; **§7 is what the service actually is now** and supersedes §4's phase plan and the seam shapes in §2.3 and §2.4.
**Scope:** the sidecar only. Nothing here changes the trust plane or any security-critical logic. §7 does move work to `chain-midnight`: every RPC call is now the caller's, and the sidecar's read seams are pure codecs over bytes it is handed.
**Companions:** [`midnight-spec.md`](./midnight-spec.md) §5.5 (what the sidecar is), [`midnight-spec-decisions.md`](./midnight-spec-decisions.md) §B.8/§B.9/§D (why it is shaped that way), [`midnight-sgn2-mpc-tasks.md`](./midnight-sgn2-mpc-tasks.md) (the PR stack this sits inside).

## 0. TL;DR

Rewrite the sidecar in TypeScript. The decisive reason is structural, not preferential: the Compact compiler's only code generation target is JavaScript, so building a circuit call is a JavaScript operation, and a Rust sidecar can only reach it by spawning Node. Midnight's own Rust toolkit does exactly that, and describes itself as an internal tool whose explicit non-users are application developers.

All three seams were reproduced in TypeScript against the live ledger-9 stack and byte-compared against the running Rust binary. `/block`, `/state`, and the state diff all matched byte for byte on live chain data, and a real `postRespondBidirectional` proved and submitted to finality twice.

A full write, build through prove through submit through confirm, was executed with **no GraphQL anywhere in the midnight-js path**, in about 40 lines. The one genuine cost, and it is real: **balancing needs a reachable Midnight indexer endpoint today**, because `WalletFacade` discovers its UTXO and dust state exclusively from the indexer and no node RPC or runtime API returns UTXO state for an address. The Rust toolkit has no such dependency, since it replays blocks from the node to build wallet state. This is an indexer *endpoint*, not necessarily an indexer *container*, it is confined to one layer, and it is the only place the Rust path is genuinely ahead. See §2.5.

Separately, and more urgently than the language question: **state-diff discovery silently depends on the node running `--state-pruning archive`, that dependency is unasserted, unconfigured, and false on every non-dev node preset.** Fix that in the current Rust code now, regardless of when or whether the port happens. See §3.1.

## 1. The decision

### 1.1 Verdict

TypeScript, for the sidecar, keeping the HTTP seam and the trust plane exactly as they are.

### 1.2 The structural argument

`compactc` emits `contract/index.js` plus a `.d.ts`, `zkir/`, and `keys/`. There is no Rust emitter and no language-neutral executable form. Verified against this project's own compiled artifacts in `packages/signet-contract/src/managed/`: `contract/index.js` is 104,652 bytes of executable circuit logic, and `compiler/contract-info.json` carries only signatures and type trees, so a Rust reader cannot recover what a circuit does from it.

The transcripts a proof is built from are produced by running that JavaScript module. `ContractCallPrototype` in `midnight-ledger` at `crate-ledger-9.1.0.0-rc.3` (`ledger/src/construct.rs:494`) demands exactly those transcripts, and `ProofPreimage::construct_proof` derives everything from them. The ledger's own Rust tests hand-write the Impact program with `program_fragments!` macros rather than read compactc output, because there is no way to read it.

So the Rust toolkit shells out. `util/toolkit/src/toolkit_js/mod.rs:405-433` runs `<toolkit-js-path>/dist/bin.js` as a subprocess, and `util/toolkit-js/package.json` describes itself verbatim as the *"Interface gateway between Rust `midnight-node-toolkit` and TS `@midnight-ntwrk` packages"*.

The boundary is therefore precise: **Node owns the step that produces the transcripts and therefore the `ProofPreimage`. Rust owns everything from a finished `ProofPreimage` onward, plus everything on the read side.** A Rust sidecar does not avoid Node, it wraps it, and adds a CLI contract plus a file-based interop layer on top.

Three corroborating signals:

- `util/toolkit/PRD.md` §3 states the toolkit is *"an internal-only tool"* and *"not a Shielded Technologies product"*, and lists under explicit non-users: *"DApp developers. They target midnight-js."*
- The ledger-9 Rust crates are not on crates.io and will not be while prerelease, by documented policy in `midnight-ledger/docs/release-process.md`. Consumption is `[patch.crates-io]` against eleven to thirteen git tags kept as a matched set, which is exactly why this sidecar needs a quarantined nested workspace and a CI firewall job. On the published v8 line, docs.rs reports 1.88% documentation coverage (17 of 903 items).
- `midnight-indexer` is Rust and is the largest third-party-shaped Rust consumer Midnight ships. It has zero references to `ProofPreimage` or `ContractCallPrototype`, against 13 to `ContractState` and 23 to `ContractCall`. In Rust, the ledger crates are a decoding library.

One timing asymmetry worth recording. The ledger-9 blocker in the Rust toolkit (`LEDGER9-TOOLKIT-JS`, every `generate-intent` test `#[ignore]`d at `node-2.0.0-rc.4`) was fixed on `main` by PR #1711, merged 2026-07-10, one day after rc.4 was tagged. No tagged release carries it. The shape of that fix is the most informative fact in the survey: it added a `compact-0.33.0` toolkit-js variant pinning `@midnight-ntwrk/compact-js` 2.5.5-rc.6, `compact-runtime` 0.18.0-rc.1, `@midnightntwrk/ledger-v9` 1.0.0-rc.3, and `onchain-runtime-v4` 4.0.0-rc.3, which is byte-identical to what `@midnight-ntwrk/midnight-js-protocol@5.0.0-beta.4` pins. When Midnight unblocked its own Rust tooling on ledger 9, the fix was to vendor a newer TypeScript stack, not to move logic into Rust. Waiting for `node-2.0.0-rc.5` blocks a Rust sidecar and is a non-event for a TypeScript one.

### 1.3 What we give up, stated fairly

- **A working implementation.** The Rust sidecar exists, passes 18 tests, and is clippy-clean. Rewriting it is churn against tested code. This is the strongest argument against, and the honest counter is that the rewrite's acceptance test is a byte-diff against that same implementation, which has already been demonstrated to pass on all three seams.
- **Single-language homogeneity.** One toolchain, one lockfile discipline, one test harness beside a Rust MPC node. The `RespondRequest` struct duplicated across the HTTP seam could otherwise become a shared crate. Against that: the shipping Rust artifact already bundles Node, toolkit-js, and compactc into its image, so the deployment is already bilingual (spec §5.5, *"Not pure Rust"*).
- **Both lines are prerelease.** npm `latest` tags still point at ledger-8; the ledger-9 packages live on `rc` and `beta`. This is a real discoverability trap and a real churn risk, and it is symmetric with the Rust side rather than better.
- **A reachable indexer endpoint on the write path.** The TypeScript wallet SDK syncs UTXO and dust state only from the indexer; the Rust toolkit replays blocks from the node instead. This is the single place Rust is genuinely ahead, it is unfixable from our side, and §2.5 sets out what it does and does not cost.

## 2. Evidence

### 2.1 How it was tested

Three agents ran against the live local stack: `midnightntwrk/midnight-node:2.0.0-rc.4`, `proof-server:9.0.0-rc.5_experimental`, `indexer-standalone:4.4.0-pre-alpha.16`, with the SGN2 singleton at `aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47` and the reference caller at `dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2`, both deployed on that chain (blocks 1352 and 1358, established by a full scan of blocks 1 to 10240).

Everything below labelled a verdict was executed, not reasoned about. Where a claim rests on source reading rather than execution it says so. The strongest results are byte-diffs against the running `midnight-publisher` binary, computed from the same chain data in the same minute.

All spike code lived in gitignored `scratch-*` directories in `midnight-integration`. No tracked file in either repo was modified.

### 2.2 Write path: prove and submit

**Verdict: worked, twice.** `findDeployedContract(...).callTx.postRespondBidirectional(...)` proved through the proof server and reached finality with status `SucceedEntirely` at blocks 10103 and 10126. The singleton's `respondBidirectionalMap` was empty beforehand, the per-request counter went absent to 1 to 2, and the two appends landed under `count=0` and `count=1`, which is the count-keyed append the contract specifies.

The proof was corroborated four ways rather than assumed from a fast wall-clock: the proof server's own log showing `/prove took 0.317979s`, the key location carrying the deployed verifier-key hash (`?vk=fa5fd5e2...`), the on-wire transaction tag reading `midnight:transaction[v12](signature[v2],proof,pedersen-schnorr[v1])` where an unproven transaction would read `pre-proof`, and a CPU spike to 335% on the proof-server container in exactly the sampling window.

The essential code is about 25 lines: compose the providers, `findDeployedContract`, call the circuit.

### 2.3 Read path: `/block`

**Verdict: worked, byte-identical.** `@polkadot/api` 16.5.6 connected to the rc.4 runtime with **zero custom type definitions**, resolved `midnight.sendMnTransaction`'s argument from on-chain metadata v16, and the extracted ledger transaction bytes were byte-identical to the committed fixture (14405 of 14405 bytes). `@midnightntwrk/ledger-v9` then deserialized it and reached `address`, `entryPoint`, `communicationCommitment`, and the transcripts' `claimedContractCalls`.

The full TypeScript pipeline, emitting the Rust seam's exact JSON shape, was byte-compared against the running Rust binary's `GET /block` for block 1366: **identical, 677 bytes.**

About 90 lines, no build step, no custom SCALE types, no indexer.

### 2.4 Read path: `/state` and the state diff

**Verdict: worked, 4 of 4 byte-identical.** The TypeScript `/state` implementation reproduced the Rust `GET /state` response exactly for both contracts at both blocks (600, 305, 1380, and 671 bytes), each pinned to an explicit `at=` hash. The raw blobs the live RPC returns are additionally byte-identical to the committed test fixtures (4510 and 4990 bytes), so there is no gap between what was decoded and what `block.rs::state_diff_yields_the_notify` asserts on.

The diff reproduced all three of that test's assertions from live reads with no fixtures involved: exactly two writes, the per-request counter initialised to `01`, and the notification carrying version 1, the caller address, and field `04`.

The walker is 30 lines and is a near-mechanical transcription of `state.rs`. It has none of `/block`'s traps: no marker triple, no `Fr` tag byte, no name-versus-hash asymmetry, no SCALE framing. `ContractState.deserialize` takes no marker arguments at all.

This seam is where TypeScript is furthest ahead operationally. The Rust implementation spawns three `curl` subprocesses per `/state` request, and `service.rs` concedes that this is *"un-consolidated rather than justified"*. The TypeScript version makes two typed `api.rpc.chain.*` calls plus one typed `provider.send<string>` over the connection it already holds.

### 2.5 Deployment: the indexer question, answered in two halves

Spec §5.5 deploys `mpc-node`, `midnight-publisher`, and the proof server, and explicitly does not run the Midnight indexer. midnight-js's contract lifecycle wants a `PublicDataProvider`, and the only shipped implementation of that interface is the indexer-backed one (verified four ways, including an org-wide code search across `midnightntwrk`). So the question was whether choosing TypeScript adds a fourth container.

**Read path: no indexer, proven by execution.** `findDeployedContract` touches exactly **three of the interface's thirteen methods**: `watchForDeployTxData`, `queryDeployContractState`, `queryContractState`. No subscriptions, no observables, no event queries. A roughly 120-line node-RPC-backed provider satisfied all three, and `findDeployedContract` ran with **no indexer in the picture** in 0.10 s using 36 node RPC calls. Every value both providers hand to midnight-js was byte-compared and all matched, including the full serialized deploy transaction, `blockHeight` 1352, and both `ContractState` blobs. The verifier-key join succeeding is the real proof, since it confirms the state the node-backed provider returned is the genuine on-chain state matching the compiled keys. The deploy height is found by binary search on the `ContractNotPresent` boundary, so it costs O(log n) rather than a block scan.

**Write path: `PublicDataProvider` is not the blocker, the wallet is.**

The write path touches three additional methods, established by instrumenting a real `callTx`: `queryBlock`, `queryZSwapAndContractState(addr, {blockHash})`, and `watchForTxData(txId)`. All three are node-servable:

- `queryBlock` is `chain_getFinalizedHead` plus `chain_getHeader`. `BlockInfo` is only `{hash, height}`.
- `queryZSwapAndContractState` is **three runtime-API calls at one pinned block hash**, executed and verified: `getZswapChainState` (1585 bytes), `getContractState` (9137 bytes, byte-identical to the `midnight_contractState` JSON-RPC result at the same block), and `getLedgerParameters` (791 bytes), each deserializing cleanly. Pinning via `api.at(hash)` also satisfies the method's documented consistency requirement by construction.
- `watchForTxData` is a backward block walk matching `tx.identifiers()`. Two honest caveats: the ledger apply result has no node RPC, so `status` must be inferred from inclusion, which is sound for a guaranteed-phase-only contract because a guaranteed-phase failure is rejected at pre-dispatch and never included (§2.6); and `FinalizedTxData` carries indexer-shaped fields (`indexerId`, `fees`, `segmentStatusMap`, `unshielded`) with no node equivalent, though midnight-js reads only `status` on this path.

There is a trap here worth recording permanently: the `midnight_*` **JSON-RPC** namespace has only five methods and serves neither the zswap chain state nor the ledger parameters. `MidnightRuntimeApi` at `#[api_version(5)]` (`pallets/midnight/src/runtime_api.rs`) declares **ten**, including all three needed above, and runtime APIs are reached through `state_call` and never appear in `rpc_methods`. Two separate investigations in this exercise concluded "the node cannot serve it" from an `rpc_methods` enumeration, and both were wrong. **`rpc_methods` understates a Substrate node's read surface by half.**

Live ledger parameters are genuinely load-bearing, established by isolation against the real indexer tuple with exactly one element swapped: substituting `LedgerParameters.initialParameters()` gets the transaction rejected with `Transcript(Execution(OutOfGas))`, because fee and price adjustment drift per block. Substituting an empty `ZswapChainState` succeeded, but this chain's live zswap state is itself empty (`firstFree=0`), so that result does not generalise to a chain with shielded activity. Treat the zswap substitution as promising and unproven; the runtime API serves the real value anyway.

**A full no-indexer post was then executed end to end, and it succeeded.** Taking the escape-hatch route rather than building a provider stub: three runtime-API reads at a pinned block (0.00 s), `createUnprovenCallTxFromInitialStates` (0.04 s, taking no `PublicDataProvider` at all), the published `httpClientProofProvider` (0.36 s), `balanceTx` through the wallet facade (0.45 s), submission over node RPC through the facade (17.67 s), and confirmation by a runtime-API contract-state read rather than `watchForTxData`. The singleton's map went from 22 to 23 entries with the expected payload. **No GraphQL was involved in any part of the midnight-js path.** The whole thing is about 40 lines, and the four data dependencies it wants (`coinPublicKey`, `initialContractState`, `initialZswapChainState`, `ledgerParameters`) map exactly onto three runtime-API calls plus the wallet's coin public key. That is the entire read surface of a write.

**The single remaining dependency is the wallet, and it sits outside `PublicDataProvider` entirely.** `WalletFacade.init` takes `indexerClientConnection: { indexerHttpUrl, indexerWsUrl }` as required configuration, and the shielded, unshielded, and dust sub-wallets discover their UTXOs through it. Pointed at a dead port with node RPC left intact, the facade loops on `Wallet.Sync` and never syncs within 25 s, so there is no coin selection, no dust, and no fee payment. Submission was never the problem; balancing is.

The node has no equivalent, established by enumerating every runtime API namespace on the chain: `midnightRuntimeApi` (ten methods), `c2mBridgeApi`, `tokenBridgeIDPRuntimeApi`, and `systemParametersApi`. None returns UTXO or dust state for an address, and `getUnclaimedAmount` is block rewards rather than UTXOs. Dropping to raw `ledger-v9` does not help: `createUnprovenCallTxFromInitialStates` already does that job in one call, `partitionTranscripts(calls, params)` needs the same `LedgerParameters` the runtime API now supplies, and nothing at that layer supplies UTXO state either.

**The Rust path does not have this dependency.** `midnight-node-toolkit` has no indexer or GraphQL dependency at all, and builds wallet state by replaying transactions fetched from `--src-url` through `build_fork_aware_context_cached`, cached in `MN_FETCH_CACHE`. This is the one place in the whole comparison where Rust is genuinely ahead, and it should be weighed honestly rather than explained away.

**The distinction that keeps the spec intact:** what TypeScript requires is an indexer **endpoint**, not an indexer **container**. "We do not run the indexer" and "we do not use an indexer" are different claims, and only the first survives. If the deployment can reach an external indexer URL alongside the external node RPC, the container count §5.5 states is unchanged and the indexer joins the node as an external dependency. If reaching one is unacceptable, that is a genuine argument for keeping the write path in Rust, and §5.4's RPC trust discussion would need to cover the indexer too.

**Security impact: integrity is unaffected; availability and disclosure are not.** The indexer feeds exactly one thing, the funding wallet's UTXO and dust discovery so `balanceTx` can pay a fee. It is downstream of every security decision and absent from the discovery pipeline entirely.

- **Trust plane holds (§5.5, decisions §D).** The signature is computed by the MPC threshold before anything reaches the publisher; `POST /respond` carries an already-computed signature and the publisher only encodes it into circuit args. The indexer never touches the request, the rid, the epsilon, or the signature.
- **The proof ladder is untouched (§5.4).** All four rungs verify discovery inputs (block body at H, contract state at H, CCC provenance, finality of H). The wallet is on the write path and none of those inputs pass through it, so the ladder's in-place property is preserved.
- **Every hostile-indexer path terminates in silence, never in a wrong response.** Fabricated UTXOs are rejected by the node because the chain validates against real state; stale ones the same; withholding stops balancing. It cannot induce a spend (spending needs wallet keys it never sees) and cannot influence outputs (those come from the intent and from change addresses derived locally from the seed). This is the failure mode §5.4 already contemplates for the RPC, *"a compromised node can forge nothing, only go silent"*, with a second component now able to cause silence.
- **New: availability surface.** Responses depend on two external endpoints rather than one. §5.4's completeness residual gains a sibling: node withholding presents as head staleness, indexer unavailability presents as inability to post. Different alarms.
- **New: disclosure.** A third-party indexer learns which addresses the funding wallet uses and its activity pattern, and shielded state needs a viewing key. Self-hosting removes this entirely, and reading from several endpoints removes the single point of silence. Both are operator choices, and neither involves client wallets, which never touch this path.
- **Bounded griefing.** A persistently malicious indexer could degrade coin selection and fragment the funding wallet. Bounded by that wallet's balance and requiring active malice, and §7 already treats the funding wallet as the publisher's one asset.

**Two documentation follow-ups.** §5.4's trust argument currently covers one endpoint (trust-your-RPC, protected by threshold independence, plus the hygiene rule against pointing the whole signing threshold at one endpoint). That argument extends to the indexer unchanged and should say so, hygiene rule included. §7 should gain an invariant: the indexer influences fee payment only, never request validity or response content, so a lying indexer is a liveness and disclosure concern and never an integrity one.

Two ways out of the dependency itself, in ascending cost. **Reach an indexer endpoint**, self-hosted or several for redundancy, which only the wallet points at and only for UTXO discovery: cheapest by far, and the chosen path here. Or **write a node-RPC UTXO scanner** for the wallet: follow finalized blocks, decode each Midnight transaction (`getDecodedTransaction` on the runtime API may help), and maintain the unshielded and dust UTXO set locally. That is a real component with block following, reorg handling, and dust generation tracking, several hundred lines plus ongoing correctness risk, and it reimplements what the indexer exists to do. The upstream ask that would remove the choice is a node-side UTXO and dust query for an address, or a wallet-sdk sync backend built on the runtime API. Everything else the write path needs already exists.

### 2.6 Concurrency and statelessness

Both were measured because both had been asserted without evidence.

**Proving is not the bottleneck.** Under three concurrent posts the proof server never returned `429` or `JobQueueFull`, its p50 was 0.402 s against 0.318 to 0.446 s single-threaded, and its memory delta was +2.5 to +3.2 MiB. Client RSS with three concurrent calls and three full wallet facades in one process was 608 MiB, essentially flat against the 598 MiB single-call figure.

**Three real serialization points were found, each hidden behind the previous:**

1. **LevelDB** holds a single exclusive handle, so concurrent scoped transactions fail with `Database failed to open`. Removed entirely by an in-memory private-state provider.
2. **One dust UTXO per wallet.** The misleading `Wallet.InsufficientFunds: could not balance dust` fires despite a large balance, because the mechanism is coin count, and every wallet on this chain has exactly one. One spendable dust UTXO means one in-flight fee-paying transaction per wallet, so concurrency needs one wallet per worker.
3. **Ledger-level optimistic concurrency.** A call's transcript pins the cells it read. Three posts under the same request id all read the counter at 6; the winner makes it 7 and the losers get `Transcript(Execution(ReadMismatch { expected: <[06]>, actual: <[07]> }))` from the node log. For a shared request id this is inherent and not fixable. Naive retry **livelocks**: lockstep retries with no jitter re-collide, and both losers burned all five attempts while the winner succeeded on its first.

With distinct request ids, which is the real MPC workload, **three posts landed in a single block across three consecutive rounds, at a total wall-clock equal to one post (about 20 s) against about 60 s sequential.** Losers are rejected at pre-dispatch in the guaranteed phase, so they are never included in a block and never charged a fee, which makes retry free and safe.

**Statelessness is free.** A roughly 30-line Map-backed private-state provider works and creates no directory on disk, verified empirically by running from an empty working directory and confirming it stayed empty. A private-state provider is required unconditionally, but only so `findDeployedContract` can set or fetch a contract-maintenance signing key, which for this singleton is inert since it was deployed with `Option.none()` for the maintenance authority. With a strict provider that throws on any access and no `privateStateId` passed, both `findDeployedContract` and `callTx` succeeded end to end, so neither path touches private state for a witness-less contract. Two instances can run side by side given distinct wallets.

Watch item: the proof server's baseline crept from 732 MiB to 803 MiB over about 95 proves. Plausibly allocator retention rather than a leak, but a long-lived sidecar should monitor it.

### 2.7 Corrections made during the investigation

Recorded because the failure modes are instructive, and because two of the three had to be corrected against agents that had produced otherwise rigorous work.

- **The 11.5 GiB proving figure is from a superseded configuration.** Spec §5.5 now mandates the proof server for these contracts, because they are compiled with `--feature-zkir-v3` and the ledger the toolkit links pins `midnight-zkir` 2.2.0, which accepts only `ir-source[v2]`, so local proving aborts outright. The Rust sidecar already implements this: `service.rs` carries a `proof_server` config (`MIDNIGHT_PUB_PROOF_SERVER_URL`) and passes `--proof-server` to `send-intent`. Both languages therefore offload proving, and the memory comparison is roughly neutral, not the 20x it appeared to be against the old local-prover configuration. Two consequences: any claim of a large memory win for TypeScript should be dropped, and `service.rs:712`'s *"Sequential by design: respond proving peaks ~11.5 GiB RSS"* is now a stale rationale for a real constraint (see §3.3).
- **The published `httpClientProofProvider` works.** It was initially reported as broken against ledger-v9 1.0.0-rc.3, requiring the repo-private `createCrossContractProofServerProvider` shim. That was wrong. The real history: `lookupKey` was present at beta.1 and beta.2, **dropped at beta.3**, and restored at beta.4. The shim's comment names 5.0.0-beta.3 by version and was accurate on the day it was written; the workspace has since moved to beta.4 and nobody removed the shim. The false negative came from two command errors, a zsh `nomatch` abort that meant grep never ran and a `head -20` truncation that cut the output before the matching line, on top of which an expensive-looking blob-SHA comparison made a wrong conclusion look well-evidenced.
- **`midnight-js` git tags are a reliable proxy for what npm ships.** Proposed as an explanation for the above and disproven: the `v5.0.0-beta.4` source tree and the published beta.4 bundle agree.
- **`queryZSwapAndContractState` is servable from the node**, and so are the live ledger parameters. Both were initially marked unavailable, independently, by two investigations reasoning from the five-method `midnight_*` JSON-RPC namespace. The runtime API is a different surface that `rpc_methods` does not list, and executing the calls settled it. The generalisable lesson is in §5: an `rpc_methods` enumeration is not a capability audit.
- **The write path does need an indexer, but not for the reason first proposed.** The first read of it named `LedgerParameters` as an unservable input; that was the `rpc_methods` error above. The real dependency is the wallet SDK's sync backend, which sits outside `PublicDataProvider` entirely and is unfixable by any adapter. See §2.5.

## 3. Findings that are independent of the language

These apply to the current Rust implementation exactly as much as to any TypeScript successor. **Fix them before, or independently of, any migration.**

### 3.1 The state-pruning dependency is unasserted, unconfigured, and false off dev [P0]

State-diff discovery (spec §5.1 step 3) is sound only while state at block N and block N-1 are both retrievable. Nothing in `service.rs` or `block.rs` asserts that, and nothing in `docker-compose.yaml` configures it.

It works on the local stack for exactly one reason: `res/cfg/dev.toml:26-27` sets `--state-pruning archive` and `--blocks-pruning archive`, and the container selects it via `CFG_PRESET=dev`. This is invisible to `docker inspect`, which reports `Cmd: null` and `Args: []`, because the node binary injects the preset's flags itself.

**`dev.toml` is the only shipped preset that sets it.** `default`, `devnet`, `govnet`, `guardnet`, `mainnet`, `perfnet`, `preprod`, `preview`, `qanet`, and `stagenet` all omit it and therefore inherit Substrate's documented `[default: 256]`, roughly 25 minutes at 6 second blocks. This project already targets stagenet, so this is the works-in-dev-breaks-in-production case, confirmed from source rather than suspected.

The failure is also hard to diagnose, because the two conditions are indistinguishable by error code:

```
pruned or unavailable state:  {"code":-32602,"message":"Unable to get requested contract state"}
contract did not exist yet:   {"code":-32602,"message":"Contract not present at the requested address"}
```

Both are `-32602` with no `data` field. In `pallets/midnight/rpc/src/lib.rs`, `get_api_version` must resolve the runtime at that block and therefore needs its state, so a pruned block fails there and maps to `UnableToGetContractState` before the contract is ever looked up, and every variant collapses to `INVALID_PARAMS_CODE`. Only the message discriminates, and messages are `Display` impls with no stability contract. `"Unable to get requested contract state"` is a catch-all that also covers an unknown block hash and any other `LedgerApiError`, so it must be read as "I could not answer" and escalated, never as proof of pruning.

There is one clean lever. `ContractNotPresent` can only be produced by the runtime API **after it successfully ran at that block**, so receiving it is positive evidence that state at that height was reachable.

**Actions:**

1. Pin the flags explicitly in `docker-compose.yaml` so they appear in `Cmd` and survive an image or preset change: `command: ['--state-pruning', 'archive', '--blocks-pruning', 'archive']`. Do the same in every non-dev deployment and in the ops runbook. Note Substrate's own constraint: the mode can only be set at database creation, so adding the flag to an existing pruned database does not restore lost state and will error on mismatch.
2. Add a sidecar startup assertion that refuses to start on a non-archive node. It needs no deployed contract and no configuration, because `ContractNotPresent` is the success case for the question: take the finalized head `H`, compute `T = max(1, H - WINDOW)` for a `WINDOW` well outside 256 and matched to the deepest reachback the sidecar could need, fetch `chain_getBlockHash(T)`, and call `midnight_contractState(<any well-formed 64-hex address>, hash)`. A hex result or `"Contract not present at the requested address"` both mean state at `T` is present. Anything else, refuse to start with a specific message naming the height.
3. Guard the runtime path: a `"Unable to get requested contract state"` on a block whose header is still fetchable is the pruning signature. Raise a distinct, loud error there. Never fold it into a generic fetch failure and never conflate it with `ContractNotPresent`.
4. Record the requirement in spec §5.4's RPC capability constraint alongside `archive-canonical` bodies.

### 3.2 Spec §5.1's catch-up conditions contradict the state-diff refactor

The catch-up bullets still read *"State pruning is separate: `--state-pruning` (default 256 blocks) limits historical state reads, not bodies, so it never affects the walk"*, and still refer to "the step-5 anchored read" where the anchored read is now step 6. That was true when discovery read writes out of transcripts, because bodies are retained by default. It is false now: step 3 makes an anchored state read per walked block, so catch-up deeper than the pruning window fails.

Either mandate `--state-pruning archive` as a hard RPC capability requirement, or define an explicit fallback for deep catch-up, for example walking the singleton's count-keyed maps at the head using §5.2's reader instead of diffing per block. The second is the state polling §5.1 rejects for live discovery, but as a bounded recovery path it may be acceptable. This should be a stated decision either way.

### 3.3 `service.rs` carries a stale rationale for a real constraint

`service.rs:712` justifies the sequential request loop with *"respond proving peaks ~11.5 GiB RSS"*, and the header comment at `service.rs:12-13` justifies the subprocess design partly on the same ground (*"as a child process an OOM kills the prover and this service answers 502"*). With proving offloaded to the proof server in that same file, neither is the live reason any more. The sequential loop may still be correct, but for different reasons: the ledger-level OCC and one-dust-UTXO constraints in §2.6. Update the comments so the next reader does not inherit a superseded model, and reconsider whether the loop should stay sequential.

### 3.4 The dependency firewall: the stated reason is false, the real reason is different [tested 2026-07-23]

The firewall is justified throughout this repo by "`chain-signatures/node` pins subxt 0.44, so the ledger crates cannot share a lockfile" (`.github/workflows/midnight-publisher.yml`, `midnight-publisher/Cargo.toml`, spec §5.5). **That is not how cargo works and it is not true.** Tested by adding `midnight-node-ledger-helpers` plus the 11-entry patch set to a probe crate in a worktree of this workspace:

```
RESOLUTION: SUCCEEDED   subxt 0.44.3 and 0.50.2 in one graph
COMPILE:    exit 0      the full decode surface builds beside subxt 0.44 (8m 44s)
subxt   0.44.0  ->  0.44.0, 0.50.2   (in the real workspace lockfile)
```

Semver-incompatible versions coexist by design; cargo links both. Cargo also placed three ledger generations (v7, v8, v9) side by side without complaint. Note also that `midnight-node-ledger-helpers` at rev `3dc40f22` *does* depend on subxt 0.50 directly, unlike at tag `node-2.0.0-rc.4`.

**The real reason to keep the firewall, which nobody had articulated:** moving the ledger crates into the main workspace makes the whole repo carry the Midnight ledger's dependency tree. Measured cost, from a resolution that succeeds:

- **80 new packages**, including the ZK tree (`halo2derive`, `blake2b_halo2`, `blst`) and native crypto (`aws-lc-rs`, `aws-lc-sys`, requiring `cmake` on every build machine).
- **60 changed version entries**, mostly benign patch drift, but including `shlex` 1.3.0 → 2.0.1 (a major bump) and `tokio` 1.45.1 → 1.53.1 (eight minors on the node's async runtime).
- **A repo-wide toolchain bump**: 87 crates in that graph are edition 2024, so `1.81.0` → `1.96.0` across 9 lines in 6 workflows. There is no `rust-toolchain.toml`; the pin lives only in CI.
- Roughly nine minutes on a cold build, borne by every developer and CI runner, not just Midnight work.

The command that resolves it, for whoever revisits this:

```
cargo update -p bip39 -p derive-where -p async-trait -p futures -p rayon \
  -p parking_lot@0.12.3 -p anyhow -p log -p tokio -p scale-encode \
  -p hashbrown@0.16.0 -p rand@0.9.1 -p const-hex -p blst -p flate2
```

Every conflict it resolves is an old patch pin against a requirement the workspace already permits (`bip39` 2.2.0 needs ^2.2.2, `anyhow` 1.0.98 needs ^1.0.102, `async-trait` 0.1.88 needs ^0.1.89); almost all trace to `integration-tests`, the member with the loosest requirements and the stalest pins.

**Decision (2026-07-23): keep the publisher.** The read seams stay behind the HTTP boundary. Revisit if the workspace ever needs the ledger crates for another reason, or if the toolchain bump happens anyway. The value of this test is that the firewall is now a measured tradeoff rather than an inherited assumption, and the wrong justification should stop being repeated.

### 3.5 The lockfile cannot be refreshed at all [P1, unrelated to Midnight]

`core2 0.4.0` is yanked from crates.io and is reachable via `chain-ethereum` → the pinned `helios` git rev → `libp2p 0.51.3` → `multiaddr` → `multihash 0.17`. Consequences, both verified:

- `cargo update` (no arguments) **fails**.
- Deleting `Cargo.lock` and resolving from scratch **fails**.

Builds from the committed lock still work, so nothing is visibly broken, but no dependency in the workspace can be updated by the normal command, including for a security advisory, and a clone that loses its lockfile cannot recover. The fix is to move `helios` to a rev with a newer libp2p. This deserves its own issue.

## 4. Migration plan

### 4.1 Principles

- **The HTTP seam is frozen and is the abstraction boundary.** `chain-midnight` talks HTTP to the sidecar and never learns what language is behind it. Every response schema stays byte-identical. This is what makes the migration self-contained and reversible.
- **Differential testing against the Rust binary is the acceptance criterion.** For each seam, run both implementations against the same live node at the same pinned block and require byte-identical output. This has already been demonstrated for all three seams, so it is a known-passable gate rather than an aspiration.
- **The trust plane does not move.** The sidecar stays mechanism, never authority (spec §5.5, decisions §D). Every security decision, the rid recompute, epsilon derivation, and signature handling, stays in `chain-midnight` in Rust over raw bytes. There will be a temptation to pull the reader and the rid twin into the TypeScript sidecar because `@sig-net/midnight` already implements them in TypeScript. **Do not.** That would collapse the boundary that makes a sidecar decode bug a dropped request rather than a wrong signature.
- **Stay in place.** The sidecar remains one self-contained folder at `chain-signatures/midnight-publisher/`, now a TypeScript package with its own `package.json`, lockfile, `Dockerfile`, and tests. This preserves spec §5.5's self-containment property and the deployment story. The root `Dockerfile` is already multi-stage and multi-language, so this is precedented.
- **Sequence by risk, ascending.** `/state` is the smallest and trap-free, `/block` is next, `/respond` is the one that touches wallets, proving, and fees.

### 4.2 Phase 0: fix the production findings (do this now, independent of everything else)

Scope: §3.1 actions 1 to 4, plus §3.2 and §3.3.

Acceptance: the sidecar refuses to start against a node whose state at head minus WINDOW is unreadable; a pruned-state read produces a distinct error from a contract-absent read; `docker-compose.yaml` shows the pruning flags in `Cmd`; spec §5.1 and §5.4 state the archive requirement.

This is worth doing in Rust today. It is small, it is a production defect, and it must be carried into the TypeScript implementation anyway.

### 4.3 Phase 1: scaffold

Scope: a TypeScript package at `chain-signatures/midnight-publisher/` with `GET /health`, the config surface (the same `MIDNIGHT_PUB_*` variables, including the loopback bind refusal and the required-never-defaulted secrets), structured logging with the same secret redaction, and its own `Dockerfile`. No seam logic yet. Keep the Rust crate in place and running.

Acceptance: `/health` responds; a non-loopback bind is refused without the explicit opt-in; the required env vars fail startup when absent; the image builds.

### 4.4 Phase 2: `/state`

Scope: port `state.rs`'s walker (30 lines) and the three-RPC drive. Replace the `curl` subprocesses with typed `@polkadot/api` calls plus `provider.send<string>('midnight_contractState', ...)`. Include the Phase 0 startup assertion here since this is the seam that needs it.

Acceptance: byte-identical `{anchor, tree}` against the Rust binary for both contracts at a pinned `at=` hash and at the finalized head; the map-entries-sorted-by-key-hex and trailing-zero-trimmed-atoms rules pinned by test; `state_diff_yields_the_notify`'s three assertions reproduced from live reads.

### 4.5 Phase 3: `/block`

Scope: port `block.rs`. Fetch via `@polkadot/api` (`chain_getBlockHash`, `chain_getBlock`, filter `midnight.sendMnTransaction`, `args[0].toU8a(true)`), decode via `ledger-v9`, walk `intents.values() → actions → instanceof ContractCall`, and emit the same `{transactions, skipped}` shape with the same per-transaction survivability.

Acceptance: byte-identical `GET /block` against the Rust binary for block 1366; an undecodable transaction still costs only itself and is reported in `skipped`; the `Fr` tag strip and the "found at least one blob" check both pinned by test, since both fail silently otherwise (§5).

### 4.6 Phase 4: `/respond`

Scope: the write path. Wire the wallet facade, `httpClientProofProvider` against the proof server, `NodeZkConfigProvider` over `managed/`, and an in-memory private-state provider. Keep the `RespondRequest` JSON contract and its validation rules byte-identical, including the fixture that pins it against `mpc_chain_midnight`'s side.

Prefer the escape-hatch route, which is what was actually executed: assemble `createCallTxOptions(...)`, spread the four data dependencies from three runtime-API calls plus the coin public key, and call `createUnprovenCallTxFromInitialStates` with `crossContract` omitted. That skips `findDeployedContract`, `PublicDataProvider`, and `watchForTxData` entirely, and is about 40 lines rather than the roughly 150-line provider adapter. Confirm by reading the contract state back over the runtime API. Note what it gives up: `findDeployedContract`'s `verifyContractState` check, so a stale `managed/` directory produces a chain-rejected proof rather than a clear client-side error. Reproduce that check explicitly, since `queryContractState` and the verifier-key comparison are both available.

**Settle the indexer question before scoping this phase**, because it decides the deployment story rather than the code. Everything except balancing has been proven indexer-free. The wallet is not solved and cannot be from our side (§2.5). Decide explicitly whether the deployment may reach an external indexer endpoint. If yes, wire the facade to it and proceed. If no, this phase does not close on the shipped wallet SDK, and either the write path stays in Rust while the read seams move, which the frozen seam makes a clean split, or someone signs up for the node-RPC UTXO scanner.

Note what disappears here: the toolkit CLI, `signer.config.ts`, the JSON5 argv codec and its arity and number-versus-string hazards (spec §5.5's circuit-arg codec section), the `.run/` file choreography, the private-state file copying, the `--toolkit-js-path` and `COMPACTC_VERSION` variant matching, and the docker intent mode. The circuit is called as a typed generated function, so the argument-shape bug class becomes a compile error.

Acceptance: a real `postRespondBidirectional` proves and submits to `SucceedEntirely` against the local stack, the append lands in `respondBidirectionalMap`, and the same `RespondRequest` JSON that the Rust binary accepts is accepted here with identical validation outcomes on the full negative-case set.

### 4.7 Phase 5: operational hardening

Scope: apply §2.6's findings. One wallet per concurrent worker; a per-request-id queue, since same-id posts serialize by construction; retry with backoff **and jitter** on `TransactionInvalidError`, which is free because losers are rejected pre-dispatch and uncharged; in-memory private state so there is no writable volume and no exclusive handle; and monitoring on the proof server's resident set.

Acceptance: N concurrent posts under distinct request ids land in one block; a same-id burst serializes without livelock; the service runs from a read-only filesystem; two instances run side by side with distinct wallets.

### 4.8 Phase 6: cutover

Scope: point `chain-midnight`'s `MidnightClient` at the TypeScript sidecar, run both in parallel against the same node for a soak period with responses diffed, then delete `chain-signatures/midnight-publisher/`'s Rust tree, its nested workspace, its `Cargo.lock`, and the `[patch.crates-io]` block.

Decide explicitly what happens to `.github/workflows/midnight-publisher.yml`. The `build-test` job is replaced by the TypeScript equivalent. The `dependency-firewall` job becomes trivially satisfiable, but it is cheap and still guards against someone reintroducing midnight or polkadot-sdk crates into the main workspace, so keeping it as a regression guard is defensible. State the choice rather than letting it happen.

Acceptance: the main workspace has no midnight or polkadot-sdk crates and no `midnightntwrk` git sources; CI is green; a full e2e signs and responds through the new sidecar.

### 4.9 Sequencing against the PR stack

`chain-midnight` does not exist yet, so PR-2 through PR-5 of `midnight-sgn2-mpc-tasks.md` are unstarted and none of them depends on the sidecar's language, only on its HTTP seam. That means the port can run in parallel with PR-2 and PR-3 rather than blocking them, and PR-4's write path can target either implementation.

The scheduling risk is the Sept 1 freeze with a target merge around Aug 18. If the port cannot be finished and soaked inside that window, the correct call is to ship PR-1's Rust sidecar as-is with Phase 0 applied, and port after the freeze. Phase 0 is required either way, and the byte-identical seam means the port is not more expensive later than it is now.

## 5. Implementation gotchas

Each of these cost real time to find. Most fail silently.

**`Fr` values carry a leading tag byte.** `communicationCommitment` is typed as a plain `string` and the claimed-call commitment as `Uint8Array`, and both arrive 33 bytes where Rust gives 32. The extra leading byte is `0x73`, constant, verified across the fixture's commitments, eight freshly generated ones, and `communicationCommitmentRandomness()`. Strip it and the remaining 32 bytes equal Rust's `Fr::as_le_bytes()` in the same order, so **endianness is a non-issue**. Nothing in the `.d.ts` hints at it. Pin the strip with a named constant and a test, because comparing against a toolkit-produced hex otherwise yields a confusing one-byte mismatch rather than an error.

**`PublicDataProvider` spans two different WASM packages.** `queryContractState` must return **`onchain-runtime-v4`**'s `ContractState`, while `FinalizedTxData.tx` must be **`ledger-v9`**'s `Transaction`. Two separate `.wasm` modules each export a class named `ContractState`, and handing over the wrong one produces the classic dual-instance "expected instance of" failure. Scope convention: `@midnightntwrk` without the dash is the WASM layer, `@midnight-ntwrk` with the dash is the JS layer.

**`Transaction.deserialize` takes stringly-typed markers.** For the tag `midnight:transaction[v12](signature[v2],proof,pedersen-schnorr[v1])` the triple is `('signature', 'proof', 'binding')`, where `pedersen-schnorr` maps to `'binding'` by elimination rather than by name. Feed it the bytes with the ASCII tag still attached; stripping it fails. A wrong-but-valid marker prints the expected versus actual header tag, so you can read the right triple off the failure. A typo'd marker instead surfaces as `Invalid signature value.` and points at the data.

**`ContractCall.entryPoint` is the human-readable name; the claimed-call tuple's entry point is its hash.** They cannot be compared directly. `entryPointHash()` bridges them.

**`intents` is keyed by segment id and includes empty segments.** Block 1366's transaction has segment 1 empty and segment 28102 carrying both calls. Iterate values, never index.

**`@polkadot/api` camelCases the call.** The runtime declares `send_mn_transaction`; the API exposes `sendMnTransaction`. Matching the snake_case name returns zero results with no error. Assert that at least one blob was found.

**`api.rpc.provider` does not exist in `@polkadot/api` 16.** Keep your own `WsProvider` reference to reach undecorated RPCs such as `midnight_contractState`. The obvious spelling fails at runtime with `Cannot read properties of undefined`, not at compile time.

**Runtime APIs are not in `rpc_methods`.** The `midnight_*` JSON-RPC namespace is five methods; `api.call.midnightRuntimeApi` exposes ten, including `getZswapChainState`, `getLedgerParameters`, `getTransactionCost`, and `getDecodedTransaction`. They are reached through `state_call` and never appear in an `rpc_methods` listing. Two separate investigations here concluded "the node cannot serve it" from that listing and both were wrong.

**Runtime-API address arguments must be `0x`-prefixed hex strings, not `Uint8Array`.** The Rust signature is `Vec<u8>`, and `@polkadot/api` treats a `Uint8Array` as already SCALE-encoded, compact-decoding its head as a length. Passing the raw bytes fails with `createType(Bytes):: Bytes length 816158570 exceeds 10485760`, an error that names a length rather than an encoding. Returns are `Result<Vec<u8>, LedgerApiError>`, so unwrap with `.isOk` / `.asOk`. The payloads are self-describing tagged ledger blobs, which makes them easy to sanity-check: `midnight:ledger-parameters[v8]`, `midnight:contract-state[v8]`, `midnight:zswap-ledger-state[v5]`. If the leading ASCII does not read like that, the argument encoding is wrong, not the deserializer.

**One method's return value mixes both WASM instances.** `queryZSwapAndContractState` returns `[ZswapChainState, ContractState, LedgerParameters]` where the middle element is `onchain-runtime-v4`'s and the outer two are `ledger-v9`'s. The tuple looks homogeneous, so importing all three from `/ledger` is the natural instinct and produces the wrong `ContractState` class. Always import from the entry point the interface itself names.

**Two `@polkadot/api` warnings on connect, one worth understanding.** The unknown-signed-extensions warning (`AuthorizeCall`, `CheckCallFilter`, `CheckThrottle`) has teeth only for *signed* extrinsics, and `midnight.sendMnTransaction` is submitted **unsigned** (extrinsic v4 where the block's others are v5), so there is no `extra` to mis-frame. Worth a regression check if that pallet ever accepts signed submissions. The not-decorated-RPC warning costs only typed helpers.

**JSON key order is load-bearing for a byte-diff.** Rust's `#[serde(tag = "kind")]` emits `kind` first; JS object literals preserve insertion order through `JSON.stringify`, so writing them in the same order matches by construction rather than by enforcement. Comment it.

**A zero atom is the empty array, not `[0x00]`.** The WASM enforces the trailing-zero-trim rule at construction and the error is opaque: `value deserialized as aligned failed alignment check`.

**The 15-element array cap is enforced by the ledger, not the compiler.** `StateValue.arrayPush` refuses element 16 with `Push would cause array to exceed 15 elements`, which is the concrete reason compactc buckets ledger fields past 15 into a chunk tree.

**npm `latest` is the ledger-8 line.** The ledger-9 packages live on the `beta` and `rc` tags. Following `latest` lands on the wrong ledger with no error.

## 6. Open items

- **Nothing consumes the new seam yet.** §7 moved every RPC call to the caller, and the caller does not exist on this branch: there is no `chain-signatures/chain-midnight`. The Rust side still has to unwrap block bodies with subxt (proven possible, §7.1), do the two state reads the decode seams now expect to be handed, and assert `GET /health`'s ledger tags at startup. Until that lands the Rust crate stays in the tree and the cutover in §4.8 is unfinished.
- **Whether the deployment may reach an external indexer endpoint.** This is a decision, not a discovery, and it is the only thing that changes the migration's shape (§2.5, §4.6). Worth raising with whoever owns spec §5.5 and §5.4's trust discussion.
- **The empty-zswap caveat.** Substituting an empty `ZswapChainState` succeeded, but only on a chain whose live zswap state is itself empty (`firstFree=0`). Untested against shielded activity. The runtime API serves the real value, so this only matters if someone tries to shortcut it.
- **A node-RPC wallet sync backend does not exist.** Worth raising upstream with the Midnight team; it is the one addition that would remove the endpoint dependency entirely.
- **Cross-contract proving was read, not executed.** `httpClientProofProvider(url, new ZKConfigRegistry([callerZk, calleeZk]))` was exercised with a single-element registry only; a true two-contract call was blocked by the stale install of `@midnight-protocol/test-caller-contract` in `midnight-integration`.
- **No pruned node was ever exercised.** The pruned-read error sample in §3.1 came from an unknown-block-hash path that reaches the identical `StateRpcError` variant. The source reading establishes that a pruned block lands on the same variant; the sample shows what that variant looks like on the wire.
- **Chunk-tree state was never decoded on either side.** Only two contracts have ever existed on the test chain, with 6 and 8 top-level ledger fields, both under the cap. The TypeScript walker recurses through nested arrays generically, but that rests on a synthetic test rather than a byte-diff. Decoding a real greater-than-15-field contract remains untested in both implementations.
- **Scope of the write-path measurements.** One chain, one transaction shape, one contract pair, and `postRespondBidirectional` is a cheap circuit. The heaviest circuit this proof server has run cost 2.9 s, so there is no sign of a cliff, but do not read 0.35 s as the cost of an arbitrary circuit.
- **`node-2.0.0-rc.5` has no announced date.** The only open milestone is past due. Relevant only if the Rust path is retained.

## 7. The codec redesign [2026-07-23]

§3.4 established what this boundary is actually for: **keeping the ledger's 80-package ZK and native-crypto tree out of the mpc workspace.** That is a narrower mandate than "the Rust dependencies conflict", and it gives a sharp test for every line here. *Does this require the ledger WASM or the prover?* If not, it belongs in Rust.

### 7.1 Rust can do every RPC, proven

The one thing that could have blocked this was whether `chain-midnight` can unwrap a block body itself. It can. A probe using the same `subxt = "0.44"` pin as `chain-signatures/node`, dynamic API, no codegen:

```
connect + metadata: OK          pallets visible: 29
Midnight pallet: OK             call: send_mn_transaction
block 1366 -> 5 extrinsics, one Midnight.send_mn_transaction
  arg bytes: 14405 (compact prefix 2B)
  leading ascii: midnight:transaction[v12](signature[v2],proof,pedersen-schnorr
  MATCHES the @polkadot/api extraction (14405): true
```

subxt 0.44 reads node rc.4's metadata v16 and produces byte-identical output to `@polkadot/api`. Contract-state reads need no metadata at all (`midnight_contractState` is plain JSON-RPC returning hex), and the runtime API is reached through `state_call`. So the publisher never needs a node connection to *read*.

Note for anyone reproducing the probe: `subxt`'s `unstable-light-client` feature pulls `smoldot`, which calls `ed25519_zebra::batch` and only compiles because something else in the mpc graph enables that crate's `alloc` feature. In an isolated crate it fails. Drop the feature; it is irrelevant to metadata and extrinsic decoding.

### 7.2 The surface

```
POST /decode/contract-state   { bytes }    -> the state tree
POST /decode/transactions     { bytes[] }  -> calls per transaction
POST /respond                 ...          -> prove + submit
GET  /health                               -> {status, ledger}

any failure                                -> {code, message}   (§7.5)
```

What went away is not mainly lines, it is **concepts**: the node URL for reads, `?at=`, the anchor, the notions of block, address and block hash, the `skipped` policy, and the pruning-error classifier. The publisher takes bytes and returns structure. The decoded shapes are unchanged and still byte-verified against the fixtures captured from the Rust implementation, so only *who fetches the bytes* moved.

This also retires a pile of design questions that were open: the atom-tree schema (it mirrors the ledger types), round-trip counts, whether the sidecar may compute a state diff (it never sees two states), and the whole read-path error taxonomy, which collapses to two cases (§7.5) now that a pruned node and an absent contract are the caller's problem to tell apart, not this service's.

### 7.3 The write path keeps its network, and why

Tested rather than assumed. `finalizeRecipe` does return a serializable `FinalizedTransaction`, 7,914 bytes tagged `midnight:transaction[v12](signature[v2],proof,pedersen-schnorr[v1])`, and submitting those bytes out-of-band via `author_submitExtrinsic` works. So handing submission to Rust is mechanically possible.

**But the node URL cannot be removed, though the originally stated reason was wrong.** Pointed at a dead port the facade produces nothing but a reconnect loop, which is what was observed. Reading the installed source shows balancing goes to the **indexer** (`RunningV1Variant` -> `syncService.blockData()`) and finalizing goes to the **proof server** (`provingService.prove` -> `HttpProverClient`); the only node consumer is `PolkadotNodeClient` inside the submission service, and the reconnect loop is `ApiPromise.create` retrying in a fire-and-forget `Deferred`. So the node is required for **submission**, not for balance or finalize. The conclusion stands; the mechanism in the original note did not.

Three measured facts worth keeping, all from the same probe:

- **The wallet tracks pending spends locally.** After `balanceUnboundTransaction`, `dustAvailable` 1→0 and `dustPending` 0→1; after `finalizeRecipe`, `pendingTxs` 0→1. A second respond attempted 0.4s later fails with `Wallet.InsufficientFunds: could not balance dust`. The dust view recovers at about **+35s**.
- **`facade.submitTransaction` blocks for ~16.6s**, which supplies roughly half that recovery window as natural backpressure. Out-of-band submission returns immediately and removes it. Neither path can post two responds faster than dust recovery; the blocking path merely hides the limit. With one wallet the ceiling is roughly **one respond per 35 seconds**, and scaling means one wallet per worker (§2.6).
- **An abandoned finalized transaction auto-reverts, on the TTL.** Finalized but never submitted, the dust coin returned at +59.3s against a **60s** TTL. That value becomes the dust-spending intent's TTL (`dust-wallet`'s `Intent.new(ttl)`), so it is how long a respond that dies between finalize and submit strands the fee coin. Found by audit at 30 minutes; `RECIPE_TTL_MS` is now **5 minutes** (`wallet.ts`), ~15x the measured ~20s round, and the reason `respond.ts` puts no deadline past the balance stage.

So the publisher's network peers are the node (wallet operation and submission), the proof server (proving), and the indexer (wallet sync).

**The write path also keeps three chain reads, and that is deliberate.** `/respond` reads the contract state, the zswap chain state and the live ledger parameters at one pinned finalized block. The original plan was to have `chain-midnight` supply those as blobs, on the same reasoning as the decode seams. Applying §7.1's test honestly kills that idea:

- The reads must be **fresh at prove time**. Ledger parameters drift per block, and stale ones are rejected as `Transcript(Execution(OutOfGas))`. Moving the fetch to the caller inserts its queueing delay between the read and the prove, and with one wallet this service is rate-limited to roughly one post per 35 seconds (§7.3 above), so that delay is not hypothetical.
- There is **no dependency to save**. The node connection has to exist for the wallet regardless. Three `state_call`s over a socket that is already open cost nothing, whereas shipping the blobs means a bigger envelope, a new class of caller mistake, and the staleness above.

The rule stands as written: everything that needs only bytes moved to Rust. These three need a *fresh* read bound to the prove that follows it, which is a different thing.

### 7.4 What is left in Rust's hands

Every RPC call, and therefore every retry, endpoint-failover and caching decision, including reading from several indexers or nodes to avoid a single point of silence. That policy now lives in one place, beside the trust decisions, rather than being split across a language boundary.

The publisher's remaining compatibility surface is a single question: **which ledger version its crates speak.** That is now explicit at the seam. `GET /health` answers with the ledger's own self-describing tags:

```json
{"status":"ok","ledger":{"contractState":"midnight:contract-state[v8]","zswapChainState":"midnight:zswap-ledger-state[v5]","ledgerParameters":"midnight:ledger-parameters[v8]","transaction":"midnight:transaction[v12]"}}
```

The caller asserts these against the chain it reads, at startup. Left implicit, a version skew arrives as a deserialization failure on bytes that are perfectly good, which reads as "the publisher is broken" and sends the operator to the wrong place. These are not a version scheme this package invented; they are what the ledger stamps into the leading bytes of everything it serializes, so they move exactly when the encoding moves. The write path checks the two blobs it reads against them before deserializing.

`/health` is liveness only. Readiness would have to reach the node, the indexer and the proof server, and a caller that reads "a dependency is down" as "the publisher is down" restarts the wrong process.

### 7.5 Errors are codes, not prose

Every non-200 is `{"code":"<machine>","message":"<prose>"}`, plus a `"stage"` (`boot|read|prove|balance|submit`) on respond-path failures so alerting can tell "proof server sick" from "chain rejecting" without string matching, plus a `"detail"` carrying the dependency's rendered cause chain (stack frames stripped, seed-redacted) whenever it says more than the one-line message: the classification is the contract, the detail is the evidence that lets a wrong classification be seen and fixed. The caller branches on code and stage; the message is for the human reading the log. That split is what makes a wording improvement a non-event instead of a breaking change. A respond 200 carries `{"status":"ok","tx_id":"<submitted>","block_hash":"<the finalized block the three reads were pinned to, bare hex>"}` for settlement observation and debugging.

| code | HTTP | means | what the caller does |
|---|---|---|---|
| `bad_request` | 400 | malformed envelope, bad hex, failed validation | fix the request; never retry |
| `not_found` | 404 | no such route | fix the client |
| `decode_failed` | 422 | the ledger refused bytes the CALLER supplied | their blob is wrong, or from another ledger line |
| `ledger_mismatch` | 502 | bytes read from the CHAIN carry a tag this build does not speak | version skew; compare against `/health` |
| `contract_absent` | 409 | no contract state at that address in the pinned block | wrong address, or not deployed yet |
| `contract_mismatch` | 409 | deployed verifier keys differ from this build's | redeploy, or repoint `MIDNIGHT_PUB_MANAGED_DIR` |
| `state_conflict` | 409 | another post won the race for the same request id | retry as-is; the loser never entered a block and paid no fee |
| `node_unavailable` | 502 | the node could not serve a pinned read, or the read hit its deadline | retry when the node is back |
| `prove_failed` | 502 | the proof server refused, failed, or hit its deadline | retry |
| `wallet_unfunded` | 503 | no spendable dust right now | back off; recovers in about 35 seconds |
| `wallet_unsynced` | 503 | the funding wallet could not sync within the boot deadline | check the indexer, then retry |
| `wallet_busy` | 503 | another respond currently holds the one dust UTXO | retry when it answers, ~35 s |
| `balance_failed` | 502 | balancing failed for a reason other than funds | investigate |
| `submit_rejected` | 502 | the chain refused the submission | investigate |
| `internal` | 500 | unclassified | the message is the only detail |

Several codes share a status on purpose. A 409 that is `state_conflict` should be retried unchanged; a 409 that is `contract_mismatch` will never succeed until this service is redeployed. The status cannot carry that and the code can. The three deadlines (`RESPOND_DEADLINES`: boot, read, prove) exist because a dead indexer or a mid-life node death otherwise leaves the request hanging forever, which is the one failure the error model cannot express; balance and submit are deliberately unbounded because abandoning a finalized recipe strands the fee coin for the dust-intent TTL.

**Where the fragility is concentrated**, and a defect found by auditing it. Some causes are only visible in the text a dependency threw, so `errors.ts`'s `RESPOND_STAGES` is the one table that matches on it. An adversarial pass found the two entries have very different standing:

- **`Wallet.InsufficientFunds` -> `wallet_unfunded` is confirmed reachable.** `Data.TaggedError` puts the tag in `name`, `DustWallet` runs its Effect with no outer wrapper, and the message is built by template at runtime (`Balancer.js:14-19`), which is why grepping `node_modules` for the literal string finds nothing.
- **`ReadMismatch` -> `state_conflict` was UNREACHABLE, and shipped that way.** `submissionService.js:31` flattens every node error into `new SubmissionError({message: 'Transaction submission error', cause: err})`, and Effect's `FiberFailure` stores its cause on `Symbol.for("effect/Runtime/FiberFailure/Cause")` rather than on `.cause`, so `describeFailure`'s walk terminated immediately. Every submit failure rendered as the same constant string. The same-request-id race, the one collision `/respond` is designed around, answered `submit_rejected` ("investigate") instead of `state_conflict` ("retry as-is, no fee paid").

The mechanical half is fixed: `inStage` now classifies against `describeFailure(error)` plus `String(error)`, because Effect's `toString` runs `Cause.pretty` and does render the nested chain. Multi-line with stack frames, so it is used for matching only, never as a response body. Verified: with the nested cause present, `state_conflict` fires.

**Still unproven is whether the node client surfaces the ledger's text at all.** `PolkadotNodeClient` reports a pre-dispatch rejection with a hardcoded `'Transaction is invalid and was rejected by the node'` and no ledger detail, and §2.6's `Transcript(Execution(ReadMismatch))` sample came from the NODE LOG, not a client error. So `state_conflict` is documented as best-effort until a live same-id race confirms it; `submit_rejected` is always correct as the fallback.

Two process lessons. The original test fabricated the failure as `new Error()` with a hand-set `.name`, passed, and proved nothing — the same self-consistent-test trap `block.ts` warns about for the `Fr` tag byte. And "observed on a live chain" was written of both patterns when it was only ever true of one. The test now builds failures through a real `Effect.runPromise` rejection.

### 7.6 The line count, finally

Implementation only, both sides: non-blank, non-comment lines under `src/`, with the Rust crate's inline `#[cfg(test)]` modules excluded so the comparison is like for like.

| | code lines |
|---|---|
| Rust `midnight-publisher/src` (the original) | **731** |
| TypeScript, first working port | 1,029 |
| after replacing hand-rolled code with the libraries' own | 862 |
| after the cleanup pass | 847 |
| after the codec redesign (§7.2) | 800 |
| **final, with error codes and the ledger declaration** | **882** |

| file | code lines | comment lines |
|---|---|---|
| `respond.ts` | 408 | 165 |
| `server.ts` | 110 | 48 |
| `block.ts` | 81 | 80 |
| `errors.ts` | 68 | 37 |
| `config.ts` | 60 | 32 |
| `wallet.ts` | 50 | 40 |
| `state.ts` | 44 | 23 |
| `node.ts` | 35 | 24 |
| `ledger.ts` | 18 | 18 |
| `index.ts` | 8 | 8 |
| **total** | **882** | **475** |

Comments were cut from 1,049 lines to 475 in a separate pass. What survives is the traps and the decisions: the dual-WASM-instance rules, the `Fr` tag byte whose absence is silent, `@polkadot/api` treating a `Uint8Array` as pre-encoded SCALE, the little-endian `sig_r`/`sig_s` order, the `localeCompare` collation hazard, the indexer `/ws` suffix, the mnemonic-widening seed check, and the ternary in `proveCall` that looks redundant and does not compile without. What went was the long-form rationale, which is this document's job, and the `@param`/`@returns` blocks that restated type signatures.

**882 against 731, and the comparison flatters Rust.** Three of those 151 lines-worth of difference are things the Rust version does not have at all: a machine-readable error vocabulary (`errors.ts`, 68 lines), a published ledger declaration (`ledger.ts`, 18), and the typed circuit-argument narrowing that makes a contract rename a compile error rather than a proving failure. Net of `errors.ts` and `ledger.ts` alone the TypeScript is 796 lines for a *smaller* surface, since the Rust crate also owns the RPC walk, the anchor, the pruning classifier and the `?at=` plumbing that §7.2 deleted.

The honest reading is that this was never a line-count win and was not chosen as one. It was chosen because `compactc` emits only JavaScript, so the transcripts `ContractCallPrototype` demands can only be produced on this side (§1). The line count is roughly a wash; what changed is that the awkward parts are now in the language whose tooling is maintained for them.

**The metric that actually matters here is dependencies, not lines**, because dependency isolation is the entire reason this package exists (§3.4). Direct dependencies went from **19 to 10**. Nine were declared but never imported: six `@midnightntwrk/wallet-sdk-*` packages left over from when `wallet.ts` wired the facade by hand rather than going through `@sig-net/midnight-contract-deploy`, plus `@midnight-ntwrk/compact-runtime`, `@midnight-ntwrk/midnight-js-contracts` and `@midnightntwrk/onchain-runtime-v4`, all of which arrive transitively.

Removing exact-version pins from a Midnight package is not obviously safe — the dual-WASM-instance failure mode (§5) is what those pins guard against — so it was tested rather than assumed. In a clean tree with the nine dropped and no lockfile, npm resolves **every** version-critical package to the identical version, with exactly one copy of `ledger-v9` and one of `onchain-runtime-v4` on disk. `tsc` clean, 135/135. The pins were redundant with what the remaining ten already require.

## Appendix A: measured numbers

| Measurement | Value |
|---|---|
| `callTx.postRespondBidirectional` total, single | 19.0 s and 21.5 s (two runs) |
| of which contract-call proof | 0.35 s |
| of which zswap/dust segment proof | 0.44 s |
| of which chain inclusion and finality | about 17 to 20 s, roughly three block times at 5.9 s/block |
| client peak RSS, single call | 598 MiB |
| client peak RSS, 3 concurrent plus 3 wallet facades | 608 MiB |
| proof server marginal memory, single prove | +6.6 MiB |
| proof server marginal memory, 3 concurrent | +2.5 to +3.2 MiB |
| proof server p50 / max across 95 operations | 0.402 s / 0.852 s |
| heaviest circuit observed on this stack | 2.889 s |
| 3 concurrent posts, distinct request ids | 3/3 in a single block, about 20 s total |
| `findDeployedContract` with node-RPC provider | 0.10 s, 36 node RPC calls |
| TypeScript `/block` pipeline | about 90 lines |
| TypeScript `/state` walker | 30 lines |
| node-RPC `PublicDataProvider` shim | about 120 lines |

## Appendix B: version pins observed

| Component | Version |
|---|---|
| midnight-node | 2.0.0-rc.4 |
| midnight-ledger crates | crate-ledger-9.1.0.0-rc.3 and the matched tag set |
| proof server | 9.0.0-rc.5_experimental |
| indexer (not required) | 4.4.0-pre-alpha.16 |
| `@midnightntwrk/ledger-v9` | 1.0.0-rc.3 |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.0-rc.3 |
| `@midnight-ntwrk/midnight-js-*` | 5.0.0-beta.4 (beta.6 published) |
| `@midnight-ntwrk/compact-js` | 2.5.5-rc.6 |
| `@midnight-ntwrk/compact-runtime` | 0.18.0-rc.1 |
| `@midnightntwrk/wallet-sdk-node-client` | 2.0.0-beta.2 |
| `@polkadot/api` | 16.5.6 |
| compactc | 0.33.0, language 0.25.0, runtime 0.18.0-rc.1 |
