# Agent notes for `localnet/`

Context an agent needs before changing anything here, weighted towards what the code does
not tell you. `README.md` is the human-facing document and is self-contained: keep it that
way, and never point a human at this file.

## What this directory is

A three-node MPC cluster packaged as ONE image, plus the Solana chain it answers on. It
exists to replace the `fakenet-signer` stand-in for local development, and it is shaped to be
consumed the way `ghcr.io/sig-net/fakenet` is: drop one service into a compose file, set a
couple of environment variables, and point a client at it.

That shape is the constraint. Anything that makes a consumer mount a volume, run a second
service, or prepare state before starting has broken the point of it. The key material, both
chains, Redis and all three nodes are baked in for that reason.

## The two invariants that matter most

**Account sort order must equal key-share index order.** The contract assigns participant
ids by iterating a `BTreeMap<AccountId, _>` and incrementing `next_id`
(`chain-signatures/contract/src/primitives.rs`), so participant *i* is whichever account
sorts *i*-th. Key shares are numbered. Break the correspondence and the cluster still
reports itself as `running` while every signature times out, with nothing in the logs to
say why. `nodes::load_all` and `keygen::write_all` both assert it, and a unit test covers
the committed files. Do not remove those checks.

**Every public value in the contract is derived, never transcribed.** The bootstrap reads
`nodes/node<N>.env` and computes the account, cipher and sign public keys from the secrets
it finds there. Adding a field that is written down twice reintroduces exactly the drift
this design removes.

## The preloaded triples and presignatures

`stockpile.rs` writes dealt protocol material straight into Redis before any node starts.

**It does not make the cluster faster, and the docs must not claim it does.** Cold start to
first signature measured 18 s and 20 s with the preload, 17 s and 18 s without. Switched off
the nodes start at zero counts and still answer one second after reaching `running`, so at
`min_triples: 8` and `min_presignatures: 4` generation was never on the critical path. What
the preload buys is determinism: identical material on every run, which makes a failure
reproducible. Reach for it as leverage only on a profile where generation would genuinely
dominate, and measure before saying it helped.

Four things about it are load-bearing.

**The Redis layout is a copy, guarded by tests.** `mpc_node::storage::{triple_storage,
presignature_storage}` own those keys. Calling them would mean compiling `mpc-node` into the
bootstrap image for four Redis commands, so the layout is written out again. Three tests read
the node's own source with `include_str!` and fail on drift: `storage_version_matches_the_node`
parses `STORAGE_VERSION` out of `storage/mod.rs`, and `triple_pair_fields_match_the_node`
parses the `TriplePair` declaration. Each was watched failing against a planted violation. Do
not weaken them into constants copied by hand.

**Pairs are cut from the intersection, not from each node's own list.** A pair is spent as a
unit and named by its first triple's id, so all nodes have to form the same pairs. In the
committed fixture, participant 2 holds shares of owners 0 and 2 that the others do not,
part-way through the list. `MpcFixtureBuilder` chunks each node's own list in stored order,
which on this fixture gives one pair id naming a different second triple on participant 2 than
on participant 0, plus a pair participant 0 forms alone. `pairs_by_owner` intersects and sorts
instead. `every_node_pairs_the_committed_fixture_identically` is the guard.

**It runs before the nodes and never touches a live cluster.** The bootstrap exits before any
node starts, and `run` returns early if either store already holds anything. Topping up a
running cluster would race its own generation and collide with ids it has already retired.

**Serving lags `running`, though far less than it once did.** On the earlier layout, with each
node in its own container, a request submitted the moment all three reported `running` went
unanswered and serving began roughly 25 seconds later. In one container the gap is about a
second. The cause was never isolated, so treat the small gap as this machine's measurement
rather than a property to rely on: a harness that fires once on `/state` and gives up is
reporting its own race, and it will look exactly like a broken stockpile.

The material is a trusted-dealer deal, which is only acceptable because it is committed to the
repository alongside the key shares and protects nothing. Everything the fixture supplies
passes through as opaque JSON, so the curve types are never re-encoded here.

## Build and test, and how the repo fights you

`.cargo/config.toml` sets `runner = "./setup.sh"` for non-wasm targets, so `cargo run` and
`cargo test` first build the NEAR contract for `wasm32-unknown-unknown` and the node in
release. On a machine without the wasm target installed, both fail with a confusing
`can't find crate for 'core'`.

```bash
cargo build -p mpc-localnet && ./target/debug/mpc-localnet <subcommand>
```

```bash
CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="env" cargo test -p mpc-localnet
```

An empty string for that variable is rejected by Cargo, hence `env` as a no-op runner.

`redis` is declared directly in `bootstrap/Cargo.toml` with `tokio-comp` spelled out rather
than taken from the workspace. The node gets those features through `deadpool-redis`, and
feature unification does not reach a `-p mpc-localnet` build that has no reason to depend on
it.

`localnet/Dockerfile` builds `mpc-node` and `mpc-localnet` in one `cargo build` invocation.
They share a workspace and most of a dependency graph, so two invocations compile that graph
twice. It also skips the hardhat stage the root `Dockerfile` runs: the ChainSignatures ABI
that `chain-signatures/node/src/rpc.rs` pulls in with `include_str!` is committed and is not
excluded by `.dockerignore`, so it arrives with the source.

The root `Dockerfile` is untouched by any of this and still builds the node on its own. It
copies `localnet/bootstrap/Cargo.toml` and deliberately not the sources, since Cargo needs
every workspace member's manifest to resolve the workspace at all while copying the sources
would invalidate its `mpc-node` build cache on every edit here. If you add a member under
`localnet/`, add its manifest there as well.

## Landmines in the MPC node's own configuration

- `MPC_ENV` is a feature switch, not a label. Only `integration-tests` starts the NEAR
  indexer (`cli.rs`). Only `local-test` stubs GCP auth, which is not needed here since
  `MPC_SK_SHARE_SECRET_ID` is unset and storage falls through to disk.
- The root `Dockerfile`'s baked entrypoint takes no arguments, starts a Redis it bundles, and
  contains a hardcoded `RUST_LOG`, since the `${RUST_LOG:-...}` written into it was expanded
  at image build time. `entrypoint.sh` invokes `mpc-node start` itself and never goes through
  that script, which is what keeps every setting under the env files.
- `MPC_SK_SHARE_LOCAL_PATH` is a prefix, not a path. The node reads `{prefix}-{account_id}`,
  which is why the shares are baked in as `/data/keyshare-<account id>` with no extension.
- Leaving `MPC_SK_SHARE_LOCAL_PATH` unset gives in-memory storage, so a node restart loses
  its share and the network needs a resharing it cannot complete.
- Each node needs its **own** Solana keypair. Sharing one means several nodes can build a
  byte-identical `respond` transaction from the same payer, instruction and blockhash, and
  the cluster rejects the duplicate signature and churns its retry loop.

## NEAR

- **near-workspaces `install` is a default feature** whose build script downloads a sandbox
  binary. It fails the build outright on linux arm64. The crate sets
  `default-features = false`, since the localnet attaches to a running sandbox and never
  spawns one. Do not re-enable it.
- Attaching rather than spawning works through
  `sandbox().rpc_addr(..).validator_key(ValidatorKey::Known(..))`, which takes the
  `(Some, Some)` branch in `network/sandbox.rs` and skips the process spawn entirely.
- `init_running` is `#[private]`, so it has to be called by the contract account on itself.
  `Contract::call` does that. It is also `#[init]`, so guard it with a state check.
- `ProtocolConfig` declares **no serde defaults**. A partial JSON config is rejected with
  `Failed to deserialize input from JSON`. Build `mpc_contract::config::Config` and override
  fields on it.
- The contract's own defaults are `min_triples: 1024` and `min_presignatures: 512`, which
  would grind a laptop for minutes before the first signature. `near.rs` lowers them.
- The contract wasm must be built with rustc **1.81**, as `build-contract.sh` pins. Newer
  rustc emits wasm features older nearcore rejects with an opaque deserialisation error.

### Why the sandbox image is built here rather than pulled

This cost real time to work out, so do not undo it.

- `ghcr.io/near/sandbox:latest` is amd64-only. Under `qemu-user` it does not run slowly, it
  hangs `neard` at 0% CPU with no listening socket. Amd64 Redis fails identically, so this
  is the emulation, not NEAR. Rosetta would fix it, but Apple has Rosetta 2 on a
  deprecation path, so it is not something to build a dev stack on.
- `ghcr.io/near/sandbox:latest-aarch64` exists and is native, but was built in 2023 against
  nearcore 1.35.0. near-workspaces 0.15 fails against it with a missing `genesis_hash`
  field.
- `nearprotocol/nearcore` publishes amd64 only, `master` included.
- NEAR publishes `Linux-aarch64` sandbox binaries from nearcore **2.6.5** onwards, at
  `https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/<platform>/<version>/near-sandbox.tar.gz`.
  `near-sandbox-utils` 0.12.0 defaults to 2.3.1, which predates them, which is the only
  reason the Rust tooling still calls arm64 unsupported.

`near-sandbox.Dockerfile` downloads one of those and inits with `--test-seed`, so the
validator key is a function of the root account name and is identical across a `--no-cache`
rebuild. That is why `main.rs` derives the key with `SecretKey::from_seed` instead of
carrying a literal. Change the seed or the account name and you must change both.

## Solana

- The bundled `chain_signatures.so` is prebuilt from `sig-net/solana-signet-program` 0.4.0
  and only works at `FR5pWwinRBn35GNhg7bsvw8Q13kRept2pm561DwZCQzT`, since anchor enforces
  `declare_id!` at instruction time. This is **not** the id in
  `chain-signatures/contract-sol/src/lib.rs`, which is a different build. Do not "fix" the
  apparent mismatch.
- The program is installed with surfpool's `surfnet_writeProgram` cheat code, not deployed.
  That removes the Solana CLI, a program keypair and the BPF loader dance.
- Surfpool **rate-limits airdrops**. `ensure_funded` only tops an account up once it falls
  below a tenth of the target, so re-runs stay quiet. Topping up on any shortfall makes the
  bootstrap fail on its second run, since by then fees have been paid.
- The node decodes events through a specific path: `getTransaction` with `JsonParsed`
  encoding, walking `meta.inner_instructions` for `PartiallyDecoded` instructions whose data
  starts with `EVENT_IX_TAG_LE`. `solana::decode_events` mirrors it deliberately, so if it
  works the node works. Keep them in step.
- `request_id.rs` duplicates a private trait impl in `chain-signatures/node/src/indexer_sol.rs`
  rather than depend on all of `mpc-node`. Verified equal against a live cluster: the
  printed request id matched the node's `sign_id`. If they ever diverge, `sign` waits
  forever for a response that is present under another id.

## One container, several processes

`entrypoint.sh` starts Redis, then the NEAR sandbox, waits for its RPC, runs the bootstrap to
completion, then starts the nodes. The ordering is not decoration: the bootstrap writes the
participant set the nodes read on startup, and it preloads Redis, so a node that starts first
sees an unprepared chain.

`wait -n` then takes the container down as soon as any of them exits. Do not replace it with
a bare `wait`. A cluster running two of three nodes still reports `running` and still times
out every signature, and that is far more expensive to debug than a container that exits.
Verified by killing one node inside a healthy container: it exited 143 and logged
`shutting down`.

To find a process in there, match on the executable rather than the command line, since a
`pgrep mpc-node` run through `docker exec` matches its own `bash -c` too and miscounts:

```bash
docker exec <container> bash -c 'for p in /proc/[0-9]*; do [ "$(readlink -f "$p/exe")" = /usr/local/bin/mpc-node ] && echo "${p#/proc/}"; done'
```

The nodes reach each other over loopback, so `node<N>.env` carries `MPC_LOCAL_ADDRESS` on
`127.0.0.1` and a distinct `MPC_WEB_PORT`. `keygen` writes both, and its `--address-template`
understands `{port}` as well as `{i}`.

Endpoint settings (`MPC_NEAR_RPC`, `MPC_REDIS_URL`, the two Solana URLs, `RUST_LOG`) are
exported by the entrypoint **after** it sources the env files, so container environment wins.
Do not also set them in `common.env`: that gives one setting two sources that drift.

Ports published: 3000 to 3002 (nodes), 3030 (NEAR), 6379 (Redis), 8899 and 8900 (Solana).

## Environment quirks seen on this machine

- Docker is colima with `vmType: vz`. `/private/tmp` is **not** mounted into the VM, so
  `docker run -v /private/tmp/...` mounts an empty directory and fails in confusing ways.
  Use paths under `$HOME`.
- The daemon uses the **classic builder**, so `TARGETARCH` and other BuildKit build args are
  unset. `near-sandbox.Dockerfile` reads `uname -m` instead, which also happens to match the
  names NEAR publishes under.
- `docker build` writes progress to stderr. Capturing only stdout gives an empty log.
- Editing anything under `localnet/` invalidates the `COPY localnet/` layer in
  `localnet/Dockerfile`, and the classic builder carries no cargo cache across layers, so the
  bootstrap image rebuilds the whole workspace in release mode. Budget around fifteen minutes
  and use the Redis-only smoke test below while iterating.

## Verifying a change

```bash
docker compose -f localnet/docker-compose.yaml down -v
docker compose -f localnet/docker-compose.yaml up -d --build
curl -s localhost:3000/state
docker compose -f localnet/docker-compose.yaml --profile tools run --rm signer sign --path test
```

All three ports should report `running` with `[0,1,2]` and triple and presignature counts that
start above zero, since `bootstrap` preloads 18 pairs and 15 presignatures per node. The
signer should print `big_r`, `s` and `recovery_id`, though not on the first attempt if you run
it the instant `/state` says `running`: give it a minute or retry. Then run
`docker compose ... run --rm bootstrap` twice more and confirm it changes nothing.

The stockpile can be exercised on its own against nothing but a Redis, which is much faster
than a stack rebuild:

```bash
docker run -d --name redis-smoke -p 16399:6379 redis:7.4.2
```

```bash
cargo build -p mpc-localnet && ./target/debug/mpc-localnet stockpile --nodes-dir localnet/nodes --keyshares-dir localnet/keyshares --fixture integration-tests/src/mpc_fixture/3_nodes.json --redis-url redis://127.0.0.1:16399
```

To see what the cluster does without it, put `LOCALNET_STOCKPILE=false` in the shell that runs
`docker compose up`. The compose file reads it through.

Any claim you add to `README.md` or to this file must come from having run something and
read the result. A wrong note here propagates into every future change.

## Out of scope

MPC v1.11.0 has no Midnight and no Substrate support, so `fakenet-signer` remains for those
legs. Confirmed by searching `chain-signatures/`, `integration-tests/` and `doc/`: the
`chain-signatures/chain-midnight` directory some checkouts carry is an empty stub.
