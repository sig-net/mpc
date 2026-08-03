# Agent notes for `localnet/`

Context an agent needs before changing anything here, weighted towards what the code does
not tell you. `README.md` is the human-facing document and is self-contained: keep it that
way, and never point a human at this file.

## What this directory is

A three-node MPC cluster in Docker, with the two chains it depends on and a one-shot job
that prepares them. It exists to replace the `fakenet-signer` stand-in in
`solana-signet-program-event-notifications` for local development.

The whole thing was verified end to end: 20 seconds from cold to three nodes reporting
`running` with participants `[0,1,2]`, and a real threshold signature back in about 510 ms.
If a change breaks that, it is a regression, not a flake.

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

The root `Dockerfile` copies `localnet/bootstrap/Cargo.toml` and deliberately not the
sources. Cargo needs every workspace member's manifest to resolve the workspace at all, but
copying the sources too would make every edit here invalidate the `mpc-node` build cache and
trigger a full Rust rebuild of the node image. If you add a member under `localnet/`, add
its manifest there as well.

## Landmines in the MPC node's own configuration

- `MPC_ENV` is a feature switch, not a label. Only `integration-tests` starts the NEAR
  indexer (`cli.rs`). Only `local-test` stubs GCP auth, which is not needed here since
  `MPC_SK_SHARE_SECRET_ID` is unset and storage falls through to disk.
- The node image's baked entrypoint takes no arguments, starts a Redis it bundles, and
  contains a hardcoded `RUST_LOG` because the `${RUST_LOG:-...}` in the root `Dockerfile`
  was expanded at image build time. Compose overrides the entrypoint for this reason. Do not
  quietly drop that override.
- `MPC_SK_SHARE_LOCAL_PATH` is a prefix, not a path. The node reads
  `{prefix}-{account_id}`, which is why the compose mounts look asymmetric.
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

## Compose

Declare a build **once per image**. Three services sharing an image but each declaring
`build:` makes compose run three concurrent Rust compiles over the same cores. `mpc-node-0`
and `bootstrap` carry the builds; the others reference the tags.

Ports published: 3000 to 3002 (nodes), 3030 (NEAR), 8899 and 8900 (Solana RPC and WS).

## Environment quirks seen on this machine

- Docker is colima with `vmType: vz`. `/private/tmp` is **not** mounted into the VM, so
  `docker run -v /private/tmp/...` mounts an empty directory and fails in confusing ways.
  Use paths under `$HOME`.
- The daemon uses the **classic builder**, so `TARGETARCH` and other BuildKit build args are
  unset. `near-sandbox.Dockerfile` reads `uname -m` instead, which also happens to match the
  names NEAR publishes under.
- `docker build` writes progress to stderr. Capturing only stdout gives an empty log.

## Verifying a change

```bash
docker compose -f localnet/docker-compose.yaml down -v
docker compose -f localnet/docker-compose.yaml up -d --build
curl -s localhost:3000/state
docker compose -f localnet/docker-compose.yaml --profile tools run --rm signer sign --path test
```

All three ports should report `running` with `[0,1,2]` and rising triple and presignature
counts. The signer should print `big_r`, `s` and `recovery_id`. Then run
`docker compose ... run --rm bootstrap` twice more and confirm it changes nothing.

Any claim you add to `README.md` or to this file must come from having run something and
read the result. A wrong note here propagates into every future change.

## Out of scope

MPC v1.11.0 has no Midnight and no Substrate support, so `fakenet-signer` remains for those
legs. Confirmed by searching `chain-signatures/`, `integration-tests/` and `doc/`: the
`chain-signatures/chain-midnight` directory some checkouts carry is an empty stub.
