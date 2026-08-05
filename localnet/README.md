# Local MPC cluster

A complete three-node MPC network on your machine, with the two chains it depends on and a
job that prepares them. One command takes you from nothing to a cluster that answers
signature requests made through the Solana signet program.

This exists to replace the `fakenet-signer` stand-in for local development. Fakenet derives
child keys from a single local root key in one process; this runs the real threshold
protocol.

## What it runs

| Service | Purpose |
|---|---|
| `near-sandbox` | NEAR localnet. Hosts the MPC contract, which is the only source of truth for the participant set. Built locally, see below. |
| `surfpool` | Solana localnet. Hosts the signet program that signature requests arrive on. |
| `redis` | Shared triple, presignature and checkpoint storage. Keys are namespaced per node account. |
| `bootstrap` | One-shot. Creates accounts, deploys and initialises the contract, installs the signet program, fills Redis with triples and presignatures. Exits when done. |
| `mpc-node-0/1/2` | The MPC nodes, on ports 3000, 3001 and 3002. |

## Before you start

Docker, and roughly 6 GB of memory free. Nothing else. Every service runs natively on both
arm64 and amd64, so no emulation and no Rosetta.

Getting the NEAR sandbox to run natively on arm64 took some finding, and the reasoning is
worth recording because the obvious choices all fail:

- `ghcr.io/near/sandbox:latest` is amd64-only. Under `qemu-user` it does not merely run
  slowly, it hangs `neard` at 0% CPU with no listening socket. Amd64 Redis fails the same
  way, so this is a general limitation of that emulation rather than anything about NEAR.
  Rosetta would fix it, but Apple has put Rosetta 2 on a deprecation path.
- `ghcr.io/near/sandbox:latest-aarch64` does exist and is genuinely native. It was built in
  2023 against nearcore 1.35.0, though, which is too old for the near-workspaces release
  this repository uses: connecting fails on a missing `genesis_hash` field.
- `nearprotocol/nearcore` publishes amd64 only, including on `master`.

What does work is that NEAR publishes `Linux-aarch64` sandbox binaries directly, from
nearcore 2.6.5 onwards. They are simply newer than the 2.3.1 that `near-sandbox-utils`
0.12.0 defaults to, which is why the Rust tooling still reports arm64 as unsupported.
`near-sandbox.Dockerfile` downloads one and builds a small native image around it, picking
the platform from `uname -m` so the same file works on amd64.

## Running it

```bash
docker compose -f localnet/docker-compose.yaml up --build
```

The first run builds three images and takes a while, mostly compiling the MPC node. After
that a cold start takes about 20 seconds: the two chains come up, `bootstrap` exits 0, and
the three nodes reach `running`.

Check the cluster agrees it is running:

```bash
curl -s localhost:3000/state | jq
```

You want `running` with all three participants listed, and triple and presignature counts
that start above zero, since the bootstrap preloads them. Ports 3001 and 3002 should say the
same thing.

`running` is not the same as ready. All three nodes report it around 16 seconds in, and a
request submitted at that moment goes unanswered. The cluster starts serving roughly 25
seconds after that, about 42 seconds from cold. Anything scripted against this stack has to
retry its request rather than trust the state endpoint. This is a property of the cluster,
not of the preload: it measures the same with `LOCALNET_STOCKPILE=false`.

To wipe the chains and start over, `docker compose -f localnet/docker-compose.yaml down -v`.
The bootstrap is safe to re-run at any time and does nothing when everything is already in
place, so you rarely need to.

## Asking it to sign something

```bash
docker compose -f localnet/docker-compose.yaml --profile tools run --rm signer sign --path test
```

This submits a request through the signet program and waits for the cluster to answer,
printing `big_r`, `s` and `recovery_id`. Add `--payload <64 hex chars>` to sign something
specific instead of a random payload. A request typically comes back in well under a
second.

To watch it happen:

```bash
docker compose -f localnet/docker-compose.yaml logs -f mpc-node-0
```

Exactly one node publishes each response, so if you are watching a single node you may see
another one win the race.

## How it is put together

```
localnet/
  docker-compose.yaml   the service graph
  Dockerfile            the bootstrap image (the node image is the repository root Dockerfile)
  nodes/                common.env plus one node<N>.env per node
  keyshares/            one key share per node account
  bootstrap/            the mpc-localnet crate
```

`nodes/node<N>.env` is the only place key material is written down. The bootstrap reads
those same files and derives every public value it registers in the contract, so the
contract cannot drift out of step with what the nodes actually run. These keys are
committed deliberately, so that startup is reproducible. They protect nothing. Never reuse
them anywhere real.

The cluster skips distributed key generation. Each node is handed a share of a key
generated once and committed under `keyshares/`, and the contract is initialised straight
into its running state with the matching public key. That removes tens of seconds from
startup and gives clients a fixed root public key to derive addresses from:

```
03FF3D22262B4BF9B4D0D293E5E28031F1D5CF0FEC44566A1DF7D7B04982DE3A2A
```

It arrives stocked as well. A signature spends a presignature, which spends a pair of
triples, and both are produced by multi-round protocols between the nodes. The bootstrap
writes 18 triple pairs and 15 presignatures per node into Redis before any node starts, dealt
in advance and taken from `integration-tests/src/mpc_fixture/3_nodes.json`, the same file the
key shares come from. Every node therefore holds material from the moment it starts, and it is
the same material on every run, which makes a failure reproducible.

Be clear about what this buys, since it is less than it looks. Measured on this three-node
profile, cold start to first signature was 42 seconds with the preload and 45 seconds without:
the same, within noise. Three nodes at `min_triples: 8` generate what they need in seconds, so
generation was never the thing you were waiting for. The preload is there for determinism, and
for profiles where generation would genuinely dominate. Set `LOCALNET_STOCKPILE=false` in your
shell before `docker compose up` to turn it off.

Dealing shares from one party is sound only when that party is trusted to forget them. It
protects nothing, exactly like the keys beside it. Never reuse any of it.

Account naming matters more than it looks. The contract assigns participant ids by walking
a `BTreeMap<AccountId, _>`, so participant *i* is whichever account sorts *i*-th, while the
key shares are numbered. `mpc0`, `mpc1` and `mpc2` keep those two orderings equal. The
bootstrap asserts it rather than trusting it, because getting it wrong produces a cluster
that reports itself as running while every signature times out.

The bootstrap checks for the effect of each step before performing it, so running it again
against a live stack does nothing.

## Rotating the keys

```bash
cargo build -p mpc-localnet && ./target/debug/mpc-localnet keygen --out-dir localnet/nodes
```

Use `cargo build` rather than `cargo run`: this repository sets a Cargo `runner` that
compiles the contract and node before running anything, which is not what you want here.

Key shares are a separate matter. The committed ones come from
`integration-tests/src/mpc_fixture/3_nodes.json`, and each node's share must keep its
numeric index. Rotating the network key means generating a fresh set of shares, not editing
these. The preloaded triples and presignatures come from that same file and are shares under
that same key, so a fresh set has to replace all three together.

## Troubleshooting

**All three nodes say `running` but signatures time out.** Almost always a mismatch between
key shares and participant indices rather than anything to do with networking. The
bootstrap checks for this, so it should not reach you.

**`bootstrap` fails waiting for the NEAR sandbox.** Check `docker compose logs
near-sandbox`. A container that is up while `docker stats` shows 0% CPU means it is being
emulated rather than running natively, which should not happen with the image built here.

**Ports already taken.** The stack publishes 3000 to 3002, 3030, 8899 and 8900.

## What this does not cover

The cluster serves the Solana leg. Ethereum works too, given an RPC and a deployed
`ChainSignatures.sol`, but is not wired up here.

There is no Midnight support and no Substrate support in MPC v1.11.0, so `fakenet-signer`
stays in place for those. Nothing under `chain-signatures/` mentions Midnight, and the
`chain-signatures/chain-midnight` directory some checkouts carry is an empty stub.

Two things also remain open before this can displace `fakenet-signer` outright in
`solana-signet-program-event-notifications`. That repository's signet program is
`SigMcRMjKfnC7RDG5q4yUMZM1s5KJ9oYTPP4NmJRDRw`, whereas the artifact bundled here is built
from `sig-net/solana-signet-program` 0.4.0 and installs at
`FR5pWwinRBn35GNhg7bsvw8Q13kRept2pm561DwZCQzT`, so event and instruction compatibility
between the two builds needs checking. And derived addresses, while still deterministic,
change: the derivation function differs from fakenet's, so any downstream fixtures pinned
to fakenet addresses need regenerating.
