# Node configuration

How `mpc-node` is configured: the principles, the four places a value may come
from, and the rules a parameter follows in each.

- The rules describe the model the node is meant to follow. Where existing
  code breaks a rule, the rule wins: do not copy that code.
- Cite a rule by its ID: `node-configuration E3`.
- `mpc-node start --help` lists the parameters. No doc repeats that list.

## Principles

1. **Fewer parameters.** Each one is a way to misconfigure a node, so it needs
   a real use case.
2. **One source per value.** No override, no fallback, no second way to set it.
3. **Strict.** A wrong or missing value stops the node at startup. It never
   runs on a guess.
4. **The operator states, the node does not guess.** Nothing about a
   deployment is detected, probed or defaulted.
5. **Shared values come from the contract**, not from each operator.
6. **A release build has no test behaviour.**
7. **Secrets stay out of output.** Any value may hold one, so an error never
   echoes a value, and logs and `--help` show only values known to be public.

## The model

A new value goes to the first source that fits.

| Source | Holds | Set by | Changes |
|---|---|---|---|
| Env variables and CLI flags | What differs per node or deployment: identity, keys, endpoints (chain RPCs, Redis, the key-share store), logging, which chains run | The operator | On restart |
| Contract | What every node must share and governance must change without a release | Governance votes | On the node's next poll, no restart |
| Feature flags | What only tests need, and unfinished work | The build | At compile time |
| Constants | Everything else: timeouts, cadences, limits | A release | With the upgrade |

## Env variables and CLI flags

An operator parameter is one clap argument on `start`, with an env variable.
A flag wins over its variable. Deployed nodes use variables only: the image
runs `mpc-node start` with no arguments. Flags serve tests and local runs.

- **E1. One name, two spellings.** `--kebab-case` for the flag and
  `MPC_UPPER_SNAKE_CASE` for the variable, the same words, starting with the
  chain's name for a chain parameter (`--sol-rpc-http-url`,
  `MPC_SOL_RPC_HTTP_URL`). A number carries its unit (`-ms`, `-secs`). No
  negative switches (`--disable-…`). Only node parameters use the `MPC_`
  prefix.
- **E2. The type says what the value is.** `Url`, `AccountId`, `Address`,
  `Pubkey`, `PathBuf`, `SecretString`, a `ValueEnum` for a fixed set and in
  place of a boolean (`--log-format json`). clap rejects a bad value before
  the node starts. A `String` parsed later is a bug. What a type cannot
  express is checked once, where the config is built (`into_config`), before
  anything connects.
- **E3. Required unless the node can run without it.** No default names a
  deployment: no RPC URL, contract id, address or network. A default is
  allowed where one value fits every node (a port, a log format), declared
  with `default_value` so `--help` shows it.
- **E4. A chain is all or nothing.** Its required parameters are tied with
  `requires`: none set, the chain is off; some set, the node does not start.
  An optional parameter `requires` the one it depends on, so it is never
  silently ignored.
- **E5. No environment switch.** No parameter picks behaviour by deployment
  name: each behaviour has its own parameter. `--env` only labels logs and
  telemetry.
- **E6. Set but empty is an error**, not an absent value. Unset what is
  unused.
- **E7. One line of help**, the doc comment: what the parameter is, its unit,
  what it affects.
- **E8. Secrets and endpoint URLs are hidden.** A key, password, token or the
  URL of a service the node calls has `hide_env_values = true` and is added
  to the list in `hide_env_values_configured_on_secret_arguments`. A secret is
  a `SecretString` ([secret-management.md](secret-management.md)).
- **E9. Only clap reads the environment.** No `std::env::var` outside tests,
  examples and benches. The exceptions are `RUST_LOG` and the credentials the
  cloud client library finds by itself.

```rust
/// Signs the node's responses on Example.
#[arg(
    long,                             // E1: --example-account-sk
    env("MPC_EXAMPLE_ACCOUNT_SK"),    // E1: the same words
    hide_env_values = true,           // E8
    requires = "example_rpc_url",     // E4: the rest of the group
)]
pub example_account_sk: Option<SecretString>, // E2
```

## Contract

The node reads three things from the signer contract:

- **Protocol config** (`ProtocolConfig`): what governance tunes while the
  network runs.
- **Protocol state** (`ProtocolContractState`): the epoch, the threshold, the
  root public key, and the participants with the URL and public keys each
  registered when it joined.
- **Checkpoints**: the backlog digests the nodes agreed on for each chain
  ([checkpoints.md](checkpoints.md)).

It polls all three and applies a change without a restart.

- **C1. The contract is the only source.** No parameter, file or constant
  repeats or overrides it: no peer list, no threshold, no local protocol
  config. Peers learn a node's `--my-address` from the protocol state.
- **C2. Contract config is small.** A value belongs in `ProtocolConfig` only
  if every node must share it and governance must change it without a
  release.
- **C3. A change is a vote**: `propose_update` and `vote_update` for
  `ProtocolConfig`; `vote_join`, `vote_leave` and `vote_threshold` for
  membership and the threshold.

## Feature flags

Cargo features of the node crate decide what is compiled: `test-feature` for
what only tests may use, `unstable-<name>` for work that is not ready,
`debug-page` and `bench` for development tools.

- **B1. A release build has no features**, and no crate it depends on turns
  `test-feature` on.
- **B2. Test-only parameters are compiled out, not hidden.** A parameter or
  value only tests use sits under `#[cfg(feature = "test-feature")]`, or the
  in-process fixture sets it directly. A test in the release flavour proves
  the release binary rejects the parameter, as
  `contract_assets_are_not_an_operator_input` does.
- **B3. Libraries know nothing about tests.** A chain crate or
  `mpc-primitives` has no test feature. It holds the production value and may
  offer a faster one; only the node chooses, and only in a `test-feature`
  build.
- **B4. Unfinished work sits behind `unstable-<name>`**
  ([CONTRIBUTING](../CONTRIBUTING.md#pull-requests)).

## Constants

- **K1. Declared where it is used.** A `const`, or a `Default` for a group
  such as `Timeouts`, with a doc comment giving the unit and the reason for
  the number.
- **K2. Pinned when others depend on it.** A value every node must share has a
  test that fails when it changes.
- **K3. Changed by a release.** There is no runtime override: an incident that
  needs another value needs a hotfix ([releasing.md](releasing.md)).

## Startup

clap parses every parameter into its type. The node then builds each chain's
config and client, opens its storage, logs `starting node` and starts its
tasks: the contract poll, the mesh, the protocol and one indexer per chain.

- **S1. A configuration error stops the node.** A bad value, a half-configured
  chain, a client that cannot be built or a key share that cannot be read
  ends startup. The node never continues without the broken part.
- **S2. An unreachable service does not.** A chain or a peer that is down is
  retried. Reachability is not configuration.
- **S3. The wrong network is refused.** Each indexer checks that its endpoint
  serves the configured network. Another network is never indexed from or
  published to.
- **S4. An error names the parameter, never the value.**
  `invalid value for MPC_NEAR_RPC (--near-rpc)`: the env variable, the flag,
  and nothing the operator typed (`Cli::parse_redacted`).
- **S5. The startup log shows identity, not secrets.** The account, public
  keys, contract and program addresses, the node's own address, and the host
  of each service it calls, never that service's full URL
  ([logging.md](logging.md)).

## Changing a parameter

The rules for any breaking change are in the
[PR template](../.github/pull_request_template.md) and in
[releasing.md](releasing.md#rolling-upgrades-and-compatibility). What they
mean for a parameter:

- **P1. Adding.** Pick the source in [The model](#the-model) and state the use
  case in the PR. Declare the parameter like the example above.
- **P2. What breaks operators.** A new required parameter, a rename, a
  removal, a changed default, a stricter check. A change to `ProtocolConfig`
  is a contract change and follows the two-phase rule in releasing.md.
- **P3. What the PR does.** The title carries `!`. The **Operator** line of
  the Breaking changes section says what breaks and what each operator must
  do, naming the env variable. That text becomes the release notes.
- **P4. What operators do.** Parameters are per node, so each operator changes
  its variables together with its own upgrade: a rolling upgrade needs no
  coordination between operators. A rollback reverts both.
- **P5. A removed variable fails silently.** clap rejects an unknown flag but
  ignores a variable it no longer declares, and deployed nodes use variables.
  The release notes are the only warning: name every retired variable.
- **P6. The previous release must keep starting.** The compatibility test is
  a required check and starts the previous release from the same harness.
  Where its arguments differ, `integration-tests/src/node_args.rs` renders
  the old ones (`is_current_node`). Remove that branch after the release.
- **P7. A rename changes both spellings and every user in the repository**:
  the harness, examples, benches and docs. The node has no code that turns a
  config back into arguments.
- **P8. A parameter nobody sets differently becomes a constant.** The PR says
  how that was checked.

## Not followed yet

Good practice the node does not follow today, to adopt over time.

- **Secrets from files or a secret store.** Keys arrive as env variables,
  which child processes inherit and crash dumps can capture. Flags accept
  them too, which shows them in the process list.
- **Refusing unknown variables.** A mistyped or retired `MPC_*` variable is
  ignored silently.
- **A deprecation step.** A renamed or removed parameter breaks at once,
  instead of the old name working with a warning for one release. The
  two-phase rule in releasing.md covers contract and wire formats only.
- **Checking a configuration before deploying it.** The only check is to
  start the node. No command validates the parameters and exits, and the
  node logs its identity and hosts, not the full set of values it uses.
