# Integration tests

## Basic guide

Running integration tests requires you to have redis and sandbox docker images present on your machine:

```BASH
docker pull redis:7.4.2
```

In case of authorization issues make sure you have logged into docker using your [access token](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic).

Then run the integration tests:

```BASH
cargo test -p integration-tests --jobs 1 -- --test-threads 1
# or if you want to run tests in docker
cargo test -p integration-tests --features docker-test
```

## Logging and Tracing
We have three types of logging available:

### FMT
This is the default logging format used for local development. It outputs logs to the console in a human-readable format.

### OTLP
OpenTelemetry Protocol is used for exporting logs to an OpenTelemetry collector. This is useful for integrating with various observability backends.

#### Configuring Local OTLP Logging
1. **Setup OTLP Backend**
Start OTLP backend of your choice. For example [Jaeger](https://www.jaegertracing.io/docs/getting-started/).

2. **Set the OTLP Endpoint**:
    - By default, the endpoint is set to `http://localhost:4318`.
    - To change it, set the environment variable `MPC_OTLP_ENDPOINT` or pass it as a parameter when starting the node with `--otlp-endpoint` flag.

3. **Set the OpenTelemetry Logging Level**:
    - By default, the logging level is set to `off` when parameters are skipped and to `debug` when running the integration tests cluster.
    - To change it, pass `-opentelemetry-level` value when starting the node, or set the environment variable `MPC_OPENTELEMETRY_LEVEL` to the desired level (`debug`, `info`, etc.).

4. **Explore traces**:
- Start the cluster or run tests
- Open the page of your backend in browser
- Explore traces

### Stackdriver
This logging format is used exclusively in Google Cloud Platform (GCP). It integrates with Google Cloud's operations suite (formerly Stackdriver) to provide structured logging.

## Benchmarking

Benchmarks collect metrics from node and represent them in a readable format for CI to pick up.

To run benchmarks, simply run the `bench.sh` script in the root:
```sh
./bench.sh
```

### Benchmark contract

The current local performance baseline is defined around a small, reproducible
scenario so future optimizations can be compared against the same workload.

- Build mode: release
- Baseline cluster: 3 nodes, threshold 2
- Key setup: pregenerated keys enabled
- Stockpile mode: warm stockpile
- Request volume: 30 end-to-end sign requests
- Primary KPI: sign latency
- Supporting metrics:
    - `sig(e2e) latency` from [benches/sign.rs](benches/sign.rs)
    - `sig(metrics) generation latency` from `/bench/metrics`
    - `presig(metrics) generation latency` from `/bench/metrics`
    - request stage latency from [../chain-signatures/node/src/metrics/requests.rs](../chain-signatures/node/src/metrics/requests.rs)

This baseline is intentionally warm-stockpile. It isolates the steady-state sign
path and avoids mixing sign latency with initial key generation and stockpile
ramp-up costs.

### Benchmark matrix

The work should proceed using the following benchmark matrix, in order:

| Priority | Scenario | Purpose | Status |
| --- | --- | --- | --- |
| 1 | Local, 3 nodes, warm stockpile | Baseline steady-state sign latency | Implemented |
| 2 | Local, 3 nodes, cold stockpile | Measure stockpile depletion and replenishment cost | Implemented |
| 3 | Local, 5 nodes, warm stockpile | Compare scaling with pregenerated keys | Planned |
| 4 | Local, 5 nodes, cold stockpile | Measure steady-state vs recovery under higher quorum | Planned |
| 5 | Local chain-specific flows: Solana | Separate indexer ingress latency from MPC latency | Planned |
| 6 | Local chain-specific flows: Ethereum | Separate finality / optimistic path cost from MPC latency | Planned |
| 7 | Local chain-specific flows: Hydration | Measure request ingestion and response publication cost | Planned |
| 8 | Integration-only NEAR path | Quantify poll-based request admission overhead | Planned |

### Implemented suites

- [benches/sign.rs](benches/sign.rs): warm and cold end-to-end sign latency
- [benches/micro.rs](benches/micro.rs): serialization and cryptographic micro-benchmarks
- [benches/async_stress.rs](benches/async_stress.rs): Tokio task, channel, and lock stress benchmarks

### Interpreting benchmark results

- Warm-stockpile runs answer: "How fast is the steady-state sign path?"
- Cold-stockpile runs answer: "How much latency is hidden by prestockpiling?"
- Chain-specific runs answer: "How much latency comes from indexing and publish paths instead of MPC generation?"

When comparing results, keep node count, threshold, stockpile mode, and chain
path fixed. Do not compare a warm-stockpile Solana run directly against a cold
stockpile Ethereum run.

## Production compatibility tests

Historical compatibility tests boot one node from the latest code and one node
from the production tags (`testnet` = 1.10.0, `mainnet` = 1.1.2). To run them
locally:

1. Build the tagged binaries (only needed once per version):
    ```bash
    ./scripts/build-compat-binaries.sh
    ```
    Set `FORCE_REBUILD=1` if you need to rebuild an existing binary.
2. Execute the tests:
    ```bash
    ./scripts/test-prod-compat.sh
    ```

The build script generates binaries under `target/compat/<channel>/<version>` so
the integration test cluster can spawn historical nodes without checking
artifacts into git.

## FAQ

### I want to run a test, but keep the docker containers from being destroyed

You can pass environment variable `TESTCONTAINERS=keep` to keep all of the docker containers. For example:

```bash
$ TESTCONTAINERS=keep cargo test -p integration-tests --jobs 1 -- --test-threads 1
```

### There are no logs anymore, how do I debug?

The easiest way is to run one isolated test of your choosing while keeping the containers (see above):

```bash
$ TESTCONTAINERS=keep cargo test -p integration-tests test_basic_action
```

Now, you can do `docker ps` and it should list all of containers related to your test (the most recent ones are always at the top, so lookout for those). For example:

```bash
CONTAINER ID   IMAGE                                            COMMAND                  CREATED         STATUS         PORTS                                           NAMES
b2724d0c9530   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32792->19985/tcp, :::32792->19985/tcp   fervent_moore
67308ab06c5d   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32791->3000/tcp, :::32791->3000/tcp     upbeat_volhard
65ec65384af4   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32790->3000/tcp, :::32790->3000/tcp     friendly_easley
b4f90b1546ec   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32789->3000/tcp, :::32789->3000/tcp     vibrant_allen
934ec13d9146   ghcr.io/near/os-relayer:latest                   "/usr/local/bin/entr…"   5 minutes ago   Up 5 minutes   0.0.0.0:32788->16581/tcp, :::32788->16581/tcp   sleepy_grothendieck
c505ead6eb18   redis:latest                                     "docker-entrypoint.s…"   5 minutes ago   Up 5 minutes   0.0.0.0:32787->6379/tcp, :::32787->6379/tcp     trusting_lederberg
2843226b16a9   google/cloud-sdk:latest                          "gcloud beta emulato…"   5 minutes ago   Up 5 minutes   0.0.0.0:32786->15805/tcp, :::32786->15805/tcp   hungry_pasteur
3f4c70020a4c   ghcr.io/near/sandbox:latest                      "near-sandbox --home…"   5 minutes ago   Up 5 minutes                                                   practical_elbakyan
```

Now, you can inspect each container's logs according to your needs using `docker logs <container-id>`. You might also want to reproduce some components of the test manually by making `curl` requests to the leader node (its web port is exposed on your host machine, use `docker ps` output above as the reference).

### How to see all the logs in terminal
```bash
RUST_BACKTRACE=full RUST_LOG=debug cargo test test_name -- --nocapture
```

### Re-building Docker image is way too slow, is there a way I can do a faster development feedback loop?

We have a CLI tool that can instantiate a short-lived development environment that has everything except for the leader node set up. You can then seamlessly plug in your own leader node instance that you have set up manually (the tool gives you a CLI command to use as a starting point, but you can attach debugger, enable extra logs etc). Try it out now (sets up 3 signer nodes):

```bash
$ export RUST_LOG=info
$ cd integration-tests
$ cargo run -- setup-env --nodes 3 --threshold 2
```

### I'm getting "Error: error trying to connect: No such file or directory (os error 2)"

It's a known issue on MacOS. Try executing the following command:

```bash
sudo ln -s $HOME/.docker/run/docker.sock /var/run/docker.sock
```
