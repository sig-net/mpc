# MPC integration test runner
# Install just: https://just.systems/man/en/packages.html

# List available recipes
default:
    @just --list

# Check system dependencies without installing (Linux/macOS)
# Usage: just setup-check [scope] (scope="" core, or "all" for Solana/Anchor/Java/dpm/Compact too)
setup-check scope="":
    ./scripts/setup-deps.sh --check {{scope}}
alias sc := setup-check

# Install missing system deps (if needed), then build WASM contract + local mpc-node binary
# Pass helios=1 to enable Helios: just setup helios=1
# Pass scope="all" to also install extended chain tooling; install auto-skips on CI (SETUP_DEPS_FORCE=1 to override) and with SETUP_DEPS_SKIP=1
setup helios="" scope="":
    ./scripts/setup-deps.sh --install {{scope}}
    {{ if helios != "" { "MPC_ENABLE_HELIOS=1 ./setup.sh" } else { "./setup.sh" } }}
alias s := setup

# Run all integration tests
# Usage: just t [filter] [helios=1]
test filter="" helios="": (setup helios)
    cargo nextest run -p integration-tests {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias t := test

# Run only lightweight fixture tests (no full cluster or Docker beyond Redis)
# Usage: just tf [filter] [helios=1]
test-fixture filter="" helios="": (setup helios)
    cargo nextest run -p integration-tests --profile fixture {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tf := test-fixture

# Run only full cluster tests
# Usage: just tc [filter] [helios=1]
test-cluster filter="" helios="": (setup helios)
    cargo nextest run -p integration-tests --profile cluster {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tc := test-cluster

# Run a single test by name, keeping containers alive for inspection
# Usage: just to <name> [helios=1]
test-one name helios="": (setup helios)
    TESTCONTAINERS=keep cargo nextest run -p integration-tests -E 'test({{name}})'
alias to := test-one

# Run all tests keeping containers alive
# Usage: just tk [filter] [helios=1]
test-keep filter="" helios="": (setup helios)
    TESTCONTAINERS=keep cargo nextest run -p integration-tests {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tk := test-keep

# Run clippy (mirrors CI: cargo clippy --tests -- -Dclippy::all)
lint:
    cargo clippy --tests -- -Dclippy::all

# Check formatting without modifying files (mirrors CI)
fmt-check:
    cargo fmt -- --check

# Format code with rustfmt
fmt:
    cargo fmt

# Fast unit tests (mirrors CI: no integration-tests, no Docker)
# Usage: just test-unit [filter]
test-unit filter="":
    cargo test --workspace --exclude integration-tests {{filter}}
alias tu := test-unit

# Full CI gate locally: format check + clippy + unit tests
ci: fmt-check lint
    cargo test --workspace --exclude integration-tests
alias c := ci

# Security audit of dependencies (mirrors CI audit job)
audit:
    @if ! command -v cargo-audit >/dev/null; then cargo install cargo-audit --locked; fi
    cargo audit

# Run all tests sequentially (single-threaded)
# Usage: just ts [filter] [helios=1]
test-seq filter="" helios="": (setup helios)
    cargo test -p integration-tests --jobs 1 -- --test-threads 1 {{ if filter != "" { filter } else { "" } }}
alias ts := test-seq

# Build artifacts: `just build` = whole Rust workspace (via setup),
# `just build eth` = EVM artifacts, `just build contract` = NEAR contract wasm,
# `just build midnight` = midnight-publisher-ts fixtures,
# `just build tests` = integration test binaries without running them,
# `just build compat` = historical prod-compat node binaries
# Usage: just build [target] [helios=1] (target="" | eth | contract | midnight | tests | compat)
build target="" helios="":
    @if [ "{{target}}" = "eth" ]; then \
      cd chain-signatures/contract-eth && npm ci && npx hardhat compile; \
    elif [ "{{target}}" = "contract" ]; then \
      ./build-contract.sh && mkdir -p target/wasm32-unknown-unknown/release && cp target/near/mpc_contract/mpc_contract.wasm target/wasm32-unknown-unknown/release/mpc_contract.wasm; \
    elif [ "{{target}}" = "midnight" ]; then \
      cd chain-signatures/midnight-publisher-ts && npm ci && npm run build && npm run compile:real-stack-caller && npm run typecheck:real-stack; \
    elif [ "{{target}}" = "tests" ]; then \
      cargo build -p integration-tests --tests{{ if helios != "" { " --features helios" } else { "" } }}; \
    elif [ "{{target}}" = "compat" ]; then \
      ./scripts/build-compat-binaries.sh; \
    elif [ -z "{{target}}" ]; then \
      just setup {{helios}} && cargo build --workspace; \
    else \
      echo "Unknown build target: {{target}} (expected '' | eth | contract | midnight | tests | compat)" >&2; exit 1; \
    fi

# Anvil-backed EVM tests: real EVM + real contract bytecode (needs anvil + eth-build output)
# Usage: just test-eth [filter]
test-eth filter="": (build "eth")
    cargo test -p mpc-chain-ethereum --features integration --tests {{filter}}
alias te := test-eth

# Clippy for integration-gated EVM code (mirrors CI)
lint-eth: (build "eth")
    cargo clippy -p mpc-chain-ethereum --tests --features integration -- -Dclippy::all

# EVM contract unit tests (hardhat, no anvil needed)
test-eth-unit:
    cd chain-signatures/contract-eth && npx hardhat test

# Midnight real-stack test (ignored by default; needs Midnight node/indexer/proof-server + anvil)
test-midnight: (setup "")
    cargo nextest run -p integration-tests --test lib --run-ignored only --no-capture -E 'test(=cases::midnight_stream::midnight_to_ethereum_to_midnight_consumes_caller_response)'

# Midnight TS/Rust seam differential (needs dist/ built via npm test in midnight-publisher-ts)
test-midnight-seam:
    cargo nextest run -p mpc-chain-midnight --run-ignored all -E 'binary(intent_seam)'

# Canton tests (default: stream; e2e via `just test-canton cases::canton`)
test-canton filter="canton_stream": (setup "")
    cargo test -p integration-tests --test lib -- {{filter}} --ignored --nocapture --test-threads 1

# Nightly helios suite
test-nightly: (setup "1")
    cargo test -p integration-tests --features helios --test lib -- cases::nightly --show-output --ignored

# Prod-compat suite (needs `just build compat` output)
test-compat:
    ./scripts/test-prod-compat.sh
