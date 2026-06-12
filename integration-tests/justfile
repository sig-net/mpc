# MPC integration test runner
# Install just: https://just.systems/man/en/packages.html

# List available recipes
default:
    @just --list

# Build WASM contract + local mpc-node binary
# Pass helios=1 to enable Helios: just setup helios=1
setup helios="":
    {{ if helios != "" { "MPC_ENABLE_HELIOS=1 ../setup.sh" } else { "../setup.sh" } }}
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

# Run all tests sequentially (single-threaded)
# Usage: just ts [filter] [helios=1]
test-seq filter="" helios="": (setup helios)
    cargo test -p integration-tests --jobs 1 -- --test-threads 1 {{ if filter != "" { filter } else { "" } }}
alias ts := test-seq
