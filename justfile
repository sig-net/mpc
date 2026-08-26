# MPC integration test runner
# Install just: https://just.systems/man/en/packages.html

# List available recipes
default:
    @just --list

# Build WASM contract + local mpc-node binary
# Pass helios=1 to enable Helios: just setup helios=1
setup helios="":
    {{ if helios != "" { "MPC_ENABLE_HELIOS=1 ./setup.sh" } else { "./setup.sh" } }}
alias s := setup

# Remove Docker networks and containers leaked by killed test runs
# (nextest timeouts / Ctrl-C skip the in-process cleanup). Safe to run
# anytime: networks owned by still-running processes are skipped.
test-clean:
    #!/usr/bin/env sh
    docker info >/dev/null 2>&1 || exit 0
    for n in $(docker network ls --filter name=mpc_it_ --format '{{"{{"}}.Name}}'); do
        pid=${n#mpc_it_}; pid=${pid%%_*}
        ps -p "$pid" >/dev/null 2>&1 && continue
        docker rm -f $(docker ps -aq --filter network="$n") >/dev/null 2>&1 || true
        docker network rm "$n" >/dev/null 2>&1 || true
    done

# Run all integration tests
# Usage: just t [filter] [helios=1]
test filter="" helios="": test-clean (setup helios)
    cargo nextest run -p integration-tests {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias t := test

# Run only lightweight fixture tests (no full cluster or Docker beyond Redis)
# Usage: just tf [filter] [helios=1]
test-fixture filter="" helios="": test-clean (setup helios)
    cargo nextest run -p integration-tests --profile fixture {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tf := test-fixture

# Run only full cluster tests
# Usage: just tc [filter] [helios=1]
test-cluster filter="" helios="": test-clean (setup helios)
    cargo nextest run -p integration-tests --profile cluster {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tc := test-cluster

# Run a single test by name, keeping containers alive for inspection
# Usage: just to <name> [helios=1]
test-one name helios="": test-clean (setup helios)
    TESTCONTAINERS=keep cargo nextest run -p integration-tests -E 'test({{name}})'
alias to := test-one

# Run all tests keeping containers alive
# Usage: just tk [filter] [helios=1]
test-keep filter="" helios="": test-clean (setup helios)
    TESTCONTAINERS=keep cargo nextest run -p integration-tests {{ if filter != "" { "-E 'test(" + filter + ")'" } else { "" } }}
alias tk := test-keep

# Run all tests sequentially (single-threaded)
# Usage: just ts [filter] [helios=1]
test-seq filter="" helios="": test-clean (setup helios)
    cargo test -p integration-tests --jobs 1 -- --test-threads 1 {{ if filter != "" { filter } else { "" } }}
alias ts := test-seq
