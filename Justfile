image := "near/mpc-recovery:latest"
__dup_stdout := "0"

set positional-arguments

@_default:
    echo "Justfile: mpc-recovery" >&2
    echo "" >&2
    echo "Usage: just [image=<IMAGE>] <RECIPE>" >&2
    echo "" >&2
    echo "RECIPE:" >&2
    echo "  docker <TASK> [ARGS...]           Execute docker-related tasks" >&2
    echo "  run <TYPE> [ARGS...]              Execute tests" >&2
    echo "  test [ARGS...]                    Execute all tests" >&2
    echo "" >&2
    echo "INFO:" >&2
    echo "  image=<IMAGE>                     Docker image to use (default: {{image}})" >&2

@_ensure_target:
    mkdir -p target

# (options: run, build, export, cache-relevance)
docker *ARGS:
    @if just -s _docker-${1:-} 2> /dev/null 1>&2; then \
        just __dup_stdout={{__dup_stdout}} _docker-{{ARGS}}; \
    else \
        echo "just docker" >&2; \
        echo "Execute docker-related tasks" >&2; \
        echo "" >&2; \
        echo "Usage: just docker <TASK>" >&2; \
        echo "" >&2; \
        echo "TASK:" >&2; \
        echo "  run [ARGS...]                    Run the mpc-recovery binary inside a docker container" >&2; \
        echo "  build                            Build the docker image, and conditionally export the cargo build artifacts" >&2; \
        echo "  export                           Export cargo build artifacts from the docker image" >&2; \
        echo "  cache-relevance                  Check if the cargo build artifacts have changed since the last docker build" >&2; \
        echo "" >&2; \
        echo "INFO:" >&2; \
        echo "  image=<IMAGE>                    Docker image to use (default: {{image}})" >&2; \
    fi

# run the mpc-recovery binary inside a docker container
_docker-run *ARGS:
    docker run -it --rm {{image}} {{ARGS}}

# build the docker image, and conditionally export the cargo build artifacts
_docker-build:
    @just _ensure_target
    docker build -t {{image}} .
    @if [[ `just __dup_stdout=1 docker cache-relevance` != *"cache hit, no update required"* ]]; then \
        just docker export; \
    fi

# check if the cargo build artifacts have changed since the last docker build
@_docker-cache-relevance:
    just _ensure_target
    if [ -f target/docker-cache.tgz ]; then \
        echo -e "\x1b[1mExtracting artifact snapshot from docker image...\x1b[0m" >&2; \
        latest_stamp_stage=$(mktemp -d); \
        docker build . --target retrieve-stamp --output $latest_stamp_stage; \
        printf "\x1b[1mTesting for cache relevance...\x1b[0m" >&2; \
        cached_stamp_stage=$(mktemp -d); \
        tar -C $cached_stamp_stage -xzf target/docker-cache.tgz usr/src/app/target/.stamp --strip-components 5; \
        if ! diff -qr $latest_stamp_stage $cached_stamp_stage; \
            then \
                echo -e "\x1b[1mcache invalidated, update required\x1b[0m" >&2; \
            else \
                echo -e "\x1b[1mcache hit, no update required\x1b[0m" \
                | tee >(cat >&2) {{ if __dup_stdout == "0" { "> /dev/null" } else { "" } }}; \
        fi; \
        rm -rf $cached_stamp_stage $latest_stamp_stage; \
    else \
        printf "\x1b[1mTesting for cache relevance...\x1b[0m" >&2; \
        echo -e "\x1b[1mno previous cache found!\x1b[0m" >&2; \
    fi

# export cargo build artifacts from the docker image
_docker-export:
    @just _ensure_target
    set -o pipefail; docker build . --target export-artifacts --output - | gzip > target/docker-cache.tar.gz
    mv target/docker-cache.{tar.gz,tgz}

# run all tests in the workspace
test *ARGS:
    cargo test --workspace {{ARGS}}

# run tests (options: unit-tests, integration-tests)
run *ARGS:
    @if just -s _run-${1:-} 2> /dev/null 1>&2; then \
        just _run-{{ARGS}}; \
    else \
        echo "just run" >&2; \
        echo "Execute tests" >&2; \
        echo "" >&2; \
        echo "Usage: just run <TYPE>" >&2; \
        echo "" >&2; \
        echo "TYPE:" >&2; \
        echo "  unit-tests [ARGS...]             Run unit tests" >&2; \
        echo "  integration-tests [ARGS...]      Run integration tests" >&2; \
    fi

_run-integration-tests *ARGS:
    @just test -p mpc-recovery-integration-tests {{ARGS}}

_run-unit-tests *ARGS:
    @just test --exclude mpc-recovery-integration-tests {{ARGS}}
