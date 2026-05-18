set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

contract:
    ./build-contract.sh

node:
    cargo build-node

unit *args:
    ./scripts/unit.sh {{args}}

it *args:
    ./scripts/it.sh {{args}}

run nodes threshold='':
    ./scripts/run-env.sh {{nodes}} {{threshold}}

sign *args:
    ./scripts/sign-env.sh {{args}}

reshare *args:
    ./scripts/reshare-env.sh {{args}}

env action='status' target='':
    @if [[ "{{action}}" == "status" ]]; then python3 ./scripts/env_manager.py status; \
    elif [[ "{{action}}" == "kill" ]]; then python3 ./scripts/env_manager.py kill; \
    else echo "unknown env action: {{action}}" >&2; exit 1; fi

build target:
    @if [[ "{{target}}" == "docker" ]]; then docker build -t mpc .; else echo "unknown build target: {{target}}" >&2; exit 1; fi

fmt:
    cargo fmt --all

check:
    cargo check --workspace

clean:
    cargo clean

status:
    python3 ./scripts/env_manager.py status
