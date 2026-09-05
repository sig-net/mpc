#!/bin/sh
# Check or install local dev dependencies (Linux + macOS).
#
# Usage:
#   ./scripts/setup-deps.sh --check [scope]
#   ./scripts/setup-deps.sh --install [scope]
#   SETUP_DEPS_SKIP=1 ./scripts/setup-deps.sh --install  # no-op for fast loops
#
# scope is "" (core) or "all" / "extended" (core + Solana, Anchor, Java,
# dpm/Canton SDK, Compact). Core covers building the workspace, unit tests,
# fixture/cluster integration tests, and Anvil EVM tests.

set -u

RUST_VERSION="1.93.0"
WASM_TARGET="wasm32-unknown-unknown"
REDIS_IMAGE="redis:7.4.2"
SOLANA_VERSION="2.3.9"
ANCHOR_VERSION="0.30.1"
CANTON_SDK="3.5.1"
COMPACT_RC="0.33.0-rc.2"

MODE="${1:-}"
SCOPE="${2:-}"
EXTENDED=0
if [ "$SCOPE" = "all" ] || [ "$SCOPE" = "extended" ] || [ "$SCOPE" = "--extended" ]; then
    EXTENDED=1
fi

OS="$(uname -s)"
FAIL=0
PATH_HINT=0

ok() { printf 'ok - %s\n' "$1"; }
miss() { FAIL=$((FAIL + 1)); printf 'missing - %s\n' "$1"; }
hint() { printf '  fix: %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

on_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

note_path_dir() {
    if [ -d "$1" ] && ! on_path "$1"; then
        PATH_HINT=1
    fi
}

check_core() {
    if have rustup; then ok "rustup $(rustup --version 2>/dev/null | head -n 1)"; else miss "rustup"; hint "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"; fi
    if have cargo; then ok "cargo $(cargo --version)"; else miss "cargo (via rustup)"; fi
    if rustup toolchain list 2>/dev/null | grep -q "^${RUST_VERSION}"; then ok "rust ${RUST_VERSION} toolchain"; else miss "rust ${RUST_VERSION} toolchain"; hint "rustup toolchain install ${RUST_VERSION}"; fi
    if rustup component list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "clippy.*(installed)"; then ok "clippy ${RUST_VERSION}"; else miss "clippy ${RUST_VERSION}"; hint "rustup component add --toolchain ${RUST_VERSION} clippy"; fi
    if rustup component list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "rustfmt.*(installed)"; then ok "rustfmt ${RUST_VERSION}"; else miss "rustfmt ${RUST_VERSION}"; hint "rustup component add --toolchain ${RUST_VERSION} rustfmt"; fi
    if rustup target list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "${WASM_TARGET} (installed)"; then ok "${WASM_TARGET} target"; else miss "${WASM_TARGET} target"; hint "rustup target add --toolchain ${RUST_VERSION} ${WASM_TARGET}"; fi
    if have cargo-near; then ok "cargo-near $(cargo-near --version 2>/dev/null | head -n 1)"; else miss "cargo-near"; hint "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/cargo-near/releases/latest/download/cargo-near-installer.sh | sh"; fi
    if have cargo-nextest; then ok "cargo-nextest $(cargo-nextest --version 2>/dev/null | head -n 1)"; else miss "cargo-nextest"; hint "curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ~/.cargo/bin (macos: .../latest/mac)"; fi
    if have cargo-audit; then ok "cargo-audit $(cargo-audit --version 2>/dev/null | head -n 1)"; else miss "cargo-audit"; hint "cargo install cargo-audit --locked"; fi
    if have just; then ok "just $(just --version)"; else miss "just"; hint "curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.cargo/bin"; fi
    if have git; then ok "git"; else miss "git"; fi
    if have curl; then ok "curl"; else miss "curl"; fi
    if have pkg-config; then ok "pkg-config"; else miss "pkg-config"; fi
    if pkg-config --exists openssl 2>/dev/null || have openssl; then ok "openssl"; else miss "openssl (system libssl)"; fi
    if have protoc; then ok "protoc"; else miss "protoc"; fi
    if have clang || have cc; then ok "clang ($({ command -v clang || command -v cc; } 2>/dev/null))"; else miss "clang"; fi
    if [ "$OS" = "Darwin" ] && [ ! -x "/opt/homebrew/opt/llvm/bin/clang" ]; then miss "homebrew llvm clang (wasm builds)"; hint "brew install llvm"; fi
    if have docker && docker info >/dev/null 2>&1; then ok "docker"; else miss "docker daemon"; hint "rerun just setup to install Docker (Desktop on macOS, docker.io on Linux), then launch/start it"; fi
    if have docker && docker info >/dev/null 2>&1; then
        if docker images -q "$REDIS_IMAGE" 2>/dev/null | grep -q .; then ok "${REDIS_IMAGE} image"; else printf 'note - %s image not cached; testcontainers pulls it on first run\n' "$REDIS_IMAGE"; fi
    fi
    if have node; then
        MAJOR="$(node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')"
        if [ -n "$MAJOR" ] && [ "$MAJOR" -ge 18 ]; then ok "node $(node -v)"; else miss "node >= 18 (found $(node -v))"; fi
    else
        miss "node >= 18"
    fi
    if have npm; then ok "npm"; else miss "npm (ships with node)"; fi
    if have anvil; then ok "anvil"; else miss "anvil (foundry)"; hint "curl -L https://foundry.paradigm.xyz | bash && foundryup"; fi
}

check_extended() {
    if have solana && solana --version 2>/dev/null | grep -q "$SOLANA_VERSION"; then ok "solana $(solana --version)"; else miss "solana ${SOLANA_VERSION}"; fi
    if have anchor && anchor --version 2>/dev/null | grep -q "$ANCHOR_VERSION"; then ok "anchor $(anchor --version)"; else miss "anchor ${ANCHOR_VERSION}"; hint "cargo install --git https://github.com/coral-xyz/anchor avm --locked && avm install ${ANCHOR_VERSION}"; fi
    if java -version 2>&1 | grep -q "21"; then ok "java 21"; else miss "java 21 (temurin)"; fi
    if have dpm; then ok "dpm $(dpm --version 2>/dev/null | head -n 1)"; else miss "dpm (Canton SDK ${CANTON_SDK})"; hint "curl -fsSL https://get.digitalasset.com/install/install.sh | sh && dpm install ${CANTON_SDK}"; fi
    if have compact; then ok "compact"; else miss "compact launcher 0.5.1 + compactc ${COMPACT_RC}"; hint "see .github/workflows/midnight.yml (Linux pins)"; fi
}

apt_install() {
    PKGS=""
    have curl || PKGS="$PKGS curl"
    have git || PKGS="$PKGS git"
    have pkg-config || PKGS="$PKGS pkg-config"
    pkg-config --exists openssl 2>/dev/null || PKGS="$PKGS libssl-dev"
    have protoc || PKGS="$PKGS protobuf-compiler"
    if ! have clang && ! have cc; then PKGS="$PKGS clang"; fi
    if [ -z "$PKGS" ]; then return 0; fi
    # shellcheck disable=SC2086
    sudo apt-get update && sudo apt-get install -y $PKGS
}

brew_install() {
    have brew || { miss "homebrew"; hint "/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""; return 1; }
    have pkg-config || brew install pkg-config
    pkg-config --exists openssl 2>/dev/null || brew install openssl@3
    have protoc || brew install protobuf
    if [ ! -x "/opt/homebrew/opt/llvm/bin/clang" ]; then brew install llvm; fi
}

ensure_rust() {
    if ! have rustup; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; fi
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    if ! rustup toolchain list 2>/dev/null | grep -q "^${RUST_VERSION}"; then
        rustup toolchain install "$RUST_VERSION" --component clippy rustfmt --target "$WASM_TARGET"
        return 0
    fi
    rustup component list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "clippy.*(installed)" || rustup component add --toolchain "$RUST_VERSION" clippy
    rustup component list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "rustfmt.*(installed)" || rustup component add --toolchain "$RUST_VERSION" rustfmt
    rustup target list --toolchain "$RUST_VERSION" 2>/dev/null | grep -q "${WASM_TARGET} (installed)" || rustup target add --toolchain "$RUST_VERSION" "$WASM_TARGET"
}

ensure_nextest() {
    have cargo-nextest && return 0
    mkdir -p "$HOME/.cargo/bin"
    case "$OS" in
        Linux) NEXTEST_OS="linux" ;;
        Darwin) NEXTEST_OS="mac" ;;
        *) return 1 ;;
    esac
    curl -LsSf "https://get.nexte.st/latest/${NEXTEST_OS}" | tar zxf - -C "$HOME/.cargo/bin"
}

ensure_cargo_near() {
    have cargo-near && return 0
    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/cargo-near/releases/latest/download/cargo-near-installer.sh | sh
}

ensure_cargo_audit() {
    have cargo-audit && return 0
    cargo install cargo-audit --locked
}

ensure_foundry() {
    have anvil && return 0
    curl -L https://foundry.paradigm.xyz | bash
    "$HOME/.foundry/bin/foundryup"
    note_path_dir "$HOME/.foundry/bin"
}

ensure_node() {
    if have node; then
        MAJOR="$(node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')"
        if [ -n "$MAJOR" ] && [ "$MAJOR" -ge 18 ]; then return 0; fi
    fi
    case "$OS" in
        Darwin) brew install node ;;
        Linux) curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs ;;
        *) return 1 ;;
    esac
}

ensure_docker() {
    if have docker && docker info >/dev/null 2>&1; then return 0; fi
    case "$OS" in
        Darwin)
            if [ ! -d "/Applications/Docker.app" ] && [ ! -d "$HOME/Applications/Docker.app" ]; then brew install --cask docker; fi
            pgrep -x "Docker" >/dev/null 2>&1 || open -a Docker 2>/dev/null || true
            printf 'waiting for docker daemon...'
            i=0
            while [ "$i" -lt 36 ]; do
                if docker info >/dev/null 2>&1; then printf ' up\n'; return 0; fi
                sleep 5
                printf '.'
                i=$((i + 1))
            done
            printf '\nnote - launch Docker Desktop and re-run\n'
            return 1
            ;;
        Linux)
            have docker || { sudo apt-get update && sudo apt-get install -y docker.io; }
            sudo systemctl enable --now docker 2>/dev/null || sudo service docker start 2>/dev/null || true
            if docker info >/dev/null 2>&1; then return 0; fi
            printf 'note - start the daemon (sudo systemctl start docker) and ensure your user can reach it\n'
            return 1
            ;;
        *)
            return 1
            ;;
    esac
}

ensure_extended() {
    case "$OS" in
        Linux) sh -c "$(curl -sSfL "https://release.solana.com/v${SOLANA_VERSION}/solana-install-init-x86_64-unknown-linux-gnu")" ;;
        Darwin) sh -c "$(curl -sSfL "https://release.solana.com/v${SOLANA_VERSION}/solana-install-init-x86_64-apple-darwin")" ;;
        *) return 1 ;;
    esac
    note_path_dir "$HOME/.local/share/solana/install/active_release/bin"
    if ! have anchor; then
        cargo install --git https://github.com/coral-xyz/anchor avm --locked
        "$HOME/.cargo/bin/avm" install "$ANCHOR_VERSION" || avm install "$ANCHOR_VERSION"
    fi
    if ! java -version 2>&1 | grep -q "21"; then
        case "$OS" in
            Darwin) brew install --cask temurin@21 ;;
            Linux) printf 'note - install Temurin 21: https://adoptium.net/installation/linux/\n' ;;
        esac
    fi
    if ! have dpm; then
        curl -fsSL https://get.digitalasset.com/install/install.sh | sh
        "$HOME/.dpm/bin/dpm" install "$CANTON_SDK" || dpm install "$CANTON_SDK"
        note_path_dir "$HOME/.dpm/bin"
    fi
    if [ "$OS" = "Linux" ] && ! have compact; then
        curl --proto '=https' --tlsv1.2 -LsSf --retry 4 -o /tmp/compact-installer.sh https://github.com/midnightntwrk/compact/releases/download/compact-v0.5.1/compact-installer.sh
        sh /tmp/compact-installer.sh
        RC_DIR="$HOME/.compact/versions/${COMPACT_RC}/x86_64-unknown-linux-musl"
        mkdir -p "$RC_DIR"
        curl -fsSL --retry 4 -o /tmp/compactc-rc.zip "https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v${COMPACT_RC}/compactc_v${COMPACT_RC}_x86_64-unknown-linux-musl.zip"
        unzip -qo /tmp/compactc-rc.zip -d "$RC_DIR"
        chmod +x "$RC_DIR"/*
        compact update "$COMPACT_RC" || ln -sfn "$RC_DIR"/* "$HOME/.compact/bin/"
        note_path_dir "$HOME/.local/bin"
        note_path_dir "$HOME/.compact/bin"
    fi
}

case "$MODE" in
    --check)
        printf 'checking %s dependencies on %s...\n' "$([ "$EXTENDED" = 1 ] && echo core+extended || echo core)" "$OS"
        check_core
        [ "$EXTENDED" = 1 ] && check_extended
        if [ "$FAIL" -gt 0 ]; then printf '%d missing requirement(s)\n' "$FAIL"; exit 1; fi
        printf 'all requirements met\n'
        ;;
    --install)
        if [ "${SETUP_DEPS_SKIP:-0}" = "1" ]; then printf 'skipping dependency install (SETUP_DEPS_SKIP=1)\n'; exit 0; fi
        if [ "${SETUP_DEPS_FORCE:-0}" != "1" ] && { [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; }; then
            printf 'skipping dependency install (CI detected; SETUP_DEPS_FORCE=1 to override)\n'
            exit 0
        fi
        case "$OS" in
            Linux) apt_install ;;
            Darwin) brew_install ;;
            *) printf 'unsupported OS: %s (Linux/macOS only)\n' "$OS"; exit 1 ;;
        esac
        ensure_rust
        ensure_nextest
        ensure_cargo_near
        ensure_cargo_audit
        ensure_node
        ensure_foundry
        ensure_docker || true
        [ "$EXTENDED" = 1 ] && ensure_extended
        note_path_dir "$HOME/.cargo/bin"
        printf 'install pass done, re-checking...\n'
        FAIL=0
        check_core
        [ "$EXTENDED" = 1 ] && check_extended
        if [ "$PATH_HINT" = 1 ]; then hint "export PATH=\"\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$HOME/.local/bin:\$PATH\""; fi
        if [ "$FAIL" -gt 0 ]; then printf '%d missing requirement(s) remain\n' "$FAIL"; exit 1; fi
        printf 'all requirements met\n'
        ;;
    *)
        printf 'usage: %s --check|--install [all|extended]\n' "$0"
        exit 2
        ;;
esac
