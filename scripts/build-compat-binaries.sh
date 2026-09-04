#!/usr/bin/env bash

# Builds production compatibility binaries from tagged releases and stores them
# under target/compat/<channel>/<version>/release/mpc-node so integration tests
# can boot historical nodes without checking binaries into git.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS_FILE="$REPO_ROOT/scripts/prod-compat-versions.json"
TARGET_ROOT="$REPO_ROOT/target/compat"
WORKTREES_ROOT="$TARGET_ROOT/worktrees"
FORCE_REBUILD="${FORCE_REBUILD:-0}"
CHANNELS=("testnet" "mainnet")

if [[ ! -f "$VERSIONS_FILE" ]]; then
  echo "Compatibility versions file not found at $VERSIONS_FILE" >&2
  exit 1
fi

mkdir -p "$TARGET_ROOT" "$WORKTREES_ROOT"
cd "$REPO_ROOT"

declare -a ACTIVE_WORKTREES=()
cleanup() {
  for worktree in "${ACTIVE_WORKTREES[@]}"; do
    if [[ -d "$worktree" ]]; then
      git worktree remove "$worktree" --force >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

get_version() {
  local channel="$1"
  jq -r --arg channel "$channel" \
    'if has($channel) then .[$channel] else error("Unknown compatibility channel \($channel).") end' "$VERSIONS_FILE"
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "This script must be run inside the git repository." >&2
  exit 1
fi

echo "Fetching tagged releases..."
git fetch --tags --force >/dev/null 2>&1

for channel in "${CHANNELS[@]}"; do
  version="$(get_version "$channel")"
  target_dir="$TARGET_ROOT/$channel/$version"
  binary_path="$target_dir/release/mpc-node"

  if [[ -f "$binary_path" && "$FORCE_REBUILD" != "1" ]]; then
    echo "➡️  ${channel} ${version} binary already exists at $binary_path (set FORCE_REBUILD=1 to rebuild)."
    continue
  fi

  worktree_dir="$WORKTREES_ROOT/${channel}-${version}"
  if [[ -d "$worktree_dir" ]]; then
    git worktree remove "$worktree_dir" --force >/dev/null 2>&1 || true
  fi

  echo "📦 Building $channel binary from tag $version..."
  git worktree add "$worktree_dir" "$version" >/dev/null
  ACTIVE_WORKTREES+=("$worktree_dir")

  mkdir -p "$target_dir"
  (
    cd "$worktree_dir"
    CARGO_TARGET_DIR="$target_dir" cargo build -p mpc-node --release --locked
  )

  git worktree remove "$worktree_dir" --force >/dev/null
  echo "✅ Stored $channel binary at $binary_path"
done

echo "All requested compatibility binaries are ready under $TARGET_ROOT"
