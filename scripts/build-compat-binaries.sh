#!/usr/bin/env bash

# Builds the mpc-node binary of the latest release tag under
# target/compat/<tag>/release/mpc-node and points target/compat/latest at it,
# so integration tests can boot a previous-release node without checking
# binaries into git.
#
# The tag is the newest X.Y.Z tag that does not point at HEAD (on a release
# commit the newest tag is HEAD itself). Set COMPAT_TAG to build another tag.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="$REPO_ROOT/target/compat"
WORKTREES_ROOT="$TARGET_ROOT/worktrees"
FORCE_REBUILD="${FORCE_REBUILD:-0}"

cd "$REPO_ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "This script must be run inside the git repository." >&2
  exit 1
fi

mkdir -p "$TARGET_ROOT" "$WORKTREES_ROOT"

worktree_dir=""
cleanup() {
  if [[ -n "$worktree_dir" && -d "$worktree_dir" ]]; then
    git worktree remove "$worktree_dir" --force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Fetching tagged releases..."
git fetch --tags --force >/dev/null

if [[ -n "${COMPAT_TAG:-}" ]]; then
  tag="$COMPAT_TAG"
else
  tag="$(git tag --sort=-v:refname --no-contains HEAD | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)"
  if [[ -z "$tag" ]]; then
    echo "No release tag found." >&2
    exit 1
  fi
fi

target_dir="$TARGET_ROOT/$tag"
binary_path="$target_dir/release/mpc-node"

if [[ -f "$binary_path" && "$FORCE_REBUILD" != "1" ]]; then
  echo "➡️  $tag binary already exists at $binary_path (set FORCE_REBUILD=1 to rebuild)."
else
  worktree_dir="$WORKTREES_ROOT/$tag"
  git worktree remove "$worktree_dir" --force >/dev/null 2>&1 || true

  echo "📦 Building mpc-node from tag $tag..."
  git worktree add "$worktree_dir" "$tag" >/dev/null

  mkdir -p "$target_dir"
  (
    cd "$worktree_dir"
    # Old code must not fail on lints added by a newer toolchain.
    CARGO_TARGET_DIR="$target_dir" env -u RUSTFLAGS cargo build -p mpc-node --release --locked --features test-feature
  )

  git worktree remove "$worktree_dir" --force >/dev/null
  worktree_dir=""
  echo "✅ Stored $tag binary at $binary_path"
fi

ln -sfn "$tag" "$TARGET_ROOT/latest"
echo "target/compat/latest -> $tag"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "::notice title=Compatibility target::HEAD vs release $tag"
  echo "Compatibility target: HEAD vs release **$tag**" >> "$GITHUB_STEP_SUMMARY"
fi
