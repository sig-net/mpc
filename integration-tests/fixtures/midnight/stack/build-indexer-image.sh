#!/usr/bin/env bash
# Builds the pinned midnight-indexer standalone image for the ledger-9 stack.
#
# The contractEvents GraphQL API only exists on the unreleased `contract-events-e2e`
# branch, so the image is built from a pinned commit rather than pulled. The tag is
# the commit's short-8 hash, matching the repo's own `just build-docker-image` recipe.
set -euo pipefail

COMMIT=c7c267ccba475c5bf63425117843e7f20164ee80
TAG="midnightntwrk/indexer-standalone:${COMMIT:0:8}"

if docker image inspect "$TAG" >/dev/null 2>&1; then
  echo "$TAG already present"
  exit 0
fi

DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT

git clone --no-checkout https://github.com/midnightntwrk/midnight-indexer "$DIR"
git -C "$DIR" checkout "$COMMIT"

RUST_VERSION=$(grep channel "$DIR/rust-toolchain.toml" | sed -r 's/channel = "(.*)"/\1/')

docker build \
  --build-arg "RUST_VERSION=$RUST_VERSION" \
  --build-arg "PROFILE=dev" \
  -t "$TAG" \
  -f "$DIR/indexer-standalone/Dockerfile" \
  "$DIR"

echo "built $TAG"
