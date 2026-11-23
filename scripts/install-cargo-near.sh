#!/bin/sh
# Installs the pinned cargo-near into ~/.cargo/bin from its release tarball,
# checked against the sha256 below. Does nothing when this version is installed.
set -eu

VERSION="0.23.0"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu sha256=94008b827a457750257eced4b571c33736062cc3bd1ffda3e7af70e2bc9a4073 ;;
    Darwin-arm64) target=aarch64-apple-darwin sha256=9b428181cae9fe655dfcef56a05c849d0cddd859ecaf73d5ebeb6199827cf0d0 ;;
    *) echo "no pinned cargo-near build for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

cargo near --version 2>/dev/null | grep -qF "$VERSION" && exit 0

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 4 -o "$tmp/cargo-near.tar.gz" \
    "https://github.com/near/cargo-near/releases/download/cargo-near-v$VERSION/cargo-near-$target.tar.gz"
echo "$sha256  $tmp/cargo-near.tar.gz" | sha256sum -c -
tar xzf "$tmp/cargo-near.tar.gz" -C "$tmp"
mkdir -p "$HOME/.cargo/bin"
install -m 755 "$tmp/cargo-near-$target/cargo-near" "$HOME/.cargo/bin/"
