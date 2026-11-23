#!/bin/sh
# Installs the pinned near-cli-rs (the `near` command) into ~/.cargo/bin from its
# release tarball, checked against the sha256 below. Does nothing when this
# version is installed.
set -eu

VERSION="0.31.1"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu sha256=8b92f4f79f324a882ad79b58d61b91dccc676dd653dc72a1f23693aa5db99e21 ;;
    Darwin-arm64) target=aarch64-apple-darwin sha256=0404ad783c44dad766fe0e0097c5b45e3fbbdbc546f9c7f4e36dfff659c14625 ;;
    *) echo "no pinned near-cli-rs build for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

near --version 2>/dev/null | grep -qF "$VERSION" && exit 0

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 4 -o "$tmp/near-cli-rs.tar.gz" \
    "https://github.com/near/near-cli-rs/releases/download/v$VERSION/near-cli-rs-$target.tar.gz"
echo "$sha256  $tmp/near-cli-rs.tar.gz" | sha256sum -c -
tar xzf "$tmp/near-cli-rs.tar.gz" -C "$tmp"
mkdir -p "$HOME/.cargo/bin"
install -m 755 "$tmp/near-cli-rs-$target/near" "$HOME/.cargo/bin/"
