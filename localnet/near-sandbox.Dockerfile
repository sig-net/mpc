# A NEAR sandbox image that runs natively on both arm64 and amd64.
#
# NEAR's own `ghcr.io/near/sandbox` is not usable here. Its `latest` tag is amd64-only, and
# on an Apple Silicon host that means emulation: plain qemu-user hangs neard at 0% CPU, and
# Rosetta is on its way out of macOS. Its `latest-aarch64` tag is native but was built in
# 2023 against nearcore 1.35.0, which is too old for the near-workspaces version this
# repository uses. It fails with a missing `genesis_hash` field.
#
# NEAR does publish Linux-aarch64 sandbox binaries, from nearcore 2.6.5 onwards. They are
# simply newer than the 2.3.1 that near-sandbox-utils 0.12.0 defaults to, which is why the
# tooling reports arm64 as unsupported. Downloading one directly gives a native image on
# both architectures without compiling nearcore.
FROM debian:stable-slim

# First version with Linux-aarch64 builds, and the closest such version to the 2.3.1 that
# near-workspaces 0.15.0 was written against. Newer versions up to 2.13.2 also publish
# arm64 binaries if this ever needs moving.
ARG NEAR_SANDBOX_VERSION=2.6.5

RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# The architecture comes from `uname -m` rather than BuildKit's TARGETARCH, so this builds
# under the classic builder too, and because its output already matches the names NEAR
# publishes under.
RUN set -eu; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      aarch64) platform=Linux-aarch64 ;; \
      x86_64)  platform=Linux-x86_64 ;; \
      *) echo "no near-sandbox build published for ${arch}" >&2; exit 1 ;; \
    esac; \
    curl --fail --silent --show-error --location \
      "https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/${platform}/${NEAR_SANDBOX_VERSION}/near-sandbox.tar.gz" \
      | tar xz -C /tmp; \
    mv "/tmp/${platform}/near-sandbox" /usr/local/bin/near-sandbox; \
    chmod +x /usr/local/bin/near-sandbox; \
    rm -rf "/tmp/${platform}"

# Initialising at build time makes genesis part of the image rather than something generated
# per container, so restarting keeps the same chain.
#
# --test-seed makes the root account's key a function of the seed instead of random, so the
# bootstrap can derive it rather than having it passed in or read out of a shared volume.
# --chain-id keeps that stable too, since init otherwise invents a random one.
# --fast shortens block production, which is what you want locally and nowhere else.
ARG NEAR_ROOT_ACCOUNT=test.near
RUN near-sandbox --home /root/.near init \
    --chain-id localnet \
    --account-id "${NEAR_ROOT_ACCOUNT}" \
    --test-seed "${NEAR_ROOT_ACCOUNT}" \
    --fast

EXPOSE 3030 24567
ENTRYPOINT ["near-sandbox", "--home", "/root/.near", "run"]
