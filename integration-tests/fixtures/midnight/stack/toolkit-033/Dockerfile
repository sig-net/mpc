# midnight-node-toolkit with a compact-0.33 toolkit-js variant.
#
# The stock 2.0.0-rc.3 toolkit image only ships toolkit-js workspaces for
# compactc 0.29/0.30/0.31. This adds a compact-0.33 workspace (pinning
# @midnight-ntwrk/compact-js* 2.5.5-rc.5, the line matching compactc 0.33 /
# compact-runtime 0.18) and patches the built compactc-resolver to accept
# COMPACTC_VERSION=0.33 and to also intercept @midnight-ntwrk/platform-js,
# @midnightntwrk/ledger-v9 and @midnightntwrk/onchain-runtime-v4 imports
# (compactc-resolver.js here is the upstream dist file with those two hunks —
# see build-toolkit-image.sh for the diff).
#
# Build: ./build-toolkit-image.sh  →  signet/midnight-node-toolkit:2.0.0-rc.3-compact033
FROM midnightntwrk/midnight-node-toolkit:2.0.0-rc.3

# Build the variant workspace OUTSIDE /toolkit-js first: the toolkit-js root
# package.json declares workspaces ["." , "compact-*"], so npm run inside
# /toolkit-js/compact-0.33 would switch context to the root project and demand
# the root lockfile know about it. Building in isolation and moving the result
# into place reproduces the shipped layout (each compact-* variant carries its
# own nested node_modules).
COPY compact-0.33/package.json compact-0.33/package-lock.json compact-0.33/tsconfig.json compact-0.33/tsconfig.base.json /build/compact-0.33/
COPY compact-0.33/src /build/compact-0.33/src

RUN cd /build/compact-0.33 && npm ci --no-audit --no-fund \
    && npm run build \
    && mv /build/compact-0.33 /toolkit-js/compact-0.33 \
    && rmdir /build

COPY compactc-resolver.js /toolkit-js/dist/compactc-resolver.js
