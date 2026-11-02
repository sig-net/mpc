# mpc-tron-wire

The Tron transaction wire format for the MPC chain-signatures stack:
hand-declared protobuf messages (`pb`), canonical parsing and signing
derivations (`tx`), address forms (`address`), and the reference-block
field derivation (`types`). Pure — no RPC client; the client and
receipts live in [`mpc-chain-tron`](../chain-tron).

Separate so source crates can assemble Tron transactions without
depending on a chain integration (as they use `alloy` for EVM).

`tests/golden.rs` replays recorded mainnet USDT transfers: proto
round-trip, ref-block derivation, assembly, signing, and txID all
reproduce recorded transactions byte-for-byte.
