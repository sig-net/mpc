## Sig.Network MPC

Sig.Network MPC is a service that facilitates the ability to sign arbitrary payloads by calling into a smart contract and getting back a signature. This signature can be used for various purposes such as deriving new public keys associated with foreign chains (Ethereum, Bitcoin, Cosmos, etc.).

### Features

- **Multi-chain Support**: Sign payloads for Ethereum, Solana, and other blockchain networks
- **Threshold Signatures**: Secure MPC-based signing with configurable threshold requirements
- **Dual Backend Support**: Choose between ECDSA-only (cait-sith) or ECDSA+EdDSA (near/threshold-signatures) backends
- **Governance**: NEAR-based governance chain for managing MPC node state

### More information:
- [Docs](https://docs.sig.network/)
- [Roadmap](https://sig.network/#network-roadmap)
- [Architecture](doc/ARCHITECTURE.md)
- [Scaling and Security](doc/SCALING_AND_SECURITY.md)
- [Contributing](./integration-tests/README.md)
