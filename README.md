## Sig.Network MPC

Sig.Network MPC is a threshold-signature network that lets a smart contract on one blockchain act on any other (Ethereum, Bitcoin, Solana, Midnight, etc.). The root key is split across the nodes, so no single party can sign. A contract calls the Sig.Network contract on its own chain and gets the result back there.

- **Sign**: a signature over an arbitrary payload, for accounts the contract controls on current or other chains.
- **Bidirectional call**: a transaction signed and executed on a destination chain, with its outcome attested back to the contract.

### More information:
- [MPC docs](doc/)
- [Integration docs](https://docs.sig.network/)
- [Contributing](./integration-tests/README.md)
