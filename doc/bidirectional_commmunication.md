### How do we identify blockchains?
Chain identification is not a well-defined subject. In the Ethereum world, [EIP155](https://eips.ethereum.org/EIPS/eip-155) is widely used, but when we want to include networks like Bitcoin, Solana, etc., we need another standard that supports a wider range of chains.

At Sig.Network we use the [CAIP2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md) standard. It allows us to distinguish chains across different ecosystems and architectures.

Exampes:
- Bitcoin Mainnet: `bip122:000000000019d6689c085ae165831e93`
- Bitcoin Testnet: `bip122:000000000933ea01ad0ee984209779ba`
- Solana Mainnet: `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
- Solana Devnet: `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`
- Ethereum Mainnet: `eip155:1`
- Ethereum Sepolia: `eip155:11155111`