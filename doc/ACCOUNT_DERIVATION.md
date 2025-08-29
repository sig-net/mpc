# Account Derivation

This document describes how Sig.Network identifies blockchains and derives user accounts using industry standards.

## Chain Identification

### How do we identify blockchains?
Chain identification is not a well-defined subject. In the Ethereum world, [EIP155](https://eips.ethereum.org/EIPS/eip-155) is widely used, but when we want to include networks like Bitcoin, Solana, etc., we need another standard that supports a wider range of chains.

At Sig.Network we use the [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) standard. It allows us to distinguish chains across different ecosystems and architectures.

### Supported Chain Examples

The following examples show how different blockchain networks are identified using CAIP-2:
- Solana Mainnet: `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
- Solana Devnet: `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`
- Ethereum Mainnet: `eip155:1`
- Ethereum Sepolia: `eip155:11155111`
- Bitcoin Mainnet: `bip122:000000000019d6689c085ae165831e93`
- Bitcoin Testnet: `bip122:000000000933ea01ad0ee984209779ba`

## Account Derivation

### How do we derive user accounts?
We are using an extended version of the [CAIP-10](https://chainagnostic.org/CAIPs/caip-10) standard.

### Derivation Path Structure

The full derivation path consists of the following variables:
```
{EPSILON_DERIVATION_PREFIX}:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}
```
Where:
- **EPSILON_DERIVATION_PREFIX** = `sig.network v1 epsilon derivation`
- **CAIP2_CHAIN_ID** - CAIP-2 chain_id, for example `eip155:1`
- **SENDER** - Account ID, often a public key, of the account that sent the signature request
- **DERIVATION_PATH** - A string provided by the SENDER, that is included at the end of the derivation path

### Contract-Based Derivation

In case the sender is a contract, `DERIVATION_PATH` can identify a specific user. Contract developers are free to choose their own scheme for user identification or follow one of the existing standards.
