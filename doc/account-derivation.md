# Account Derivation

This document describes how Sig.Network identifies blockchains and derives user accounts using industry standards.

## Chain Identification

### How do we identify blockchains?
Chain identification is not a well-defined subject. In the Ethereum world, [EIP155](https://eips.ethereum.org/EIPS/eip-155) is widely used, but when we want to include networks like Bitcoin, Solana, etc., we need another standard that supports a wider range of chains.

At Sig.Network we use the [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) standard. It allows us to distinguish chains across different ecosystems and architectures.

### Supported Chain Examples

The following examples show how different blockchain networks are identified using CAIP-2:
- Solana Mainnet: `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
- Ethereum Mainnet: `eip155:1`
- Bitcoin Mainnet: `bip122:000000000019d6689c085ae165831e93`

For simplicity, we reuse Mainnet derivation paths for all dev and testnet networks. For example, Ethereum Sepolia will have the same derivation path as Ethereum Mainnet.

## Account Derivation

### How do we derive user accounts?
We are using an extended version of the [CAIP-10](https://chainagnostic.org/CAIPs/caip-10) standard.

### Derivation Path Structure

The derivation path depends on the key's kind, which is what the key signs:

| Key kind | Signs | `KEY_KIND` | Derivation path |
|---|---|---|---|
| Plain | [plain sign requests](glossary.md#plain-sign-request) | none | `{EPSILON_DERIVATION_PREFIX}:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}` |
| Bidirectional | [bidirectional requests](glossary.md#bidirectional-request) | `bidirectional` | `{EPSILON_DERIVATION_PREFIX}:{KEY_KIND}:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}` |
| Attestation | [attestations](glossary.md#attestation) of bidirectional requests | `attestation` | `{EPSILON_DERIVATION_PREFIX}:{KEY_KIND}:{CAIP2_CHAIN_ID}:{SENDER}` |

Where:
- **EPSILON_DERIVATION_PREFIX** = `sig.network v2.0.0 epsilon derivation`
- **CAIP2_CHAIN_ID** - CAIP-2 chain_id, for example `eip155:1`
- **SENDER** - Account ID, often a public key, of the account that sent the signature request
- **DERIVATION_PATH** - A string provided by the SENDER, that is included at the end of the derivation path

Two kinds never derive the same key, whatever the sender and path: the field after the prefix is either `KEY_KIND` or the namespace of `CAIP2_CHAIN_ID`, which [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) limits to 8 characters, too short for `bidirectional` or `attestation`.

The attestation key has no `DERIVATION_PATH`: a contract has one, used for all its attestations. For bidirectional and attestation keys, `SENDER` is the contract that made the request.

These formats belong to key version 1. Key version 0 is unchanged and has only the plain kind: bidirectional requests need key version 1 or later ([bidirectional-calls.md §7.1](bidirectional-calls.md#71-request-signbidirectionaleventv1)).

### Contract-Based Derivation

In case the sender is a contract, `DERIVATION_PATH` can identify a specific user. Contract developers are free to choose their own scheme for user identification or follow one of the existing standards.
