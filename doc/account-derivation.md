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

At [key version](glossary.md#key-version) 2, a key's derivation path names the key version and the key's [purpose](glossary.md#purpose-of-the-key), which is what the key signs. This section gives key version 2; [Earlier Key Versions](#earlier-key-versions) gives versions 0 and 1.

| `PURPOSE` | Signs | Derivation path |
|---|---|---|
| `plain` | [plain sign requests](glossary.md#plain-sign-request) | `{SIGNET_DERIVATION_PREFIX}:{KEY_VERSION}:{PURPOSE}:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}` |
| `bidirectional` | [bidirectional requests](glossary.md#bidirectional-request) | `{SIGNET_DERIVATION_PREFIX}:{KEY_VERSION}:{PURPOSE}:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}` |
| `attestation` | [attestations](glossary.md#attestation) of bidirectional requests | `{SIGNET_DERIVATION_PREFIX}:{KEY_VERSION}:{PURPOSE}:{CAIP2_CHAIN_ID}:{SENDER}` |
| `system` | transactions of a [system account](glossary.md#system-account) | `{SIGNET_DERIVATION_PREFIX}:{KEY_VERSION}:{PURPOSE}:{CAIP2_CHAIN_ID}:{DERIVATION_PATH}` |

Where:
- **SIGNET_DERIVATION_PREFIX** = `sig.network derivation`
- **KEY_VERSION** - The key version, in decimal: `2`
- **PURPOSE** - The key's purpose, from the table above
- **CAIP2_CHAIN_ID** - CAIP-2 chain_id, for example `eip155:1`
- **SENDER** - Account ID, often a public key, of the account that sent the signature request
- **DERIVATION_PATH** - A string provided by the SENDER, or by the MPC network for a system account, that is included at the end of the derivation path

Two purposes never derive the same key, whatever the sender and path: neither the prefix, the key version nor a purpose contains `:`, so every derivation path names its purpose in the same field. A key version 2 path never equals one of an earlier version, whose prefix differs.

The attestation key has no `DERIVATION_PATH`: a contract has one per key version, used for all its attestations.

Key versions 0, 1 and 2 derive from the same MPC root key, so keys of two of them differ by their derivation paths. Every key version after 2 has a root key of its own. A plain key at key version 2 is a different key from the same sender and path at key version 1, so an application keeps the key version its users' accounts are under.

### Earlier Key Versions

| Key version | Derivation path |
|---|---|
| 1 | `sig.network v2.0.0 epsilon derivation:{CAIP2_CHAIN_ID}:{SENDER}:{DERIVATION_PATH}` |
| 0 | `sig.network v1.0.0 epsilon derivation,{CHAIN_ID},{SENDER},{DERIVATION_PATH}`, with `CHAIN_ID` in a legacy format (`0x1` for Ethereum) |

These formats do not encode the key's purpose. A [system account](glossary.md#system-account) derives with the sender `%admin#`.

Bidirectional requests need key version 1 or later ([bidirectional-calls.md §7.1](bidirectional-calls.md#71-request-signbidirectionaleventv1)), so key version 0 has no bidirectional or attestation key. At key version 1 a bidirectional key derives as a plain key, and a contract's attestation key as a plain key under its source chain's reserved path (`<chain> response key`, for example `solana response key` on Solana). Below key version 2 no request from a chain may name that chain's reserved path, on any signing API ([bidirectional-calls.md §4.3](bidirectional-calls.md#43-mpc-network), M1).

### Contract-Based Derivation

In case the sender is a contract, `DERIVATION_PATH` can identify a specific user. Contract developers are free to choose their own scheme for user identification or follow one of the existing standards.
