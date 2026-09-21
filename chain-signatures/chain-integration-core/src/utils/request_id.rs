//! [`RequestId`] derivations shared by the chains whose contracts hash an ABI
//! encoding of the request: Solana and Hydration. Ethereum encodes the sender as
//! an address rather than a string and so has its own derivation in
//! `mpc-chain-ethereum`. See the registry on [`RequestId`] for every scheme.

use alloy::primitives::{keccak256, U256};
use alloy::sol_types::SolValue;
use mpc_primitives::RequestId;

pub trait EvmRequestId {
    /// Solana and Hydration `sign`:
    /// `keccak256(abi.encode(sender, payload, path, uint256(key_version), chain_id, algo, dest, params))`
    /// with the sender rendered as a string.
    #[allow(clippy::too_many_arguments)]
    fn from_evm_sign_request(
        sender: &str,
        payload: &[u8; 32],
        path: &str,
        key_version: u32,
        chain_id: &str,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> RequestId;

    /// Solana and Hydration `sign_bidirectional`:
    /// `keccak256(abi.encodePacked(sender, serialized_transaction, caip2_id, uint32(key_version), path, algo, dest, params))`,
    /// matching the TypeScript client SDK.
    #[allow(clippy::too_many_arguments)]
    fn from_evm_bidirectional_request(
        sender: &str,
        serialized_transaction: &[u8],
        caip2_id: &str,
        key_version: u32,
        path: &str,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> RequestId;
}

impl EvmRequestId for RequestId {
    fn from_evm_sign_request(
        sender: &str,
        payload: &[u8; 32],
        path: &str,
        key_version: u32,
        chain_id: &str,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> RequestId {
        let encoded = (
            sender,
            payload.to_vec(),
            path,
            U256::from(key_version),
            chain_id,
            algo,
            dest,
            params,
        )
            .abi_encode_params();
        RequestId::new(keccak256(&encoded).0)
    }

    fn from_evm_bidirectional_request(
        sender: &str,
        serialized_transaction: &[u8],
        caip2_id: &str,
        key_version: u32,
        path: &str,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> RequestId {
        let encoded = (
            sender,
            serialized_transaction.to_vec(),
            caip2_id,
            key_version,
            path,
            algo,
            dest,
            params,
        )
            .abi_encode_packed();
        RequestId::new(keccak256(&encoded).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Args = (
        &'static str,
        [u8; 32],
        &'static str,
        u32,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    );

    fn default_args() -> Args {
        (
            "sender.near",
            [0u8; 32],
            "m/44'/397'/0'",
            0,
            "ethereum",
            "secp256k1",
            "0xDEAD",
            "",
        )
    }

    fn sign(args: Args) -> RequestId {
        let (sender, payload, path, kv, chain, algo, dest, params) = args;
        RequestId::from_evm_sign_request(sender, &payload, path, kv, chain, algo, dest, params)
    }

    #[test]
    fn sign_request_is_deterministic() {
        assert_eq!(sign(default_args()), sign(default_args()));
    }

    #[test]
    fn sign_request_differs_by_each_field() {
        let base = sign(default_args());
        let mut payload_b = [0u8; 32];
        payload_b[31] = 1;
        let variants: [Args; 8] = [
            (
                "bob.near",
                [0u8; 32],
                "m/44'/397'/0'",
                0,
                "ethereum",
                "secp256k1",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                payload_b,
                "m/44'/397'/0'",
                0,
                "ethereum",
                "secp256k1",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/1'",
                0,
                "ethereum",
                "secp256k1",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/0'",
                1,
                "ethereum",
                "secp256k1",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/0'",
                0,
                "near",
                "secp256k1",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/0'",
                0,
                "ethereum",
                "ed25519",
                "0xDEAD",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/0'",
                0,
                "ethereum",
                "secp256k1",
                "0xBEEF",
                "",
            ),
            (
                "sender.near",
                [0u8; 32],
                "m/44'/397'/0'",
                0,
                "ethereum",
                "secp256k1",
                "0xDEAD",
                "extra",
            ),
        ];
        for variant in variants {
            assert_ne!(base, sign(variant), "{variant:?}");
        }
    }

    #[test]
    fn sign_request_key_version_max_does_not_panic() {
        let (sender, payload, path, _, chain, algo, dest, params) = default_args();
        let _ = RequestId::from_evm_sign_request(
            sender,
            &payload,
            path,
            u32::MAX,
            chain,
            algo,
            dest,
            params,
        );
    }

    #[test]
    fn bidirectional_request_is_deterministic_and_field_sensitive() {
        let id = |tx: &[u8], caip2: &str| {
            RequestId::from_evm_bidirectional_request(
                "sender", tx, caip2, 0, "path", "ecdsa", "", "",
            )
        };
        assert_eq!(id(&[1, 2, 3], "eip155:1"), id(&[1, 2, 3], "eip155:1"));
        assert_ne!(id(&[1, 2, 3], "eip155:1"), id(&[1, 2, 4], "eip155:1"));
        assert_ne!(id(&[1, 2, 3], "eip155:1"), id(&[1, 2, 3], "eip155:2"));
    }
}
