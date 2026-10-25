//! The signing payload of a bidirectional request, per target chain, and the
//! key derivation the owner binding rests on.

use alloy::primitives::Address;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use mpc_crypto::derive_key;
use mpc_primitives::{Chain, ScalarExt};
use sha2::Digest;

pub fn public_key_to_address(public_key: &[u8]) -> Address {
    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = *alloy::primitives::keccak256(&public_key[1..]);

    Address::from_slice(&hash[12..])
}

pub fn derive_user_address(mpc_pk: mpc_crypto::PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk = derive_key(mpc_pk, derivation_epsilon);

    public_key_to_address(user_pk.to_encoded_point(false).as_bytes())
}

/// The scalar the MPC signs for a bidirectional request's transaction.
/// Tron signs its transaction id (sha256 of the raw bytes), other
/// targets sign keccak256.
pub fn bidirectional_payload_scalar(target: Chain, serialized: &[u8]) -> anyhow::Result<Scalar> {
    match target {
        Chain::Tron => {
            let txid: [u8; 32] = sha2::Sha256::digest(serialized).into();
            Ok(Scalar::from_non_biased(txid))
        }
        _ => {
            let hash: [u8; 32] = alloy::primitives::keccak256(serialized).into();
            let Some(payload) = Scalar::from_bytes(hash) else {
                anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {hash:?}");
            };
            Ok(payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tron_signs_sha256_while_other_targets_sign_keccak256() {
        let raw = {
            let mut bytes = vec![0u8; 31];
            bytes.push(1);
            bytes
        };
        // sha256(00…01), reduced into the field, computed independently.
        let expected: [u8; 32] = [
            0xec, 0x49, 0x16, 0xdd, 0x28, 0xfc, 0x4c, 0x10, 0xd7, 0x8e, 0x28, 0x7c, 0xa5, 0xd9,
            0xcc, 0x51, 0xee, 0x1a, 0xe7, 0x3c, 0xbf, 0xde, 0x08, 0xc6, 0xb3, 0x73, 0x24, 0xcb,
            0xfa, 0xac, 0x8b, 0xc5,
        ];
        let tron = bidirectional_payload_scalar(Chain::Tron, &raw).unwrap();
        assert_eq!(tron.to_bytes().as_slice(), &expected[..]);
        let evm = bidirectional_payload_scalar(Chain::Ethereum, &raw).unwrap();
        assert_ne!(evm, tron);
    }
}
