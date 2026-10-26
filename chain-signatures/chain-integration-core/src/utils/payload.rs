//! The signing payload of a bidirectional request, per target chain, and the
//! key derivation the owner binding rests on.

use alloy::primitives::{keccak256, Address};
use k256::elliptic_curve::{bigint::U256, ops::Reduce, sec1::FromEncodedPoint, sec1::ToEncodedPoint};
use k256::{FieldBytes, Scalar};
use mpc_crypto::derive_key;
use mpc_primitives::{Chain, ScalarExt};
use sha2::{Digest, Sha256};

/// The 20-byte EVM address of a public key: `keccak256(X ‖ Y)[12..]`. The point
/// is normalized through its affine form, so any SEC1 encoding of a key names
/// the same address.
pub fn public_key_to_address(public_key: &k256::EncodedPoint) -> Address {
    let affine =
        Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(public_key))
            .expect("a secp256k1 point");
    let hash: [u8; 32] = *keccak256(&affine.to_encoded_point(false).as_bytes()[1..]);

    Address::from_slice(&hash[12..])
}

pub fn derive_user_address(mpc_pk: mpc_crypto::PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk = derive_key(mpc_pk, derivation_epsilon);

    public_key_to_address(&user_pk.to_encoded_point(false))
}

/// The scalar the MPC signs for a bidirectional request's transaction.
/// Tron signs its transaction id (sha256 of the raw), reduced mod n: the raw
/// is deterministic, so an over-field hash has no re-nonce escape — and
/// verification is mod n, so reduce(txid) still verifies. Ethereum signs
/// keccak256 and rejects a non-canonical hash, as the plain signing flow
/// does; no other chain is a bidirectional signing target.
pub fn bidirectional_payload_scalar(target: Chain, serialized: &[u8]) -> anyhow::Result<Scalar> {
    match target {
        Chain::Tron => Ok(reduce(Sha256::digest(serialized).into())),
        Chain::Ethereum => {
            let hash: [u8; 32] = keccak256(serialized).into();
            let Some(payload) = Scalar::from_bytes(hash) else {
                anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {hash:?}");
            };
            Ok(payload)
        }
        Chain::NEAR
        | Chain::Solana
        | Chain::Bitcoin
        | Chain::Hydration
        | Chain::Canton
        | Chain::Midnight => anyhow::bail!("no bidirectional signing scheme for {target}"),
    }
}

/// `bytes mod n`, total over all 32-byte inputs.
fn reduce(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
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
        // sha256(00…01), computed independently.
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

    #[test]
    fn every_chain_gets_a_deliberate_scheme() {
        let raw = [0u8; 32];
        assert!(bidirectional_payload_scalar(Chain::Tron, &raw).is_ok());
        assert!(bidirectional_payload_scalar(Chain::Ethereum, &raw).is_ok());
        for chain in [
            Chain::NEAR,
            Chain::Solana,
            Chain::Bitcoin,
            Chain::Hydration,
            Chain::Canton,
            Chain::Midnight,
        ] {
            assert!(
                bidirectional_payload_scalar(chain, &raw).is_err(),
                "{chain} must have no scheme"
            );
        }
    }
}
