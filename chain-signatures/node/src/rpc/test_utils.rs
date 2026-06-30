#![cfg(test)]

use crate::protocol::{Chain, IndexedSignRequest};
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use mpc_crypto::kdf::derive_secret_key;
use mpc_primitives::{SignArgs, SignId, SignKind};

use super::PublishAction;

pub fn scalar(bytes: &[u8; 32]) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
        bytes.into(),
    )
}

pub fn make_signature(
    sk: &k256::SecretKey,
    epsilon: k256::Scalar,
    payload: k256::Scalar,
) -> FullSignature<Secp256k1> {
    use k256::elliptic_curve::point::DecompressPoint;
    let signing_key = k256::ecdsa::SigningKey::from(&derive_secret_key(sk, epsilon));
    let (ecdsa_sig, _): (k256::ecdsa::Signature, _) =
        <k256::ecdsa::SigningKey as k256::ecdsa::signature::hazmat::PrehashSigner<_>>::sign_prehash(
            &signing_key,
            &payload.to_bytes(),
        )
        .expect("signing should succeed");
    let (r_bytes, _) = ecdsa_sig.split_bytes();
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    FullSignature {
        big_r,
        s: *ecdsa_sig.s().as_ref(),
    }
}

pub fn make_indexed(
    chain: Chain,
    epsilon: k256::Scalar,
    payload: k256::Scalar,
    kind: SignKind,
) -> IndexedSignRequest {
    IndexedSignRequest {
        id: SignId::new([0u8; 32]),
        args: SignArgs {
            entropy: [0u8; 32],
            epsilon,
            payload,
            path: "test".into(),
            key_version: 0,
        },
        chain,
        unix_timestamp_indexed: 0,
        kind,
    }
}

pub fn make_publish_action(chain: Chain, kind: SignKind) -> PublishAction {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk: AffinePoint = sk.public_key().into();
    let epsilon = scalar(&[1u8; 32]);
    let payload = scalar(&[42u8; 32]);
    let output = make_signature(&sk, epsilon, payload);
    let indexed = make_indexed(chain, epsilon, payload, kind);
    PublishAction::new(pk, indexed, output, vec![])
        .expect("valid signature should produce a publish action")
}
