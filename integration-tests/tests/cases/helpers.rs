use cait_sith::protocol::Participant;
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::backlog::BacklogEntry;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::storage::PresignatureStorage;
use mpc_primitives::{Chain, IndexedSignRequest, SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use sha2::Digest;
use std::sync::Arc;

pub(crate) fn dummy_indexed_sign_request(id: u8, chain: Chain) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::sign(
        SignId::new([id; 32]),
        SignArgs {
            entropy: [id; 32],
            epsilon: k256::Scalar::ONE,
            payload: k256::Scalar::ONE,
            path: "m/0".to_string(),
            key_version: 0,
        },
        chain,
        0,
    ))
}

pub(crate) fn dummy_backlog_entry(id: u8, chain: Chain) -> BacklogEntry {
    BacklogEntry::new(dummy_indexed_sign_request(id, chain))
}

pub(crate) fn dummy_presignature(id: u64) -> Presignature {
    dummy_presignature_with_holders(id, vec![Participant::from(1), Participant::from(2)])
}

pub(crate) fn dummy_presignature_with_holders(
    id: u64,
    participants: Vec<Participant>,
) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        holders: Some(participants.clone()),
        participants,
    }
}

pub(crate) async fn insert_presignatures_for_owner(
    presignatures: &PresignatureStorage,
    owner: Participant,
    holders: &[Participant],
    ids: impl IntoIterator<Item = u64>,
) {
    let holders = holders.to_vec();
    for id in ids {
        presignatures
            .create_slot(id, owner)
            .await
            .unwrap()
            .insert(dummy_presignature_with_holders(id, holders.clone()), owner)
            .await;
    }
}

pub(crate) async fn assert_presig_owned_state(
    presignatures: &PresignatureStorage,
    owner: Participant,
    expected_present: &[u64],
    expected_absent: &[u64],
) {
    for id in expected_present {
        assert!(
            presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be present for owner={owner:?}"
        );
    }

    for id in expected_absent {
        assert!(
            !presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be absent for owner={owner:?}"
        );
    }
}

pub fn test_sign_arg(seed: impl Into<u32>) -> SignArgs {
    let seed = seed.into();
    // entropy should have well-distributed bits even in tests
    let entropy: [u8; 32] = sha2::Sha256::digest(seed.to_be_bytes())
        .as_slice()
        .try_into()
        .expect("digest length should be 32");
    SignArgs {
        entropy,
        epsilon: k256::Scalar::default(),
        payload: k256::Scalar::default(),
        path: "test".to_owned(),
        key_version: LATEST_MPC_KEY_VERSION,
    }
}

pub(crate) fn sign_request(seed: u32, chain: Chain) -> IndexedSignRequest {
    let bytes: [u8; 32] = seed.to_be_bytes().repeat(8).try_into().unwrap();
    IndexedSignRequest::sign(SignId::new(bytes), test_sign_arg(seed), chain, 0)
}
