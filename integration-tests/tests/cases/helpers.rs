use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use mpc_primitives::{SignArgs, LATEST_MPC_KEY_VERSION};
use sha2::Digest;

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

pub(crate) fn dummy_pair(id: u64) -> TriplePair {
    dummy_pair_with_holders(id, vec![Participant::from(1), Participant::from(2)])
}

pub(crate) fn dummy_pair_with_holders(id: u64, participants: Vec<Participant>) -> TriplePair {
    TriplePair {
        id,
        triple0: dummy_triple_with_holders(participants.clone()),
        triple1: dummy_triple_with_holders(participants.clone()),
        holders: Some(participants),
    }
}

pub(crate) fn dummy_triple_with_holders(participants: Vec<Participant>) -> Triple {
    Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants,
            threshold: 5,
        },
    }
}

pub(crate) async fn insert_triples_for_owner(
    triples: &TripleStorage,
    owner: Participant,
    holders: &[Participant],
    ids: impl IntoIterator<Item = u64>,
) {
    let holders = holders.to_vec();
    for id in ids {
        triples
            .create_slot(id, owner)
            .await
            .unwrap()
            .insert(dummy_pair_with_holders(id, holders.clone()), owner)
            .await;
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

pub(crate) async fn assert_triples_owned_state(
    triples: &TripleStorage,
    owner: Participant,
    expected_present: &[u64],
    expected_absent: &[u64],
) {
    for id in expected_present {
        assert!(
            triples.contains_by_owner(*id, owner).await,
            "triple={id} should be present for owner={owner:?}"
        );
    }

    for id in expected_absent {
        assert!(
            !triples.contains_by_owner(*id, owner).await,
            "triple={id} should be absent for owner={owner:?}"
        );
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
