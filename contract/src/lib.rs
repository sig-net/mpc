pub mod primitives;

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::CurveArithmetic;
use k256::{AffinePoint, EncodedPoint, FieldBytes, Scalar, Secp256k1, U256};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::log;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, Promise, PromiseOrValue, PublicKey};
use primitives::{CandidateInfo, Candidates, Participants, PkVotes, Votes};
use std::collections::{BTreeMap, HashSet};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    // TODO: only store diff to save on storage
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<([u8; 32], [u8; 32]), Option<(String, String)>>,
}

#[near_bindgen]
impl MpcContract {
    #[init]
    pub fn init(threshold: usize, candidates: BTreeMap<AccountId, CandidateInfo>) -> Self {
        log!(
            "init: signer={}, treshhold={}, candidates={}",
            env::signer_account_id(),
            threshold,
            serde_json::to_string(&candidates).unwrap()
        );
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: Candidates { candidates },
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: LookupMap::new(b"m"),
        }
    }

    pub fn state(self) -> ProtocolContractState {
        self.protocol_state
    }

    pub fn join(
        &mut self,
        url: String,
        cipher_pk: primitives::hpke::PublicKey,
        sign_pk: PublicKey,
    ) {
        log!(
            "join: signer={}, url={}, cipher_pk={:?}, sign_pk={:?}",
            env::signer_account_id(),
            url,
            cipher_pk,
            sign_pk
        );
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                participants,
                candidates,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if participants.contains_key(&signer_account_id) {
                    env::panic_str("this participant is already in the participant set");
                }
                candidates.insert(
                    signer_account_id.clone(),
                    CandidateInfo {
                        account_id: signer_account_id,
                        url,
                        cipher_pk,
                        sign_pk,
                    },
                );
            }
            _ => env::panic_str("protocol state can't accept new participants right now"),
        }
    }

    pub fn vote_join(&mut self, candidate_account_id: AccountId) -> bool {
        log!(
            "vote_join: signer={}, candidate_account_id={}",
            env::signer_account_id(),
            candidate_account_id
        );
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                join_votes,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if !participants.contains_key(&signer_account_id) {
                    env::panic_str("calling account is not in the participant set");
                }
                let candidate_info = candidates
                    .get(&candidate_account_id)
                    .unwrap_or_else(|| env::panic_str("candidate is not registered"));
                let voted = join_votes.entry(candidate_account_id.clone());
                voted.insert(signer_account_id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants
                        .insert(candidate_account_id.clone(), candidate_info.clone().into());
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashSet::new(),
                        });
                    true
                } else {
                    false
                }
            }
            _ => env::panic_str("protocol state can't accept new participants right now"),
        }
    }

    pub fn vote_leave(&mut self, acc_id_to_leave: AccountId) -> bool {
        log!(
            "vote_leave: signer={}, acc_id_to_leave={}",
            env::signer_account_id(),
            acc_id_to_leave
        );
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                leave_votes,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if !participants.contains_key(&signer_account_id) {
                    env::panic_str("calling account is not in the participant set");
                }
                if !participants.contains_key(&acc_id_to_leave) {
                    env::panic_str("account to leave is not in the participant set");
                }
                let voted = leave_votes.entry(acc_id_to_leave.clone());
                voted.insert(signer_account_id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.remove(&acc_id_to_leave);
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashSet::new(),
                        });
                    true
                } else {
                    false
                }
            }
            _ => env::panic_str("protocol state can't kick participants right now"),
        }
    }

    pub fn vote_pk(&mut self, public_key: PublicKey) -> bool {
        log!(
            "vote_pk: signer={}, public_key={:?}",
            env::signer_account_id(),
            public_key
        );
        match &mut self.protocol_state {
            ProtocolContractState::Initializing(InitializingContractState {
                candidates,
                threshold,
                pk_votes,
            }) => {
                let signer_account_id = env::signer_account_id();
                if !candidates.contains_key(&signer_account_id) {
                    env::panic_str("calling account is not in the participant set");
                }
                let voted = pk_votes.entry(public_key.clone());
                voted.insert(signer_account_id);
                if voted.len() >= *threshold {
                    self.protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: 0,
                        participants: candidates.clone().into(),
                        threshold: *threshold,
                        public_key,
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::Running(state) if state.public_key == public_key => true,
            ProtocolContractState::Resharing(state) if state.public_key == public_key => true,
            _ => env::panic_str("can't change public key anymore"),
        }
    }

    pub fn vote_reshared(&mut self, epoch: u64) -> bool {
        log!(
            "vote_reshared: signer={}, epoch={}",
            env::signer_account_id(),
            epoch
        );
        match &mut self.protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                old_participants,
                new_participants,
                threshold,
                public_key,
                finished_votes,
            }) => {
                if *old_epoch + 1 != epoch {
                    env::panic_str("mismatched epochs");
                }
                let signer_account_id = env::signer_account_id();
                if !old_participants.contains_key(&signer_account_id) {
                    env::panic_str("calling account is not in the old participant set");
                }
                finished_votes.insert(signer_account_id);
                if finished_votes.len() >= *threshold {
                    self.protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::Running(state) => {
                if state.epoch == epoch {
                    true
                } else {
                    env::panic_str("protocol is not resharing right now")
                }
            }
            _ => env::panic_str("protocol is not resharing right now"),
        }
    }

    #[allow(unused_variables)]
    /// `key_version` must be less than or equal to the value at `latest_key_version`
    pub fn sign(&mut self, payload: [u8; 32], path: String, key_version: u32) -> Promise {
        let latest_key_version: u32 = self.latest_key_version();
        assert!(
            key_version <= latest_key_version,
            "This version of the signer contract doesn't support versions greater than {}",
            latest_key_version,
        );
        let predecessor = env::predecessor_account_id();
        let epsilon = self.derive_epsilon(&predecessor, &path);
        log!(
            "sign: predecessor={}, epsilon={:?}, payload={:?}, path={:?}, key_version={}",
            predecessor,
            epsilon,
            payload,
            path,
            key_version
        );

        match self.pending_requests.get(&(payload, epsilon)) {
            None => {
                self.pending_requests.insert(&(payload, epsilon), &None);
                log!(&serde_json::to_string(&near_sdk::env::random_seed_array()).unwrap());
                Self::ext(env::current_account_id()).sign_helper(payload, epsilon, 0)
            }
            Some(_) => env::panic_str("Signature for this payload already requested"),
        }
    }

    #[private]
    pub fn sign_helper(
        &mut self,
        payload: [u8; 32],
        epsilon: [u8; 32],
        depth: usize,
    ) -> PromiseOrValue<(String, String)> {
        if let Some(signature) = self.pending_requests.get(&(payload, epsilon)) {
            match signature {
                Some(signature) => {
                    log!(
                        "sign_helper: signature ready: {:?}, depth: {:?}",
                        signature,
                        depth
                    );
                    self.pending_requests.remove(&(payload, epsilon));
                    PromiseOrValue::Value(signature)
                }
                None => {
                    log!(&format!(
                        "sign_helper: signature not ready yet (depth={})",
                        depth
                    ));
                    let account_id = env::current_account_id();
                    PromiseOrValue::Promise(Self::ext(account_id).sign_helper(
                        payload,
                        epsilon,
                        depth + 1,
                    ))
                }
            }
        } else {
            env::panic_str("unexpected request");
        }
    }

    pub fn respond(&mut self, payload: [u8; 32], epsilon: [u8; 32], big_r: String, s: String) {
        log!(
            "respond: signer={}, payload={:?} big_r={} s={}",
            env::signer_account_id(),
            payload,
            big_r,
            s
        );

        // let expected = self.pending_requests.get(&([0; 32], [0; 32]));
        match self.pending_requests.get(&(payload, epsilon)) {
            // There is an outstanding request, and it hasn't been answered
            Some(None) => {
                self.verify_signature(payload, epsilon, &big_r, &s);
                self.pending_requests
                    .insert(&(payload, epsilon), &Some((big_r, s)));
            }
            Some(_) => env::panic_str("This request has already been answered, but not returned"),
            None => env::panic_str(&format!(
                "This request either wasn't made or has been returned to the sender already",
                // expected.unwrap().unwrap().0
            )),
        };
    }

    fn verify_signature(&self, payload_hash: [u8; 32], epsilon: [u8; 32], big_r: &str, s: &str) {
        let expected_key = self.derive_key(&epsilon).to_encoded_point(false).to_bytes();

        let big_r = hex::decode(big_r).unwrap();
        let big_r = EncodedPoint::from_bytes(big_r).unwrap();
        let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
        // let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;

        fn x_coordinate(
            point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
        ) -> <Secp256k1 as CurveArithmetic>::Scalar {
            <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
                <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
            >>::reduce_bytes(&point.x())
        }

        let s = hex::decode(s).unwrap();
        let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));
        let r = x_coordinate(&big_r);

        let signature: [u8; 64] = {
            let mut signature = [0u8; 64]; // TODO: is there a better way to get these bytes?
            signature[..32].copy_from_slice(&r.to_bytes());
            signature[32..].copy_from_slice(&s.to_bytes());
            signature
        };

        // Try with a recovery ID of 0
        let recovered_key = env::ecrecover(&payload_hash, &signature, 0, false)
            // If that doesn't work with a recovery ID of 1
            .or_else(|| env::ecrecover(&payload_hash, &signature, 1, false));

        assert_eq!(Some(&*expected_key), recovered_key.as_ref().map(|k| &k[..]));
    }

    #[private]
    #[init(ignore_state)]
    pub fn clean(keys: Vec<near_sdk::json_types::Base64VecU8>) -> Self {
        log!("clean: keys={:?}", keys);
        for key in keys.iter() {
            env::storage_remove(&key.0);
        }
        Self {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: LookupMap::new(b"m"),
        }
    }

    /// This is the root public key combined from all the public keys of the participants.
    pub fn public_key(&self) -> PublicKey {
        match &self.protocol_state {
            ProtocolContractState::Running(state) => state.public_key.clone(),
            ProtocolContractState::Resharing(state) => state.public_key.clone(),
            _ => env::panic_str("public key not available (protocol is not running or resharing)"),
        }
    }

    /// Key versions refer new versions of the root key that we may choose to generate on cohort changes
    /// Older key versions will always work but newer key versions were never held by older signers
    /// Newer key versions may also add new security features, like only existing within a secure enclave
    /// Currently only 0 is a valid key version
    pub const fn latest_key_version(&self) -> u32 {
        0
    }

    fn derive_epsilon(&self, predecessor: &AccountId, path: &str) -> [u8; 32] {
        // Constant prefix that ensures epsilon derivation values are used specifically for
        // near-mpc-recovery with key derivation protocol vX.Y.Z.
        // TODO put this somewhere shared
        const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

        let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", predecessor, path);
        let mut res = env::sha256(&derivation_path.into_bytes());
        // Our key derivation algorithm is backwards for reasons of historical mistake
        res.reverse();

        res.try_into().expect("That sha256 is 32 bytes long")
    }

    pub fn derive_key(&self, epsilon: &[u8; 32]) -> PublicKeyA {
        let epsilon = scalar_from_bytes(epsilon);
        // This will always succeed because the underlying type is [u8;64]
        let uncompressed_public_key: [u8; 64] = self.public_key().into_bytes().try_into().unwrap();
        let (x, y) = uncompressed_public_key.split_at(32);
        let x = FieldBytes::from_slice(&x);
        let y = FieldBytes::from_slice(&y);
        let encoded_point = EncodedPoint::from_affine_coordinates(x, y, true);

        let public_key =
            AffinePoint::from_encoded_point(&encoded_point).expect("Valid public key conversion");

        // let public_key: AffinePoint = AffinePoint::from_bytes(&public_key_a).unwrap();

        (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key)
            .to_affine()
    }
}

// Our wasm runtime doesn't support good syncronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definately panic, because they normally expect randomness to be private
use getrandom::{register_custom_getrandom, Error};
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
register_custom_getrandom!(randomness_unsupported);

// TODO Give this a better name
pub type PublicKeyA = <Secp256k1 as CurveArithmetic>::AffinePoint;

// TODO put in shared lib
fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    Scalar::from_uint_unchecked(U256::from_le_slice(bytes))
}
