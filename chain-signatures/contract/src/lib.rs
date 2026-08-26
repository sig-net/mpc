pub mod config;
pub mod errors;
mod migration;
pub mod primitives;
pub mod state;
pub mod update;
pub mod utils;

use errors::{
    CheckpointError, ConversionError, InitError, InvalidParameters, InvalidState, JoinError,
    PublicKeyError, RespondError, SignError, VoteError,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use mpc_crypto::{
    derive_epsilon_near, derive_key, kdf::check_ec_signature, near_public_key_to_affine_point,
    ScalarExt as _,
};
use mpc_primitives::ConsensusCheckpointDigest;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::env::panic_str;
use near_sdk::json_types::U128;
use near_sdk::store::IterableMap;
use near_sdk::{
    env, log, near, AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise, PromiseError,
    PublicKey,
};
use primitives::{
    CandidateEntry, CandidateInfo, Candidates, CheckpointReset, CheckpointVotes,
    InternalSignRequest, Participants, PendingRequest, PkVotes, Read, SignPoll, SignRequest,
    StorageKey, View, Votes, YieldIndex,
};
use signet_primitives::{Chain, SignId, Signature, LATEST_MPC_KEY_VERSION};
use std::collections::{BTreeMap, HashSet};

use crate::config::Config;
use crate::errors::Error;
use crate::primitives::ThresholdVotes;
use crate::update::{ProposeUpdateArgs, ProposedUpdates, UpdateId};
use crate::utils::compute_threshold;

pub use state::{
    InitializingContractState, InitializingContractStateView, ProtocolContractState,
    ProtocolContractStateView, ResharingContractState, RunningContractState,
    RunningContractStateView,
};

const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(50);

// Register used to receive data id from `promise_await_data`.
const DATA_ID_REGISTER: u64 = 0;

// Prepaid gas for a `clear_state_on_finish` call
const CLEAR_STATE_ON_FINISH_CALL_GAS: Gas = Gas::from_tgas(20);

// Prepaid gas for a `return_signature_on_finish` call
const RETURN_SIGNATURE_ON_FINISH_CALL_GAS: Gas = Gas::from_tgas(10);

// Prepaid gas for a `update_config` call
const UPDATE_CONFIG_GAS: Gas = Gas::from_tgas(5);

// Maximum number of concurrent requests
const MAX_CONCURRENT_REQUESTS: u32 = 128;

/// Maximum accepted byte length for a candidate node URL.
pub const MAX_JOIN_URL_LEN: usize = 2048;

/// Fixed anti-spam deposit required to join as a candidate.
pub const REQUIRED_JOIN_DEPOSIT: NearToken = NearToken::from_near(1);

#[near(contract_state)]
#[derive(Debug)]
pub enum VersionedMpcContract {
    V0(MpcContract),
}

impl Default for VersionedMpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, ConsensusCheckpointDigest>,
    checkpoint_votes: CheckpointVotes,
}

impl MpcContract {
    fn lock_request(&mut self, sign_id: SignId, payload: Scalar, epsilon: Scalar) {
        self.pending_requests.insert(
            sign_id,
            PendingRequest {
                payload,
                epsilon,
                index: None,
            },
        );
    }

    fn set_request_yield(&mut self, sign_id: &SignId, data_id: CryptoHash) {
        if let Some(request) = self.pending_requests.get_mut(sign_id) {
            request.index = Some(YieldIndex { data_id });
        }
    }

    fn remove_request(&mut self, sign_id: &SignId) -> Result<PendingRequest, Error> {
        self.pending_requests
            .remove(sign_id)
            .ok_or(InvalidParameters::RequestNotFound.into())
    }

    pub fn init(
        threshold: usize,
        candidates: BTreeMap<AccountId, CandidateInfo>,
        config: Option<Config>,
    ) -> Self {
        let mut stored_candidates = Candidates::new();
        for (account_id, info) in candidates {
            stored_candidates.insert(account_id, info);
        }
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: stored_candidates,
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: config.unwrap_or_default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
}

// User contract API
#[near]
impl VersionedMpcContract {
    /// `key_version` must be less than or equal to the value at `latest_key_version`
    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each signature request.
    /// The fee changes based on how busy the network is.
    #[handle_result]
    #[payable]
    pub fn sign(&mut self, request: SignRequest) -> Result<near_sdk::Promise, Error> {
        let SignRequest {
            payload: payload_bytes,
            path,
            key_version,
        } = request;
        // It's important we fail here because the MPC nodes will fail in an identical way.
        // This allows users to get the error message
        let payload = Scalar::from_bytes(payload_bytes).ok_or(
            InvalidParameters::MalformedPayload
                .message("Payload hash cannot be convereted to Scalar"),
        )?;
        if key_version > self.latest_key_version() {
            return Err(SignError::UnsupportedKeyVersion.into());
        }
        // Check deposit
        let deposit = env::attached_deposit();
        let required_deposit: u128 = self.experimental_signature_deposit().into();
        if deposit.as_yoctonear() < required_deposit {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Attached {}, Required {}",
                deposit.as_yoctonear(),
                required_deposit,
            )));
        }
        // Make sure sign call will not run out of gas doing yield/resume logic
        if env::prepaid_gas() < GAS_FOR_SIGN_CALL {
            return Err(InvalidParameters::InsufficientGas.message(format!(
                "Provided: {}, required: {}",
                env::prepaid_gas(),
                GAS_FOR_SIGN_CALL
            )));
        }

        if self.pending_requests() >= MAX_CONCURRENT_REQUESTS {
            return Err(SignError::RequestLimitExceeded.into());
        }
        let predecessor = env::predecessor_account_id();
        let sign_id = SignId::from_parts(predecessor.as_str(), &payload_bytes, &path, key_version);
        if self.contains_request(&sign_id) {
            return Err(SignError::RequestCollision.into());
        }

        log!(
            "sign: predecessor={predecessor}, payload={payload:?}, path={path:?}, key_version={key_version}",
        );
        let entropy = near_sdk::env::random_seed_array();
        env::log_str(&serde_json::to_string(&entropy).unwrap());
        let epsilon = derive_epsilon_near(request.key_version, &predecessor, &path);

        // lock the request such that it can't be submitted again until released either by erroring out
        // or by finishing the request when the signature is submitted.
        self.lock_request(sign_id, payload, epsilon);

        let request = InternalSignRequest {
            id: sign_id,
            requester: predecessor,
            deposit,
            required_deposit: NearToken::from_yoctonear(required_deposit),
        };
        Ok(Self::ext(env::current_account_id()).sign_helper(request))
    }

    /// This is the root public key combined from all the public keys of the participants.
    #[handle_result]
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        match self.state_ref() {
            ProtocolContractState::Running(state) => Ok(state.public_key.clone()),
            ProtocolContractState::Resharing(state) => Ok(state.public_key.clone()),
            _ => Err(InvalidState::ProtocolStateNotRunningOrResharing.into()),
        }
    }

    /// This is the derived public key of the caller given path and predecessor
    /// if predecessor is not provided, it will be the caller of the contract
    #[handle_result]
    pub fn derived_public_key(
        &self,
        key_version: u32,
        path: String,
        predecessor: Option<AccountId>,
    ) -> Result<PublicKey, Error> {
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let epsilon = derive_epsilon_near(key_version, &predecessor, &path);
        let derived_public_key =
            derive_key(near_public_key_to_affine_point(self.public_key()?), epsilon);
        let encoded_point = derived_public_key.to_encoded_point(false);
        let slice: &[u8] = &encoded_point.as_bytes()[1..65];
        let mut data: Vec<u8> = vec![near_sdk::CurveType::SECP256K1 as u8];
        data.extend(slice.to_vec());
        PublicKey::try_from(data).map_err(|_| PublicKeyError::DerivedKeyConversionFailed.into())
    }

    /// Key versions refer new versions of the root key that we may choose to generate on cohort changes
    /// Older key versions will always work but newer key versions were never held by older signers
    /// Newer key versions may also add new security features, like only existing within a secure enclave
    pub const fn latest_key_version(&self) -> u32 {
        LATEST_MPC_KEY_VERSION
    }

    /// This experimental function calculates the fee for a signature request.
    /// The fee is volatile and depends on the number of pending requests.
    /// If used on a client side, it can give outdated results.
    pub fn experimental_signature_deposit(&self) -> U128 {
        if cfg!(feature = "bench") {
            return U128(1);
        }
        match self.system_load() {
            0..=25 => U128(1),
            26..=50 => U128(NearToken::from_millinear(50).as_yoctonear()),
            51..=75 => U128(NearToken::from_millinear(500).as_yoctonear()),
            76..=100 => U128(NearToken::from_near(1).as_yoctonear()),
            _ => U128(NearToken::from_near(1).as_yoctonear()),
        }
    }
}

// Node API
#[near]
impl VersionedMpcContract {
    #[handle_result]
    pub fn respond(&mut self, sign_id: SignId, signature: Signature) -> Result<(), Error> {
        let protocol_state = self.mutable_state();
        if !matches!(protocol_state, ProtocolContractState::Running(_)) {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        let signer = env::signer_account_id();
        log!(
            "respond: signer={}, sign_id={:?} big_r={:?} s={:?}",
            &signer,
            &sign_id,
            &signature.big_r,
            &signature.s
        );

        let Some(PendingRequest {
            payload,
            epsilon,
            index: Some(index),
        }) = self.get_request(&sign_id)
        else {
            return Err(InvalidParameters::RequestNotFound.into());
        };

        // generate the expected public key
        let pk = self.public_key()?;
        let expected_public_key = derive_key(near_public_key_to_affine_point(pk), *epsilon);

        // Check the signature is correct
        if check_ec_signature(
            &expected_public_key,
            &signature.big_r,
            &signature.s,
            *payload,
            signature.recovery_id,
        )
        .is_err()
        {
            return Err(RespondError::InvalidSignature.into());
        }

        env::promise_yield_resume(&index.data_id, serde_json::to_vec(&signature).unwrap());
        Ok(())
    }

    #[payable]
    #[handle_result]
    pub fn join(
        &mut self,
        url: String,
        cipher_pk: primitives::hpke::PublicKey,
        sign_pk: PublicKey,
    ) -> Result<(), Error> {
        let url_len = url.len();
        if url_len > MAX_JOIN_URL_LEN {
            return Err(JoinError::UrlTooLong.message(format!(
                "Provided {}, maximum {}",
                url_len, MAX_JOIN_URL_LEN,
            )));
        }
        let deposit = env::attached_deposit();
        if deposit < REQUIRED_JOIN_DEPOSIT {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Attached {}, Required {}",
                deposit.as_yoctonear(),
                REQUIRED_JOIN_DEPOSIT.as_yoctonear(),
            )));
        }

        log!(
            "join: signer={}, url={}, cipher_pk={:?}, sign_pk={:?}",
            env::signer_account_id(),
            url,
            cipher_pk,
            sign_pk
        );
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                participants,
                ref mut candidates,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if participants.contains_key(&signer_account_id) {
                    return Err(JoinError::JoinAlreadyParticipant.into());
                }
                if let Some(diff) = deposit.checked_sub(REQUIRED_JOIN_DEPOSIT) {
                    if diff > NearToken::from_yoctonear(0) {
                        Promise::new(signer_account_id.clone())
                            .transfer(diff)
                            .detach();
                    }
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
                Ok(())
            }
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }

    #[handle_result]
    pub fn remove_candidacy(&mut self) -> Result<(), Error> {
        log!("remove_candidacy: signer={}", env::signer_account_id());
        let protocol_state = self.mutable_state();

        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                candidates,
                join_votes,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if candidates.get(&signer_account_id).is_none() {
                    return Err(JoinError::RevokeNotCandidate.into());
                }

                // cleanup the existing votes
                join_votes.remove(&signer_account_id);

                // remove from candidates
                candidates.remove(&signer_account_id);

                Ok(())
            }
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }

    #[handle_result]
    pub fn vote_join(&mut self, candidate: AccountId) -> Result<bool, Error> {
        log!(
            "vote_join: signer={}, candidate={}",
            env::signer_account_id(),
            candidate
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                join_votes,
                ..
            }) => {
                let candidate_info = candidates
                    .get(&candidate)
                    .ok_or(VoteError::JoinNotCandidate)?;
                let voted = join_votes.entry(candidate.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.insert(candidate, candidate_info.clone().into());
                    candidates.clear();
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        threshold: *threshold,
                        new_threshold: compute_threshold(new_participants.len()),
                        new_participants,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
                        cancel_votes: HashSet::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_leave(&mut self, kick: AccountId) -> Result<bool, Error> {
        log!(
            "vote_leave: signer={}, kick={}",
            env::signer_account_id(),
            kick
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                leave_votes,
                ..
            }) => {
                if !participants.contains_key(&kick) {
                    return Err(VoteError::KickNotParticipant.into());
                }
                if participants.len() <= *threshold {
                    return Err(VoteError::ParticipantsBelowThreshold.into());
                }
                let voted = leave_votes.entry(kick.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.remove(&kick);
                    candidates.clear();
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        threshold: *threshold,
                        new_threshold: compute_threshold(new_participants.len()),
                        new_participants,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
                        cancel_votes: HashSet::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    /// Vote to change the running threshold without otherwise modifying the
    /// participant set. Each participant backs at most one proposed threshold
    /// at a time (casting a new vote removes any prior vote). The first
    /// proposed threshold to reach the current `threshold` triggers a resharing
    /// whose `new_threshold` is the proposed value. Voting for the same
    /// threshold as the current one in the network will remove a prior vote.
    #[handle_result]
    pub fn vote_threshold(&mut self, new_threshold: usize) -> Result<bool, Error> {
        log!(
            "vote_threshold: signer={}, new_threshold={}",
            env::signer_account_id(),
            new_threshold
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                threshold_votes,
                ..
            }) => {
                // same threshold removes prior vote
                if new_threshold == *threshold {
                    threshold_votes.remove(&voter);
                    return Ok(false);
                }

                let participants_len = participants.len();
                let min_threshold = compute_threshold(participants_len);
                let max_threshold = participants_len.saturating_sub(1);
                if new_threshold < min_threshold || new_threshold > max_threshold {
                    return Err(VoteError::ThresholdOutOfRange.into());
                }
                if threshold_votes.vote(new_threshold, voter) >= *threshold {
                    // Same participants, different threshold; the resharing
                    // protocol re-shares the key with a new threshold.
                    candidates.clear();
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        threshold: *threshold,
                        new_threshold,
                        new_participants: participants.clone(),
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
                        cancel_votes: HashSet::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_pk(&mut self, public_key: PublicKey) -> Result<bool, Error> {
        log!(
            "vote_pk: signer={}, public_key={:?}",
            env::signer_account_id(),
            public_key
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Initializing(InitializingContractState {
                candidates,
                threshold,
                pk_votes,
            }) => {
                let voted = pk_votes.entry(public_key.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    let participants = Participants::from(&*candidates);
                    candidates.clear();
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: 0,
                        participants,
                        threshold: *threshold,
                        public_key,
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                        threshold_votes: ThresholdVotes::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ProtocolContractState::Running(state) if state.public_key == public_key => Ok(true),
            ProtocolContractState::Resharing(state) if state.public_key == public_key => Ok(true),
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_reshared(&mut self, epoch: u64) -> Result<bool, Error> {
        log!(
            "vote_reshared: signer={}, epoch={}",
            env::signer_account_id(),
            epoch
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                new_participants,
                threshold,
                new_threshold,
                public_key,
                finished_votes,
                ..
            }) => {
                if *old_epoch + 1 != epoch {
                    return Err(InvalidState::EpochMismatch.into());
                }
                finished_votes.insert(voter);
                // Completion is attested by the old participants, so it is gated by
                // the old threshold. The reshared key adopts the new threshold.
                if finished_votes.len() >= *threshold {
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *new_threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                        threshold_votes: ThresholdVotes::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ProtocolContractState::Running(state) => {
                if state.epoch == epoch {
                    Ok(true)
                } else {
                    Err(InvalidState::UnexpectedProtocolState.message("Running: invalid epoch"))
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_cancel_resharing(&mut self) -> Result<bool, Error> {
        let voter = self.voter()?;
        log!("vote_cancel_resharing: signer={voter:?}");
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                old_participants,
                threshold,
                public_key,
                cancel_votes,
                ..
            }) => {
                cancel_votes.insert(voter);
                if cancel_votes.len() >= *threshold {
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch,
                        participants: old_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                        threshold_votes: ThresholdVotes::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    /// Propose an update to the contract. [`Update`] are all the possible updates that can be proposed.
    ///
    /// returns Some(id) if the proposal was successful, None otherwise
    #[payable]
    #[handle_result]
    pub fn propose_update(
        &mut self,
        #[serializer(borsh)] args: ProposeUpdateArgs,
    ) -> Result<UpdateId, Error> {
        // Only voters can propose updates:
        let proposer = self.voter()?;

        let attached = env::attached_deposit();
        let required = ProposedUpdates::required_deposit(&args.code, &args.config);
        if attached < required {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Attached {}, Required {}",
                attached.as_yoctonear(),
                required.as_yoctonear(),
            )));
        }

        let Some(id) = self.proposed_updates().propose(args.code, args.config) else {
            return Err(ConversionError::DataConversion
                .message("Cannot propose update due to incorrect parameters."));
        };

        // Refund the difference if the propser attached more than required.
        if let Some(diff) = attached.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                Promise::new(proposer).transfer(diff).detach();
            }
        }

        Ok(id)
    }

    /// Vote for a proposed update given the [`UpdateId`] of the update.
    ///
    /// Returns Ok(true) if the amount of voters surpassed the threshold and the update was executed.
    /// Returns Ok(false) if the amount of voters did not surpass the threshold. Returns Err if the update
    /// was not found or if the voter is not a participant in the protocol.
    #[handle_result]
    pub fn vote_update(&mut self, id: UpdateId) -> Result<bool, Error> {
        log!(
            "vote_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );
        let threshold = self.threshold()?;
        let voter = self.voter()?;
        let Some(votes) = self.proposed_updates().vote(&id, voter) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        // Not enough votes, wait for more.
        if votes.len() < threshold {
            return Ok(false);
        }

        let Some(_promise) = self.proposed_updates().do_update(&id, UPDATE_CONFIG_GAS) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        Ok(true)
    }
}

// Contract developer helper API
#[near]
impl VersionedMpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        threshold: usize,
        candidates: BTreeMap<AccountId, CandidateInfo>,
        config: Option<Config>,
    ) -> Result<Self, Error> {
        log!(
            "init: signer={}, threshold={}, candidates={}, config={:?}",
            env::signer_account_id(),
            threshold,
            serde_json::to_string(&candidates).unwrap(),
            config,
        );

        if threshold > candidates.len() {
            return Err(InitError::ThresholdTooHigh.into());
        }

        Ok(Self::V0(MpcContract::init(threshold, candidates, config)))
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        epoch: u64,
        participants: Participants,
        threshold: usize,
        public_key: PublicKey,
        config: Option<Config>,
        checkpoints: Option<BTreeMap<Chain, ConsensusCheckpointDigest>>,
    ) -> Result<Self, Error> {
        log!(
            "init_running: signer={}, epoch={}, participants={}, threshold={}, public_key={:?}, config={:?}, checkpoints={:?}",
            env::signer_account_id(),
            epoch,
            serde_json::to_string(&participants).unwrap(),
            threshold,
            public_key,
            config,
            checkpoints,
        );

        if threshold > participants.len() {
            return Err(InitError::ThresholdTooHigh.into());
        }

        let mut latest_checkpoints = IterableMap::new(StorageKey::LatestCheckpointDigests);
        if let Some(checkpoints) = checkpoints {
            for (chain, checkpoint) in checkpoints {
                latest_checkpoints.insert(chain, checkpoint);
            }
        }

        Ok(Self::V0(MpcContract {
            protocol_state: ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates: Candidates::new(),
                join_votes: Votes::new(),
                leave_votes: Votes::new(),
                threshold_votes: ThresholdVotes::new(),
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: config.unwrap_or_default(),
            latest_checkpoints,
            checkpoint_votes: CheckpointVotes::new(),
        }))
    }

    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        let state_bytes =
            env::storage_read(b"STATE").ok_or(InvalidState::ContractStateIsMissing)?;
        migration::migrate(&state_bytes)
    }

    pub fn state(&self) -> ProtocolContractStateView {
        match self.state_ref() {
            ProtocolContractState::NotInitialized => ProtocolContractStateView::NotInitialized,
            ProtocolContractState::Initializing(state) => {
                ProtocolContractStateView::Initializing(state.into())
            }
            ProtocolContractState::Running(state) => {
                ProtocolContractStateView::Running(state.into())
            }
            ProtocolContractState::Resharing(state) => {
                ProtocolContractStateView::Resharing(state.clone())
            }
        }
    }

    pub fn config(&self) -> &Config {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.config,
        }
    }

    pub fn latest_checkpoint(&self, chain: Chain) -> Option<&ConsensusCheckpointDigest> {
        self.latest_checkpoints().get(&chain)
    }

    /// Returns information and admission votes for a running candidate.
    pub fn candidate_info(&self, account_id: AccountId) -> Option<CandidateEntry> {
        match self.state_ref() {
            ProtocolContractState::Running(state) => {
                state.candidates.get(&account_id).cloned().map(|info| {
                    let join_votes = state
                        .join_votes
                        .votes
                        .get(&account_id)
                        .cloned()
                        .unwrap_or_default();
                    CandidateEntry { info, join_votes }
                })
            }
            _ => None,
        }
    }

    pub fn read(&self, reads: Vec<Read>) -> Vec<View> {
        let mut views = Vec::with_capacity(reads.len());

        for read in reads {
            let view = match read {
                Read::State => View::State(self.state()),
                Read::Config => View::Config(self.config().clone()),
                Read::Checkpoints => View::Checkpoints(
                    Chain::iter()
                        .into_iter()
                        .filter_map(|chain| self.latest_checkpoint(chain).map(|cp| (chain, *cp)))
                        .collect(),
                ),
            };
            views.push(view);
        }

        views
    }

    /// Vote for a checkpoint digest.
    ///
    /// Checkpoints are ordered by `(chain, height)`. The latest checkpoint is
    /// advanced only after votes from at least the protocol threshold of
    /// participants have been collected.
    ///
    /// The submitted checkpoint is handled as follows:
    ///
    /// - If the contract already has a checkpoint at a greater height, the
    ///   request is rejected with [`CheckpointError::CheckpointBehind`]. No
    ///   vote is recorded or removed.
    /// - If the contract already has a checkpoint at the same height with the
    ///   same digest, the request is an idempotent no-op. No vote is recorded
    ///   or removed.
    /// - If the contract already has a checkpoint at the same height with a
    ///   different digest, the request is rejected as conflicting.
    /// - If the submitted height is greater than the current checkpoint, the
    ///   caller votes for the submitted digest. Competing digests at the same
    ///   unfinalized height may retain overlapping voters.
    /// - If the resulting vote count is below the threshold, the vote remains
    ///   stored and the latest checkpoint is unchanged.
    /// - If the resulting vote count reaches the threshold, the submitted
    ///   checkpoint becomes the latest checkpoint. Votes for that chain at
    ///   this height or any lower height are removed; votes for higher heights
    ///   are retained.
    ///
    /// The return value is `Ok(true)` when the submitted checkpoint is already
    /// settled at the same height or becomes settled during this call. It is
    /// `Ok(false)` when the vote was recorded but more votes are still
    /// required.
    ///
    /// Returns an error if the protocol is not running, the caller is not an
    /// eligible participant, the submitted checkpoint is behind the latest
    /// checkpoint, or the caller submits a different digest for an already
    /// finalized height.
    #[handle_result]
    pub fn vote_checkpoint(
        &mut self,
        checkpoint: ConsensusCheckpointDigest,
    ) -> Result<bool, Error> {
        let voter = self.voter()?;
        let threshold = match self.state_ref() {
            ProtocolContractState::Running(state) => state.threshold,
            _ => return Err(InvalidState::ProtocolStateNotRunning.into()),
        };

        if let Some(existing) = self.latest_checkpoint(checkpoint.chain) {
            if existing.height > checkpoint.height {
                // checkpoint is behind, reject.
                return Err(CheckpointError::CheckpointBehind.into());
            }
            if existing.height == checkpoint.height {
                if existing.digest == checkpoint.digest {
                    // checkpoint is already settled, no-op.
                    return Ok(true);
                }
                return Err(CheckpointError::ConflictingCheckpoint.into());
            }
        }

        let vote_count = {
            let checkpoint_votes = self.checkpoint_votes_mut();
            let voters = checkpoint_votes.entry(checkpoint);
            voters.insert(voter);
            voters.len()
        };

        if vote_count < threshold {
            return Ok(false);
        }
        self.insert_checkpoint(checkpoint.chain, checkpoint);

        // Remove stale votes where candidate checkpoint is less than or equal to
        // this voted in consensus checkpoint.
        self.checkpoint_votes_mut().votes.retain(|candidate, _| {
            candidate.chain != checkpoint.chain || candidate.height > checkpoint.height
        });
        Ok(true)
    }

    pub fn checkpoint_votes(&self, chain: Chain) -> Vec<(ConsensusCheckpointDigest, usize)> {
        let votes = match self {
            Self::V0(mpc_contract) => &mpc_contract.checkpoint_votes,
        };

        votes
            .votes
            .iter()
            .filter(|(checkpoint, _)| checkpoint.chain == chain)
            .map(|(checkpoint, voters)| (*checkpoint, voters.len()))
            .collect()
    }

    pub fn system_load(&self) -> u32 {
        let pending_requests = self.pending_requests();
        ((pending_requests as f64 / MAX_CONCURRENT_REQUESTS as f64) * 100.0)
            .min(100.0)
            .round() as u32
    }

    pub fn pending_requests(&self) -> u32 {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.len(),
        }
    }

    pub fn pending_requests_data(&self) -> Vec<(&SignId, &PendingRequest)> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.iter().collect(),
        }
    }

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[private]
    pub fn sign_helper(&mut self, request: InternalSignRequest) {
        let yield_promise = env::promise_yield_create(
            "clear_state_on_finish",
            serde_json::to_vec(&(&request,)).unwrap(),
            CLEAR_STATE_ON_FINISH_CALL_GAS,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        // Store the request in the contract's local state
        let Some(bytes) = env::read_register(DATA_ID_REGISTER) else {
            let _ = self.remove_request(&request.id);
            panic_str("failed to read register for data id");
        };
        let Ok(data_id) = bytes.try_into() else {
            let _ = self.remove_request(&request.id);
            panic_str("failed to convert data id");
        };

        self.set_request_yield(&request.id, data_id);

        // NOTE: there's another promise after the clear_state_on_finish to avoid any errors
        // that would rollback the state.
        let final_yield_promise = env::promise_then(
            yield_promise,
            env::current_account_id(),
            "return_signature_on_finish",
            [],
            NearToken::from_near(0),
            RETURN_SIGNATURE_ON_FINISH_CALL_GAS,
        );
        // The return value for this function call will be the value
        // returned by the `sign_on_finish` callback.
        env::promise_return(final_yield_promise);
    }

    #[private]
    #[handle_result]
    pub fn return_signature_on_finish(
        &mut self,
        #[callback_unwrap] signature: SignPoll,
    ) -> Result<Signature, Error> {
        match signature {
            SignPoll::Ready(signature) => {
                log!("Signature is ready.");
                Ok(signature)
            }
            SignPoll::Timeout => Err(SignError::Timeout.into()),
        }
    }

    fn refund_on_fail(request: &InternalSignRequest) {
        let amount = request.deposit;
        let to = request.requester.clone();
        log!("refund {amount} to {to} due to fail");
        Promise::new(to).transfer(amount).detach();
    }

    fn refund_on_success(request: &InternalSignRequest) {
        let deposit = request.deposit;
        let required = request.required_deposit;
        if let Some(diff) = deposit.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                let to = request.requester.clone();
                log!("refund more than required deposit {diff} to {to}");
                Promise::new(to).transfer(diff).detach();
            }
        }
    }

    #[private]
    #[handle_result]
    pub fn clear_state_on_finish(
        &mut self,
        request: InternalSignRequest,
        #[callback_result] signature: Result<Signature, PromiseError>,
    ) -> Result<SignPoll, Error> {
        // Clean up the local state
        if let Err(err) = self.remove_request(&request.id) {
            // refund must happen in clear_state_on_finish, because regardless of this success or fail
            // the promise created by clear_state_on_finish is executed, because of callback_unwrap and
            // promise_then. but if return_signature_on_finish fail (returns error), the promise created
            // by it won't execute.
            Self::refund_on_fail(&request);
            return Err(err);
        }
        match signature {
            Ok(signature) => {
                Self::refund_on_success(&request);
                Ok(SignPoll::Ready(signature))
            }
            Err(_) => {
                Self::refund_on_fail(&request);
                Ok(SignPoll::Timeout)
            }
        }
    }

    #[private]
    pub fn update_config(&mut self, config: Config) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.config = config;
            }
        }
    }

    fn mutable_state(&mut self) -> &mut ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mut mpc_contract.protocol_state,
        }
    }

    fn state_ref(&self) -> &ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    fn contains_request(&self, id: &SignId) -> bool {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.contains_key(id),
        }
    }

    fn lock_request(&mut self, id: SignId, payload: Scalar, epsilon: Scalar) {
        match self {
            Self::V0(mpc_contract) => mpc_contract.lock_request(id, payload, epsilon),
        }
    }

    fn get_request(&self, id: &SignId) -> Option<&PendingRequest> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.get(id),
        }
    }

    fn set_request_yield(&mut self, sign_id: &SignId, data_id: CryptoHash) {
        match self {
            Self::V0(mpc_contract) => mpc_contract.set_request_yield(sign_id, data_id),
        }
    }

    fn remove_request(&mut self, id: &SignId) -> Result<PendingRequest, Error> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.remove_request(id),
        }
    }

    fn threshold(&self) -> Result<usize, Error> {
        match self {
            Self::V0(contract) => match &contract.protocol_state {
                ProtocolContractState::Initializing(state) => Ok(state.threshold),
                ProtocolContractState::Running(state) => Ok(state.threshold),
                ProtocolContractState::Resharing(state) => Ok(state.threshold),
                ProtocolContractState::NotInitialized => {
                    Err(InvalidState::UnexpectedProtocolState
                        .message(contract.protocol_state.name()))
                }
            },
        }
    }

    fn proposed_updates(&mut self) -> &mut ProposedUpdates {
        match self {
            Self::V0(contract) => &mut contract.proposed_updates,
        }
    }

    /// Get our own account id as a voter. Check to see if we are a participant in the protocol.
    /// If we are not a participant, return an error.
    fn voter(&self) -> Result<AccountId, Error> {
        let voter = env::signer_account_id();
        match self {
            Self::V0(contract) => match &contract.protocol_state {
                ProtocolContractState::Initializing(state) => {
                    if !state.candidates.contains_key(&voter) {
                        return Err(VoteError::VoterNotParticipant.into());
                    }
                }
                ProtocolContractState::Running(state) => {
                    if !state.participants.contains_key(&voter) {
                        return Err(VoteError::VoterNotParticipant.into());
                    }
                }
                ProtocolContractState::Resharing(state) => {
                    if !state.old_participants.contains_key(&voter) {
                        return Err(VoteError::VoterNotParticipant.into());
                    }
                }
                ProtocolContractState::NotInitialized => {
                    return Err(InvalidState::UnexpectedProtocolState
                        .message(contract.protocol_state.name()));
                }
            },
        }
        Ok(voter)
    }

    fn latest_checkpoints(&self) -> &IterableMap<Chain, ConsensusCheckpointDigest> {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.latest_checkpoints,
        }
    }

    fn insert_checkpoint(&mut self, chain: Chain, checkpoint: ConsensusCheckpointDigest) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.latest_checkpoints.insert(chain, checkpoint);
            }
        }
    }

    fn checkpoint_votes_mut(&mut self) -> &mut CheckpointVotes {
        match self {
            Self::V0(mpc_contract) => &mut mpc_contract.checkpoint_votes,
        }
    }

    /// Settle each chain's *canonical reset checkpoint*: the one asserting an
    /// empty backlog at `resume_after`.
    ///
    /// Its digest is derived from `(chain, resume_after)` alone, so every node
    /// can rebuild it locally and regress onto it through the ordinary
    /// divergence path. Votes for the chain are dropped, since they describe
    /// the abandoned history.
    ///
    /// `resume_after` is exclusive: indexing resumes at `resume_after + 1`.
    ///
    /// The resulting checkpoint is deliberately indistinguishable from one the
    /// network settled with an empty backlog at the same height, because it
    /// describes the same state. What makes a reset recognisable is the event
    /// logged here, not the state it leaves behind.
    ///
    /// Callable only by the contract account itself.
    #[private]
    pub fn reset_checkpoints(&mut self, resets: Vec<CheckpointReset>) {
        let mut chains = HashSet::new();
        for CheckpointReset {
            chain,
            resume_after,
        } in resets
        {
            chains.insert(chain);
            self.insert_checkpoint(
                chain,
                ConsensusCheckpointDigest::new(
                    chain,
                    resume_after,
                    mpc_primitives::reset_checkpoint_digest(chain, resume_after),
                ),
            );
            env::log_str(
                &serde_json::json!({
                    "event": "checkpoint_reset",
                    "chain": chain,
                    "resume_after": resume_after,
                })
                .to_string(),
            );
        }
        self.checkpoint_votes_mut()
            .votes
            .retain(|checkpoint, _| !chains.contains(&checkpoint.chain));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::borsh::BorshSerialize;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    #[derive(BorshSerialize)]
    struct OldMpcContract {
        protocol_state: ProtocolContractState,
        pending_requests: IterableMap<SignId, PendingRequest>,
        proposed_updates: ProposedUpdates,
        config: Config,
    }

    #[derive(BorshSerialize)]
    enum VersionedOldMpcContract {
        V0(OldMpcContract),
    }

    #[derive(BorshSerialize)]
    struct IterableMapValueAndIndexForTest<V> {
        value: V,
        key_index: u32,
    }

    // Mirrors near-sdk's `IterableMap::with_hasher` layout for the map half:
    // `LatestCheckpointDigests` is split into a vector of iterable keys under
    // `<prefix>v` and a lookup map under `<prefix>m`.
    fn latest_checkpoints_map_prefix() -> Vec<u8> {
        let mut prefix = Vec::new();
        StorageKey::LatestCheckpointDigests
            .serialize(&mut prefix)
            .unwrap();
        [prefix.as_slice(), b"m"].concat()
    }

    // Seed only the lookup-map entry and intentionally do not seed the vector
    // key entry. This reproduces the observed deployed state where
    // `latest_checkpoint(chain)` works because it uses `.get()`, while
    // `IterableMap::iter()` returns no checkpoints.
    fn seed_checkpoint_lookup_without_iterable_key(
        chain: Chain,
        checkpoint: ConsensusCheckpointDigest,
    ) {
        let mut key_bytes = latest_checkpoints_map_prefix();
        chain.serialize(&mut key_bytes).unwrap();
        let storage_key = env::sha256_array(&key_bytes);

        let value = IterableMapValueAndIndexForTest {
            value: checkpoint,
            key_index: 0,
        };
        let value_bytes = borsh::to_vec(&value).unwrap();
        env::storage_write(&storage_key, &value_bytes);
    }

    #[test]
    fn test_migrate_idempotent() {
        let context = VMContextBuilder::new()
            .current_account_id("contract.near".parse().unwrap())
            .build();
        testing_env!(context);

        // 1. Serialize and write the OLD contract state to storage
        let old_contract = OldMpcContract {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::default(),
        };
        let versioned_old = VersionedOldMpcContract::V0(old_contract);
        let old_bytes = borsh::to_vec(&versioned_old).unwrap();
        env::storage_write(b"STATE", &old_bytes);

        // 2. Call migrate for the first time
        let migrated_res = VersionedMpcContract::migrate();
        assert!(
            migrated_res.is_ok(),
            "First migrate failed: {:?}",
            migrated_res.err()
        );
        let migrated = migrated_res.unwrap();

        // Write the migrated state to storage (simulate what near_bindgen does on success)
        let migrated_bytes = borsh::to_vec(&migrated).unwrap();
        env::storage_write(b"STATE", &migrated_bytes);

        // Verify the migrated state has latest_checkpoints initialized
        match &migrated {
            VersionedMpcContract::V0(contract) => {
                assert!(contract.latest_checkpoints.is_empty());
            }
        }

        // 3. Call migrate for the second time (idempotent check)
        let second_migrated_res = VersionedMpcContract::migrate();
        assert!(
            second_migrated_res.is_ok(),
            "Second migrate (idempotent) failed: {:?}",
            second_migrated_res.err()
        );
        let second_migrated = second_migrated_res.unwrap();

        // Verify the second migrated state matches
        match &second_migrated {
            VersionedMpcContract::V0(contract) => {
                assert!(contract.latest_checkpoints.is_empty());
            }
        }
    }

    #[test]
    fn test_checkpoint_read_handles_missing_iterable_keys() {
        let context = VMContextBuilder::new()
            .current_account_id("contract.near".parse().unwrap())
            .build();
        testing_env!(context);

        let checkpoint = ConsensusCheckpointDigest::new(Chain::Solana, 120, [7u8; 32]);
        seed_checkpoint_lookup_without_iterable_key(Chain::Solana, checkpoint);

        // Construct a contract whose `latest_checkpoints` map points at the
        // seeded storage. The map itself has an empty iterable key vector.
        let contract = VersionedMpcContract::V0(MpcContract {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        });

        // Prove the test setup matches production: direct lookup sees the
        // checkpoint, but iteration over the same map does not.
        assert!(
            contract.latest_checkpoint(Chain::Solana).is_some(),
            "direct checkpoint lookup should reproduce production .get() behavior"
        );
        assert!(
            contract.latest_checkpoints().iter().next().is_none(),
            "test setup should reproduce the broken iterable index"
        );

        // `read(Checkpoints)` is the path nodes use to learn confirmed
        // checkpoints. It must not rely on `IterableMap::iter()` here.
        let checkpoints = contract
            .read(vec![Read::Checkpoints])
            .into_iter()
            .find_map(|view| match view {
                View::Checkpoints(checkpoints) => Some(checkpoints),
                _ => None,
            })
            .expect("read should return checkpoints view");

        let stored = checkpoints
            .get(&Chain::Solana)
            .expect("read(Checkpoints) should not rely on IterableMap::iter()");
        assert_eq!(stored.height, checkpoint.height);
        assert_eq!(stored.digest, checkpoint.digest);
    }

    // A Running-state contract with `alice.near` as sole participant, so that
    // `vote_checkpoint` gets past the voter and protocol-state checks.
    fn running_contract(threshold: usize) -> VersionedMpcContract {
        use std::str::FromStr;

        testing_env!(VMContextBuilder::new()
            .current_account_id("contract.near".parse().unwrap())
            .signer_account_id("alice.near".parse().unwrap())
            .build());

        let public_key =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
        let alice: AccountId = "alice.near".parse().unwrap();
        let mut participants = Participants::new();
        participants.insert(
            alice.clone(),
            primitives::ParticipantInfo {
                account_id: alice,
                url: "https://alice.example".to_owned(),
                cipher_pk: [7; 32],
                sign_pk: public_key.clone(),
            },
        );

        VersionedMpcContract::V0(MpcContract {
            protocol_state: ProtocolContractState::Running(RunningContractState {
                epoch: 0,
                participants,
                threshold,
                public_key,
                candidates: Candidates::new(),
                join_votes: Votes::new(),
                leave_votes: Votes::new(),
                threshold_votes: ThresholdVotes::new(),
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::default(),
            latest_checkpoints: IterableMap::new(StorageKey::LatestCheckpointDigests),
            checkpoint_votes: CheckpointVotes::new(),
        })
    }

    #[test]
    fn reset_settles_the_canonical_checkpoint_and_clears_votes() {
        let mut contract = VersionedMpcContract::V0(MpcContract::init(0, BTreeMap::new(), None));
        let solana_checkpoint = ConsensusCheckpointDigest::new(Chain::Solana, 10, [1u8; 32]);
        let ethereum_checkpoint = ConsensusCheckpointDigest::new(Chain::Ethereum, 20, [2u8; 32]);

        contract.insert_checkpoint(Chain::Solana, solana_checkpoint);
        contract
            .checkpoint_votes_mut()
            .entry(solana_checkpoint)
            .insert("voter.near".parse().unwrap());
        contract
            .checkpoint_votes_mut()
            .entry(ethereum_checkpoint)
            .insert("voter.near".parse().unwrap());

        contract.reset_checkpoints(vec![CheckpointReset {
            chain: Chain::Solana,
            resume_after: 5,
        }]);

        // The reset is an ordinary settled checkpoint whose digest is derived
        // from the pair, which is what every node re-derives locally.
        assert_eq!(
            contract.latest_checkpoint(Chain::Solana),
            Some(&ConsensusCheckpointDigest::new(
                Chain::Solana,
                5,
                mpc_primitives::reset_checkpoint_digest(Chain::Solana, 5),
            ))
        );
        assert!(contract.checkpoint_votes(Chain::Solana).is_empty());
        assert_eq!(contract.checkpoint_votes(Chain::Ethereum).len(), 1);
    }

    #[test]
    fn reset_height_is_a_vote_floor_without_extra_logic() {
        let mut contract = running_contract(1);
        contract.reset_checkpoints(vec![CheckpointReset {
            chain: Chain::Solana,
            resume_after: 100,
        }]);

        // Below the reset height the ordinary "behind" rule already rejects.
        let behind = ConsensusCheckpointDigest::new(Chain::Solana, 99, [1u8; 32]);
        assert!(contract
            .vote_checkpoint(behind)
            .unwrap_err()
            .to_string()
            .contains(&CheckpointError::CheckpointBehind.to_string()));
        assert!(contract.checkpoint_votes(Chain::Solana).is_empty());

        // Re-submitting the reset checkpoint itself is an idempotent no-op,
        // which is what lets nodes confirm it rather than fight over it.
        let reset = ConsensusCheckpointDigest::new(
            Chain::Solana,
            100,
            mpc_primitives::reset_checkpoint_digest(Chain::Solana, 100),
        );
        assert!(contract.vote_checkpoint(reset).unwrap());

        // A competing digest at the reset height is a conflict, not a silent
        // overwrite of the state the network was told to restart from.
        let conflicting = ConsensusCheckpointDigest::new(Chain::Solana, 100, [2u8; 32]);
        assert!(contract
            .vote_checkpoint(conflicting)
            .unwrap_err()
            .to_string()
            .contains(&CheckpointError::ConflictingCheckpoint.to_string()));

        // Above it, voting resumes normally and settles past the reset.
        let above = ConsensusCheckpointDigest::new(Chain::Solana, 101, [3u8; 32]);
        assert!(contract.vote_checkpoint(above).unwrap());
        assert_eq!(
            contract.latest_checkpoint(Chain::Solana),
            Some(&above),
            "a settled checkpoint replaces the reset checkpoint"
        );
    }

    #[test]
    fn reset_logs_the_event_that_identifies_it() {
        let mut contract = running_contract(1);
        contract.reset_checkpoints(vec![CheckpointReset {
            chain: Chain::Solana,
            resume_after: 100,
        }]);

        // The settled checkpoint is deliberately indistinguishable from an
        // ordinary empty-backlog one, so this log is the only record that a
        // reset happened. Operators and indexers read it, hence the assertion.
        let logs = near_sdk::test_utils::get_logs();
        let event = logs
            .iter()
            .find(|line| line.contains("checkpoint_reset"))
            .expect("a reset must log an event identifying it");
        let event: serde_json::Value = serde_json::from_str(event).expect("event must be JSON");
        assert_eq!(event["event"], "checkpoint_reset");
        assert_eq!(event["chain"], serde_json::json!(Chain::Solana));
        assert_eq!(event["resume_after"], 100);
    }

    #[test]
    fn reset_can_be_reissued_at_a_different_height() {
        let mut contract = running_contract(1);
        contract.reset_checkpoints(vec![CheckpointReset {
            chain: Chain::Solana,
            resume_after: 100,
        }]);
        // Correcting an operator mistake: a second reset simply settles a
        // different checkpoint, including backwards.
        contract.reset_checkpoints(vec![CheckpointReset {
            chain: Chain::Solana,
            resume_after: 30,
        }]);

        assert_eq!(
            contract.latest_checkpoint(Chain::Solana),
            Some(&ConsensusCheckpointDigest::new(
                Chain::Solana,
                30,
                mpc_primitives::reset_checkpoint_digest(Chain::Solana, 30),
            ))
        );
    }
}
