pub mod config;
pub mod errors;
pub mod primitives;
pub mod state;
pub mod update;

use errors::{
    ConversionError, InitError, InvalidParameters, InvalidState, JoinError, PublicKeyError,
    RespondError, SignError, VoteError,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use mpc_crypto::{
    derive_epsilon_near, derive_key, kdf::check_ec_signature, near_public_key_to_affine_point,
    ScalarExt as _,
};
use mpc_primitives::{SignId, Signature};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::env::panic_str;
use near_sdk::json_types::U128;
use near_sdk::store::IterableMap;
use near_sdk::{
    env, log, near_bindgen, AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise,
    PromiseError, PublicKey,
};
use primitives::{
    CandidateInfo, Candidates, InternalSignRequest, Participants, PendingRequest, PkVotes,
    SignPoll, SignRequest, StorageKey, Votes, YieldIndex,
};
use std::collections::{BTreeMap, HashSet};

use crate::config::Config;
use crate::errors::Error;
use crate::update::{ProposeUpdateArgs, ProposedUpdates, UpdateId};

pub use state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
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

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Debug)]
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
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: Candidates { candidates },
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: config.unwrap_or_default(),
        }
    }
}

// User contract API
#[near_bindgen]
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
        let sign_id = SignId::from_parts(&predecessor, &payload_bytes, &path, key_version);
        if self.contains_request(&sign_id) {
            return Err(SignError::RequestCollision.into());
        }

        log!(
            "sign: predecessor={predecessor}, payload={payload:?}, path={path:?}, key_version={key_version}",
        );
        let entropy = near_sdk::env::random_seed_array();
        env::log_str(&serde_json::to_string(&entropy).unwrap());
        let epsilon = derive_epsilon_near(&predecessor, &path);

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
        match self.state() {
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
        path: String,
        predecessor: Option<AccountId>,
    ) -> Result<PublicKey, Error> {
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let epsilon = derive_epsilon_near(&predecessor, &path);
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
    /// Currently only 0 is a valid key version
    pub const fn latest_key_version(&self) -> u32 {
        0
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
#[near_bindgen]
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

        env::promise_yield_resume(&index.data_id, &serde_json::to_vec(&signature).unwrap());
        Ok(())
    }

    #[handle_result]
    pub fn join(
        &mut self,
        url: String,
        cipher_pk: primitives::hpke::PublicKey,
        sign_pk: PublicKey,
    ) -> Result<(), Error> {
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
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        new_participants,
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
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
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        new_participants,
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
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
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: 0,
                        participants: candidates.clone().into(),
                        threshold: *threshold,
                        public_key,
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
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
                old_participants: _,
                new_participants,
                threshold,
                public_key,
                finished_votes,
            }) => {
                if *old_epoch + 1 != epoch {
                    return Err(InvalidState::EpochMismatch.into());
                }
                finished_votes.insert(voter);
                if finished_votes.len() >= *threshold {
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
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
                Promise::new(proposer).transfer(diff);
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
#[near_bindgen]
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
    ) -> Result<Self, Error> {
        log!(
            "init_running: signer={}, epoch={}, participants={}, threshold={}, public_key={:?}, config={:?}",
            env::signer_account_id(),
            epoch,
            serde_json::to_string(&participants).unwrap(),
            threshold,
            public_key,
            config,
        );

        if threshold > participants.len() {
            return Err(InitError::ThresholdTooHigh.into());
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
            }),
            pending_requests: IterableMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
            config: config.unwrap_or_default(),
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
        let old: MpcContract = env::state_read().ok_or(InvalidState::ContractStateIsMissing)?;
        Ok(VersionedMpcContract::V0(old))
    }

    pub fn state(&self) -> &ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    pub fn config(&self) -> &Config {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.config,
        }
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

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[private]
    pub fn sign_helper(&mut self, request: InternalSignRequest) {
        let yield_promise = env::promise_yield_create(
            "clear_state_on_finish",
            &serde_json::to_vec(&(&request,)).unwrap(),
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
            &[],
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
        Promise::new(to).transfer(amount);
    }

    fn refund_on_success(request: &InternalSignRequest) {
        let deposit = request.deposit;
        let required = request.required_deposit;
        if let Some(diff) = deposit.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                let to = request.requester.clone();
                log!("refund more than required deposit {diff} to {to}");
                Promise::new(to).transfer(diff);
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
            Self::V0(ref mut mpc_contract) => &mut mpc_contract.protocol_state,
        }
    }

    fn contains_request(&self, id: &SignId) -> bool {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.contains_key(id),
        }
    }

    fn lock_request(&mut self, id: SignId, payload: Scalar, epsilon: Scalar) {
        match self {
            Self::V0(ref mut mpc_contract) => mpc_contract.lock_request(id, payload, epsilon),
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
}
