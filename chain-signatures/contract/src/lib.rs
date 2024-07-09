pub mod primitives;

use crypto_shared::{
    derive_epsilon, derive_key, kdf::check_ec_signature, near_public_key_to_affine_point,
    types::SignatureResponse, ScalarExt as _, SerializableScalar,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::serde::{Deserialize, Serialize};

use near_sdk::{
    env, log, near_bindgen, AccountId, BorshStorageKey, Gas, NearToken, Promise, PromiseOrValue,
    PublicKey,
};

use primitives::{
    CandidateInfo, Candidates, ParticipantInfo, Participants, PkVotes, SignRequest, Votes,
};
use std::collections::{BTreeMap, HashSet};

const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(250);

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

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
pub enum StorageKey {
    PendingRequests,
}

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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct SignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: [u8; 32],
}

impl SignatureRequest {
    pub fn new(payload_hash: [u8; 32], predecessor_id: &AccountId, path: &str) -> Self {
        let scalar = derive_epsilon(predecessor_id, path);
        let epsilon = SerializableScalar { scalar };
        SignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, Option<SignatureResponse>>,
    request_counter: u32,
}

impl MpcContract {
    fn add_request(&mut self, request: &SignatureRequest, result: &Option<SignatureResponse>) {
        if self.request_counter > 8 {
            env::panic_str("Too many pending requests. Please, try again later.");
        }
        if !self.pending_requests.contains_key(request) {
            self.request_counter += 1;
        }
        self.pending_requests.insert(request, result);
    }

    fn remove_request(&mut self, payload: &SignatureRequest) {
        self.pending_requests.remove(payload);
        self.request_counter -= 1;
    }

    fn add_sign_result(&mut self, payload: &SignatureRequest, signature: SignatureResponse) {
        if self.pending_requests.contains_key(payload) {
            self.pending_requests.insert(payload, &Some(signature));
        }
    }

    fn clean_payloads(&mut self, requests: Vec<SignatureRequest>, counter: u32) {
        log!("clean_payloads");
        for payload in requests.iter() {
            self.pending_requests.remove(payload);
        }
        self.request_counter = counter;
    }

    pub fn init(threshold: usize, candidates: BTreeMap<AccountId, CandidateInfo>) -> Self {
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: Candidates { candidates },
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_counter: 0,
        }
    }
}

// User contract API
#[near_bindgen]
impl VersionedMpcContract {
    #[allow(unused_variables)]
    /// `key_version` must be less than or equal to the value at `latest_key_version`
    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each signature request.
    /// The fee changes based on how busy the network is.
    #[payable]
    pub fn sign(&mut self, request: SignRequest) -> Promise {
        let SignRequest {
            payload,
            path,
            key_version,
        } = request;
        let latest_key_version: u32 = self.latest_key_version();
        assert!(
            key_version <= latest_key_version,
            "This version of the signer contract doesn't support versions greater than {}",
            latest_key_version,
        );
        // Check deposit
        let deposit = env::attached_deposit();
        let required_deposit = self.signature_deposit();
        if deposit.as_yoctonear() < required_deposit {
            env::panic_str(&format!(
                "Attached deposit is {}, required deposit is {}",
                deposit, required_deposit
            ));
        }
        // Make sure sign call will not run out of gas doing recursive calls because the payload will never be removed
        assert!(
            env::prepaid_gas() >= GAS_FOR_SIGN_CALL,
            "Insufficient gas provided. Provided: {} Required: {}",
            env::prepaid_gas(),
            GAS_FOR_SIGN_CALL
        );
        let predecessor = env::predecessor_account_id();
        log!(
            "sign: predecessor={}, payload={:?}, path={:?}, key_version={}",
            predecessor,
            payload,
            path,
            key_version
        );

        let request = SignatureRequest::new(payload, &predecessor, &path);
        match self.sign_result(&request) {
            None => {
                self.add_sign_request(&request);
                log!(&serde_json::to_string(&near_sdk::env::random_seed_array()).unwrap());
                Self::ext(env::current_account_id()).sign_helper(request, 0)
            }
            Some(_) => env::panic_str("Signature for this payload already requested"),
        }
    }

    /// This is the root public key combined from all the public keys of the participants.
    pub fn public_key(&self) -> PublicKey {
        match self.state() {
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

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    pub fn respond(&mut self, request: SignatureRequest, response: SignatureResponse) {
        let protocol_state = self.mutable_state();
        if let ProtocolContractState::Running(_) = protocol_state {
            let signer = env::signer_account_id();
            // TODO add back in a check to see that the caller is a participant (it's horrible to test atm)
            // It's not strictly necessary, since we verify the payload is correct
            log!(
                "respond: signer={}, request={:?} big_r={:?} s={:?}",
                &signer,
                &request,
                &response.big_r,
                &response.s
            );

            // generate the expected public key
            let expected_public_key = derive_key(
                near_public_key_to_affine_point(self.public_key()),
                request.epsilon.scalar,
            );

            // Check the signature is correct
            if check_ec_signature(
                &expected_public_key,
                &response.big_r.affine_point,
                &response.s.scalar,
                k256::Scalar::from_bytes(&request.payload_hash[..]),
                response.recovery_id,
            )
            .is_err()
            {
                env::panic_str("Signature could not be verified");
            }

            self.add_sign_result(&request, response);
        } else {
            env::panic_str("protocol is not in a running state");
        }
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
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                participants,
                ref mut candidates,
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
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
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

    pub fn vote_leave(&mut self, kick: AccountId) -> bool {
        log!(
            "vote_leave: signer={}, kick={}",
            env::signer_account_id(),
            kick
        );
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
                let signer_account_id = env::signer_account_id();
                if !participants.contains_key(&signer_account_id) {
                    env::panic_str("calling account is not in the participant set");
                }
                if !participants.contains_key(&kick) {
                    env::panic_str("account to leave is not in the participant set");
                }
                if participants.len() <= *threshold {
                    env::panic_str("the number of participants can not go below the threshold");
                }
                let voted = leave_votes.entry(kick.clone());
                voted.insert(signer_account_id);
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
        let protocol_state = self.mutable_state();
        match protocol_state {
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
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
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
        let protocol_state = self.mutable_state();
        match protocol_state {
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
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
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
}

// Contract developer helper API
#[near_bindgen]
impl VersionedMpcContract {
    #[init]
    pub fn init(threshold: usize, candidates: BTreeMap<AccountId, CandidateInfo>) -> Self {
        log!(
            "init: signer={}, treshhold={}, candidates={}",
            env::signer_account_id(),
            threshold,
            serde_json::to_string(&candidates).unwrap()
        );
        Self::V0(MpcContract::init(threshold, candidates))
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init(ignore_state)]
    pub fn init_running(
        epoch: u64,
        participants: BTreeMap<AccountId, ParticipantInfo>,
        threshold: usize,
        public_key: PublicKey,
    ) -> Self {
        log!(
            "init_running: signer={}, epoch={}, participants={}, threshold={}, public_key={:?}",
            env::signer_account_id(),
            epoch,
            serde_json::to_string(&participants).unwrap(),
            threshold,
            public_key
        );
        Self::V0(MpcContract {
            protocol_state: ProtocolContractState::Running(RunningContractState {
                epoch,
                participants: Participants { participants },
                threshold,
                public_key,
                candidates: Candidates::new(),
                join_votes: Votes::new(),
                leave_votes: Votes::new(),
            }),
            pending_requests: LookupMap::new(b"m"),
            request_counter: 0,
        })
    }

    #[private]
    pub fn sign_helper(
        &mut self,
        request: SignatureRequest,
        depth: usize,
    ) -> PromiseOrValue<SignatureResponse> {
        if let Some(signature) = self.sign_result(&request) {
            match signature {
                Some(signature) => {
                    log!(
                        "sign_helper: signature ready: {:?}, depth: {:?}",
                        signature,
                        depth
                    );
                    self.remove_sign_request(&request);
                    PromiseOrValue::Value(signature)
                }
                None => {
                    // Make sure we have enough gas left to do 1 more call and clean up afterwards
                    // Observationally 30 calls < 300 TGas so 2 calls < 20 TGas
                    // We keep one call back so we can cleanup then call panic on the next call
                    // Start cleaning up if there's less than 25 teragas left regardless of how deep you are.
                    if depth > 30 || env::prepaid_gas() < Gas::from_tgas(25) {
                        self.remove_sign_request(&request);
                        let self_id = env::current_account_id();
                        PromiseOrValue::Promise(Self::ext(self_id).fail_helper(
                            "Signature was not provided in time. Please, try again.".to_string(),
                        ))
                    } else {
                        log!(&format!(
                            "sign_helper: signature not ready yet (depth={})",
                            depth
                        ));
                        let account_id = env::current_account_id();
                        PromiseOrValue::Promise(
                            Self::ext(account_id).sign_helper(request, depth + 1),
                        )
                    }
                }
            }
        } else {
            env::panic_str("unexpected request")
        }
    }

    /// This allows us to return a panic, without rolling back the state from this call
    #[private]
    pub fn fail_helper(&mut self, message: String) {
        env::panic_str(&message);
    }

    pub fn state(&self) -> &ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    #[private]
    #[init(ignore_state)]
    pub fn clean(keys: Vec<near_sdk::json_types::Base64VecU8>) -> Self {
        log!("clean: keys={:?}", keys);
        for key in keys.iter() {
            env::storage_remove(&key.0);
        }
        Self::V0(MpcContract {
            protocol_state: ProtocolContractState::NotInitialized,
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_counter: 0,
        })
    }

    #[private]
    pub fn clean_payloads(&mut self, requests: Vec<SignatureRequest>, counter: u32) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.clean_payloads(requests, counter);
            }
        }
    }

    #[private]
    #[init(ignore_state)]
    pub fn migrate_state_old_to_v0() -> Self {
        let old_contract: MpcContract = env::state_read().expect("Old state doesn't exist");
        Self::V0(MpcContract {
            protocol_state: old_contract.protocol_state,
            pending_requests: old_contract.pending_requests,
            request_counter: old_contract.request_counter,
        })
    }

    fn remove_sign_request(&mut self, request: &SignatureRequest) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.remove_request(request);
            }
        }
    }

    fn add_sign_request(&mut self, request: &SignatureRequest) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.add_request(request, &None);
            }
        }
    }

    fn add_sign_result(&mut self, request: &SignatureRequest, response: SignatureResponse) {
        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.add_sign_result(request, response);
            }
        }
    }

    fn mutable_state(&mut self) -> &mut ProtocolContractState {
        match self {
            Self::V0(ref mut mpc_contract) => &mut mpc_contract.protocol_state,
        }
    }

    fn sign_result(&self, request: &SignatureRequest) -> Option<Option<SignatureResponse>> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.get(request),
        }
    }

    fn signature_deposit(&self) -> u128 {
        const CHEAP_REQUESTS: u32 = 3;
        let pending_requests = match self {
            Self::V0(mpc_contract) => mpc_contract.request_counter,
        };
        match pending_requests {
            0..=CHEAP_REQUESTS => 1,
            _ => {
                (pending_requests - CHEAP_REQUESTS) as u128
                    * NearToken::from_millinear(50).as_yoctonear()
            }
        }
    }
}
