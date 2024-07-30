#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use borsh::BorshDeserialize;
use near_sdk::collections::LookupMap;
use near_sdk::{env, AccountId};

use crate::config::Config;
use crate::errors::{InitError, MpcContractError};
use crate::primitives::{SignatureRequest, YieldIndex};
use crate::{update, MpcContract, ProtocolContractState, VersionedMpcContract};

#[derive(BorshDeserialize)]
pub struct OldConfig {
    pub triple_timeout: u64,
    pub presignature_timeout: u64,
    pub signature_timeout: u64,
}

#[derive(BorshDeserialize)]
enum OldUpdate {
    Config(OldConfig),
    Contract(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OldUpdateId(pub(crate) u64);

impl BorshDeserialize for OldUpdateId {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let id = match u64::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing update id: {:?}", err));
                return Err(err);
            }
        };
        Ok(OldUpdateId(id))
    }
}

pub struct OldProposedUpdates {
    updates: HashMap<OldUpdateId, Vec<OldUpdate>>,
    votes: HashMap<OldUpdateId, HashSet<AccountId>>,
    next_id: u64,
}

impl BorshDeserialize for OldProposedUpdates {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let updates = match HashMap::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing updates: {:?}", err));
                return Err(err);
            }
        };
        let votes = match HashMap::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing votes: {:?}", err));
                return Err(err);
            }
        };
        let next_id = match u64::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing next_id: {:?}", err));
                return Err(err);
            }
        };
        Ok(OldProposedUpdates {
            updates,
            votes,
            next_id,
        })
    }
}

pub struct OldContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_counter: u32,
    proposed_updates: OldProposedUpdates,
    config: OldConfig,
}

impl BorshDeserialize for OldContract {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let protocol_state = match ProtocolContractState::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing protocol state: {:?}", err));
                return Err(err);
            }
        };

        let pending_requests = match LookupMap::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!(
                    "Error deserializing pending requests state: {:?}",
                    err
                ));
                return Err(err);
            }
        };
        let request_counter = match u32::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing request counter: {:?}", err));
                return Err(err);
            }
        };
        let proposed_updates = match OldProposedUpdates::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!(
                    "Error deserializing propose updates state: {:?}",
                    err
                ));
                return Err(err);
            }
        };
        let config = match OldConfig::deserialize_reader(reader) {
            Ok(state) => state,
            Err(err) => {
                env::log_str(&format!("Error deserializing config state: {:?}", err));
                return Err(err);
            }
        };
        Ok(OldContract {
            protocol_state,
            pending_requests,
            request_counter,
            proposed_updates,
            config,
        })
    }
}

#[derive(BorshDeserialize)]
enum OldVersionedMpcContract {
    V0(OldContract),
}

pub fn migrate_testnet_dev() -> Result<VersionedMpcContract, MpcContractError> {
    // try to load state, if it doesn't work, then we need to do migration for dev.
    // NOTE: that since we're in dev, there will be many changes. If state was able
    // to be loaded successfully, then that means a migration was not necessary and
    // the developer did not change the contract state.
    let data = env::storage_read(b"STATE")
        .ok_or_else(|| MpcContractError::InitError(InitError::ContractStateIsMissing))?;

    if let Ok(loaded) = MpcContract::try_from_slice(&data) {
        return Ok(VersionedMpcContract::V0(loaded));
    };

    // NOTE: for any PRs that have this error, change the code in this block so we can keep
    // our dev environment not broken.

    let old = OldVersionedMpcContract::try_from_slice(&data).unwrap();
    let mut old = match old {
        OldVersionedMpcContract::V0(old) => old,
    };
    let mut new_updates = update::ProposedUpdates::default();
    for (id, updates) in old.proposed_updates.updates {
        let updates: Vec<_> = updates
            .into_iter()
            .map(|update| match update {
                OldUpdate::Config(_) => update::Update::Config(Config::default()),
                OldUpdate::Contract(contract) => update::Update::Contract(contract),
            })
            .collect();

        let entry = update::UpdateEntry {
            bytes_used: update::bytes_used_updates(&updates),
            updates,
            votes: old.proposed_updates.votes.remove(&id).unwrap(),
        };
        new_updates.entries.insert(update::UpdateId(id.0), entry);
    }
    new_updates.id = update::UpdateId(old.proposed_updates.next_id);

    let migrated = VersionedMpcContract::V0(MpcContract {
        protocol_state: old.protocol_state,
        pending_requests: old.pending_requests,
        request_counter: old.request_counter,
        proposed_updates: new_updates,
        config: Config::default(),
    });

    return Ok(migrated);
}

fn deserialize_or_log<T: BorshDeserialize, R: borsh::io::Read>(
    reader: &mut R,
    which_state: &str,
) -> Result<T, MpcContractError> {
    match T::deserialize_reader(reader) {
        Ok(state) => Ok(state),
        Err(err) => {
            env::log_str(&format!("Error deserializing {which_state} state: {err:?}"));
            Err(MpcContractError::InitError(
                InitError::ContractStateIsBroken,
            ))
        }
    }
}
