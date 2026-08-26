use crate::config::Config;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    CandidateInfo, Candidates, CheckpointVotes, Participants, PendingRequest, PkVotes, StorageKey,
    ThresholdVotes, Votes,
};
use crate::state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
use crate::update::ProposedUpdates;
use crate::{MpcContract, VersionedMpcContract};

use borsh::BorshDeserialize;
use mpc_primitives::{Chain, CheckpointDirective, ConsensusCheckpointDigest, SignId};
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, PublicKey};
use std::collections::BTreeMap;

#[derive(BorshDeserialize)]
pub struct LegacyCandidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

fn migrate_candidates(candidates: LegacyCandidates) -> Candidates {
    let mut migrated = Candidates::new();
    for (account_id, info) in candidates.candidates {
        migrated.insert(account_id, info);
    }
    migrated
}

#[derive(BorshDeserialize)]
pub struct LegacyInitializingContractState {
    pub candidates: LegacyCandidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

fn migrate_initializing(state: LegacyInitializingContractState) -> InitializingContractState {
    InitializingContractState {
        candidates: migrate_candidates(state.candidates),
        threshold: state.threshold,
        pk_votes: state.pk_votes,
    }
}

#[derive(BorshDeserialize)]
pub struct OldRunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: LegacyCandidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

#[derive(BorshDeserialize)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(LegacyInitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}

fn upgrade_protocol_state(old: OldProtocolContractState) -> ProtocolContractState {
    match old {
        OldProtocolContractState::NotInitialized => ProtocolContractState::NotInitialized,
        OldProtocolContractState::Initializing(state) => {
            ProtocolContractState::Initializing(migrate_initializing(state))
        }
        OldProtocolContractState::Running(state) => {
            ProtocolContractState::Running(RunningContractState {
                epoch: state.epoch,
                participants: state.participants,
                threshold: state.threshold,
                public_key: state.public_key,
                candidates: migrate_candidates(state.candidates),
                join_votes: state.join_votes,
                leave_votes: state.leave_votes,
                threshold_votes: ThresholdVotes::new(),
            })
        }
        OldProtocolContractState::Resharing(state) => ProtocolContractState::Resharing(state),
    }
}

/// The contract state shape currently deployed on devnet: identical to
/// [`MpcContract`] except that `latest_checkpoints` stores bare
/// [`ConsensusCheckpointDigest`] values.
///
/// Its blob layout is byte-identical to the current shape (store collections
/// serialize only their prefixes and never their entries or value types), so
/// it is never selected by borsh rejection — `migrate` routes to it via
/// [`detect_checkpoint_layout`].
#[derive(BorshDeserialize)]
pub(crate) struct PreviousDevnet {
    protocol_state: ProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
    latest_checkpoints: IterableMap<Chain, ConsensusCheckpointDigest>,
    checkpoint_votes: CheckpointVotes,
}

impl PreviousDevnet {
    fn upgrade(self) -> MpcContract {
        MpcContract {
            protocol_state: self.protocol_state,
            pending_requests: self.pending_requests,
            proposed_updates: self.proposed_updates,
            config: self.config,
            latest_checkpoints: wrap_digest_checkpoints(self.latest_checkpoints),
            checkpoint_votes: self.checkpoint_votes,
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousTestnet {
    protocol_state: OldProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

impl PreviousTestnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        } = self;
        MpcContract {
            protocol_state: upgrade_protocol_state(protocol_state),
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::CheckpointDirectives),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
}

#[derive(BorshDeserialize)]
pub(crate) struct PreviousMainnet {
    protocol_state: OldProtocolContractState,
    pending_requests: IterableMap<SignId, PendingRequest>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

impl PreviousMainnet {
    fn upgrade(self) -> MpcContract {
        let Self {
            protocol_state,
            pending_requests,
            proposed_updates,
            config,
        } = self;
        MpcContract {
            protocol_state: upgrade_protocol_state(protocol_state),
            pending_requests,
            proposed_updates,
            config,
            latest_checkpoints: IterableMap::new(StorageKey::CheckpointDirectives),
            checkpoint_votes: CheckpointVotes::new(),
        }
    }
}

fn wrap_digest_checkpoints(
    mut old: IterableMap<Chain, ConsensusCheckpointDigest>,
) -> IterableMap<Chain, CheckpointDirective> {
    // Snapshot the legacy entries before writing anything: `migrated` uses a
    // different storage prefix, but reading through the old map after any
    // new-format write would be unsafe if they shared one.
    let mut entries = Vec::new();
    for (chain, checkpoint) in old.iter() {
        entries.push((*chain, *checkpoint));
    }

    let mut migrated = IterableMap::new(StorageKey::CheckpointDirectives);
    for (chain, checkpoint) in &entries {
        migrated.insert(*chain, CheckpointDirective::Consensus(*checkpoint));
    }

    // Reclaim the trie keys holding legacy-encoded values.
    for (chain, _) in &entries {
        old.remove(chain);
    }
    migrated
}

#[derive(BorshDeserialize)]
enum VersionedPreviousDevnet {
    V0(PreviousDevnet),
}

/// A blob interpreted as either already-migrated current state or as
/// pre-marker devnet state awaiting upgrade.
enum DevnetState {
    Current(VersionedMpcContract),
    Legacy(VersionedPreviousDevnet),
}

impl VersionedPreviousDevnet {
    /// The serialized tail of an empty `IterableMap`: everything after the
    /// element count, i.e. exactly the keys-vector and lookup-map storage
    /// prefixes. Maps with different fingerprints can never alias each
    /// other's trie keys.
    fn checkpoint_prefix_fingerprint<V>(prefix: StorageKey) -> Vec<u8>
    where
        V: borsh::BorshSerialize,
    {
        let empty = IterableMap::<Chain, V>::new(prefix);
        let bytes = borsh::to_vec(&empty).expect("empty map serialization cannot fail");
        bytes[std::mem::size_of::<u32>()..].to_vec()
    }

    /// Interprets a blob whose layout matches both this devnet shape and the
    /// current contract shape. The two are byte-identical — store collections
    /// serialize only their prefixes and never their entries or value types,
    /// so borsh alone accepts either reading — but they store checkpoints
    /// under different prefixes (`CheckpointDirectiveDigests` vs
    /// `CheckpointDirectives`). The prefix fingerprint distinguishes them
    /// without touching (and potentially mis-decoding) any entry.
    ///
    /// Returns `Ok(None)` when the bytes describe an older generation; those
    /// fall through to their own probes in [`migrate`].
    fn interpret(state_bytes: &[u8]) -> Result<Option<DevnetState>, Error> {
        let Ok(current) = VersionedMpcContract::try_from_slice(state_bytes) else {
            return Ok(None);
        };

        let actual = match &current {
            VersionedMpcContract::V0(contract) => borsh::to_vec(&contract.latest_checkpoints)
                .expect("map metadata serialization cannot fail")[std::mem::size_of::<u32>()..]
                .to_vec(),
        };
        if actual
            == Self::checkpoint_prefix_fingerprint::<CheckpointDirective>(
                StorageKey::CheckpointDirectives,
            )
        {
            return Ok(Some(DevnetState::Current(current)));
        }
        if actual
            == Self::checkpoint_prefix_fingerprint::<ConsensusCheckpointDigest>(
                StorageKey::CheckpointDirectiveDigests,
            )
        {
            // Layout equality with the current shape was already proven
            // above, so this parse cannot fail.
            let legacy = Self::try_from_slice(state_bytes).map_err(|_| {
                InvalidState::ContractStateIsMissing
                    .message("digest-checkpoint state failed to re-parse")
            })?;
            return Ok(Some(DevnetState::Legacy(legacy)));
        }
        Err(InvalidState::ContractStateIsMissing
            .message("unrecognized latest_checkpoints storage prefix"))
    }
}

#[derive(BorshDeserialize)]
enum VersionedPreviousTestnet {
    V0(PreviousTestnet),
}

pub(crate) fn migrate(state_bytes: &[u8]) -> Result<VersionedMpcContract, Error> {
    // The deployed devnet shape and the current shape share one blob layout,
    // so a single probe covers both; `interpret` decides between returning
    // the state unchanged and running the digest-to-enum upgrade. Older
    // generations differ in bytes and fall through to their own probes.
    if let Some(state) = VersionedPreviousDevnet::interpret(state_bytes)? {
        return Ok(match state {
            DevnetState::Current(versioned) => versioned,
            DevnetState::Legacy(VersionedPreviousDevnet::V0(previous)) => {
                VersionedMpcContract::V0(previous.upgrade())
            }
        });
    }

    if let Ok(VersionedPreviousTestnet::V0(previous)) =
        VersionedPreviousTestnet::try_from_slice(state_bytes)
    {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    if let Ok(previous) = PreviousMainnet::try_from_slice(state_bytes) {
        return Ok(VersionedMpcContract::V0(previous.upgrade()));
    }

    Err(InvalidState::ContractStateIsMissing.message("Failed to deserialize contract state"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::borsh::BorshSerialize;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    // Mirrors the pre-upgrade contract shape: identical to `MpcContract` but
    // with bare digests in `latest_checkpoints`.
    #[derive(BorshSerialize)]
    struct DigestCheckpointsContract {
        protocol_state: ProtocolContractState,
        pending_requests: IterableMap<SignId, PendingRequest>,
        proposed_updates: ProposedUpdates,
        config: Config,
        latest_checkpoints: IterableMap<Chain, ConsensusCheckpointDigest>,
        checkpoint_votes: CheckpointVotes,
    }

    #[derive(BorshSerialize)]
    enum VersionedDigestCheckpointsContract {
        V0(DigestCheckpointsContract),
    }

    #[test]
    fn migrating_digest_checkpoint_state_wraps_into_consensus() {
        testing_env!(VMContextBuilder::new()
            .current_account_id("contract.near".parse().unwrap())
            .build());

        let checkpoint = ConsensusCheckpointDigest::new(Chain::Solana, 120, [7u8; 32]);
        let mut latest_checkpoints = IterableMap::new(StorageKey::CheckpointDirectiveDigests);
        latest_checkpoints.insert(Chain::Solana, checkpoint);

        let old_bytes = borsh::to_vec(&VersionedDigestCheckpointsContract::V0(
            DigestCheckpointsContract {
                protocol_state: ProtocolContractState::NotInitialized,
                pending_requests: IterableMap::new(StorageKey::PendingRequests),
                proposed_updates: ProposedUpdates::default(),
                config: Config::default(),
                latest_checkpoints,
                checkpoint_votes: CheckpointVotes::new(),
            },
        ))
        .unwrap();

        let migrated = migrate(&old_bytes).expect("digest-checkpoint state should migrate");

        let VersionedMpcContract::V0(contract) = migrated;
        assert_eq!(
            contract.latest_checkpoints.get(&Chain::Solana),
            Some(&CheckpointDirective::Consensus(checkpoint))
        );
    }

    #[test]
    fn migrating_current_state_preserves_restart_markers() {
        testing_env!(VMContextBuilder::new()
            .current_account_id("contract.near".parse().unwrap())
            .build());

        // Current-shape state carrying a restart marker. Store collections
        // serialize only prefixes into the blob, so this is byte-identical to
        // the legacy devnet shape: only the storage-prefix fingerprint tells
        // them apart.
        let mut current = VersionedMpcContract::V0(MpcContract::init(0, BTreeMap::new(), None));
        current.reset_checkpoints(vec![(Chain::Solana, 42)]);
        let bytes = borsh::to_vec(&current).unwrap();

        // Store collections buffer writes in memory until flush; dropping
        // mirrors the on-chain flow where the previous transaction committed
        // state to the trie before `migrate` ever runs.
        drop(current);

        // Re-running migrate on already-migrated state must be a no-op, not a
        // wipe of the marker.
        let migrated = migrate(&bytes).expect("current state should migrate");

        let VersionedMpcContract::V0(contract) = migrated;
        assert_eq!(
            contract.latest_checkpoints.get(&Chain::Solana),
            Some(&CheckpointDirective::Restart(42)),
            "re-migration must preserve restart markers"
        );
    }
}
