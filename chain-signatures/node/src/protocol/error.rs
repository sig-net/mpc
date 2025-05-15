use cait_sith::protocol::{InitializationError, Participant};
use mpc_primitives::SignId;

use super::{presignature::PresignatureId, triple::TripleId};

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("triple {0} is generating or missing")]
    TripleGeneratingOrMissing(TripleId),
    #[error("triple {0} and {1} are missing")]
    TripleMissing(TripleId, TripleId),
    #[error("presignature {0} is generating or missing")]
    PresignatureGeneratingOrMissing(PresignatureId),
    #[error("presignature bad parameters")]
    PresignatureBadParameters,
    #[error("unable to reserve a slot for presignature")]
    PresignatureReserveError,
    #[error("waiting for missing sign request id={0:?}")]
    WaitingForIndexer(SignId),
    #[error("invalid proposer expected={0:?}, actual={1:?}")]
    InvalidProposer(Participant, Participant),
}
