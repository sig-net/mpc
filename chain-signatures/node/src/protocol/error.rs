use cait_sith::protocol::{InitializationError, Participant};
use mpc_primitives::SignId;

use super::{presignature::PresignatureId, triple::TripleId};

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("triple one of or both {0} and {1} are missing")]
    TripleIsMissing(TripleId, TripleId),
    #[error("triple {0} is generating")]
    TripleIsGenerating(TripleId),
    #[error("triple access denied: id={0}, {1}")]
    TripleDenied(TripleId, &'static str),
    #[error("presignature {0} is generating")]
    PresignatureIsGenerating(PresignatureId),
    #[error("presignature {0} is missing")]
    PresignatureIsMissing(PresignatureId),
    #[error("presignature access denied: id={0}, {1}")]
    PresignatureDenied(PresignatureId, &'static str),
    #[error("presignature bad parameters")]
    PresignatureBadParameters,
    #[error("unable to reserve a slot for presignature")]
    PresignatureReserveError,
    #[error("waiting for missing sign request id={0:?}")]
    WaitingForIndexer(SignId),
    #[error("invalid proposer expected={0:?}, actual={1:?}")]
    InvalidProposer(Participant, Participant),
}
