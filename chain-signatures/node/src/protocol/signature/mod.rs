mod generation;
mod request;

pub use request::{Sign, SignatureSpawnerTask};

#[cfg(feature = "test-feature")]
pub use request::organize_posit_timeout;

use crate::protocol::posit::PositAction;
use crate::protocol::presignature::PresignatureId;
use cait_sith::protocol::Participant;

/// Outcome of a signature task. Produced by both layers: `generation` on a
/// protocol/abort error, `request` when organizing cannot proceed.
#[derive(Debug, Clone, Copy)]
enum SignError {
    Aborted,
}

/// Posit messages routed to a running signature task. Owned by `request`, but
/// `generation` also consumes them to reject late `Propose`s while generating.
enum SignTaskMessage {
    PositMessage {
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
    },
}
