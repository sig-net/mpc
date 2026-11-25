//! NEAR chain integration for the MPC node: contract polling indexer and signature publisher.

mod gates;
mod indexer;
mod publisher;
mod util;

pub use gates::{NearRpcGates, is_signer_error};
pub use indexer::{SignCommand, run};
pub use publisher::NearClient;
pub use util::AffinePointExt;
