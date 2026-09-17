//! NEAR chain integration for the MPC node: contract polling indexer and signature publisher.

mod gates;
mod indexer;
mod publisher;
mod util;

pub use gates::{is_signer_error, NearRpcGates};
pub use indexer::{run, SignCommand};
pub use publisher::NearClient;
pub use util::AffinePointExt;
