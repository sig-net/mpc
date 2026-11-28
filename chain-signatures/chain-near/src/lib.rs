//! NEAR chain integration for the MPC node: contract polling indexer and signature publisher.

mod classify;
mod gates;
mod indexer;
mod publisher;
#[cfg(any(test, feature = "test-support"))]
pub mod test_utils;
mod util;

pub use gates::{is_signer_error, view_json, NearRpcGates};
pub use indexer::{run, SignCommand};
pub use publisher::NearClient;
pub use util::AffinePointExt;
