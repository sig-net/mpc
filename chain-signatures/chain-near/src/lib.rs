//! NEAR chain integration for the MPC node: contract polling indexer and signature publisher.

mod indexer;
mod publisher;
mod util;

pub use indexer::{run, SignCommand};
pub use publisher::NearClient;
pub use util::AffinePointExt;
