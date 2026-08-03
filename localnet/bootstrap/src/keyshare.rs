//! Reading the committed key shares.
//!
//! The localnet skips distributed key generation: each node is handed a share of a key that
//! was generated once and committed, and the contract is initialised straight into the
//! running state with the matching public key. That takes cluster startup from tens of
//! seconds of live key generation down to nothing, and it gives clients a fixed root public
//! key to derive addresses from.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// One node's share of the network key.
///
/// This mirrors `PersistentNodeData` in `chain-signatures/node/src/protocol/state.rs` field
/// for field, which is what the node's `DiskNodeStorage` reads. It is duplicated rather
/// than imported so the bootstrap image does not have to compile `mpc-node`. Delete this
/// struct and import the real one if `mpc-node` ever becomes a dependency here for another
/// reason, or if the type moves into `mpc-primitives`.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub epoch: u64,
    pub private_share: k256::Scalar,
    pub public_key: mpc_crypto::PublicKey,
}

impl KeyShare {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the key share at {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("parsing the key share at {}", path.display()))
    }
}

/// Load the key share belonging to each node, in participant order.
///
/// Files are named after the account that owns them, so a mismatch between the file set and
/// the node set surfaces here rather than as unexplained signature timeouts later.
pub fn load_all(dir: &Path, nodes: &[crate::nodes::NodeSpec]) -> anyhow::Result<Vec<KeyShare>> {
    nodes
        .iter()
        .map(|node| KeyShare::load(&dir.join(format!("{}.json", node.account_id))))
        .collect()
}

/// Check that every node was given a share of the same key.
pub fn shared_public_key(shares: &[KeyShare]) -> anyhow::Result<mpc_crypto::PublicKey> {
    let Some(first) = shares.first() else {
        anyhow::bail!("no key shares were loaded");
    };
    for (index, share) in shares.iter().enumerate() {
        if share.public_key != first.public_key {
            anyhow::bail!(
                "key share {index} carries a different public key to key share 0, so the shares \
                 are not shares of one key"
            );
        }
    }
    Ok(first.public_key)
}
