//! Reading the committed per-node env files.
//!
//! These files are the single source of truth for the localnet's key material. Every
//! public value the bootstrap registers in the MPC contract is derived from them, so the
//! contract cannot drift out of step with what the nodes actually run.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context};
use near_account_id::AccountId;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

/// Everything the bootstrap needs to know about one node.
pub struct NodeSpec {
    pub account_id: AccountId,
    pub account_sk: near_crypto::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_sk: mpc_keys::hpke::SecretKey,
    /// The URL peers reach this node on, registered verbatim in the contract.
    pub local_address: String,
    pub solana_sk: Keypair,
}

impl NodeSpec {
    pub fn solana_pubkey(&self) -> solana_sdk::pubkey::Pubkey {
        self.solana_sk.pubkey()
    }
}

/// Parse a `KEY=VALUE` env file. Blank lines and `#` comments are skipped, a leading
/// `export ` is tolerated, and a single layer of surrounding quotes is stripped.
fn parse_env(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(key.trim().to_string(), value.to_string());
    }
    out
}

fn require<'a>(vars: &'a HashMap<String, String>, key: &str, file: &Path) -> anyhow::Result<&'a str> {
    vars.get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{} is missing from {}", key, file.display()))
}

fn load_one(path: &Path) -> anyhow::Result<NodeSpec> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading node env file {}", path.display()))?;
    let vars = parse_env(&text);

    let account_id: AccountId = require(&vars, "MPC_ACCOUNT_ID", path)?
        .parse()
        .context("MPC_ACCOUNT_ID is not a valid NEAR account id")?;
    let account_sk: near_crypto::SecretKey = require(&vars, "MPC_ACCOUNT_SK", path)?
        .parse()
        .context("MPC_ACCOUNT_SK is not a valid NEAR secret key")?;
    let sign_sk: near_crypto::SecretKey = require(&vars, "MPC_SIGN_SK", path)?
        .parse()
        .context("MPC_SIGN_SK is not a valid NEAR secret key")?;

    let cipher_bytes = hex::decode(require(&vars, "MPC_CIPHER_SK", path)?)
        .context("MPC_CIPHER_SK is not valid hex")?;
    let cipher_sk = mpc_keys::hpke::SecretKey::try_from_bytes(&cipher_bytes)
        .map_err(|err| anyhow!("MPC_CIPHER_SK is not a valid HPKE secret key: {err:?}"))?;

    let solana_bytes = bs58::decode(require(&vars, "MPC_SOL_ACCOUNT_SK", path)?)
        .into_vec()
        .context("MPC_SOL_ACCOUNT_SK is not valid base58")?;
    let solana_sk = Keypair::from_bytes(&solana_bytes)
        .map_err(|err| anyhow!("MPC_SOL_ACCOUNT_SK is not a valid Solana keypair: {err}"))?;

    Ok(NodeSpec {
        account_id,
        account_sk,
        sign_sk,
        cipher_sk,
        local_address: require(&vars, "MPC_LOCAL_ADDRESS", path)?.to_string(),
        solana_sk,
    })
}

/// Load every `node<N>.env` in `dir`, ordered by participant index.
///
/// The contract assigns participant ids by iterating a `BTreeMap<AccountId, _>`, so
/// participant *i* is whichever account sorts *i*-th. The committed key shares are indexed
/// numerically, so the two orderings have to agree or every signature fails while the
/// cluster still reports itself as running. That is an expensive failure to debug, so it is
/// asserted here instead.
pub fn load_all(dir: &Path) -> anyhow::Result<Vec<NodeSpec>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading node env directory {}", dir.display()))?
    {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(index) = name
            .strip_prefix("node")
            .and_then(|rest| rest.strip_suffix(".env"))
            .and_then(|digits| digits.parse::<usize>().ok())
        else {
            continue;
        };
        paths.push((index, path));
    }

    if paths.is_empty() {
        anyhow::bail!("no node<N>.env files found in {}", dir.display());
    }

    paths.sort_by_key(|(index, _)| *index);
    for (position, (index, path)) in paths.iter().enumerate() {
        if *index != position {
            anyhow::bail!(
                "node env files must be numbered 0..N with no gaps, but found {} at position {}",
                path.display(),
                position
            );
        }
    }

    let nodes = paths
        .iter()
        .map(|(_, path)| load_one(path))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut sorted: Vec<&AccountId> = nodes.iter().map(|node| &node.account_id).collect();
    sorted.sort();
    for (position, account_id) in sorted.iter().enumerate() {
        if **account_id != nodes[position].account_id {
            anyhow::bail!(
                "account ids must sort into the same order as their file indices, but \
                 {} sorts at position {} while node{}.env expects {}. Rename the accounts so \
                 lexicographic order matches numeric order, otherwise each node would be \
                 handed the key share belonging to a different participant.",
                account_id,
                position,
                position,
                nodes[position].account_id,
            );
        }
    }

    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_quotes_and_exports() {
        let vars = parse_env("# comment\n\nexport A=1\nB=\"two\"\nC='three'\n");
        assert_eq!(vars.get("A").map(String::as_str), Some("1"));
        assert_eq!(vars.get("B").map(String::as_str), Some("two"));
        assert_eq!(vars.get("C").map(String::as_str), Some("three"));
    }

    /// The committed localnet accounts must keep lexicographic order equal to numeric
    /// order, since that is what binds key share *i* to participant *i*.
    #[test]
    fn committed_accounts_sort_into_index_order() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../nodes");
        let nodes = load_all(&dir).expect("committed node env files must load");
        assert_eq!(nodes.len(), 3, "localnet is a 3 node cluster");
        let mut sorted: Vec<String> = nodes.iter().map(|n| n.account_id.to_string()).collect();
        sorted.sort();
        let as_listed: Vec<String> = nodes.iter().map(|n| n.account_id.to_string()).collect();
        assert_eq!(sorted, as_listed, "sorted order must equal file index order");
    }
}
