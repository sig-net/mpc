pub mod checkpoint_storage;
pub mod midnight_wallet_storage;
pub mod presignature_storage;
pub mod protocol_storage;
pub mod secret_storage;
pub mod triple_storage;

use cait_sith::protocol::Participant;
pub use checkpoint_storage::CheckpointStorage;
pub use midnight_wallet_storage::MidnightWalletStorage;
pub use presignature_storage::PresignatureStorage;
pub use protocol_storage::StorageError;
pub use triple_storage::TripleStorage;

// Can be used to "clear" redis storage in case of a breaking change
pub const STORAGE_VERSION: &str = "v12";

/// Configures storage. Production nodes keep the key share in GCP Secret
/// Manager; test builds may use a file instead.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "storage_options")]
#[command(group(clap::ArgGroup::new("sk_share").required(true)))]
pub struct Options {
    /// GCP project of the Secret Manager holding the key share.
    #[arg(long, env("MPC_GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
    /// Keep the key share in GCP Secret Manager under this secret id.
    #[arg(
        long,
        env("MPC_SK_SHARE_SECRET_ID"),
        group = "sk_share",
        requires = "gcp_project_id"
    )]
    pub sk_share_secret_id: Option<String>,
    /// Keep the key share in a file at this path, suffixed with the account id.
    #[cfg(feature = "test-feature")]
    #[arg(long, env("MPC_SK_SHARE_LOCAL_PATH"), group = "sk_share")]
    pub sk_share_local_path: Option<String>,
    #[arg(long, env("MPC_REDIS_URL"), hide_env_values = true)]
    pub redis_url: String,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = Vec::new();
        if let Some(gcp_project_id) = self.gcp_project_id {
            opts.extend(["--gcp-project-id".to_string(), gcp_project_id]);
        }
        if let Some(sk_share_secret_id) = self.sk_share_secret_id {
            opts.extend(vec!["--sk-share-secret-id".to_string(), sk_share_secret_id]);
        }
        #[cfg(feature = "test-feature")]
        if let Some(sk_share_local_path) = self.sk_share_local_path {
            opts.extend(vec![
                "--sk-share-local-path".to_string(),
                sk_share_local_path,
            ]);
        }

        opts
    }
}

fn owner_key(base: &str, owner: Participant) -> String {
    format!("{base}:p{}", Into::<u32>::into(owner))
}

#[cfg(test)]
mod tests {
    use super::Options;
    use clap::Parser as _;

    fn parse(extra: &[&str]) -> Result<Options, clap::Error> {
        Options::try_parse_from(
            ["test", "--redis-url", "redis://localhost"]
                .into_iter()
                .chain(extra.iter().copied()),
        )
    }

    #[test]
    fn secret_manager_needs_its_project() {
        assert!(parse(&[]).is_err(), "a store must be chosen");
        assert!(
            parse(&["--sk-share-secret-id", "s"]).is_err(),
            "Secret Manager needs a project"
        );
        assert!(parse(&["--sk-share-secret-id", "s", "--gcp-project-id", "p"]).is_ok());
    }

    #[cfg(feature = "test-feature")]
    #[test]
    fn test_builds_accept_one_file_store() {
        assert!(parse(&["--sk-share-local-path", "/tmp/share"]).is_ok());
        assert!(
            parse(&[
                "--sk-share-secret-id",
                "s",
                "--gcp-project-id",
                "p",
                "--sk-share-local-path",
                "/tmp/share",
            ])
            .is_err(),
            "two stores are rejected"
        );
    }
}
