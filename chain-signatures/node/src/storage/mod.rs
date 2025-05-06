pub mod app_data_storage;
pub mod presignature_storage;
pub mod secret_storage;
pub mod triple_storage;

use cait_sith::protocol::Participant;
pub use presignature_storage::PresignatureStorage;
pub use triple_storage::TripleStorage;

// Can be used to "clear" redis storage in case of a breaking change
pub const STORAGE_VERSION: &str = "v8";

/// Configures storage.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "storage_options")]
pub struct Options {
    /// env used to differentiate among environments.
    #[clap(long, env("MPC_ENV"))]
    pub env: String,
    /// GCP project ID.
    #[clap(long, env("MPC_GCP_PROJECT_ID"))]
    pub gcp_project_id: String,
    /// GCP Secret Manager ID that will be used to load/store the node's secret key share.
    #[clap(long, env("MPC_SK_SHARE_SECRET_ID"), requires_all=["gcp_project_id"])]
    pub sk_share_secret_id: Option<String>,
    /// Mostly for integration tests.
    #[arg(long, env("MPC_SK_SHARE_LOCAL_PATH"))]
    pub sk_share_local_path: Option<String>,
    #[arg(long, env("MPC_REDIS_URL"))]
    pub redis_url: String,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = vec![
            "--env".to_string(),
            self.env,
            "--gcp-project-id".to_string(),
            self.gcp_project_id,
        ];
        if let Some(sk_share_secret_id) = self.sk_share_secret_id {
            opts.extend(vec!["--sk-share-secret-id".to_string(), sk_share_secret_id]);
        }
        if let Some(sk_share_local_path) = self.sk_share_local_path {
            opts.extend(vec![
                "--sk-share-local-path".to_string(),
                sk_share_local_path,
            ]);
        }

        opts
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("protocol is generating: {0}")]
    ProtocolIsGenerating(String),
    #[error("protocol is missing: {0}")]
    ProtocolIsMissing(String),
    #[error("protocol trying to be used by other owner: {0}")]
    ProtocolForeignUsage(String),
    #[error("protocol trying to be used by incorrect owner: {0}")]
    ProtocolIncorrectOwner(String),
    #[error("redis: {0}")]
    RedisError(redis::RedisError),
}

impl From<redis::RedisError> for StoreError {
    fn from(err: redis::RedisError) -> Self {
        let msg = err.to_string();
        if msg.contains("generating or taken") {
            StoreError::ProtocolIsGenerating(msg)
        } else if msg.contains("taken as foreign owned") {
            StoreError::ProtocolForeignUsage(msg)
        } else {
            StoreError::RedisError(err)
        }
    }
}

fn owner_key(base: &str, owner: Participant) -> String {
    format!("{base}:p{}", Into::<u32>::into(owner))
}
