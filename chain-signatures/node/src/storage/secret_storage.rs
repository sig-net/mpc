use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::{GcpService, SecretResult};
use crate::storage::Options;
use crate::{gcp::SecretManagerService, protocol::state::PersistentNodeData};
use async_trait::async_trait;

use near_account_id::AccountId;

#[async_trait]
pub trait SecretNodeStorage {
    /// Stores the given `PersistentNodeData` securely.
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()>;
    /// Loads the `PersistentNodeData` if it exists.
    /// Returns `Ok(None)` if the data does not exist.
    async fn load(&self) -> SecretResult<Option<PersistentNodeData>>;
}

/// In-memory implementation of `SecretNodeStorage`.
#[derive(Default)]
pub struct MemoryNodeStorage {
    node_data: Option<PersistentNodeData>,
}

#[async_trait]
impl SecretNodeStorage for MemoryNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using MemoryNodeStorage");
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using MemoryNodeStorage");
        Ok(self.node_data.clone())
    }
}

/// GCP Secret Manager implementation of `SecretNodeStorage`.
pub struct SecretManagerNodeStorage {
    secret_manager: SecretManagerService,
    sk_share_secret_id: String,
}

impl SecretManagerNodeStorage {
    fn new(secret_manager: &SecretManagerService, sk_share_secret_id: String) -> Self {
        Self {
            secret_manager: secret_manager.clone(),
            sk_share_secret_id,
        }
    }
}

#[async_trait]
impl SecretNodeStorage for SecretManagerNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using SecretManagerNodeStorage");
        self.secret_manager
            .store_secret(&serde_json::to_vec(data)?, &self.sk_share_secret_id)
            .await?;
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using SecretManagerNodeStorage");
        let raw_data = self
            .secret_manager
            .load_secret(&self.sk_share_secret_id)
            .await?;
        match raw_data {
            Some(data) if data.len() > 1 => match serde_json::from_slice(&data) {
                Ok(persistent_node_data) => Ok(Some(persistent_node_data)),
                Err(err) => {
                    tracing::error!(%err, data_len = data.len(), "failed to convert stored data to key share, presuming it is missing");
                    Ok(None)
                }
            },
            _ => {
                tracing::error!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }
}

/// Local disk storage implementation of `SecretNodeStorage`.
pub struct DiskNodeStorage {
    path: PathBuf,
}

impl DiskNodeStorage {
    pub fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }
}

#[async_trait]
impl SecretNodeStorage for DiskNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using DiskNodeStorage");

        // Serialize the person object to JSON and convert directly to bytes
        let json_bytes = serde_json::to_vec(data)?;

        // Write the JSON bytes to a temporary file first to ensure atomicitys, then rename it to the target path
        let tmp_path = self.path.with_extension("tmp");

        let mut file = File::create(&tmp_path).await?;
        file.write_all(&json_bytes).await?;

        // Ensure all data is flushed to disk before renaming
        file.sync_all().await?;

        drop(file);

        fs::rename(&tmp_path, &self.path).await?;

        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        // Open the file asynchronously
        let file_res = File::open(self.path.as_os_str()).await;

        match file_res {
            Ok(mut file) => {
                tracing::info!("loading PersistentNodeData using DiskNodeStorage");
                let mut contents = Vec::new();
                // Read the contents of the file into the vector
                file.read_to_end(&mut contents).await?;

                // Deserialize the JSON content to a PersistentNodeData object
                let data: PersistentNodeData = serde_json::from_slice(&contents)?;

                Ok(Some(data))
            }
            // If the file is not found, treat it as if there is no existing data, rather than an error
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("loading PersistentNodeData using DiskNodeStorage: no file");
                Ok(None)
            }
            // Propagate other types of errors
            Err(e) => {
                tracing::error!(%e, "failed to load PersistentNodeData");
                Err(e.into())
            }
        }
    }
}

/// Enum representing the different variants of secret node storage.
pub enum SecretNodeStorageVariant {
    /// In-memory storage variant, primarily for testing or ephemeral use cases.
    Memory(MemoryNodeStorage),
    /// Google Cloud Secret Manager storage variant
    Gcp(SecretManagerNodeStorage),
    /// Local disk storage variant, storing secrets in a file on the local filesystem.
    Disk(DiskNodeStorage),
}

impl SecretNodeStorageVariant {
    /// Stores the given `PersistentNodeData` using the underlying storage mechanism.
    pub async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        match self {
            SecretNodeStorageVariant::Memory(s) => s.store(data).await,
            SecretNodeStorageVariant::Gcp(s) => s.store(data).await,
            SecretNodeStorageVariant::Disk(s) => s.store(data).await,
        }
    }

    /// Loads the `PersistentNodeData` from the underlying storage mechanism, if it exists.
    pub async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        match self {
            SecretNodeStorageVariant::Memory(s) => s.load().await,
            SecretNodeStorageVariant::Gcp(s) => s.load().await,
            SecretNodeStorageVariant::Disk(s) => s.load().await,
        }
    }
}

/// Initializes the appropriate `SecretNodeStorageVariant` based on the provided options and GCP service.
pub fn init(
    gcp_service: Option<&GcpService>,
    opts: &Options,
    account_id: &AccountId,
) -> SecretNodeStorageVariant {
    match gcp_service {
        Some(gcp) if opts.sk_share_secret_id.is_some() => {
            tracing::info!("using SecretManagerNodeStorage");
            SecretNodeStorageVariant::Gcp(SecretManagerNodeStorage::new(
                &gcp.secret_manager.clone(),
                opts.sk_share_secret_id.clone().unwrap(),
            ))
        }
        _ => {
            if let Some(sk_share_local_path) = &opts.sk_share_local_path {
                let path = format!("{sk_share_local_path}-{account_id}");
                tracing::info!("using DiskNodeStorage with path: {}", path);
                SecretNodeStorageVariant::Disk(DiskNodeStorage::new(&path))
            } else {
                tracing::info!("using MemoryNodeStorage");
                SecretNodeStorageVariant::Memory(MemoryNodeStorage::default())
            }
        }
    }
}

#[cfg(feature = "test-feature")]
pub fn test_store(
    epoch: u64,
    private_share: crate::types::SecretKeyShare,
    public_key: mpc_crypto::PublicKey,
) -> SecretNodeStorageVariant {
    let store = MemoryNodeStorage {
        node_data: Some(PersistentNodeData {
            epoch,
            private_share,
            public_key,
        }),
    };
    SecretNodeStorageVariant::Memory(store)
}
