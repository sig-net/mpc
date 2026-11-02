#[cfg(any(test, feature = "test-feature"))]
use std::path::PathBuf;
#[cfg(any(test, feature = "test-feature"))]
use tokio::fs::{self, File};
#[cfg(any(test, feature = "test-feature"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::SecretResult;
use crate::storage::Options;
use crate::{gcp::SecretManagerService, protocol::state::KeyShareRecord};
use anyhow::Context as _;
use async_trait::async_trait;

use near_account_id::AccountId;

#[async_trait]
pub trait SecretNodeStorage {
    /// Stores the given `KeyShareRecord` securely.
    async fn store(&mut self, data: &KeyShareRecord) -> SecretResult<()>;
    /// Loads the `KeyShareRecord` if it exists.
    /// Returns `Ok(None)` if the data does not exist.
    async fn load(&self) -> SecretResult<Option<KeyShareRecord>>;
}

/// In-memory implementation of `SecretNodeStorage`, for in-process tests.
#[cfg(any(test, feature = "test-feature"))]
#[derive(Default)]
pub struct MemoryStore {
    node_data: Option<KeyShareRecord>,
}

#[cfg(any(test, feature = "test-feature"))]
#[async_trait]
impl SecretNodeStorage for MemoryStore {
    async fn store(&mut self, data: &KeyShareRecord) -> SecretResult<()> {
        tracing::info!("storing KeyShareRecord using MemoryStore");
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<KeyShareRecord>> {
        tracing::info!("loading KeyShareRecord using MemoryStore");
        Ok(self.node_data.clone())
    }
}

/// GCP Secret Manager implementation of `SecretNodeStorage`.
pub struct GcpSecretManagerStore {
    secret_manager: SecretManagerService,
    sk_share_secret_id: String,
}

impl GcpSecretManagerStore {
    fn new(secret_manager: SecretManagerService, sk_share_secret_id: String) -> Self {
        Self {
            secret_manager,
            sk_share_secret_id,
        }
    }
}

#[async_trait]
impl SecretNodeStorage for GcpSecretManagerStore {
    async fn store(&mut self, data: &KeyShareRecord) -> SecretResult<()> {
        tracing::info!("storing KeyShareRecord using GcpSecretManagerStore");
        self.secret_manager
            .store_secret(&serde_json::to_vec(data)?, &self.sk_share_secret_id)
            .await?;
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<KeyShareRecord>> {
        tracing::info!("loading KeyShareRecord using GcpSecretManagerStore");
        let raw_data = self
            .secret_manager
            .load_secret(&self.sk_share_secret_id)
            .await?;
        let Some(data) = raw_data else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&data)?))
    }
}

/// File implementation of `SecretNodeStorage`, for the test harness.
#[cfg(any(test, feature = "test-feature"))]
pub struct FileStore {
    path: PathBuf,
}

#[cfg(any(test, feature = "test-feature"))]
impl FileStore {
    pub fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }
}

#[cfg(any(test, feature = "test-feature"))]
#[async_trait]
impl SecretNodeStorage for FileStore {
    async fn store(&mut self, data: &KeyShareRecord) -> SecretResult<()> {
        tracing::info!("storing KeyShareRecord using FileStore");

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

    async fn load(&self) -> SecretResult<Option<KeyShareRecord>> {
        // Open the file asynchronously
        let file_res = File::open(self.path.as_os_str()).await;

        match file_res {
            Ok(mut file) => {
                tracing::info!("loading KeyShareRecord using FileStore");
                let mut contents = Vec::new();
                // Read the contents of the file into the vector
                file.read_to_end(&mut contents).await?;

                // Deserialize the JSON content to a KeyShareRecord object
                let data: KeyShareRecord = serde_json::from_slice(&contents)?;

                Ok(Some(data))
            }
            // If the file is not found, treat it as if there is no existing data, rather than an error
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("loading KeyShareRecord using FileStore: no file");
                Ok(None)
            }
            // Propagate other types of errors
            Err(e) => {
                tracing::error!(%e, "failed to load KeyShareRecord");
                Err(e.into())
            }
        }
    }
}

/// Enum representing the different variants of secret node storage.
pub enum KeyShareStore {
    /// In-memory storage for in-process tests.
    #[cfg(any(test, feature = "test-feature"))]
    Memory(MemoryStore),
    /// Google Cloud Secret Manager storage variant
    GcpSecretManager(GcpSecretManagerStore),
    /// File storage for the test harness.
    #[cfg(any(test, feature = "test-feature"))]
    File(FileStore),
}

impl KeyShareStore {
    /// Stores the given `KeyShareRecord` using the underlying storage mechanism.
    pub async fn store(&mut self, data: &KeyShareRecord) -> SecretResult<()> {
        match self {
            #[cfg(any(test, feature = "test-feature"))]
            KeyShareStore::Memory(s) => s.store(data).await,
            KeyShareStore::GcpSecretManager(s) => s.store(data).await,
            #[cfg(any(test, feature = "test-feature"))]
            KeyShareStore::File(s) => s.store(data).await,
        }
    }

    /// Loads the `KeyShareRecord` from the underlying storage mechanism, if it exists.
    pub async fn load(&self) -> SecretResult<Option<KeyShareRecord>> {
        match self {
            #[cfg(any(test, feature = "test-feature"))]
            KeyShareStore::Memory(s) => s.load().await,
            KeyShareStore::GcpSecretManager(s) => s.load().await,
            #[cfg(any(test, feature = "test-feature"))]
            KeyShareStore::File(s) => s.load().await,
        }
    }
}

/// Opens the key-share store the options name. Production builds know only
/// Secret Manager, whose id clap pairs with a GCP project. Test builds may
/// name a file.
pub async fn init(
    opts: &Options,
    #[cfg_attr(not(feature = "test-feature"), allow(unused_variables))] account_id: &AccountId,
) -> anyhow::Result<KeyShareStore> {
    #[cfg(feature = "test-feature")]
    if let Some(sk_share_local_path) = &opts.sk_share_local_path {
        let path = format!("{sk_share_local_path}-{account_id}");
        tracing::info!("using FileStore with path: {}", path);
        return Ok(KeyShareStore::File(FileStore::new(&path)));
    }
    let secret_id = opts
        .sk_share_secret_id
        .as_ref()
        .context("clap requires a key-share store")?;
    let project_id = opts
        .gcp_project_id
        .as_ref()
        .context("clap pairs the Secret Manager id with a GCP project")?;
    let secret_manager = SecretManagerService::new(project_id)?;
    tracing::info!("using GcpSecretManagerStore");
    Ok(KeyShareStore::GcpSecretManager(GcpSecretManagerStore::new(
        secret_manager,
        secret_id.clone(),
    )))
}

#[cfg(feature = "test-feature")]
pub fn test_store(
    epoch: u64,
    private_share: crate::types::SecretKeyShare,
    public_key: mpc_crypto::PublicKey,
) -> KeyShareStore {
    let store = MemoryStore {
        node_data: Some(KeyShareRecord {
            epoch,
            private_share,
            public_key,
        }),
    };
    KeyShareStore::Memory(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecretKeyShare;
    use k256::elliptic_curve::group::GroupEncoding;
    use mpc_crypto::PublicKey;
    use mpc_primitives::ScalarExt;

    /// Helper function to create a test account ID.
    fn make_test_account_id() -> AccountId {
        "test.near".parse().unwrap()
    }

    /// Creates a test secret key share.
    fn make_test_secret_key_share() -> SecretKeyShare {
        SecretKeyShare::from_bytes([0u8; 32]).unwrap()
    }

    /// Creates a test public key.
    fn make_test_public_key() -> PublicKey {
        PublicKey::from_bytes((&[0u8; 33]).into()).unwrap()
    }

    #[tokio::test]
    async fn disk_load_nonexistent_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let storage = FileStore { path };

        let result = storage.load().await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn disk_store_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node_data.json");

        let mut storage = FileStore { path };

        let expected = KeyShareRecord {
            epoch: 42,
            private_share: make_test_secret_key_share(),
            public_key: make_test_public_key(),
        };

        storage.store(&expected).await.unwrap();

        let loaded = storage.load().await.unwrap();

        assert_eq!(loaded, Some(expected));
    }

    #[tokio::test]
    async fn disk_load_invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node_data.json");

        tokio::fs::write(&path, b"not a valid json").await.unwrap();

        let storage = FileStore { path };

        assert!(storage.load().await.is_err());
    }

    #[tokio::test]
    async fn memory_store_and_load_round_trip() {
        let mut storage = MemoryStore::default();

        let expected = KeyShareRecord {
            epoch: 42,
            private_share: make_test_secret_key_share(),
            public_key: make_test_public_key(),
        };

        storage.store(&expected).await.unwrap();

        let loaded = storage.load().await.unwrap();

        assert_eq!(loaded, Some(expected));
    }

    #[cfg(feature = "test-feature")]
    #[tokio::test]
    async fn init_uses_disk_when_local_path_provided() {
        let opts = Options {
            sk_share_local_path: Some("/tmp/share".into()),
            sk_share_secret_id: None,
            gcp_project_id: None,
            redis_url: "redis://localhost".to_string(),
        };

        let storage = init(&opts, &make_test_account_id()).await.unwrap();

        assert!(matches!(storage, KeyShareStore::File(_)));
    }

    #[tokio::test]
    async fn init_uses_gcp_when_secret_id_present() {
        let opts = Options {
            sk_share_secret_id: Some("secret-id".to_string()),
            #[cfg(feature = "test-feature")]
            sk_share_local_path: None,
            gcp_project_id: Some("test-project".to_string()),
            redis_url: "redis://localhost".to_string(),
        };
        let storage = init(&opts, &make_test_account_id()).await.unwrap();

        assert!(matches!(storage, KeyShareStore::GcpSecretManager(_)));
    }
}
