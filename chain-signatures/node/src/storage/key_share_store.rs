#[cfg(any(test, feature = "test-feature"))]
use std::path::PathBuf;
#[cfg(any(test, feature = "test-feature"))]
use tokio::fs::{self, File};
#[cfg(any(test, feature = "test-feature"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::{self, SecretManagerService};
use crate::protocol::state::KeyShareRecord;
use crate::storage::Options;
use anyhow::Context as _;
use near_account_id::AccountId;

#[derive(thiserror::Error, Debug)]
pub enum KeyShareStoreError {
    #[error(transparent)]
    Gcp(#[from] gcp::Error),
    #[cfg(any(test, feature = "test-feature"))]
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Where the node keeps its key share. Production builds know only Secret
/// Manager; test builds add a file and an in-memory store.
pub enum KeyShareStore {
    GcpSecretManager(GcpSecretManagerStore),
    #[cfg(any(test, feature = "test-feature"))]
    File(FileStore),
    #[cfg(any(test, feature = "test-feature"))]
    Memory(MemoryStore),
}

impl KeyShareStore {
    /// Opens the store the options name. `async` because the Secret Manager
    /// credentials can only be built inside a running Tokio runtime.
    pub async fn init(
        opts: &Options,
        #[cfg_attr(not(feature = "test-feature"), allow(unused_variables))] account_id: &AccountId,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "test-feature")]
        if let Some(base_path) = &opts.sk_share_local_path {
            let path = format!("{base_path}-{account_id}");
            tracing::info!(%path, "keeping the key share in a file");
            return Ok(Self::File(FileStore::new(&path)));
        }
        let secret_id = opts
            .sk_share_secret_id
            .as_ref()
            .context("clap requires a key-share store")?;
        let project_id = opts
            .gcp_project_id
            .as_ref()
            .context("clap pairs the Secret Manager id with a GCP project")?;
        tracing::info!("keeping the key share in Secret Manager");
        Ok(Self::GcpSecretManager(GcpSecretManagerStore {
            secret_manager: SecretManagerService::new(project_id)?,
            secret_id: secret_id.clone(),
        }))
    }

    pub async fn store(&mut self, data: &KeyShareRecord) -> Result<(), KeyShareStoreError> {
        match self {
            Self::GcpSecretManager(s) => s.store(data).await,
            #[cfg(any(test, feature = "test-feature"))]
            Self::File(s) => s.store(data).await,
            #[cfg(any(test, feature = "test-feature"))]
            Self::Memory(s) => s.store(data),
        }
    }

    /// Loads the key share, or `None` when the store holds nothing yet.
    pub async fn load(&self) -> Result<Option<KeyShareRecord>, KeyShareStoreError> {
        match self {
            Self::GcpSecretManager(s) => s.load().await,
            #[cfg(any(test, feature = "test-feature"))]
            Self::File(s) => s.load().await,
            #[cfg(any(test, feature = "test-feature"))]
            Self::Memory(s) => s.load(),
        }
    }
}

/// In-memory store for in-process tests.
#[cfg(any(test, feature = "test-feature"))]
pub struct MemoryStore {
    record: Option<KeyShareRecord>,
}

#[cfg(any(test, feature = "test-feature"))]
impl MemoryStore {
    /// A store already holding `record`, or empty when `None`.
    pub fn new(record: Option<KeyShareRecord>) -> Self {
        Self { record }
    }

    fn store(&mut self, data: &KeyShareRecord) -> Result<(), KeyShareStoreError> {
        self.record = Some(data.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<KeyShareRecord>, KeyShareStoreError> {
        Ok(self.record.clone())
    }
}

/// GCP Secret Manager store.
pub struct GcpSecretManagerStore {
    secret_manager: SecretManagerService,
    secret_id: String,
}

impl GcpSecretManagerStore {
    async fn store(&mut self, data: &KeyShareRecord) -> Result<(), KeyShareStoreError> {
        self.secret_manager
            .store_secret(&serde_json::to_vec(data)?, &self.secret_id)
            .await?;
        Ok(())
    }

    async fn load(&self) -> Result<Option<KeyShareRecord>, KeyShareStoreError> {
        let Some(data) = self.secret_manager.load_secret(&self.secret_id).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&data)?))
    }
}

/// File store for the test harness.
#[cfg(any(test, feature = "test-feature"))]
pub struct FileStore {
    path: PathBuf,
}

#[cfg(any(test, feature = "test-feature"))]
impl FileStore {
    fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }

    async fn store(&mut self, data: &KeyShareRecord) -> Result<(), KeyShareStoreError> {
        let json_bytes = serde_json::to_vec(data)?;
        // Write to a temporary file first, then rename it into place atomically.
        let tmp_path = self.path.with_extension("tmp");
        let mut file = File::create(&tmp_path).await?;
        file.write_all(&json_bytes).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp_path, &self.path).await?;
        Ok(())
    }

    async fn load(&self) -> Result<Option<KeyShareRecord>, KeyShareStoreError> {
        match File::open(self.path.as_os_str()).await {
            Ok(mut file) => {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).await?;
                Ok(Some(serde_json::from_slice(&contents)?))
            }
            // No file yet means no key share yet.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
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
        let mut storage = MemoryStore::new(None);

        let expected = KeyShareRecord {
            epoch: 42,
            private_share: make_test_secret_key_share(),
            public_key: make_test_public_key(),
        };

        storage.store(&expected).unwrap();

        let loaded = storage.load().unwrap();

        assert_eq!(loaded, Some(expected));
    }

    #[cfg(feature = "test-feature")]
    #[tokio::test]
    async fn init_opens_a_file_store() {
        let opts = Options {
            sk_share_local_path: Some("/tmp/share".into()),
            sk_share_secret_id: None,
            gcp_project_id: None,
            redis_url: "redis://localhost".to_string(),
        };

        let store = KeyShareStore::init(&opts, &make_test_account_id())
            .await
            .unwrap();

        assert!(matches!(store, KeyShareStore::File(_)));
    }

    #[tokio::test]
    async fn init_opens_secret_manager() {
        let opts = Options {
            sk_share_secret_id: Some("secret-id".to_string()),
            #[cfg(feature = "test-feature")]
            sk_share_local_path: None,
            gcp_project_id: Some("test-project".to_string()),
            redis_url: "redis://localhost".to_string(),
        };

        let store = KeyShareStore::init(&opts, &make_test_account_id())
            .await
            .unwrap();

        assert!(matches!(store, KeyShareStore::GcpSecretManager(_)));
    }
}
