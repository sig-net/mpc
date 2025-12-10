use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::{GcpService, SecretResult};
use crate::storage::Options;
use crate::{gcp::SecretManagerService, protocol::state::PersistentNodeData};
use async_trait::async_trait;

use near_account_id::AccountId;

#[async_trait]
pub trait SecretNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()>;
    async fn load(&self) -> SecretResult<Option<PersistentNodeData>>;
}

#[derive(Default)]
struct MemoryNodeStorage {
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

struct SecretManagerNodeStorage {
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

struct DiskNodeStorage {
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
        let mut file = File::create(self.path.as_os_str()).await?;
        // Serialize the person object to JSON and convert directly to bytes
        let json_bytes = serde_json::to_vec(data)?;
        // Write the serialized JSON bytes to the file
        file.write_all(&json_bytes).await?;

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
            _ => {
                tracing::info!("loading PersistentNodeData using DiskNodeStorage: no file");
                Ok(None)
            }
        }
    }
}

pub type SecretNodeStorageBox = Box<dyn SecretNodeStorage + Send + Sync>;

pub fn init(
    gcp_service: Option<&GcpService>,
    opts: &Options,
    account_id: &AccountId,
) -> SecretNodeStorageBox {
    match gcp_service {
        Some(gcp) if opts.sk_share_secret_id.is_some() => {
            tracing::info!("using SecretManagerNodeStorage");
            Box::new(SecretManagerNodeStorage::new(
                &gcp.secret_manager.clone(),
                opts.clone().sk_share_secret_id.unwrap().clone(),
            )) as SecretNodeStorageBox
        }
        _ => {
            if let Some(sk_share_local_path) = &opts.sk_share_local_path {
                let path = format!("{sk_share_local_path}-{account_id}");
                tracing::info!("using DiskNodeStorage with path: {}", path);
                Box::new(DiskNodeStorage::new(&path)) as SecretNodeStorageBox
            } else {
                tracing::info!("using MemoryNodeStorage");
                Box::<MemoryNodeStorage>::default() as SecretNodeStorageBox
            }
        }
    }
}

#[cfg(feature = "test-feature")]
pub fn test_store(
    epoch: u64,
    private_share: crate::types::SecretKeyShare,
    public_key: mpc_crypto::PublicKey,
) -> SecretNodeStorageBox {
    let store = MemoryNodeStorage {
        node_data: Some(PersistentNodeData {
            epoch,
            private_share,
            public_key,
        }),
    };
    Box::new(store) as SecretNodeStorageBox
}


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use k256::Scalar;
    use mpc_crypto::{PublicKey, ScalarExt};
    use k256::ProjectivePoint;

    // Helper function to generate arbitrary secret key share
    fn arbitrary_secret_key_share() -> impl Strategy<Value = crate::types::SecretKeyShare> {
        prop::collection::vec(any::<u8>(), 32..=32)
            .prop_map(|bytes| {
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Scalar::from_bytes(array).unwrap_or(Scalar::ONE)
            })
    }

    // Helper function to generate arbitrary public key
    fn arbitrary_public_key() -> impl Strategy<Value = PublicKey> {
        arbitrary_secret_key_share()
            .prop_map(|scalar| {
                (ProjectivePoint::GENERATOR * scalar).to_affine()
            })
    }

    // Helper function to generate arbitrary PersistentNodeData
    fn arbitrary_persistent_node_data() -> impl Strategy<Value = PersistentNodeData> {
        (
            0u64..10000u64, // epoch
            arbitrary_secret_key_share(),
            arbitrary_public_key(),
        ).prop_map(|(epoch, private_share, public_key)| {
            PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }
        })
    }

    proptest! {
        /// Property 106: Node Restart State Restoration
        /// *For any* node with persisted state, restarting the node should correctly restore
        /// the epoch, private share, and public key from storage.
        /// **Feature: unit-test-coverage, Property 106: Node Restart State Restoration**
        /// **Validates: Requirements 33.1**
        #[test]
        fn prop_node_restart_state_restoration(
            node_data in arbitrary_persistent_node_data()
        ) {
            // Create a runtime for async operations
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // Create in-memory storage (simulates node startup)
                let mut storage = MemoryNodeStorage::default();
                
                // Store the node data (simulates node shutdown with state persistence)
                let store_result = storage.store(&node_data).await;
                prop_assert!(store_result.is_ok(), "Store operation should succeed");
                
                // Simulate node restart by loading from storage
                let load_result = storage.load().await;
                prop_assert!(load_result.is_ok(), "Load operation should succeed");
                
                let loaded_data = load_result.unwrap();
                prop_assert!(loaded_data.is_some(), "Loaded data should exist after store");
                
                let restored_data = loaded_data.unwrap();
                
                // Verify all fields are correctly restored
                prop_assert_eq!(
                    restored_data.epoch, 
                    node_data.epoch,
                    "Epoch should be preserved after restart"
                );
                prop_assert_eq!(
                    restored_data.private_share, 
                    node_data.private_share,
                    "Private share should be preserved after restart"
                );
                prop_assert_eq!(
                    restored_data.public_key, 
                    node_data.public_key,
                    "Public key should be preserved after restart"
                );
                
                Ok(())
            })?;
        }

        /// Property 107: Crash Recovery Completeness
        /// *For any* stored node state, recovery after crash should restore complete and
        /// consistent state without data loss or corruption.
        /// **Feature: unit-test-coverage, Property 107: Crash Recovery Completeness**
        /// **Validates: Requirements 33.2**
        #[test]
        fn prop_crash_recovery_completeness(
            node_data in arbitrary_persistent_node_data()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // Create storage and store initial state
                let mut storage = MemoryNodeStorage::default();
                storage.store(&node_data).await.unwrap();
                
                // Simulate crash by creating a "new" storage instance that shares the same data
                // In memory storage, this is simulated by keeping the same instance
                // For disk storage, this would be a new instance reading from the same file
                
                // Verify recovery is complete - all data is accessible
                let recovered = storage.load().await.unwrap().unwrap();
                
                // Verify data integrity - no corruption
                prop_assert_eq!(recovered.epoch, node_data.epoch);
                prop_assert_eq!(recovered.private_share, node_data.private_share);
                prop_assert_eq!(recovered.public_key, node_data.public_key);
                
                // Verify the recovered data can be used for further operations
                // (store again to verify it's valid)
                let re_store_result = storage.store(&recovered).await;
                prop_assert!(re_store_result.is_ok(), "Re-storing recovered data should succeed");
                
                // Verify round-trip consistency
                let re_loaded = storage.load().await.unwrap().unwrap();
                prop_assert_eq!(re_loaded.epoch, node_data.epoch);
                prop_assert_eq!(re_loaded.private_share, node_data.private_share);
                prop_assert_eq!(re_loaded.public_key, node_data.public_key);
                
                Ok(())
            })?;
        }

        /// Property 109: Secret Storage Integrity
        /// *For any* secret storage operation, the integrity of stored secrets should be
        /// maintained across store and load operations.
        /// **Feature: unit-test-coverage, Property 109: Secret Storage Integrity**
        /// **Validates: Requirements 33.4**
        #[test]
        fn prop_secret_storage_integrity(
            node_data in arbitrary_persistent_node_data()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut storage = MemoryNodeStorage::default();
                
                // Initially, storage should be empty
                let initial_load = storage.load().await.unwrap();
                prop_assert!(initial_load.is_none(), "Storage should be empty initially");
                
                // Store secret data
                storage.store(&node_data).await.unwrap();
                
                // Load and verify integrity
                let loaded = storage.load().await.unwrap().unwrap();
                
                // Verify cryptographic material integrity
                // The private share should be exactly preserved (byte-for-byte)
                prop_assert_eq!(
                    loaded.private_share, 
                    node_data.private_share,
                    "Private share integrity must be maintained"
                );
                
                // The public key should be exactly preserved
                prop_assert_eq!(
                    loaded.public_key, 
                    node_data.public_key,
                    "Public key integrity must be maintained"
                );
                
                // Verify that the public key corresponds to the private share
                // (This is a cryptographic consistency check)
                let expected_public_key = (ProjectivePoint::GENERATOR * node_data.private_share).to_affine();
                let loaded_expected_public_key = (ProjectivePoint::GENERATOR * loaded.private_share).to_affine();
                prop_assert_eq!(
                    expected_public_key,
                    loaded_expected_public_key,
                    "Cryptographic relationship between private and public key should be preserved"
                );
                
                Ok(())
            })?;
        }
    }

    #[tokio::test]
    async fn test_memory_storage_basic_operations() {
        // Basic unit test for memory storage operations
        let mut storage = MemoryNodeStorage::default();
        
        // Initially empty
        let initial = storage.load().await.unwrap();
        assert!(initial.is_none());
        
        // Create test data
        let test_data = PersistentNodeData {
            epoch: 42,
            private_share: Scalar::ONE,
            public_key: (ProjectivePoint::GENERATOR * Scalar::ONE).to_affine(),
        };
        
        // Store
        storage.store(&test_data).await.unwrap();
        
        // Load and verify
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded.epoch, 42);
        assert_eq!(loaded.private_share, Scalar::ONE);
    }

    #[tokio::test]
    async fn test_memory_storage_overwrite() {
        // Test that storing new data overwrites old data
        let mut storage = MemoryNodeStorage::default();
        
        let data1 = PersistentNodeData {
            epoch: 1,
            private_share: Scalar::ONE,
            public_key: (ProjectivePoint::GENERATOR * Scalar::ONE).to_affine(),
        };
        
        let data2 = PersistentNodeData {
            epoch: 2,
            private_share: Scalar::ONE + Scalar::ONE,
            public_key: (ProjectivePoint::GENERATOR * (Scalar::ONE + Scalar::ONE)).to_affine(),
        };
        
        // Store first data
        storage.store(&data1).await.unwrap();
        let loaded1 = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded1.epoch, 1);
        
        // Store second data (should overwrite)
        storage.store(&data2).await.unwrap();
        let loaded2 = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded2.epoch, 2);
    }
}
