//! Shared test utilities for unit tests across the MPC node codebase.
//!
//! This module provides:
//! - In-memory storage builders for testing without external dependencies
//! - Test data generators for creating valid test inputs
//! - Assertion helpers for validating test outcomes

use crate::storage::checkpoint_storage::CheckpointStorage;

/// Create an in-memory checkpoint storage for testing.
///
/// This storage implementation uses a HashMap wrapped in Arc<RwLock<>> for thread-safe
/// access without requiring Redis or other external dependencies.
pub fn in_memory_checkpoint_storage() -> CheckpointStorage {
    CheckpointStorage::in_memory()
}

/// Verify that checkpoint storage is empty.
pub async fn assert_checkpoint_storage_empty(storage: &CheckpointStorage) {
    match storage {
        CheckpointStorage::InMemory(map) => {
            let guard = map.read().await;
            assert!(
                guard.is_empty(),
                "Expected checkpoint storage to be empty, but found {} entries",
                guard.len()
            );
        }
        CheckpointStorage::Redis(_, _) => {
            panic!("Cannot assert on Redis storage in unit tests");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_infrastructure_availability() {
        // Property 1: Test Infrastructure Availability
        // Validates: Requirements 1.1
        //
        // For any test infrastructure setup, the system SHALL provide
        // in-memory storage variants that can be instantiated without
        // external dependencies.

        // Create in-memory checkpoint storage
        let storage = in_memory_checkpoint_storage();

        // Verify it's empty initially
        assert_checkpoint_storage_empty(&storage).await;

        // Verify we can use it (basic operation)
        match storage {
            CheckpointStorage::InMemory(_) => {
                // Successfully created in-memory storage
            }
            CheckpointStorage::Redis(_, _) => {
                panic!("Expected InMemory variant");
            }
        }
    }
}
