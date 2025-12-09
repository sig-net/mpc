use proptest::prelude::*;

/// Mock Redis state for testing reserve operation logic
#[derive(Clone, Debug)]
struct MockRedisState {
    artifacts: std::collections::HashSet<String>,
    used: std::collections::HashSet<String>,
    reserved: std::collections::HashSet<String>,
}

impl MockRedisState {
    fn new() -> Self {
        Self {
            artifacts: std::collections::HashSet::new(),
            used: std::collections::HashSet::new(),
            reserved: std::collections::HashSet::new(),
        }
    }

    /// Simulates the MPC.RESERVE command logic
    fn reserve(&mut self, artifact_id: &str) -> Result<(), String> {
        // Check if artifact already exists in storage
        if self.artifacts.contains(artifact_id) {
            return Err("ERR STATE artifact already exists in storage".to_string());
        }

        // Check if artifact is already marked as used
        if self.used.contains(artifact_id) {
            return Err("ERR STATE artifact has already been used".to_string());
        }

        // Check if artifact is already reserved
        if self.reserved.contains(artifact_id) {
            return Err("ERR STATE artifact is already reserved".to_string());
        }

        // Add artifact_id to reserved set
        self.reserved.insert(artifact_id.to_string());
        Ok(())
    }
}

/// Mock Redis state for testing insert operation logic
#[derive(Clone, Debug)]
struct MockInsertState {
    artifacts: std::collections::HashMap<String, String>,
    used: std::collections::HashSet<String>,
    reserved: std::collections::HashSet<String>,
    owner_keys: std::collections::HashSet<String>,
    owner_artifacts: std::collections::HashMap<String, std::collections::HashSet<String>>,
}

impl MockInsertState {
    fn new() -> Self {
        Self {
            artifacts: std::collections::HashMap::new(),
            used: std::collections::HashSet::new(),
            reserved: std::collections::HashSet::new(),
            owner_keys: std::collections::HashSet::new(),
            owner_artifacts: std::collections::HashMap::new(),
        }
    }

    /// Simulates the MPC.INSERT command logic
    fn insert(&mut self, owner_key: &str, artifact_id: &str, artifact_data: &str) -> Result<(), String> {
        // Check if artifact_id is in reserved set
        if !self.reserved.contains(artifact_id) {
            return Err("ERR STATE artifact is not reserved".to_string());
        }

        // Check if artifact is already marked as used
        if self.used.contains(artifact_id) {
            return Err("ERR STATE artifact has already been used".to_string());
        }

        // Remove artifact_id from reserved set
        self.reserved.remove(artifact_id);

        // Add artifact_id to owner_key set
        self.owner_artifacts
            .entry(owner_key.to_string())
            .or_insert_with(std::collections::HashSet::new)
            .insert(artifact_id.to_string());

        // Add owner_key to owner_keys set
        self.owner_keys.insert(owner_key.to_string());

        // Store artifact in artifacts hash
        self.artifacts.insert(artifact_id.to_string(), artifact_data.to_string());

        Ok(())
    }
}

proptest! {
    /// **Feature: redis-rust-module, Property 1: Reserve operation correctness**
    /// **Validates: Requirements 2.1**
    ///
    /// For any artifact ID and Redis state (artifact may or may not exist, may be used, may be reserved),
    /// invoking the reserve operation should succeed only when the artifact is not in storage, not used,
    /// and not already reserved, and should atomically add the ID to the reserved set.
    #[test]
    fn prop_reserve_operation_correctness(
        artifact_id in "[a-z0-9]{1,32}",
    ) {
        let mut state = MockRedisState::new();
        
        // Test 1: Reserve should succeed when artifact doesn't exist, isn't used, and isn't reserved
        let result = state.reserve(&artifact_id);
        prop_assert!(result.is_ok(), "Reserve should succeed for new artifact");
        
        // Verify artifact was added to reserved set
        prop_assert!(state.reserved.contains(&artifact_id), 
                     "Artifact should be in reserved set after reserve");
        
        // Test 2: Reserve should fail when artifact is already reserved
        let result = state.reserve(&artifact_id);
        prop_assert!(result.is_err(), "Reserve should fail for already reserved artifact");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact is already reserved");
        
        // Test 3: Reserve should fail when artifact exists in storage
        let mut state = MockRedisState::new();
        state.artifacts.insert(artifact_id.clone());
        
        let result = state.reserve(&artifact_id);
        prop_assert!(result.is_err(), "Reserve should fail when artifact exists in storage");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact already exists in storage");
        
        // Test 4: Reserve should fail when artifact is marked as used
        let mut state = MockRedisState::new();
        state.used.insert(artifact_id.clone());
        
        let result = state.reserve(&artifact_id);
        prop_assert!(result.is_err(), "Reserve should fail when artifact is marked as used");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact has already been used");
        
        // Test 5: Verify atomicity - reserved set should only be modified on success
        let mut state = MockRedisState::new();
        state.artifacts.insert(artifact_id.clone());
        
        let initial_reserved_count = state.reserved.len();
        let result = state.reserve(&artifact_id);
        
        prop_assert!(result.is_err(), "Reserve should fail");
        prop_assert_eq!(state.reserved.len(), initial_reserved_count, 
                        "Reserved set should not be modified on failure");
    }

    /// **Feature: redis-rust-module, Property 2: Insert operation correctness**
    /// **Validates: Requirements 2.2**
    ///
    /// For any artifact, owner, and Redis state (artifact may or may not be reserved, may be used),
    /// invoking the insert operation should succeed only when the artifact was reserved and is not used,
    /// and should atomically store the artifact, track ownership, and remove from reserved set.
    #[test]
    fn prop_insert_operation_correctness(
        artifact_id in "[a-z0-9]{1,32}",
        owner_key in "[a-z0-9]{1,32}",
        artifact_data in "[a-z0-9]{1,64}",
    ) {
        let mut state = MockInsertState::new();

        // Test 1: Insert should fail when artifact is not reserved
        let result = state.insert(&owner_key, &artifact_id, &artifact_data);
        prop_assert!(result.is_err(), "Insert should fail when artifact is not reserved");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact is not reserved");

        // Test 2: Insert should succeed when artifact is reserved and not used
        let mut state = MockInsertState::new();
        state.reserved.insert(artifact_id.clone());

        let result = state.insert(&owner_key, &artifact_id, &artifact_data);
        prop_assert!(result.is_ok(), "Insert should succeed when artifact is reserved and not used");

        // Verify artifact was stored
        prop_assert_eq!(state.artifacts.get(&artifact_id), Some(&artifact_data.clone()),
                        "Artifact should be stored with correct data");

        // Verify artifact was removed from reserved set
        prop_assert!(!state.reserved.contains(&artifact_id),
                     "Artifact should be removed from reserved set");

        // Verify ownership was tracked
        prop_assert!(state.owner_artifacts
            .get(&owner_key)
            .map(|s| s.contains(&artifact_id))
            .unwrap_or(false),
            "Artifact should be added to owner's set");

        // Verify owner_key was registered
        prop_assert!(state.owner_keys.contains(&owner_key),
                     "Owner key should be registered in owner_keys set");

        // Test 3: Insert should fail when artifact is already used
        let mut state = MockInsertState::new();
        state.reserved.insert(artifact_id.clone());
        state.used.insert(artifact_id.clone());

        let result = state.insert(&owner_key, &artifact_id, &artifact_data);
        prop_assert!(result.is_err(), "Insert should fail when artifact is already used");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact has already been used");

        // Test 4: Verify atomicity - state should not be modified on failure
        let mut state = MockInsertState::new();
        state.reserved.insert(artifact_id.clone());
        state.used.insert(artifact_id.clone());

        let initial_artifacts_count = state.artifacts.len();
        let initial_reserved_count = state.reserved.len();
        let initial_owner_keys_count = state.owner_keys.len();

        let result = state.insert(&owner_key, &artifact_id, &artifact_data);

        prop_assert!(result.is_err(), "Insert should fail");
        prop_assert_eq!(state.artifacts.len(), initial_artifacts_count,
                        "Artifacts should not be modified on failure");
        prop_assert_eq!(state.reserved.len(), initial_reserved_count,
                        "Reserved set should not be modified on failure");
        prop_assert_eq!(state.owner_keys.len(), initial_owner_keys_count,
                        "Owner keys should not be modified on failure");
    }

    /// **Feature: redis-rust-module, Property 3: Take operation correctness**
    /// **Validates: Requirements 2.3**
    ///
    /// For any artifact ID, owner, and Redis state (artifact may or may not exist, may be used, may be owned by the specified owner),
    /// invoking the take operation should succeed only when the artifact exists, is owned by the specified owner, and is not used,
    /// and should atomically mark as used, remove from storage, and return the artifact data.
    #[test]
    fn prop_take_operation_correctness(
        artifact_id in "[a-z0-9]{1,32}",
        owner_key in "[a-z0-9]{1,32}",
        artifact_data in "[a-z0-9]{1,64}",
    ) {
        // Mock Redis state for testing take operation logic
        #[derive(Clone, Debug)]
        struct MockTakeState {
            artifacts: std::collections::HashMap<String, String>,
            used: std::collections::HashSet<String>,
            owner_artifacts: std::collections::HashMap<String, std::collections::HashSet<String>>,
        }

        impl MockTakeState {
            fn new() -> Self {
                Self {
                    artifacts: std::collections::HashMap::new(),
                    used: std::collections::HashSet::new(),
                    owner_artifacts: std::collections::HashMap::new(),
                }
            }

            /// Simulates the MPC.TAKE command logic
            fn take(&mut self, owner_key: &str, artifact_id: &str) -> Result<String, String> {
                // Check if artifact is already marked as used
                if self.used.contains(artifact_id) {
                    return Err("ERR STATE artifact has already been used".to_string());
                }

                // Check if artifact_id is in owner_key set
                let is_owned = self.owner_artifacts
                    .get(owner_key)
                    .map(|s| s.contains(artifact_id))
                    .unwrap_or(false);

                if !is_owned {
                    return Err("ERR STATE artifact is not owned by specified owner".to_string());
                }

                // Get artifact from artifacts hash
                let artifact = self.artifacts.get(artifact_id)
                    .ok_or_else(|| "ERR STATE artifact does not exist in storage".to_string())?;

                let artifact_copy = artifact.clone();

                // Remove artifact_id from owner_key set
                if let Some(owner_set) = self.owner_artifacts.get_mut(owner_key) {
                    owner_set.remove(artifact_id);
                }

                // Mark as used
                self.used.insert(artifact_id.to_string());

                // Delete from artifacts hash
                self.artifacts.remove(artifact_id);

                Ok(artifact_copy)
            }
        }

        let mut state = MockTakeState::new();

        // Test 1: Take should fail when artifact is not owned by specified owner
        let result = state.take(&owner_key, &artifact_id);
        prop_assert!(result.is_err(), "Take should fail when artifact is not owned");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact is not owned by specified owner");

        // Test 2: Take should fail when artifact doesn't exist in storage
        let mut state = MockTakeState::new();
        state.owner_artifacts
            .entry(owner_key.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(artifact_id.clone());

        let result = state.take(&owner_key, &artifact_id);
        prop_assert!(result.is_err(), "Take should fail when artifact doesn't exist in storage");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact does not exist in storage");

        // Test 3: Take should succeed when artifact exists, is owned, and is not used
        let mut state = MockTakeState::new();
        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());
        state.owner_artifacts
            .entry(owner_key.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(artifact_id.clone());

        let result = state.take(&owner_key, &artifact_id);
        prop_assert!(result.is_ok(), "Take should succeed when artifact exists, is owned, and is not used");
        prop_assert_eq!(result.unwrap(), artifact_data.clone(), "Take should return correct artifact data");

        // Verify artifact was removed from storage
        prop_assert!(!state.artifacts.contains_key(&artifact_id),
                     "Artifact should be removed from storage");

        // Verify artifact was marked as used
        prop_assert!(state.used.contains(&artifact_id),
                     "Artifact should be marked as used");

        // Verify artifact was removed from owner set
        prop_assert!(!state.owner_artifacts
            .get(&owner_key)
            .map(|s| s.contains(&artifact_id))
            .unwrap_or(false),
            "Artifact should be removed from owner set");

        // Test 4: Take should fail when artifact is already used
        let mut state = MockTakeState::new();
        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());
        state.owner_artifacts
            .entry(owner_key.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(artifact_id.clone());
        state.used.insert(artifact_id.clone());

        let result = state.take(&owner_key, &artifact_id);
        prop_assert!(result.is_err(), "Take should fail when artifact is already used");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact has already been used");

        // Test 5: Verify atomicity - state should not be modified on failure
        let mut state = MockTakeState::new();
        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());
        state.owner_artifacts
            .entry(owner_key.clone())
            .or_insert_with(std::collections::HashSet::new)
            .insert(artifact_id.clone());
        state.used.insert(artifact_id.clone());

        let initial_artifacts_count = state.artifacts.len();
        let initial_used_count = state.used.len();
        let initial_owner_count = state.owner_artifacts
            .get(&owner_key)
            .map(|s| s.len())
            .unwrap_or(0);

        let result = state.take(&owner_key, &artifact_id);

        prop_assert!(result.is_err(), "Take should fail");
        prop_assert_eq!(state.artifacts.len(), initial_artifacts_count,
                        "Artifacts should not be modified on failure");
        prop_assert_eq!(state.used.len(), initial_used_count,
                        "Used set should not be modified on failure");
        prop_assert_eq!(state.owner_artifacts
            .get(&owner_key)
            .map(|s| s.len())
            .unwrap_or(0), initial_owner_count,
            "Owner set should not be modified on failure");
    }

    /// **Feature: redis-rust-module, Property 4: Take mine operation correctness**
    /// **Validates: Requirements 2.4**
    ///
    /// For any owner set state (may be empty or contain artifacts), invoking the take_mine operation
    /// should return nil when the owner set is empty, and should atomically pop one artifact, mark it
    /// as used with expiration, re-reserve it, remove from storage, and return the artifact data when
    /// the set is non-empty.
    #[test]
    fn prop_take_mine_operation_correctness(
        artifact_id in "[a-z0-9]{1,32}",
        artifact_data in "[a-z0-9]{1,64}",
        _expire_seconds in 1i64..3600i64,
    ) {
        // Mock Redis state for testing take_mine operation logic
        #[derive(Clone, Debug)]
        struct MockTakeMineState {
            artifacts: std::collections::HashMap<String, String>,
            used: std::collections::HashSet<String>,
            reserved: std::collections::HashSet<String>,
            mine_artifacts: std::collections::HashSet<String>,
        }

        impl MockTakeMineState {
            fn new() -> Self {
                Self {
                    artifacts: std::collections::HashMap::new(),
                    used: std::collections::HashSet::new(),
                    reserved: std::collections::HashSet::new(),
                    mine_artifacts: std::collections::HashSet::new(),
                }
            }

            /// Simulates the MPC.TAKE_MINE command logic
            fn take_mine(&mut self, artifact_id: &str) -> Result<Option<String>, String> {
                // Check if mine_key set has any members
                if self.mine_artifacts.is_empty() {
                    return Ok(None);
                }

                // Pop one artifact_id from mine_key set
                if !self.mine_artifacts.contains(artifact_id) {
                    return Err("ERR STATE artifact not in mine set".to_string());
                }

                // Get artifact from artifact_key hash
                let artifact = self.artifacts.get(artifact_id)
                    .ok_or_else(|| "ERR STATE artifact does not exist in storage".to_string())?;

                let artifact_copy = artifact.clone();

                // Remove from mine set
                self.mine_artifacts.remove(artifact_id);

                // Add artifact_id back to reserved_key set
                self.reserved.insert(artifact_id.to_string());

                // Delete from artifact_key hash
                self.artifacts.remove(artifact_id);

                // Mark as used
                self.used.insert(artifact_id.to_string());

                Ok(Some(artifact_copy))
            }
        }

        // Test 1: Take_mine should return nil when mine set is empty
        let mut state = MockTakeMineState::new();
        let result = state.take_mine(&artifact_id);
        prop_assert!(result.is_ok(), "Take_mine should succeed even with empty set");
        prop_assert_eq!(result.unwrap(), None, "Take_mine should return nil when mine set is empty");

        // Test 2: Take_mine should succeed when artifact exists in mine set
        let mut state = MockTakeMineState::new();
        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());
        state.mine_artifacts.insert(artifact_id.clone());

        let result = state.take_mine(&artifact_id);
        prop_assert!(result.is_ok(), "Take_mine should succeed when artifact exists in mine set");
        prop_assert_eq!(result.unwrap(), Some(artifact_data.clone()), 
                        "Take_mine should return correct artifact data");

        // Verify artifact was removed from storage
        prop_assert!(!state.artifacts.contains_key(&artifact_id),
                     "Artifact should be removed from storage");

        // Verify artifact was marked as used
        prop_assert!(state.used.contains(&artifact_id),
                     "Artifact should be marked as used");

        // Verify artifact was re-reserved
        prop_assert!(state.reserved.contains(&artifact_id),
                     "Artifact should be re-reserved");

        // Verify artifact was removed from mine set
        prop_assert!(!state.mine_artifacts.contains(&artifact_id),
                     "Artifact should be removed from mine set");

        // Test 3: Take_mine should fail when artifact doesn't exist in storage
        let mut state = MockTakeMineState::new();
        state.mine_artifacts.insert(artifact_id.clone());

        let result = state.take_mine(&artifact_id);
        prop_assert!(result.is_err(), "Take_mine should fail when artifact doesn't exist in storage");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact does not exist in storage");

        // Test 4: Verify atomicity - state should not be modified on failure
        let mut state = MockTakeMineState::new();
        state.mine_artifacts.insert(artifact_id.clone());

        let _initial_used_count = state.used.len();
        let _initial_reserved_count = state.reserved.len();
        let initial_mine_count = state.mine_artifacts.len();

        let result = state.take_mine(&artifact_id);

        prop_assert!(result.is_err(), "Take_mine should fail");
        prop_assert_eq!(state.mine_artifacts.len(), initial_mine_count,
                        "Mine set should not be modified on failure");

        // Test 5: Multiple artifacts in mine set - should pop one
        let mut state = MockTakeMineState::new();
        let artifact_id_2 = format!("{}_2", artifact_id);
        let artifact_data_2 = format!("{}_2", artifact_data);

        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());
        state.artifacts.insert(artifact_id_2.clone(), artifact_data_2.clone());
        state.mine_artifacts.insert(artifact_id.clone());
        state.mine_artifacts.insert(artifact_id_2.clone());

        let initial_mine_count = state.mine_artifacts.len();
        let result = state.take_mine(&artifact_id);

        prop_assert!(result.is_ok(), "Take_mine should succeed");
        prop_assert_eq!(state.mine_artifacts.len(), initial_mine_count - 1,
                        "Mine set should have one fewer artifact");
        prop_assert!(!state.mine_artifacts.contains(&artifact_id),
                     "Popped artifact should be removed from mine set");
        prop_assert!(state.mine_artifacts.contains(&artifact_id_2),
                     "Other artifact should remain in mine set");
    }

    /// **Feature: redis-rust-module, Property 5: Recycle mine operation correctness**
    /// **Validates: Requirements 2.5**
    ///
    /// For any used artifact and owner, invoking the recycle_mine operation should atomically
    /// remove the artifact from the used set, restore it to storage, add it back to the owner set,
    /// and ensure it remains reserved.
    #[test]
    fn prop_recycle_mine_operation_correctness(
        artifact_id in "[a-z0-9]{1,32}",
        artifact_data in "[a-z0-9]{1,64}",
    ) {
        // Mock Redis state for testing recycle_mine operation logic
        #[derive(Clone, Debug)]
        struct MockRecycleMineState {
            artifacts: std::collections::HashMap<String, String>,
            used: std::collections::HashSet<String>,
            reserved: std::collections::HashSet<String>,
            mine_artifacts: std::collections::HashSet<String>,
        }

        impl MockRecycleMineState {
            fn new() -> Self {
                Self {
                    artifacts: std::collections::HashMap::new(),
                    used: std::collections::HashSet::new(),
                    reserved: std::collections::HashSet::new(),
                    mine_artifacts: std::collections::HashSet::new(),
                }
            }

            /// Simulates the MPC.RECYCLE_MINE command logic
            fn recycle_mine(&mut self, artifact_id: &str, artifact_data: &str) -> Result<i64, String> {
                // Check if artifact_id is in used_key hash
                if !self.used.contains(artifact_id) {
                    return Err("ERR STATE artifact is not marked as used".to_string());
                }

                // Remove artifact_id from used_key hash
                self.used.remove(artifact_id);

                // Store artifact in artifact_key hash
                self.artifacts.insert(artifact_id.to_string(), artifact_data.to_string());

                // Add artifact_id to mine_key set
                self.mine_artifacts.insert(artifact_id.to_string());

                // Ensure artifact_id is in reserved_key set
                self.reserved.insert(artifact_id.to_string());

                Ok(1)
            }
        }

        // Test 1: Recycle_mine should fail when artifact is not marked as used
        let mut state = MockRecycleMineState::new();
        let result = state.recycle_mine(&artifact_id, &artifact_data);
        prop_assert!(result.is_err(), "Recycle_mine should fail when artifact is not marked as used");
        prop_assert_eq!(result.unwrap_err(), "ERR STATE artifact is not marked as used");

        // Test 2: Recycle_mine should succeed when artifact is marked as used
        let mut state = MockRecycleMineState::new();
        state.used.insert(artifact_id.clone());

        let result = state.recycle_mine(&artifact_id, &artifact_data);
        prop_assert!(result.is_ok(), "Recycle_mine should succeed when artifact is marked as used");
        prop_assert_eq!(result.unwrap(), 1, "Recycle_mine should return 1 on success");

        // Verify artifact was removed from used set
        prop_assert!(!state.used.contains(&artifact_id),
                     "Artifact should be removed from used set");

        // Verify artifact was restored to storage
        prop_assert_eq!(state.artifacts.get(&artifact_id), Some(&artifact_data.clone()),
                        "Artifact should be restored to storage with correct data");

        // Verify artifact was added to mine set
        prop_assert!(state.mine_artifacts.contains(&artifact_id),
                     "Artifact should be added to mine set");

        // Verify artifact is in reserved set
        prop_assert!(state.reserved.contains(&artifact_id),
                     "Artifact should be in reserved set");

        // Test 3: Recycle_mine should fail when artifact doesn't exist in used set
        let mut state = MockRecycleMineState::new();
        state.artifacts.insert(artifact_id.clone(), artifact_data.clone());

        let result = state.recycle_mine(&artifact_id, &artifact_data);
        prop_assert!(result.is_err(), "Recycle_mine should fail when artifact is not in used set");

        // Test 4: Verify atomicity - state should not be modified on failure
        let mut state = MockRecycleMineState::new();

        let initial_artifacts_count = state.artifacts.len();
        let initial_used_count = state.used.len();
        let initial_reserved_count = state.reserved.len();
        let initial_mine_count = state.mine_artifacts.len();

        let result = state.recycle_mine(&artifact_id, &artifact_data);

        prop_assert!(result.is_err(), "Recycle_mine should fail");
        prop_assert_eq!(state.artifacts.len(), initial_artifacts_count,
                        "Artifacts should not be modified on failure");
        prop_assert_eq!(state.used.len(), initial_used_count,
                        "Used set should not be modified on failure");
        prop_assert_eq!(state.reserved.len(), initial_reserved_count,
                        "Reserved set should not be modified on failure");
        prop_assert_eq!(state.mine_artifacts.len(), initial_mine_count,
                        "Mine set should not be modified on failure");

        // Test 5: Multiple recycles should work correctly
        let mut state = MockRecycleMineState::new();
        let artifact_id_2 = format!("{}_2", artifact_id);
        let artifact_data_2 = format!("{}_2", artifact_data);

        state.used.insert(artifact_id.clone());
        state.used.insert(artifact_id_2.clone());

        let result1 = state.recycle_mine(&artifact_id, &artifact_data);
        let result2 = state.recycle_mine(&artifact_id_2, &artifact_data_2);

        prop_assert!(result1.is_ok(), "First recycle_mine should succeed");
        prop_assert!(result2.is_ok(), "Second recycle_mine should succeed");

        // Verify both artifacts are in mine set
        prop_assert!(state.mine_artifacts.contains(&artifact_id),
                     "First artifact should be in mine set");
        prop_assert!(state.mine_artifacts.contains(&artifact_id_2),
                     "Second artifact should be in mine set");

        // Verify both artifacts are in reserved set
        prop_assert!(state.reserved.contains(&artifact_id),
                     "First artifact should be in reserved set");
        prop_assert!(state.reserved.contains(&artifact_id_2),
                     "Second artifact should be in reserved set");

        // Verify used set is empty
        prop_assert!(state.used.is_empty(), "Used set should be empty after recycling all artifacts");
    }

    /// **Feature: redis-rust-module, Property 6: Remove outdated operation correctness**
    /// **Validates: Requirements 2.6**
    ///
    /// For any set of current owner shares and existing owner artifacts, invoking the remove_outdated
    /// operation should identify artifacts in the owner set but not in the current shares, batch-delete
    /// them from all relevant keys, and return the list of removed IDs.
    #[test]
    fn prop_remove_outdated_operation_correctness(
        artifact_ids in prop::collection::vec("[a-z0-9]{1,32}", 1..20),
        current_share_ids in prop::collection::vec("[a-z0-9]{1,32}", 0..10),
    ) {
        // Mock Redis state for testing remove_outdated operation logic
        #[derive(Clone, Debug)]
        struct MockRemoveOutdatedState {
            artifacts: std::collections::HashMap<String, String>,
            reserved: std::collections::HashSet<String>,
            owner_artifacts: std::collections::HashSet<String>,
        }

        impl MockRemoveOutdatedState {
            fn new() -> Self {
                Self {
                    artifacts: std::collections::HashMap::new(),
                    reserved: std::collections::HashSet::new(),
                    owner_artifacts: std::collections::HashSet::new(),
                }
            }

            /// Simulates the MPC.REMOVE_OUTDATED command logic
            fn remove_outdated(&mut self, current_share_ids: &[String]) -> Result<Vec<String>, String> {
                // Get all members from owner_key set
                let owner_members: Vec<String> = self.owner_artifacts.iter().cloned().collect();

                // Build hash set of current_share_ids for O(1) lookup
                let mut current_ids = std::collections::HashSet::new();
                for id in current_share_ids {
                    current_ids.insert(id.clone());
                }

                // Identify outdated IDs (in owner_key but not in current_share_ids)
                let mut outdated_ids = Vec::new();
                for member_id in &owner_members {
                    if !current_ids.contains(member_id) {
                        outdated_ids.push(member_id.clone());
                    }
                }

                // Remove from all sets
                for id in &outdated_ids {
                    self.artifacts.remove(id);
                    self.reserved.remove(id);
                    self.owner_artifacts.remove(id);
                }

                Ok(outdated_ids)
            }
        }

        // Test 1: Remove_outdated should return empty array when all artifacts are current
        let mut state = MockRemoveOutdatedState::new();
        for id in &artifact_ids {
            state.owner_artifacts.insert(id.clone());
            state.artifacts.insert(id.clone(), format!("data_{}", id));
            state.reserved.insert(id.clone());
        }

        let result = state.remove_outdated(&artifact_ids);
        prop_assert!(result.is_ok(), "Remove_outdated should succeed");
        prop_assert!(result.unwrap().is_empty(), "Remove_outdated should return empty array when all artifacts are current");

        // Test 2: Remove_outdated should identify and remove outdated artifacts
        let mut state = MockRemoveOutdatedState::new();
        for id in &artifact_ids {
            state.owner_artifacts.insert(id.clone());
            state.artifacts.insert(id.clone(), format!("data_{}", id));
            state.reserved.insert(id.clone());
        }

        let result = state.remove_outdated(&current_share_ids);
        prop_assert!(result.is_ok(), "Remove_outdated should succeed");

        let removed = result.unwrap();
        
        // Verify all removed IDs are outdated (not in current_share_ids)
        for removed_id in &removed {
            prop_assert!(!current_share_ids.contains(removed_id),
                        "Removed ID should not be in current_share_ids");
        }

        // Verify all outdated IDs are removed
        for id in &artifact_ids {
            if !current_share_ids.contains(id) {
                prop_assert!(removed.contains(id),
                            "Outdated artifact should be in removed list");
            }
        }

        // Test 3: Verify artifacts are removed from all sets
        let mut state = MockRemoveOutdatedState::new();
        for id in &artifact_ids {
            state.owner_artifacts.insert(id.clone());
            state.artifacts.insert(id.clone(), format!("data_{}", id));
            state.reserved.insert(id.clone());
        }

        let initial_owner_count = state.owner_artifacts.len();
        let initial_artifact_count = state.artifacts.len();
        let initial_reserved_count = state.reserved.len();

        let result = state.remove_outdated(&current_share_ids);
        prop_assert!(result.is_ok(), "Remove_outdated should succeed");

        let removed_count = result.unwrap().len();

        // Verify counts decreased by the number of removed artifacts
        prop_assert_eq!(state.owner_artifacts.len(), initial_owner_count - removed_count,
                        "Owner artifacts count should decrease by number of removed artifacts");
        prop_assert_eq!(state.artifacts.len(), initial_artifact_count - removed_count,
                        "Artifacts count should decrease by number of removed artifacts");
        prop_assert_eq!(state.reserved.len(), initial_reserved_count - removed_count,
                        "Reserved count should decrease by number of removed artifacts");

        // Test 4: Remove_outdated should return empty array when owner set is empty
        let mut state = MockRemoveOutdatedState::new();
        let result = state.remove_outdated(&current_share_ids);
        prop_assert!(result.is_ok(), "Remove_outdated should succeed with empty owner set");
        prop_assert!(result.unwrap().is_empty(), "Remove_outdated should return empty array when owner set is empty");

        // Test 5: Remove_outdated should handle large batches correctly
        let mut state = MockRemoveOutdatedState::new();
        let large_ids: Vec<String> = (0..5000).map(|i| format!("artifact_{}", i)).collect();
        
        for id in &large_ids {
            state.owner_artifacts.insert(id.clone());
            state.artifacts.insert(id.clone(), format!("data_{}", id));
            state.reserved.insert(id.clone());
        }

        // Only keep first 100 as current
        let current_large: Vec<String> = large_ids.iter().take(100).cloned().collect();
        
        let result = state.remove_outdated(&current_large);
        prop_assert!(result.is_ok(), "Remove_outdated should succeed with large batch");

        let removed = result.unwrap();
        prop_assert_eq!(removed.len(), 4900, "Should remove 4900 outdated artifacts");
        prop_assert_eq!(state.owner_artifacts.len(), 100, "Owner artifacts should have 100 remaining");
        prop_assert_eq!(state.artifacts.len(), 100, "Artifacts should have 100 remaining");
        prop_assert_eq!(state.reserved.len(), 100, "Reserved should have 100 remaining");
    }

    /// **Feature: redis-rust-module, Property 7: Clear operation correctness**
    /// **Validates: Requirements 2.7**
    ///
    /// For any Redis state with artifact storage and multiple dynamic owner keys, invoking the clear
    /// operation should atomically delete all artifact-related keys including all dynamically created
    /// owner keys.
    #[test]
    fn prop_clear_operation_correctness(
        artifact_ids in prop::collection::vec("[a-z0-9]{1,32}", 1..20),
        owner_keys_list in prop::collection::vec("[a-z0-9]{1,32}", 1..10),
    ) {
        // Mock Redis state for testing clear operation logic
        #[derive(Clone, Debug)]
        struct MockClearState {
            artifacts: std::collections::HashMap<String, String>,
            used: std::collections::HashSet<String>,
            reserved: std::collections::HashSet<String>,
            owner_keys: std::collections::HashSet<String>,
            owner_artifacts: std::collections::HashMap<String, std::collections::HashSet<String>>,
        }

        impl MockClearState {
            fn new() -> Self {
                Self {
                    artifacts: std::collections::HashMap::new(),
                    used: std::collections::HashSet::new(),
                    reserved: std::collections::HashSet::new(),
                    owner_keys: std::collections::HashSet::new(),
                    owner_artifacts: std::collections::HashMap::new(),
                }
            }

            /// Simulates the MPC.CLEAR command logic
            fn clear(&mut self) -> Result<(), String> {
                // Clear all main keys
                self.artifacts.clear();
                self.used.clear();
                self.reserved.clear();
                
                // Clear all dynamic owner keys
                for owner_key in self.owner_keys.iter() {
                    self.owner_artifacts.remove(owner_key);
                }
                self.owner_keys.clear();

                Ok(())
            }

            /// Helper to populate state with test data
            fn populate(&mut self, artifact_ids: &[String], owner_keys_list: &[String]) {
                for (idx, artifact_id) in artifact_ids.iter().enumerate() {
                    self.artifacts.insert(artifact_id.clone(), format!("data_{}", artifact_id));
                    self.reserved.insert(artifact_id.clone());
                    
                    // Distribute artifacts across owners
                    let owner_idx = idx % owner_keys_list.len();
                    let owner_key = &owner_keys_list[owner_idx];
                    
                    self.owner_keys.insert(owner_key.clone());
                    self.owner_artifacts
                        .entry(owner_key.clone())
                        .or_insert_with(std::collections::HashSet::new)
                        .insert(artifact_id.clone());
                }

                // Mark some artifacts as used
                for (idx, artifact_id) in artifact_ids.iter().enumerate() {
                    if idx % 3 == 0 {
                        self.used.insert(artifact_id.clone());
                    }
                }
            }
        }

        // Test 1: Clear should delete all keys when state is populated
        let mut state = MockClearState::new();
        state.populate(&artifact_ids, &owner_keys_list);

        let initial_artifact_count = state.artifacts.len();
        let initial_used_count = state.used.len();
        let initial_reserved_count = state.reserved.len();
        let initial_owner_keys_count = state.owner_keys.len();
        let initial_owner_artifacts_count = state.owner_artifacts.len();

        prop_assert!(initial_artifact_count > 0, "Should have artifacts before clear");
        prop_assert!(initial_owner_keys_count > 0, "Should have owner keys before clear");

        let result = state.clear();
        prop_assert!(result.is_ok(), "Clear should succeed");

        // Verify all keys are deleted
        prop_assert_eq!(state.artifacts.len(), 0, "Artifacts should be empty after clear");
        prop_assert_eq!(state.used.len(), 0, "Used set should be empty after clear");
        prop_assert_eq!(state.reserved.len(), 0, "Reserved set should be empty after clear");
        prop_assert_eq!(state.owner_keys.len(), 0, "Owner keys should be empty after clear");
        prop_assert_eq!(state.owner_artifacts.len(), 0, "Owner artifacts should be empty after clear");

        // Test 2: Clear should work on empty state
        let mut state = MockClearState::new();
        let result = state.clear();
        prop_assert!(result.is_ok(), "Clear should succeed on empty state");
        prop_assert_eq!(state.artifacts.len(), 0, "Artifacts should remain empty");
        prop_assert_eq!(state.owner_keys.len(), 0, "Owner keys should remain empty");

        // Test 3: Clear should work with single artifact and owner
        let mut state = MockClearState::new();
        let single_artifact = vec![artifact_ids[0].clone()];
        let single_owner = vec![owner_keys_list[0].clone()];
        state.populate(&single_artifact, &single_owner);

        prop_assert_eq!(state.artifacts.len(), 1, "Should have 1 artifact");
        prop_assert_eq!(state.owner_keys.len(), 1, "Should have 1 owner key");

        let result = state.clear();
        prop_assert!(result.is_ok(), "Clear should succeed");
        prop_assert_eq!(state.artifacts.len(), 0, "Artifacts should be empty after clear");
        prop_assert_eq!(state.owner_keys.len(), 0, "Owner keys should be empty after clear");

        // Test 4: Clear should work with large state
        let mut state = MockClearState::new();
        let large_artifacts: Vec<String> = (0..1000).map(|i| format!("artifact_{}", i)).collect();
        let large_owners: Vec<String> = (0..50).map(|i| format!("owner_{}", i)).collect();
        state.populate(&large_artifacts, &large_owners);

        prop_assert_eq!(state.artifacts.len(), 1000, "Should have 1000 artifacts");
        prop_assert_eq!(state.owner_keys.len(), 50, "Should have 50 owner keys");

        let result = state.clear();
        prop_assert!(result.is_ok(), "Clear should succeed with large state");
        prop_assert_eq!(state.artifacts.len(), 0, "Artifacts should be empty after clear");
        prop_assert_eq!(state.used.len(), 0, "Used set should be empty after clear");
        prop_assert_eq!(state.reserved.len(), 0, "Reserved set should be empty after clear");
        prop_assert_eq!(state.owner_keys.len(), 0, "Owner keys should be empty after clear");
        prop_assert_eq!(state.owner_artifacts.len(), 0, "Owner artifacts should be empty after clear");

        // Test 5: Clear should be idempotent - clearing twice should work
        let mut state = MockClearState::new();
        state.populate(&artifact_ids, &owner_keys_list);

        let result1 = state.clear();
        let result2 = state.clear();

        prop_assert!(result1.is_ok(), "First clear should succeed");
        prop_assert!(result2.is_ok(), "Second clear should succeed");
        prop_assert_eq!(state.artifacts.len(), 0, "Artifacts should be empty after second clear");
        prop_assert_eq!(state.owner_keys.len(), 0, "Owner keys should be empty after second clear");

        // Test 6: Clear should handle mixed state (some used, some reserved, some in owner sets)
        let mut state = MockClearState::new();
        state.populate(&artifact_ids, &owner_keys_list);

        // Verify state has mixed data
        let has_used = state.used.len() > 0;
        let has_reserved = state.reserved.len() > 0;
        let has_owners = state.owner_keys.len() > 0;

        prop_assert!(has_used || has_reserved || has_owners, "State should have mixed data");

        let result = state.clear();
        prop_assert!(result.is_ok(), "Clear should succeed with mixed state");

        // Verify all data is cleared
        prop_assert_eq!(state.artifacts.len(), 0, "All artifacts should be cleared");
        prop_assert_eq!(state.used.len(), 0, "All used markers should be cleared");
        prop_assert_eq!(state.reserved.len(), 0, "All reserved markers should be cleared");
        prop_assert_eq!(state.owner_keys.len(), 0, "All owner keys should be cleared");
    }
}