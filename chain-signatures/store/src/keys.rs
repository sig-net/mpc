/// Storage version constant, sourced from redis.toml at compile time.
pub const STORAGE_VERSION: &str = env!("MPC_STORAGE_VERSION");

/// Checkpoint version constant, sourced from redis.toml at compile time.
pub const CHECKPOINT_VERSION: &str = env!("MPC_CHECKPOINT_VERSION");

/// Constructs the holders key for a given artifact.
///
/// # Arguments
/// * `artifact_key` - The artifact hash key
/// * `artifact_id` - The artifact ID
///
/// # Returns
/// The holders key in the format `{artifact_key}:holders:{artifact_id}`
pub fn holders_key(artifact_key: &str, artifact_id: &str) -> String {
    format!("{artifact_key}:holders:{artifact_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_holders_key() {
        let artifact_key = "test:artifact:key";
        let artifact_id = "test-artifact-id";
        let result = holders_key(artifact_key, artifact_id);
        assert_eq!(result, "test:artifact:key:holders:test-artifact-id");
    }

    #[test]
    fn test_holders_key_with_special_chars() {
        let artifact_key = "prefix:v11:account.id";
        let artifact_id = "artifact-123";
        let result = holders_key(artifact_key, artifact_id);
        assert_eq!(result, "prefix:v11:account.id:holders:artifact-123");
    }
}
