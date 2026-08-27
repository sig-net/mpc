pub mod error;
pub mod gcp;

pub use error::SecretStorageError;
pub use gcp::{AuthProvider, SecretManagerService, SecretResult};

#[derive(Clone)]
pub struct GcpService {
    pub project_id: String,
    pub secret_manager: SecretManagerService,
    pub account_id: String,
}

impl GcpService {
    pub async fn init(account_id: &str, env: &str, gcp_project_id: &str) -> anyhow::Result<Self> {
        let auth_provider = if env == "local-test" {
            AuthProvider::Mock("TOKEN".to_string())
        } else {
            let auth = gcp_auth::provider()
                .await
                .map_err(|e| anyhow::anyhow!("failed to initialize GCP auth provider: {e}"))?;
            AuthProvider::Adc(auth)
        };

        let secret_manager = SecretManagerService::new(gcp_project_id, auth_provider);
        Ok(Self {
            account_id: account_id.to_string(),
            secret_manager,
            project_id: gcp_project_id.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init_local_test() {
        let service = GcpService::init("test.near", "local-test", "test-project")
            .await
            .unwrap();
        assert_eq!(service.project_id, "test-project");
        assert_eq!(service.account_id, "test.near");
    }
}
