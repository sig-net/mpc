pub mod error;

use crate::storage;

use google_datastore1::api::Key;
use google_secretmanager1::api::{AddSecretVersionRequest, SecretPayload};
use google_secretmanager1::SecretManager;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use yup_oauth2::{
    authenticator::{
        AccessTokenAuthenticator, ApplicationDefaultCredentialsAuthenticator,
        ApplicationDefaultCredentialsTypes,
    },
    ApplicationDefaultCredentialsFlowOpts,
};

use near_account_id::AccountId;

pub type SecretResult<T> = std::result::Result<T, error::SecretStorageError>;

#[derive(Clone)]
pub struct SecretManagerService {
    secret_manager: SecretManager<HttpConnector>,
    project_id: String,
}

impl SecretManagerService {
    #[tracing::instrument(level = "debug", skip_all, fields(name = name.as_ref()))]
    pub async fn load_secret<T: AsRef<str>>(&self, name: T) -> SecretResult<Option<Vec<u8>>> {
        let (_, response) = self
            .secret_manager
            .projects()
            .secrets_versions_access(&format!(
                "projects/{}/secrets/{}/versions/latest",
                self.project_id,
                name.as_ref()
            ))
            .doit()
            .await?;
        match response.payload {
            // GCP does not allow to upload empty secrets, so we reserve 1-byte values as a
            // placeholder for empty secrets.
            Some(SecretPayload {
                data: Some(data), ..
            }) if data.len() > 1 => Ok(Some(data)),
            _ => {
                tracing::error!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }

    pub async fn store_secret<T: AsRef<str>>(
        &mut self,
        data: &[u8],
        name: T,
    ) -> SecretResult<()> {
        self.secret_manager
            .projects()
            .secrets_add_version(
                AddSecretVersionRequest {
                    payload: Some(SecretPayload {
                        data: Some(data.to_owned()),
                        ..Default::default()
                    }),
                },
                &format!("projects/{}/secrets/{}", self.project_id, name.as_ref()),
            )
            .doit()
            .await
            .map_err(|e| {
                tracing::error!(%e, "failed to store secret");
                e
            })?;
        Ok(())
    }
}

pub trait Keyable: KeyKind {
    fn key(&self) -> Key;
}

pub trait KeyKind {
    fn kind() -> String;
}

#[derive(Clone)]
pub struct GcpService {
    pub project_id: String,
    pub secret_manager: SecretManagerService,
    pub account_id: AccountId,
}

impl GcpService {
    pub async fn init(
        account_id: &AccountId,
        storage_options: &storage::Options,
    ) -> anyhow::Result<Self> {
        let project_id = storage_options.gcp_project_id.clone();
        let secret_manager;
        if storage_options.env == "local-test" {
            // For local testing, use HTTP-only client to avoid HTTPS trait issues
            let client =
                hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
            // Assuming we are in a test environment, token does not matter
            let authenticator = AccessTokenAuthenticator::builder("TOKEN".to_string())
                .build()
                .await?;
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
        } else {
            // For production, also use HTTP-only client due to HTTPS trait compatibility issues
            // TODO: Fix HTTPS client compatibility when Google API libraries are updated
            let client =
                hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
            let opts = ApplicationDefaultCredentialsFlowOpts { metadata_url: None };
            let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts)
                .await
            {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
            };
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
        }

        Ok(Self {
            account_id: account_id.clone(),
            secret_manager: SecretManagerService {
                secret_manager,
                project_id: project_id.clone(),
            },
            project_id,
        })
    }
}
