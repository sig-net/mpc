pub mod error;
pub mod value;

use crate::storage;

use google_datastore1::api::Key;
use google_datastore1::oauth2::AccessTokenAuthenticator;
use google_secretmanager1::api::{AddSecretVersionRequest, SecretPayload};
use google_secretmanager1::oauth2::authenticator::ApplicationDefaultCredentialsTypes;
use google_secretmanager1::oauth2::{
    ApplicationDefaultCredentialsAuthenticator, ApplicationDefaultCredentialsFlowOpts,
};
use google_secretmanager1::SecretManager;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;

use near_account_id::AccountId;

pub type SecretResult<T> = std::result::Result<T, error::SecretStorageError>;

#[derive(Clone)]
pub struct SecretManagerService {
    secret_manager: SecretManager<HttpsConnector<HttpConnector>>,
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

    pub async fn store_secret<T: AsRef<str>>(&mut self, data: &[u8], name: T) -> SecretResult<()> {
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
        // TODO: check string
        if storage_options.env == "local-test" {
            let client = hyper::Client::builder().build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_or_http()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            );
            // Assuming we are in a test environment, token does not matter
            let authenticator = AccessTokenAuthenticator::builder("TOKEN".to_string())
                .build()
                .await?;
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
        } else {
            // restring client to use https in production
            let client = hyper::Client::builder().build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            );
            let opts = ApplicationDefaultCredentialsFlowOpts::default();
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
