pub mod error;
pub mod value;

use self::value::{FromValue, IntoValue};
use crate::gcp::error::DatastoreStorageError;
use crate::storage;

use google_datastore1::api::Filter;
use google_datastore1::api::{
    CommitRequest, Entity, EntityResult, Key, KindExpression, LookupRequest, Mutation, PathElement,
    Query, RunQueryRequest,
};
use google_datastore1::oauth2::AccessTokenAuthenticator;
use google_datastore1::Datastore;
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
                tracing::info!("failed to load existing key share, presuming it is missing");
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
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DatastoreService {
    datastore: Datastore<HttpsConnector<HttpConnector>>,
    project_id: String,
    env: String,
    is_emulator: bool,
}

pub type DatastoreResult<T> = std::result::Result<T, error::DatastoreStorageError>;

pub trait Keyable: KeyKind {
    fn key(&self) -> Key;
}

pub trait KeyKind {
    fn kind() -> String;
}

impl DatastoreService {
    pub fn is_emulator(&self) -> bool {
        self.is_emulator
    }

    #[tracing::instrument(level = "debug", skip_all, fields(key = name_key.to_string()))]
    pub async fn get<K: ToString, T: FromValue + KeyKind>(
        &self,
        name_key: K,
    ) -> DatastoreResult<T> {
        let request = LookupRequest {
            keys: Some(vec![Key {
                path: Some(vec![PathElement {
                    // We can't create multiple datastore databases in GCP, so we have to suffix
                    // type kinds with env (`dev`, `prod`).
                    kind: Some(format!("{}-{}", T::kind(), self.env)),
                    name: Some(name_key.to_string()),
                    id: None,
                }]),
                partition_id: None,
            }]),
            read_options: None,
            database_id: Some("".to_string()),
        };
        let (_, response) = self
            .datastore
            .projects()
            .lookup(request, &self.project_id)
            .doit()
            .await?;
        match response
            .found
            .and_then(|mut results| results.pop())
            .and_then(|result| result.entity)
        {
            Some(found_entity) => Ok(T::from_value(found_entity.into_value())?),
            None => Err(DatastoreStorageError::EntityNotFound(name_key.to_string())),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn insert<T: IntoValue + KeyKind>(&self, value: T) -> DatastoreResult<()> {
        let mut entity = Entity::from_value(value.into_value())?;
        let path_element = entity
            .key
            .as_mut()
            .and_then(|k| k.path.as_mut())
            .and_then(|p| p.first_mut());
        if let Some(path_element) = path_element {
            // We can't create multiple datastore databases in GCP, so we have to suffix
            // type kinds with env (`dev`, `prod`).
            path_element.kind = Some(format!("{}-{}", T::kind(), self.env))
        }

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(vec![Mutation {
                insert: Some(entity),
                delete: None,
                update: None,
                base_version: None,
                upsert: None,
                update_time: None,
            }]),
            single_use_transaction: None,
            transaction: None,
        };
        let (_, _) = self
            .datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn update<T: IntoValue + KeyKind>(&self, value: T) -> DatastoreResult<()> {
        let mut entity = Entity::from_value(value.into_value())?;
        let path_element = entity
            .key
            .as_mut()
            .and_then(|k| k.path.as_mut())
            .and_then(|p| p.first_mut());
        if let Some(path_element) = path_element {
            // We can't create multiple datastore databases in GCP, so we have to suffix
            // type kinds with env (`dev`, `prod`).
            path_element.kind = Some(format!("{}-{}", T::kind(), self.env))
        }

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(vec![Mutation {
                insert: None,
                delete: None,
                update: Some(entity),
                base_version: None,
                upsert: None,
                update_time: None,
            }]),
            single_use_transaction: None,
            transaction: None,
        };
        let (_, _) = self
            .datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;

        Ok(())
    }

    pub async fn upsert<T: IntoValue + KeyKind>(&self, value: T) -> DatastoreResult<()> {
        let mut entity = Entity::from_value(value.into_value())?;
        let path_element = entity
            .key
            .as_mut()
            .and_then(|k| k.path.as_mut())
            .and_then(|p| p.first_mut());
        if let Some(path_element) = path_element {
            // We can't create multiple datastore databases in GCP, so we have to suffix
            // type kinds with env (`dev`, `prod`).
            path_element.kind = Some(format!("{}-{}", T::kind(), self.env))
        }

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(vec![Mutation {
                insert: None,
                delete: None,
                update: None,
                base_version: None,
                upsert: Some(entity),
                update_time: None,
            }]),
            single_use_transaction: None,
            transaction: None,
        };

        let (_, _) = self
            .datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;

        Ok(())
    }

    pub async fn fetch_entities<T: KeyKind>(
        &self,
        filter: Option<Filter>,
    ) -> DatastoreResult<Vec<EntityResult>> {
        let kind: String = format!("{}-{}", T::kind(), self.env);
        let req = RunQueryRequest {
            database_id: Some("".to_string()),
            partition_id: Default::default(),
            read_options: Default::default(),
            query: Some(Query {
                projection: None,
                kind: Some(vec![KindExpression { name: Some(kind) }]),
                filter,
                order: None,
                distinct_on: Some(vec![]),
                start_cursor: None,
                end_cursor: None,
                offset: None,
                limit: None,
            }),
            gql_query: None,
        };
        let (_hyper_resp, query_resp) = self
            .datastore
            .projects()
            .run_query(req, &self.project_id)
            .doit()
            .await?;
        let batch = query_resp.batch.ok_or_else(|| {
            DatastoreStorageError::FetchEntitiesError(
                "Could not retrieve batch while fetching entities".to_string(),
            )
        })?;

        // NOTE: if entity_results is None, we return an empty Vec since the fetch query
        // could not find any entities in the DB.
        Ok(batch.entity_results.unwrap_or_default())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn delete<T: Keyable>(&self, keyable: T) -> DatastoreResult<()> {
        self.delete_many(&[keyable]).await
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn delete_many<T: Keyable>(&self, keyables: &[T]) -> DatastoreResult<()> {
        let mutations = keyables
            .iter()
            .map(|keyable| {
                let mut key = keyable.key();
                if let Some(path) = key.path.as_mut().and_then(|p| p.first_mut()) {
                    path.kind = Some(format!("{}-{}", T::kind(), self.env));
                }
                Mutation {
                    insert: None,
                    delete: Some(key),
                    update: None,
                    base_version: None,
                    upsert: None,
                    update_time: None,
                }
            })
            .collect::<Vec<_>>();

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(mutations),
            single_use_transaction: None,
            transaction: None,
        };
        let (_, _) = self
            .datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct GcpService {
    pub project_id: String,
    pub datastore: DatastoreService,
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
        let client = hyper::Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );
        let datastore = if let Some(gcp_datastore_url) = storage_options.gcp_datastore_url.clone() {
            // Assuming custom GCP URL points to an emulator, so the token does not matter
            let authenticator = AccessTokenAuthenticator::builder("TOKEN".to_string())
                .build()
                .await?;
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
            let mut datastore = Datastore::new(client, authenticator);
            datastore.base_url(gcp_datastore_url.clone());
            datastore.root_url(gcp_datastore_url);
            datastore
        } else {
            let opts = ApplicationDefaultCredentialsFlowOpts::default();
            let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts)
                .await
            {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
            };
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
            Datastore::new(client, authenticator)
        };

        Ok(Self {
            account_id: account_id.clone(),
            datastore: DatastoreService {
                datastore,
                project_id: project_id.clone(),
                env: storage_options.env.clone(),
                is_emulator: storage_options.gcp_datastore_url.is_some(),
            },
            secret_manager: SecretManagerService {
                secret_manager,
                project_id: project_id.clone(),
            },
            project_id,
        })
    }
}
