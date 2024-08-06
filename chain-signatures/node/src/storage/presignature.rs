use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::gcp::GcpService;
use crate::gcp::{error, Keyable};
use crate::gcp::{
    error::ConvertError,
    value::{FromValue, IntoValue, Value},
    KeyKind,
};
use crate::protocol::presignature::{Presignature, PresignatureId};

use async_trait::async_trait;
use cait_sith::PresignOutput;
use google_datastore1::api::{
    Filter, Key, PathElement, PropertyFilter, PropertyReference, Value as DatastoreValue,
};
use tokio::sync::RwLock;

use near_account_id::AccountId;

use super::triple_storage::{DataStoreNodeStorage, StorageResult};

pub struct PresignatureKey<'a> {
    pub account_id: &'a str,
    pub presignature_id: PresignatureId,
}

impl KeyKind for PresignatureKey<'_> {
    fn kind() -> String {
        "presignature".to_string()
    }
}

impl Keyable for PresignatureKey<'_> {
    fn key(&self) -> Key {
        Key {
            path: Some(vec![PathElement {
                kind: None,
                name: Some(format!("{}/{}", self.account_id, self.presignature_id)),
                id: None,
            }]),
            partition_id: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PresignatureData {
    pub account_id: AccountId,
    pub presignature: Presignature,
    pub mine: bool,
}

impl KeyKind for PresignatureData {
    fn kind() -> String {
        "presignature".to_string()
    }
}

impl Keyable for PresignatureData {
    fn key(&self) -> Key {
        Key {
            path: Some(vec![PathElement {
                kind: None,
                name: Some(format!("{}/{}", self.account_id, self.presignature.id)),
                id: None,
            }]),
            partition_id: None,
        }
    }
}

fn put_field<T: serde::Serialize>(properties: &mut HashMap<String, Value>, field: &str, value: &T) {
    properties.insert(
        field.to_string(),
        Value::StringValue(serde_json::to_string(&value).unwrap()),
    );
}

fn take_field<T: serde::de::DeserializeOwned>(
    properties: &mut HashMap<String, Value>,
    field: &str,
) -> Result<T, ConvertError> {
    let (_, value) = properties
        .remove_entry(field)
        .ok_or_else(|| ConvertError::MissingProperty(field.to_string()))?;
    let value = String::from_value(value)?;
    serde_json::from_str(&value)
        .map_err(|e| ConvertError::MalformedProperty(format!("{}, {}", e, field)))
}

impl IntoValue for PresignatureData {
    fn into_value(self) -> Value {
        let presignature_key = PresignatureKey {
            account_id: self.account_id.as_str(),
            presignature_id: self.presignature.id,
        };
        let mut properties = HashMap::new();

        put_field(&mut properties, "account_id", &self.account_id);
        put_field(&mut properties, "id", &self.presignature.id);
        put_field(
            &mut properties,
            "participants",
            &self.presignature.participants,
        );
        put_field(&mut properties, "mine", &self.mine);

        // Output Field
        put_field(&mut properties, "k", &self.presignature.output.k);
        put_field(&mut properties, "sigma", &self.presignature.output.sigma);
        put_field(&mut properties, "big_r", &self.presignature.output.big_r);

        Value::EntityValue {
            key: presignature_key.key(),
            properties,
        }
    }
}

impl FromValue for PresignatureData {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let account_id = take_field(&mut properties, "account_id")?;
                let id = take_field(&mut properties, "id")?;
                let participants = take_field(&mut properties, "participants")?;
                let mine = take_field(&mut properties, "mine")?;
                // Output fields
                let k = take_field(&mut properties, "k")?;
                let sigma = take_field(&mut properties, "sigma")?;
                let big_r = take_field(&mut properties, "big_r")?;

                Ok(Self {
                    account_id,
                    presignature: Presignature {
                        id,
                        participants,
                        output: PresignOutput { big_r, k, sigma },
                    },
                    mine,
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

/// This trait is an abstracted version of the Presignature Store
#[async_trait]
pub trait PresignatureStorage {
    async fn insert(&mut self, presignature: Presignature, mine: bool) -> StorageResult<()>;
    async fn delete(&mut self, id: PresignatureId) -> StorageResult<()>;
    async fn clear(&mut self) -> StorageResult<Vec<PresignatureData>>;
    async fn load(&self) -> StorageResult<Vec<PresignatureData>>;
    fn account_id(&self) -> &AccountId;
}

#[derive(Clone)]
struct MemoryPresignatureStorage {
    presignatures: HashMap<PresignatureId, Presignature>,
    mine: HashSet<PresignatureId>,
    account_id: AccountId,
}

#[async_trait]
impl PresignatureStorage for MemoryPresignatureStorage {
    async fn insert(&mut self, presignature: Presignature, mine: bool) -> StorageResult<()> {
        if mine {
            self.mine.insert(presignature.id);
        }
        self.presignatures.insert(presignature.id, presignature);
        Ok(())
    }

    async fn delete(&mut self, id: PresignatureId) -> StorageResult<()> {
        self.presignatures.remove(&id);
        self.mine.remove(&id);
        Ok(())
    }

    async fn clear(&mut self) -> StorageResult<Vec<PresignatureData>> {
        let res = self.load().await?;
        self.presignatures.clear();
        self.mine.clear();
        Ok(res)
    }

    async fn load(&self) -> StorageResult<Vec<PresignatureData>> {
        let mut res: Vec<PresignatureData> = vec![];
        for (presignature_id, presignature) in self.presignatures.clone() {
            let mine = self.mine.contains(&presignature_id);
            res.push(PresignatureData {
                account_id: self.account_id().clone(),
                presignature,
                mine,
            });
        }
        Ok(res)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[async_trait]
impl PresignatureStorage for DataStoreNodeStorage {
    async fn insert(&mut self, presignature: Presignature, mine: bool) -> StorageResult<()> {
        tracing::debug!(
            id = presignature.id,
            "inserting presignature using datastore"
        );
        self.datastore
            .upsert(PresignatureData {
                account_id: self.account_id.clone(),
                presignature,
                mine,
            })
            .await?;
        Ok(())
    }

    async fn delete(&mut self, id: PresignatureId) -> StorageResult<()> {
        tracing::debug!(id, "deleting presignature using datastore");
        self.datastore
            .delete(PresignatureKey {
                account_id: self.account_id.as_str(),
                presignature_id: id,
            })
            .await?;
        Ok(())
    }

    async fn clear(&mut self) -> StorageResult<Vec<PresignatureData>> {
        let presignatures = PresignatureStorage::load(self).await?;
        self.datastore.delete_many(&presignatures).await?;
        Ok(presignatures)
    }

    async fn load(&self) -> StorageResult<Vec<PresignatureData>> {
        tracing::debug!("loading presignature using datastore");
        let filter = if self.datastore.is_emulator() {
            None
        } else {
            Some(Filter {
                composite_filter: None,
                property_filter: Some(PropertyFilter {
                    op: Some("Equal".to_string()),
                    property: Some(PropertyReference {
                        name: Some("account_id".to_string()),
                    }),
                    value: Some(DatastoreValue::from_value(
                        self.account_id.as_str().into_value(),
                    )?),
                }),
            })
        };
        let response = self
            .datastore
            .fetch_entities::<PresignatureData>(filter)
            .await?;
        let mut res: Vec<PresignatureData> = vec![];
        for entity_result in response {
            let entity = entity_result.entity.ok_or_else(|| {
                error::DatastoreStorageError::FetchEntitiesError(
                    "entity was not able to unwrapped".to_string(),
                )
            })?;
            let presignature_data = PresignatureData::from_value(entity.into_value())?;
            if &presignature_data.account_id == &self.account_id {
                res.push(presignature_data);
            }
        }
        tracing::debug!(count = res.len(), "loading presignatures success");
        Ok(res)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

pub type PresignatureStorageBox = Box<dyn PresignatureStorage + Send + Sync>;

pub type PresignatureLockNodeStorageBox = Arc<RwLock<PresignatureStorageBox>>;

pub fn init(gcp_service: Option<&GcpService>, account_id: &AccountId) -> PresignatureStorageBox {
    match gcp_service {
        Some(gcp) => Box::new(DataStoreNodeStorage::new(gcp.datastore.clone(), account_id))
            as PresignatureStorageBox,
        _ => Box::new(MemoryPresignatureStorage {
            presignatures: HashMap::new(),
            mine: HashSet::new(),
            account_id: account_id.clone(),
        }) as PresignatureStorageBox,
    }
}
