//! Typed structs for the Canton JSON Ledger API v2.
//!
//! Derived from the OpenAPI spec (version 3.4.11). Only types that the MPC node
//! or integration tests actually use are included.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Commands (request construction)
// ---------------------------------------------------------------------------

/// Wrapper for `POST /v2/commands/submit-and-wait-for-transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAndWaitForTransactionRequest {
    pub commands: JsCommands,
}

/// The commands payload sent to the ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsCommands {
    pub command_id: String,
    pub user_id: String,
    pub act_as: Vec<String>,
    #[serde(default)]
    pub read_as: Vec<String>,
    pub commands: Vec<Command>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosed_contracts: Vec<DisclosedContract>,
}

/// A single ledger command (externally tagged enum).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    CreateCommand {
        #[serde(rename = "templateId")]
        template_id: String,
        #[serde(rename = "createArguments")]
        create_arguments: Value,
    },
    ExerciseCommand {
        #[serde(rename = "templateId")]
        template_id: String,
        #[serde(rename = "contractId")]
        contract_id: String,
        choice: String,
        #[serde(rename = "choiceArgument")]
        choice_argument: Value,
    },
}

/// A disclosed contract for cross-party visibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosedContract {
    pub template_id: Value,
    pub contract_id: Value,
    pub created_event_blob: Value,
    pub synchronizer_id: Value,
}

/// Response from `POST /v2/commands/submit-and-wait-for-transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAndWaitForTransactionResponse {
    pub transaction: Transaction,
}

// ---------------------------------------------------------------------------
// Events (response parsing)
// ---------------------------------------------------------------------------

/// A ledger transaction containing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub offset: Value,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// A ledger event (externally tagged enum).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    CreatedEvent(CreatedEvent),
    ArchivedEvent(ArchivedEvent),
    /// Exercised events are emitted when a choice is exercised.
    /// We capture the full JSON since we don't need typed access.
    ExercisedEvent(Value),
}

/// A contract creation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedEvent {
    pub contract_id: String,
    pub template_id: String,
    /// The contract payload. Use domain types from [`crate::contracts`] to
    /// deserialize into typed structs via `serde_json::from_value()`.
    #[serde(alias = "createArgument")]
    pub payload: Value,
    #[serde(default)]
    pub created_event_blob: Option<String>,
}

/// A contract archive event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedEvent {
    pub contract_id: String,
    pub template_id: String,
}

// ---------------------------------------------------------------------------
// WebSocket subscription
// ---------------------------------------------------------------------------

/// Subscription message sent to `ws://.../v2/updates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUpdatesRequest {
    pub begin_exclusive: u64,
    pub verbose: bool,
    pub filter: UpdatesFilter,
}

/// Filters for the updates stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesFilter {
    #[serde(default)]
    pub filters_by_party: serde_json::Map<String, Value>,
}

/// A message received from the updates WebSocket stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMessage {
    #[serde(default)]
    pub update: Option<Update>,
    #[serde(default)]
    pub error: Option<Value>,
}

/// Discriminated update types from the WebSocket stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Update {
    Transaction {
        value: TransactionUpdate,
    },
    OffsetCheckpoint {
        value: OffsetCheckpointValue,
    },
}

/// The value inside an `Update::Transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionUpdate {
    pub offset: u64,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// The value inside an `Update::OffsetCheckpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OffsetCheckpointValue {
    pub offset: u64,
}

// ---------------------------------------------------------------------------
// Parties
// ---------------------------------------------------------------------------

/// Request body for `POST /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyRequest {
    pub party_id_hint: String,
    #[serde(default)]
    pub identity_provider_id: String,
    #[serde(default)]
    pub synchronizer_id: String,
    #[serde(default)]
    pub user_id: String,
}

/// Response from `POST /v2/parties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatePartyResponse {
    pub party_details: PartyDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyDetails {
    pub party: String,
    #[serde(default)]
    pub is_local: bool,
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Request body for `POST /v2/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    pub user: UserInfo,
    #[serde(default)]
    pub rights: Vec<UserRight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: String,
    pub primary_party: String,
    #[serde(default)]
    pub is_deactivated: bool,
    #[serde(default)]
    pub identity_provider_id: String,
}

/// A user right (externally tagged enum with nested kind wrapper).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRight {
    pub kind: UserRightKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRightKind {
    CanActAs { value: PartyValue },
    CanReadAs { value: PartyValue },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyValue {
    pub party: String,
}

// ---------------------------------------------------------------------------
// Active Contracts
// ---------------------------------------------------------------------------

/// Request body for `POST /v2/state/active-contracts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetActiveContractsRequest {
    pub active_at_offset: u64,
    pub event_format: EventFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventFormat {
    pub filters_by_party: serde_json::Map<String, Value>,
    #[serde(default)]
    pub verbose: bool,
}

/// A single item in the active contracts response array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContractEntry {
    #[serde(default)]
    pub contract_entry: Option<ContractEntry>,
}

/// Wraps the active contract variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractEntry {
    JsActiveContract(JsActiveContract),
}

/// An active contract with its created event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsActiveContract {
    pub created_event: CreatedEvent,
    #[serde(default)]
    pub synchronizer_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Ledger End
// ---------------------------------------------------------------------------

/// Response from `GET /v2/state/ledger-end`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEndResponse {
    pub offset: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Canton error response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CantonError {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub cause: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a template ID ends with a given suffix (e.g., `"Signer:Signer"`).
pub fn template_suffix_matches(template_id: &str, suffix: &str) -> bool {
    template_id.ends_with(suffix)
}

/// Build a `UserRight` for CanActAs.
pub fn can_act_as(party: &str) -> UserRight {
    UserRight {
        kind: UserRightKind::CanActAs {
            value: PartyValue {
                party: party.to_string(),
            },
        },
    }
}

/// Build a `UserRight` for CanReadAs.
pub fn can_read_as(party: &str) -> UserRight {
    UserRight {
        kind: UserRightKind::CanReadAs {
            value: PartyValue {
                party: party.to_string(),
            },
        },
    }
}
