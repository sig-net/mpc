//! Typed structs for the Canton JSON Ledger API v2.
//!
//! Hand-translated from the OpenAPI spec (version 3.4.11). Only types that the
//! MPC node or integration tests actually use are included. Could be
//! auto-generated with `openapi-generator` in the future.

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
    pub template_id: String,
    pub contract_id: String,
    pub created_event_blob: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synchronizer_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Events (response parsing)
// ---------------------------------------------------------------------------

/// Response from `POST /v2/commands/submit-and-wait-for-transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAndWaitForTransactionResponse {
    pub transaction: Transaction,
}

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
    ExercisedEvent(ExercisedEvent),
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
    /// Parties that are signatories on this contract.
    #[serde(default)]
    pub signatories: Vec<String>,
    /// Parties whose participants witnessed (confirmed) this transaction.
    #[serde(default)]
    pub witness_parties: Vec<String>,
    /// Position of this event in the transaction tree (LEDGER_EFFECTS only).
    #[serde(default)]
    pub node_id: Option<u32>,
    /// The package name of the contract.
    #[serde(default)]
    pub package_name: Option<String>,
}

/// A contract archive event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedEvent {
    pub contract_id: String,
    pub template_id: String,
    #[serde(default)]
    pub package_name: Option<String>,
}

/// A choice exercise event (LEDGER_EFFECTS shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExercisedEvent {
    pub contract_id: String,
    pub template_id: String,
    pub choice: String,
    #[serde(default)]
    pub acting_parties: Vec<String>,
    #[serde(default)]
    pub consuming: bool,
    #[serde(default)]
    pub node_id: Option<u32>,
    /// Upper boundary of descendant node IDs in this transaction.
    #[serde(default)]
    pub last_descendant_node_id: Option<u32>,
    #[serde(default)]
    pub package_name: Option<String>,
}

// ---------------------------------------------------------------------------
// WebSocket subscription
// ---------------------------------------------------------------------------

/// Subscription message sent to `ws://.../v2/updates`.
///
/// Uses `updateFormat` (Canton 3.4+) instead of the deprecated
/// `filter`/`verbose` top-level fields
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUpdatesRequest {
    pub begin_exclusive: u64,
    pub update_format: UpdateFormat,
}

/// Specifies what updates to include and how to render them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFormat {
    pub include_transactions: TransactionFormat,
}

/// Specifies the transaction shape and event format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionFormat {
    pub transaction_shape: String,
    pub event_format: EventFormat,
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
    Transaction { value: TransactionUpdate },
    OffsetCheckpoint { value: OffsetCheckpoint },
}

/// The value inside an Update::Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionUpdate {
    pub offset: u64,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// The value inside an Update::OffsetCheckpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OffsetCheckpoint {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synchronizer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
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
    #[serde(default)]
    pub filters_by_party: serde_json::Map<String, Value>,
    #[serde(default)]
    pub verbose: bool,
}

/// A party-level filter for active contracts queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyFilter {
    pub cumulative: Vec<CumulativeFilter>,
}

/// A single cumulative filter entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CumulativeFilter {
    pub identifier_filter: IdentifierFilter,
}

/// Discriminated identifier filter type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentifierFilter {
    TemplateFilter { value: TemplateFilterValue },
}

/// Value inside a TemplateFilter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateFilterValue {
    pub template_id: String,
    #[serde(default)]
    pub include_created_event_blob: bool,
}

/// A single item in the active contracts response array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContractEntry {
    #[serde(default)]
    pub contract_entry: Option<ContractEntry>,
}

/// Wraps the active contract variant.
/// Canton API can return JsEmpty, JsIncompleteAssigned, JsIncompleteUnassigned
/// in addition to JsActiveContract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractEntry {
    JsActiveContract(JsActiveContract),
    JsEmpty(Value),
    JsIncompleteAssigned(Value),
    JsIncompleteUnassigned(Value),
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
// Template constants and matching
// ---------------------------------------------------------------------------

/// Known Daml template suffixes from daml-signer.
pub mod templates {
    pub const SIGNER: &str = "Signer:Signer";
    pub const SIGN_BIDIRECTIONAL_EVENT: &str = "Signer:SignBidirectionalEvent";
    pub const SIGNATURE_RESPONDED_EVENT: &str = "Signer:SignatureRespondedEvent";
    pub const RESPOND_BIDIRECTIONAL_EVENT: &str = "Signer:RespondBidirectionalEvent";
    pub const SIGNING_NONCE: &str = "Signer:SigningNonce";
}

/// Check if a template ID matches a given suffix at a module boundary.
/// Requires the suffix to be preceded by `:` (package separator) or match exactly.
///
/// TODO(test): every event gets filtered through this — a bug means events are
/// silently ignored. Test exact match ("Signer:Signer"), prefix match
/// ("abc123:Signer:Signer"), and near-misses ("FakeSigner:Signer",
/// "Signer:SignerExtra").
pub fn template_suffix_matches(template_id: &str, suffix: &str) -> bool {
    template_id == suffix || template_id.ends_with(&format!(":{suffix}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a UserRight for CanActAs.
pub fn can_act_as(party: &str) -> UserRight {
    UserRight {
        kind: UserRightKind::CanActAs {
            value: PartyValue {
                party: party.to_string(),
            },
        },
    }
}

/// Build a UserRight for CanReadAs.
pub fn can_read_as(party: &str) -> UserRight {
    UserRight {
        kind: UserRightKind::CanReadAs {
            value: PartyValue {
                party: party.to_string(),
            },
        },
    }
}
