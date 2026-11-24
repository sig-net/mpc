//! The publisher's node facade: pinned finalized reads, a per-block memo, and
//! the read-verdict carrier every read error carries.

use anyhow::Context as _;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::client::OnlineClient;
use subxt::utils::H256;
use subxt::SubstrateConfig;

use super::reads::{
    attach_read_carrier, network_id, publisher_contract_state, unwrap_runtime_api_result,
};
use super::transport::connect_http;

use crate::config::MidnightConfig;
use crate::types::{BlockHash, MidnightAddress, NetworkId};

/// Runtime API name from Midnight node 2.0.0-rc.4 metadata.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";

/// Finalized reads and transaction submission for the Midnight publisher.
///
/// Only `rpc` and `legacy` are `pub(super)`: the `SubmitChain` impl in
/// `submit.rs` drives them, and nothing outside `rpc/` sees either type.
pub struct MidnightPublisherRpc {
    pub(super) rpc: RpcClient,
    pub(super) legacy: LegacyRpcMethods<SubstrateConfig>,
    genesis_hash: H256,
    /// One subxt client per runtime version met, each with the metadata read at a
    /// block of that runtime.
    clients: std::sync::Mutex<
        std::collections::HashMap<RuntimeVersionKey, OnlineClient<SubstrateConfig>>,
    >,
    blocks: std::sync::Mutex<BlockMemo>,
    network_id: NetworkId,
}

/// `(spec_version, transaction_version)`.
type RuntimeVersionKey = (u32, u32);

pub(super) type Header = <SubstrateConfig as subxt::Config>::Header;

/// Recently read blocks' headers, executing-runtime clients and times, by hash. None
/// changes once a block exists, so a landing scan, its TTL check and the fee's head
/// reads share one read of each.
#[derive(Default)]
pub(super) struct BlockMemo {
    headers: std::collections::VecDeque<(H256, Header)>,
    clients: std::collections::VecDeque<(H256, OnlineClient<SubstrateConfig>)>,
    pub(super) times: std::collections::VecDeque<(H256, midnight_base_crypto::time::Timestamp)>,
}

/// Blocks a memo keeps: more than one landing poll scans.
const BLOCK_MEMO_LEN: usize = 16;

pub(super) fn remember<T>(
    entries: &mut std::collections::VecDeque<(H256, T)>,
    hash: H256,
    value: T,
) {
    if entries.len() == BLOCK_MEMO_LEN {
        entries.pop_front();
    }
    entries.push_back((hash, value));
}

pub(super) fn recall<T: Clone>(
    entries: &std::collections::VecDeque<(H256, T)>,
    hash: H256,
) -> Option<T> {
    entries
        .iter()
        .find(|(known, _)| *known == hash)
        .map(|(_, value)| value.clone())
}

impl MidnightPublisherRpc {
    /// A publisher over an explicit transport, for tests that drive its reads
    /// without dialing `connect`.
    #[cfg(test)]
    pub(super) fn with_transport(transport: RpcClient) -> Self {
        Self {
            rpc: transport.clone(),
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(transport),
            genesis_hash: H256([0x11; 32]),
            clients: Default::default(),
            blocks: Default::default(),
            network_id: NetworkId::Undeployed,
        }
    }

    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        tokio::time::timeout(config.rpc.connect_timeout, async {
            let rpc = connect_http(config)?;
            let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone());
            let network_id = network_id(&legacy).await?;
            let genesis_hash = legacy
                .genesis_hash()
                .await
                .context("failed to fetch the midnight genesis hash")?;
            let publisher = Self {
                rpc,
                legacy,
                genesis_hash,
                clients: Default::default(),
                blocks: Default::default(),
                network_id,
            };
            publisher
                .client_at(None)
                .await
                .context("failed to initialise the midnight subxt client")?;
            anyhow::Ok(publisher)
        })
        .await
        .context("timed out connecting the midnight publisher to the node")?
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// The subxt client for the runtime in `at`'s state, or the best block's when
    /// `None`: the runtime the node's pool validates a submit against. Version and
    /// metadata are read at the same block, so an upgrade not yet finalized cannot
    /// pair new metadata with an old version or the reverse.
    pub(super) async fn client_at(
        &self,
        at: Option<H256>,
    ) -> anyhow::Result<OnlineClient<SubstrateConfig>> {
        let at = match at {
            Some(at) => at,
            None => self
                .legacy
                .chain_get_block_hash(None)
                .await
                .context("failed to fetch the midnight best block")?
                .context("midnight node has no best block")?,
        };
        let version = self
            .legacy
            .state_get_runtime_version(Some(at))
            .await
            .context("failed to fetch the midnight runtime version")?;
        let key = (version.spec_version, version.transaction_version);
        if let Some(client) = self.clients().get(&key) {
            return Ok(client.clone());
        }
        let metadata = metadata_at(&self.rpc, at).await?;
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            self.genesis_hash,
            subxt::client::RuntimeVersion {
                spec_version: key.0,
                transaction_version: key.1,
            },
            metadata,
            self.rpc.clone(),
        )
        .context("failed to build the midnight subxt client")?;
        Ok(self.clients().entry(key).or_insert(client).clone())
    }

    /// The subxt client for the runtime that executed block `hash`: its parent's.
    pub(super) async fn client_for_block(
        &self,
        hash: H256,
    ) -> anyhow::Result<OnlineClient<SubstrateConfig>> {
        if let Some(client) = recall(&self.blocks().clients, hash) {
            return Ok(client);
        }
        let header = self.header(hash).await?;
        let client = self.client_at(Some(header.parent_hash)).await?;
        remember(&mut self.blocks().clients, hash, client.clone());
        Ok(client)
    }

    pub(super) async fn header(&self, hash: H256) -> anyhow::Result<Header> {
        if let Some(header) = recall(&self.blocks().headers, hash) {
            return Ok(header);
        }
        let header = self
            .legacy
            .chain_get_header(Some(hash))
            .await
            .context("failed to fetch a midnight block header")?
            .with_context(|| {
                format!("midnight node has no header for {}", BlockHash::from(hash))
            })?;
        remember(&mut self.blocks().headers, hash, header.clone());
        Ok(header)
    }

    pub(super) fn blocks(&self) -> std::sync::MutexGuard<'_, BlockMemo> {
        self.blocks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clients(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<RuntimeVersionKey, OnlineClient<SubstrateConfig>>,
    > {
        self.clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The newest metadata version subxt reads that the runtime in `at`'s state serves,
/// tried the way `OnlineClient::from_rpc_client` tries them.
async fn metadata_at(rpc: &RpcClient, at: H256) -> anyhow::Result<subxt::Metadata> {
    use subxt::backend::BackendExt as _;

    let backend =
        subxt::backend::legacy::LegacyBackend::<SubstrateConfig>::builder().build(rpc.clone());
    for version in subxt::metadata::types::SUPPORTED_METADATA_VERSIONS {
        if let Ok(metadata) = backend.metadata_at_version(version, at).await {
            return Ok(metadata);
        }
    }
    backend
        .legacy_metadata(at)
        .await
        .context("failed to fetch the midnight runtime metadata")
}

/// Finalized reads used by the publisher and its in-process tests, every one
/// addressed by the hash `finalized_head` answers with. Every error out of
/// an impl carries a read-partition verdict carrier (`attach_read_carrier`).
#[async_trait::async_trait]
pub trait PinnedReads: Send + Sync {
    async fn finalized_head(&self) -> anyhow::Result<BlockHash>;
    async fn contract_state(
        &self,
        address: &MidnightAddress,
        at_hash: &BlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn ledger_parameters(&self, at_hash: &BlockHash) -> anyhow::Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl PinnedReads for MidnightPublisherRpc {
    async fn finalized_head(&self) -> anyhow::Result<BlockHash> {
        let finalized = self
            .legacy
            .chain_get_finalized_head()
            .await
            .context("failed to fetch the midnight finalized head")
            .map_err(attach_read_carrier)?;
        Ok(finalized.into())
    }

    async fn contract_state(
        &self,
        address: &MidnightAddress,
        at_hash: &BlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        publisher_contract_state(&self.rpc, address, at_hash)
            .await
            .map_err(attach_read_carrier)
    }

    async fn ledger_parameters(&self, at_hash: &BlockHash) -> anyhow::Result<Vec<u8>> {
        let at = H256::from(*at_hash);
        let read = async {
            let answer = self
                .legacy
                .state_call(LEDGER_PARAMETERS_ENTRY, Some(&[]), Some(at))
                .await
                .context("failed to fetch midnight ledger parameters")?;
            unwrap_runtime_api_result(&answer)?
                .with_context(|| format!("midnight node has no ledger parameters at {at_hash}"))
        };
        read.await.map_err(attach_read_carrier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;
    use jsonrpsee::server::ServerBuilder;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use crate::rpc::reads::is_oversized_contract_state;
    use crate::rpc::submit::Landing;
    use crate::rpc::submit::SubmitChain as _;
    use crate::rpc::support::captured_applied_status_record;
    use crate::types::LedgerTxHash;
    use http::StatusCode;
    use jsonrpsee::types::error::OVERSIZED_RESPONSE_CODE;
    use jsonrpsee::RpcModule;
    use mpc_chain_integration_core::utils::retry::{
        is_provider_throttled, is_retryable, RpcFailure,
    };
    use serde_json::json;
    use std::time::Duration;
    use subxt::ext::codec::{DecodeAll as _, Encode as _};

    #[tokio::test]
    async fn real_publish_read_statuses_follow_the_read_partition() {
        // Every read's own wrapper against a real transport: the carrier must
        // land on the wire shape, not just the synthetic one.
        for (status, reason, retryable, throttled) in [
            (403u16, "Forbidden", false, false),
            (409, "Conflict", true, false),
            (429, "Too Many Requests", true, true),
            (500, "Internal Server Error", true, false),
        ] {
            let (address, _calls, server) = http_status_server(status, reason).await;
            let transport = connect_http(&http_config(address)).expect("build request-only client");
            let rpc = MidnightPublisherRpc::with_transport(transport);
            let responder = test_address();
            let at_hash = test_at_hash();

            for error in [
                PinnedReads::finalized_head(&rpc)
                    .await
                    .expect_err("an HTTP rejection must fail the read"),
                PinnedReads::contract_state(&rpc, &responder, &at_hash)
                    .await
                    .expect_err("an HTTP rejection must fail the read"),
                PinnedReads::ledger_parameters(&rpc, &at_hash)
                    .await
                    .expect_err("an HTTP rejection must fail the read"),
            ] {
                let carrier = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<RpcFailure>())
                    .unwrap_or_else(|| panic!("the read attaches its carrier: {error:#}"));
                assert_eq!(
                    carrier.status(),
                    StatusCode::from_u16(status).ok(),
                    "status {status} was lost from the carrier: {error:#}"
                );
                assert_eq!(
                    is_retryable(&error),
                    retryable,
                    "status {status}: {error:#}"
                );
                assert_eq!(
                    is_provider_throttled(&error),
                    throttled,
                    "status {status}: {error:#}"
                );
            }
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn client_cap_size_refusal_terminates_the_publish_read() {
        let (transport, _calls) = stub_rpc(Canned::ClientTooLarge);
        let rpc = MidnightPublisherRpc::with_transport(transport);

        let error = PinnedReads::contract_state(&rpc, &test_address(), &test_at_hash())
            .await
            .expect_err("the refusal must fail the read");
        assert!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<RpcFailure>())
                .is_some(),
            "the read attaches its carrier: {error:#}"
        );
        assert!(!is_retryable(&error), "{error:#}");
        assert!(!is_provider_throttled(&error), "{error:#}");
    }

    #[tokio::test]
    async fn node_cap_size_refusal_is_retryable_on_the_publish_read() {
        // A proving cap and a small cap both stay retryable on the publish path;
        // the operator can raise the node's response cap.
        for (data, cap) in [
            ("\"Exceeded max limit of 15728640\"", "proving"),
            ("\"Exceeded max limit of 65536\"", "small"),
        ] {
            let (transport, calls) = stub_rpc(Canned::UserWithData(
                OVERSIZED_RESPONSE_CODE,
                "Response is too big",
                data,
            ));
            let rpc = MidnightPublisherRpc::with_transport(transport);

            let error = PinnedReads::contract_state(&rpc, &test_address(), &test_at_hash())
                .await
                .expect_err("the refusal must fail the read");
            assert!(
                error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<RpcFailure>())
                    .is_some(),
                "{cap}: the read attaches its carrier: {error:#}"
            );
            assert!(is_retryable(&error), "{cap}: {error:#}");
            assert!(!is_provider_throttled(&error), "{cap}: {error:#}");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "{cap}: no retries in the test"
            );
        }
    }

    /// The publisher reads the responder through the same classifier, but only
    /// a client-cap size refusal is terminal; a node-cap refusal is retryable.
    #[tokio::test]
    async fn a_node_cap_refusal_on_the_publisher_read_is_retryable() {
        let server = ServerBuilder::default()
            .max_response_body_size(15 * 1024 * 1024)
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("midnight_contractState", |_, _, _| {
                "ab".repeat(8 * 1024 * 1024)
            })
            .expect("register state method");
        let _handle = server.start(module);

        let rpc = connect_http(&http_config(address)).expect("build transport");
        let err = publisher_contract_state(&rpc, &test_address(), &test_at_hash())
            .await
            .expect_err("the server refuses the response");
        assert!(
            !is_oversized_contract_state(&err),
            "a node-cap refusal must not carry the oversized marker: {err:#}"
        );
    }

    #[tokio::test]
    async fn publisher_startup_is_bounded_if_the_endpoint_dies_during_initialization() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bootstrap endpoint");
        let address = listener.local_addr().expect("bootstrap endpoint address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener
                .accept()
                .await
                .expect("accept publisher connection");
            std::future::pending::<()>().await;
        });
        let mut config = crate::config::MidnightConfig {
            node_url: format!("http://{address}").parse().unwrap(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            responder_address: MidnightAddress::from_bytes([0xcd; 32]),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.rpc.connect_timeout = Duration::from_millis(75);
        config.rpc.request_timeout = Duration::from_secs(5);

        let result = tokio::time::timeout(
            Duration::from_millis(750),
            MidnightPublisherRpc::connect(&config),
        )
        .await;
        server.abort();

        let error = match result.expect("publisher startup outlived its connection budget") {
            Ok(_) => panic!("publisher initialized after its endpoint vanished"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("midnight"),
            "startup error has no RPC context: {error:#}"
        );
    }

    /// Block `0x0b` is the best block and the first under spec 2, so its parent
    /// `0x0a` still runs spec 1 and `0x0c`'s parent is `0x0b`. Each runtime's
    /// metadata must be read at a block of that runtime, once.
    #[tokio::test]
    async fn the_publisher_reads_each_runtime_at_a_block_of_that_runtime() {
        let raw_metadata = include_bytes!("../../fixtures/fallible-block-432-metadata.scale");
        let opaque = format!("0x{}", hex::encode(raw_metadata.to_vec().encode()));
        let metadata_reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let config = http_config(server.local_addr().unwrap());
        let transport = connect_http(&config).unwrap();
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getBlockHash", |params, _, _| {
                let asked = params.parse::<Vec<Option<u64>>>().unwrap_or_default();
                assert!(asked.iter().all(Option::is_none), "{asked:?}");
                hash_of_byte(0x0b)
            })
            .unwrap();
        module
            .register_method("chain_getHeader", |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                let parent = match hash.as_str() {
                    hash if hash == hash_of_byte(0x0b) => hash_of_byte(0x0a),
                    hash if hash == hash_of_byte(0x0c) => hash_of_byte(0x0b),
                    other => panic!("no header for {other}"),
                };
                json!({
                    "parentHash": parent,
                    "number": "0x2a",
                    "stateRoot": hash_of_byte(0x66),
                    "extrinsicsRoot": hash_of_byte(0x77),
                    "digest": { "logs": [] }
                })
            })
            .unwrap();
        module
            .register_method("state_getRuntimeVersion", |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                let spec = if hash == hash_of_byte(0x0a) { 1 } else { 2 };
                json!({
                    "specName": "midnight",
                    "implName": "midnight",
                    "authoringVersion": 1,
                    "specVersion": spec,
                    "implVersion": 0,
                    "apis": [],
                    "transactionVersion": spec,
                    "stateVersion": 1
                })
            })
            .unwrap();
        let reads = metadata_reads.clone();
        module
            .register_method("state_call", move |params, _, _| {
                let (method, _data, at) = params.parse::<(String, String, String)>().unwrap();
                match method.as_str() {
                    "Metadata_metadata_at_version" => "0x00".to_string(),
                    "Metadata_metadata" => {
                        reads.lock().unwrap().push(at);
                        opaque.clone()
                    }
                    other => panic!("unexpected runtime call {other}"),
                }
            })
            .unwrap();
        let _handle = server.start(module);
        let rpc = MidnightPublisherRpc::with_transport(transport);

        let submit = rpc.client_at(None).await.unwrap();
        assert_eq!(submit.runtime_version().spec_version, 2);
        let upgrade_block = rpc.client_for_block(H256([0x0b; 32])).await.unwrap();
        assert_eq!(upgrade_block.runtime_version().spec_version, 1);
        let after = rpc.client_for_block(H256([0x0c; 32])).await.unwrap();
        assert_eq!(after.runtime_version().spec_version, 2);
        assert_eq!(after.runtime_version().transaction_version, 2);

        assert_eq!(
            *metadata_reads.lock().unwrap(),
            [hash_of_byte(0x0b), hash_of_byte(0x0a)],
            "each runtime's metadata is read once, at a block running it"
        );
    }

    /// Serves the captured block 432 as `0x43`, whose parent `0x42` runs the
    /// captured runtime, with `events` as its `System::Events` and
    /// `Timestamp::Now` at `millis`. The log names each node read, in order.
    async fn captured_landing_node(
        events: Vec<u8>,
        millis: Option<u64>,
    ) -> (
        MidnightPublisherRpc,
        jsonrpsee::server::ServerHandle,
        Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let raw_metadata = include_bytes!("../../fixtures/fallible-block-432-metadata.scale");
        let metadata = subxt::Metadata::decode_all(&mut &raw_metadata[..]).unwrap();
        let opaque = format!("0x{}", hex::encode(raw_metadata.to_vec().encode()));
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let transport = connect_http(&http_config(server.local_addr().unwrap())).unwrap();
        let keys = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )
        .unwrap();
        let storage_key = |pallet: &str, entry: &str| {
            let key = keys
                .storage()
                .address_bytes(&subxt::dynamic::storage(
                    pallet,
                    entry,
                    Vec::<subxt::dynamic::Value>::new(),
                ))
                .unwrap();
            format!("0x{}", hex::encode(key))
        };
        let events_key = storage_key("System", "Events");
        let now_key = storage_key("Timestamp", "Now");
        let mut module = RpcModule::new(());
        let logged = log.clone();
        module
            .register_method("chain_getHeader", move |params, _, _| {
                logged.lock().unwrap().push("chain_getHeader");
                let [hash] = params.parse::<[String; 1]>().unwrap();
                assert_eq!(hash, hash_of_byte(0x43));
                json!({
                    "parentHash": hash_of_byte(0x42),
                    "number": "0x1b0",
                    "stateRoot": hash_of_byte(0x44),
                    "extrinsicsRoot": hash_of_byte(0x45),
                    "digest": { "logs": [] }
                })
            })
            .unwrap();
        let logged = log.clone();
        module
            .register_method("state_getRuntimeVersion", move |params, _, _| {
                logged.lock().unwrap().push("state_getRuntimeVersion");
                let [hash] = params.parse::<[String; 1]>().unwrap();
                assert_eq!(
                    hash,
                    hash_of_byte(0x42),
                    "block 0x43 ran its parent's runtime"
                );
                json!({
                    "specName": "midnight",
                    "implName": "midnight",
                    "authoringVersion": 1,
                    "specVersion": 1,
                    "implVersion": 0,
                    "apis": [],
                    "transactionVersion": 1,
                    "stateVersion": 1
                })
            })
            .unwrap();
        module
            .register_method("state_call", move |params, _, _| {
                let (method, _data, _at) = params.parse::<(String, String, String)>().unwrap();
                match method.as_str() {
                    "Metadata_metadata_at_version" => "0x00".to_string(),
                    "Metadata_metadata" => opaque.clone(),
                    other => panic!("unexpected runtime call {other}"),
                }
            })
            .unwrap();
        let logged = log.clone();
        module
            .register_method("state_getStorage", move |params, _, _| {
                let (key, at) = params.parse::<(String, String)>().unwrap();
                assert_eq!(at, hash_of_byte(0x43));
                if key == events_key {
                    logged.lock().unwrap().push("System::Events");
                    json!(format!("0x{}", hex::encode(&events)))
                } else if key == now_key {
                    logged.lock().unwrap().push("Timestamp::Now");
                    match millis {
                        Some(millis) => json!(format!("0x{}", hex::encode(millis.encode()))),
                        None => serde_json::Value::Null,
                    }
                } else {
                    panic!("unexpected storage key {key}")
                }
            })
            .unwrap();
        let handle = server.start(module);
        let rpc = MidnightPublisherRpc::with_transport(transport);
        (rpc, handle, log)
    }

    #[tokio::test]
    async fn a_missing_block_time_names_the_block_hash_in_full() {
        let block = BlockHash::from_0x_hex(&hash_of_byte(0x43)).unwrap();
        let (rpc, _handle, _log) = captured_landing_node(Vec::new(), None).await;
        let err = rpc
            .block_time(&block)
            .await
            .expect_err("a node with no Timestamp::Now has no block time");
        let rendered = format!("{err:#}");
        assert!(rendered.contains(&hash_of_byte(0x43)), "{rendered}");
        assert!(!rendered.contains('\u{2026}'), "{rendered}");
    }

    #[tokio::test]
    async fn the_publisher_reads_a_landing_and_the_block_time_from_a_captured_block() {
        let applied = LedgerTxHash::from_bytes(crate::test_utils::hex_32(
            "ba41ac43f2cfa97e32357877b85210a7f2105f4930b60515e19aa9ec00bb0f5d",
        ));
        let mut other = *applied.as_bytes();
        other[0] ^= 1;
        let other = LedgerTxHash::from_bytes(other);
        let block = BlockHash::from_0x_hex(&hash_of_byte(0x43)).unwrap();

        let (rpc, _handle, _log) = captured_landing_node(
            include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec(),
            Some(1_761_400_000_999),
        )
        .await;
        assert_eq!(
            rpc.landing(&block, applied).await.unwrap(),
            Some(Landing::Applied)
        );
        assert_eq!(rpc.landing(&block, other).await.unwrap(), None);
        assert_eq!(
            rpc.block_time(&block).await.unwrap(),
            midnight_base_crypto::time::Timestamp::from_secs(1_761_400_000),
            "Timestamp::Now is milliseconds"
        );

        let mut partial = captured_applied_status_record();
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        let (rpc, _handle, _log) =
            captured_landing_node(encode_status_records(&[partial]), Some(0)).await;
        assert_eq!(
            rpc.landing(&block, applied).await.unwrap(),
            Some(Landing::PartialSuccess)
        );
        assert_eq!(
            rpc.landing(&block, other).await.unwrap(),
            None,
            "another transaction's partial success is not this one landing"
        );
    }

    /// A landing scan reads a block's number, events and time, and the fee reads the
    /// head's time too: the header, the runtime that executed the block and its time
    /// are each read once.
    #[tokio::test]
    async fn the_publisher_reads_a_block_header_and_runtime_once() {
        let applied = LedgerTxHash::from_bytes(crate::test_utils::hex_32(
            "ba41ac43f2cfa97e32357877b85210a7f2105f4930b60515e19aa9ec00bb0f5d",
        ));
        let block = BlockHash::from_0x_hex(&hash_of_byte(0x43)).unwrap();
        let (rpc, _handle, log) = captured_landing_node(
            include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec(),
            Some(1_761_400_000_999),
        )
        .await;

        assert_eq!(rpc.block_number(&block).await.unwrap(), 0x1b0);
        assert_eq!(
            rpc.landing(&block, applied).await.unwrap(),
            Some(Landing::Applied)
        );
        assert_eq!(
            rpc.block_time(&block).await.unwrap(),
            midnight_base_crypto::time::Timestamp::from_secs(1_761_400_000)
        );
        assert_eq!(rpc.block_number(&block).await.unwrap(), 0x1b0);
        // The fee's head read and the landing scan's TTL check of the same block.
        assert_eq!(
            rpc.block_time(&block).await.unwrap(),
            midnight_base_crypto::time::Timestamp::from_secs(1_761_400_000)
        );

        assert_eq!(
            *log.lock().unwrap(),
            [
                "chain_getHeader",
                "state_getRuntimeVersion",
                "System::Events",
                "Timestamp::Now"
            ]
        );
    }

    /// A publisher node whose `chain_getHeader` answers any hash `[b; 32]` as block `b`,
    /// with the hashes it was asked for.
    async fn numbered_header_node() -> (
        MidnightPublisherRpc,
        jsonrpsee::server::ServerHandle,
        Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let transport = connect_http(&http_config(server.local_addr().unwrap())).unwrap();
        let reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut module = RpcModule::new(());
        let logged = reads.clone();
        module
            .register_method("chain_getHeader", move |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                logged.lock().unwrap().push(hash.clone());
                let byte = u8::from_str_radix(&hash[2..4], 16).unwrap();
                json!({
                    "parentHash": hash_of_byte(byte.wrapping_sub(1)),
                    "number": format!("0x{byte:x}"),
                    "stateRoot": hash_of_byte(0x44),
                    "extrinsicsRoot": hash_of_byte(0x45),
                    "digest": { "logs": [] }
                })
            })
            .unwrap();
        let handle = server.start(module);
        let rpc = MidnightPublisherRpc::with_transport(transport);
        (rpc, handle, reads)
    }

    /// The publisher answers each block from its own header and keeps the last 16: the
    /// 17th evicts the oldest, which is then read again.
    #[tokio::test]
    async fn the_publisher_keeps_the_last_sixteen_headers() {
        let (rpc, _handle, reads) = numbered_header_node().await;
        for byte in 1u8..=17 {
            assert_eq!(
                rpc.block_number(&BlockHash::from_0x_hex(&hash_of_byte(byte)).unwrap())
                    .await
                    .unwrap(),
                u64::from(byte)
            );
        }
        assert_eq!(reads.lock().unwrap().len(), 17);
        rpc.block_number(&BlockHash::from_0x_hex(&hash_of_byte(2)).unwrap())
            .await
            .unwrap();
        assert_eq!(reads.lock().unwrap().len(), 17, "block 2 is still kept");
        rpc.block_number(&BlockHash::from_0x_hex(&hash_of_byte(1)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            reads.lock().unwrap().last(),
            Some(&hash_of_byte(1)),
            "block 1 was evicted"
        );
        assert_eq!(reads.lock().unwrap().len(), 18);
    }
}
