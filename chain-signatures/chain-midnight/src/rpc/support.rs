//! Test harness shared by the rpc submodules: HTTP stub servers, canned node
//! errors, fixture codecs, and the addresses every fixture mints.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use jsonrpsee::core::client::Error as JsonrpseeClientError;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use subxt::SubstrateConfig;
use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClient, RpcClientT};
use subxt::ext::codec::{DecodeAll as _, Encode as _};
use subxt::ext::scale_decode::DecodeAsType;
use subxt::ext::subxt_rpcs::{Error as RawRpcError, UserError};
use subxt::utils::H256;

use crate::rpc::reader::BlockRef;
use crate::rpc::statics::TxApplied;
use crate::types::{BlockHash, MidnightAddress};

/// The `Timestamp::set` moment the synthetic test body carries, unix ms.
pub const FIXTURE_BLOCK_TIME_MS: u64 = 1_700_000_000_000;

/// The timestamp extrinsic the synthetic test body carries.
pub enum FixtureTimestamp {
    Set,
    /// Trailing garbage inside the call payload: framing valid, decode not.
    Corrupted,
    Absent,
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub struct CaptureCallDetails {
    pub tx_hash: [u8; 32],
    pub contract_address: Vec<u8>,
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub struct CaptureContractCall(pub CaptureCallDetails);

impl subxt::events::StaticEvent for CaptureContractCall {
    const PALLET: &'static str = "Midnight";
    const EVENT: &'static str = "ContractCall";
}

pub fn captured_status_events(
    bytes: Vec<u8>,
    extrinsic: u32,
) -> subxt::blocks::ExtrinsicEvents<SubstrateConfig> {
    let metadata = subxt::Metadata::decode_all(
        &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
    )
    .expect("captured node metadata");
    subxt::blocks::ExtrinsicEvents::new(
        H256::zero(),
        extrinsic,
        subxt::events::Events::decode_from(bytes, metadata),
    )
}

pub fn encode_status_records(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = subxt::ext::codec::Compact(records.len() as u32).encode();
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}
pub fn http_config(address: SocketAddr) -> crate::config::MidnightConfig {
    crate::config::MidnightConfig {
        node_url: format!("http://{address}").parse().unwrap(),
        central_address: MidnightAddress::from_bytes([0xab; 32]),
        responder_address: MidnightAddress::from_bytes([0xcd; 32]),
        publisher: Default::default(),
        rpc: Default::default(),
        indexer: Default::default(),
    }
}

pub async fn http_status_server(
    status: u16,
    reason: &'static str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw HTTP status server");
    let address = listener.local_addr().expect("raw HTTP server address");
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept HTTP request");
            let mut request_start = [0; 1];
            stream
                .read_exact(&mut request_start)
                .await
                .expect("read HTTP request");
            server_calls.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write HTTP status response");
        }
    });
    (address, calls, server)
}
pub fn hash_of_byte(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}
#[derive(Clone, Copy)]
pub enum Canned {
    User(i32, &'static str),
    UserWithData(i32, &'static str, &'static str),
    ClientErr,
    ClientTooLarge,
}

impl Canned {
    fn into_error(self) -> RawRpcError {
        match self {
            Self::User(code, message) => RawRpcError::User(UserError {
                code,
                message: message.to_string(),
                data: None,
            }),
            Self::UserWithData(code, message, data) => RawRpcError::User(UserError {
                code,
                message: message.to_string(),
                data: Some(
                    RawValue::from_string(data.to_string())
                        .expect("canned user-error data is JSON"),
                ),
            }),
            Self::ClientErr => RawRpcError::Client(Box::new(JsonrpseeClientError::Transport(
                "connection reset by peer".into(),
            ))),
            Self::ClientTooLarge => RawRpcError::Client(Box::new(JsonrpseeClientError::Transport(
                Box::new(jsonrpsee::http_client::transport::Error::Http(
                    jsonrpsee::core::http_helpers::HttpError::TooLarge,
                )),
            ))),
        }
    }
}

pub const ADDRESS: &str = "abababababababababababababababababababababababababababababababab";
pub const AT_HASH: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";

pub fn test_address() -> MidnightAddress {
    MidnightAddress::from_hex(ADDRESS).expect("test address is 64 hex chars")
}

pub fn test_at_hash() -> BlockHash {
    BlockHash::from_0x_hex(AT_HASH).expect("test at-hash is 0x-prefixed 32-byte hex")
}
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A budget of `max_times` retries with near-zero delays, so tests pin attempt
/// counts without waiting out production backoff.
pub fn attempts(max_times: usize) -> RetryConfig {
    RetryConfig {
        min_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
        max_times,
        jitter: false,
    }
}

#[derive(Clone)]
pub struct StubRpc {
    reply: Canned,
    calls: Arc<AtomicUsize>,
}

impl RpcClientT for StubRpc {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        _params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        assert_eq!(method, "midnight_contractState");
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self.reply;
        Box::pin(async move { Err(reply.into_error()) })
    }

    fn subscribe_raw<'a>(
        &'a self,
        _sub: &'a str,
        _params: Option<Box<RawValue>>,
        _unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async { panic!("these tests never subscribe") })
    }
}

pub fn stub_rpc(reply: Canned) -> (RpcClient, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let node = StubRpc {
        reply,
        calls: calls.clone(),
    };
    (RpcClient::new(node), calls)
}
pub fn addr(byte: u8) -> MidnightAddress {
    MidnightAddress::from_bytes([byte; 32])
}

pub fn numbered_block_ref(byte: u8) -> BlockRef {
    BlockRef {
        number: 0x1b0 + u64::from(byte) - 0x43,
        hash: BlockHash::from_bytes([byte; 32]),
        parent_hash: BlockHash::from_bytes([byte - 1; 32]),
    }
}

pub fn captured_applied_status_record() -> Vec<u8> {
    captured_status_events(
        include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec(),
        4,
    )
    .iter()
    .map(Result::unwrap)
    .find(|event| event.as_event::<TxApplied>().unwrap().is_some())
    .expect("captured applied status")
    .bytes()
    .to_vec()
}

/// Counts requests through a real transport, for attempt assertions.
#[derive(Clone)]
pub struct CountingRpc {
    pub(super) inner: RpcClient,
    pub(super) calls: Arc<AtomicUsize>,
}

impl RpcClientT for CountingRpc {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { self.inner.request_raw(method, params).await })
    }

    fn subscribe_raw<'a>(
        &'a self,
        _sub: &'a str,
        _params: Option<Box<RawValue>>,
        _unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async { panic!("these tests never subscribe") })
    }
}
