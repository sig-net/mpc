use std::collections::HashSet;
use std::fmt;
use std::future::IntoFuture;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anchor_client::anchor_lang::{AnchorDeserialize, Discriminator};
use anchor_client::{Client, Cluster as AnchorCluster};
use anyhow::Context as _;
use cait_sith::FullSignature;
use elliptic_curve::sec1::FromEncodedPoint;
use futures::StreamExt;
use generic_array::GenericArray;
use k256::Secp256k1;
use mpc_contract::primitives::SignRequest;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::Account;
use rand::Rng;
use solana_client::nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient};
use solana_client::rpc_config::{
    RpcTransactionConfig, RpcTransactionLogsConfig, RpcTransactionLogsFilter,
};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature as SolSignature;
use solana_sdk::signer::Signer as _;
use tokio::sync::oneshot;
use tokio::time::sleep;

use crate::actions::{self, wait_for};
use crate::cluster::Cluster;
use crate::containers;

use signet_program::{RespondBidirectionalEvent, SignatureRespondedEvent};

// ChainSignatures contract ABI
alloy::sol! {
    #[sol(rpc)]
    interface ChainSignatures {
        struct SignRequest {
            bytes32 payload;
            string path;
            uint32 keyVersion;
            string algo;
            string dest;
            string params;
        }

        struct AffinePoint {
            uint256 x;
            uint256 y;
        }

        struct Signature {
            AffinePoint bigR;
            uint256 s;
            uint8 recoveryId;
        }

        function sign(SignRequest memory _request) external payable;
        function getSignatureDeposit() external view returns (uint256);

        event SignatureRequested(
            address indexed sender,
            bytes32 payload,
            uint32 keyVersion,
            uint256 deposit,
            uint256 chainId,
            string path,
            string algo,
            string dest,
            string params
        );

        event SignatureResponded(
            bytes32 indexed requestId,
            address indexed responder,
            Signature signature
        );
    }

    // Event encoding for request_id calculation
    event SignatureRequestedEncoding(
        address sender,
        bytes payload,
        string path,
        uint32 keyVersion,
        uint256 chainId,
        string algo,
        string dest,
        string params
    );
}

pub const SIGN_GAS: Gas = Gas::from_tgas(50);
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

pub struct SignOutcome {
    /// The account that signed the payload.
    pub account: Account,

    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub signature: FullSignature<Secp256k1>,
}

impl fmt::Debug for SignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignOutcome")
            .field("account", &self.account)
            .field("payload", &self.payload)
            .field("payload_hash", &self.payload_hash)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .finish()
    }
}

#[derive(Clone, Default)]
struct SolanaSignArgs {
    transaction_data: Option<Vec<u8>>,
    caip2_id: String,
    program_id: Option<solana_sdk::pubkey::Pubkey>,
    output_deserialization_schema: Vec<u8>,
    respond_serialization_schema: Vec<u8>,
}

pub struct SignAction<'a> {
    nodes: &'a Cluster,
    count: usize,
    account: Option<Account>,
    payload: Option<[u8; 32]>,
    payload_hash_override: Option<[u8; 32]>,
    path: String,
    key_version: u32,
    gas: Gas,
    deposit: NearToken,
    algo: String,
    dest: String,
    params: String,
}

impl<'a> SignAction<'a> {
    pub fn new(nodes: &'a Cluster) -> Self {
        Self {
            nodes,
            count: 1,
            account: None,
            payload: None,
            payload_hash_override: None,
            path: "test".into(),
            key_version: LATEST_MPC_KEY_VERSION,
            gas: SIGN_GAS,
            deposit: SIGN_DEPOSIT,
            algo: "secp256k1".into(),
            dest: "integration_test".into(),
            params: "{}".into(),
        }
    }
}

impl<'a> SignAction<'a> {
    /// Specify how many sign calls to be performed sequentially. If not specified, only
    /// one sign call will be performed.
    pub fn many(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    /// Set the account to sign with. If not set, a new account will be created.
    pub fn account(mut self, account: Account) -> Self {
        self.account = Some(account);
        self
    }

    /// Set the payload of this sign call. The keccak hash of this payload will be signed.
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the derivation path of this sign call.
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.into();
        self
    }

    /// Set the key version of this sign call. If not set, the default key version will be used.
    pub fn key_version(mut self, key_version: u32) -> Self {
        self.key_version = key_version;
        self
    }

    /// Set the gas for this sign call. If not set, the default gas will be used.
    pub fn gas(mut self, gas: Gas) -> Self {
        self.gas = gas;
        self
    }

    /// Set the deposit for this sign call. If not set, the default deposit will be used.
    pub fn deposit(mut self, deposit: NearToken) -> Self {
        self.deposit = deposit;
        self
    }

    /// Override the payload hash that will be signed. When set, the supplied value will be used
    /// directly instead of hashing the payload bytes again.
    pub fn payload_hash(mut self, payload_hash: [u8; 32]) -> Self {
        self.payload_hash_override = Some(payload_hash);
        self
    }

    /// Set the signing algorithm metadata used by downstream chains.
    pub fn algorithm(mut self, algo: &str) -> Self {
        self.algo = algo.into();
        self
    }

    /// Set the destination metadata used by downstream chains.
    pub fn destination(mut self, dest: &str) -> Self {
        self.dest = dest.into();
        self
    }

    /// Set the additional parameter metadata used by downstream chains.
    pub fn parameters(mut self, params: &str) -> Self {
        self.params = params.into();
        self
    }

    /// Create an ETH contract sign request builder
    pub fn eth(self) -> EthSignAction<'a> {
        EthSignAction::new(self)
    }

    /// Create a Solana-specific sign action that calls the Solana contract's sign function
    pub fn solana(self) -> SolSignAction<'a> {
        SolSignAction::new(self)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SignCall {
    #[default]
    Sign,
    Bidirectional,
}

/// Solana-specific sign action that calls the Solana contract's respond function
pub struct SolSignAction<'a> {
    inner: SignAction<'a>,
    call: SignCall,
    args: SolanaSignArgs,
}

impl<'a> SolSignAction<'a> {
    fn new(inner: SignAction<'a>) -> Self {
        Self {
            inner,
            call: SignCall::default(),
            args: SolanaSignArgs::default(),
        }
    }

    /// Execute the Solana sign + respond flow explicitly.
    pub fn bidirectional(mut self) -> Self {
        self.call = SignCall::Bidirectional;
        self
    }

    /// Set the payload of this sign call.
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.inner = self.inner.payload(payload);
        self
    }

    /// Override the payload hash for this sign call.
    pub fn payload_hash(mut self, payload_hash: [u8; 32]) -> Self {
        self.inner = self.inner.payload_hash(payload_hash);
        self
    }

    /// Set the derivation path of this sign call.
    pub fn path(mut self, path: &str) -> Self {
        self.inner = self.inner.path(path);
        self
    }

    /// Set the key version of this sign call.
    pub fn key_version(mut self, key_version: u32) -> Self {
        self.inner = self.inner.key_version(key_version);
        self
    }

    /// Set the algorithm metadata for the sign request.
    pub fn algorithm(mut self, algo: &str) -> Self {
        self.inner = self.inner.algorithm(algo);
        self
    }

    /// Set the destination metadata for the sign request.
    pub fn destination(mut self, dest: &str) -> Self {
        self.inner = self.inner.destination(dest);
        self
    }

    /// Set the additional parameters metadata for the sign request.
    pub fn parameters(mut self, params: &str) -> Self {
        self.inner = self.inner.parameters(params);
        self
    }

    /// Attach raw transaction data to be used with bidirectional flows.
    pub fn transaction_data(mut self, data: Vec<u8>) -> Self {
        self.args.transaction_data = Some(data);
        self
    }

    /// Set the CAIP-2 chain identifier for bidirectional flows.
    pub fn caip2_id(mut self, caip2_id: &str) -> Self {
        self.args.caip2_id = caip2_id.to_string();
        self
    }

    /// Override the optional callback program identifier for bidirectional flows.
    pub fn program_id(mut self, program_id: Pubkey) -> Self {
        self.args.program_id = Some(program_id);
        self
    }

    /// Configure output deserialization schema metadata for bidirectional flows.
    pub fn output_deserialization_schema(mut self, schema: Vec<u8>) -> Self {
        self.args.output_deserialization_schema = schema;
        self
    }

    /// Configure respond serialization schema metadata for bidirectional flows.
    pub fn respond_serialization_schema(mut self, schema: Vec<u8>) -> Self {
        self.args.respond_serialization_schema = schema;
        self
    }
}

impl<'a> IntoFuture for SolSignAction<'a> {
    type Output = anyhow::Result<SolSignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

pub struct SolSignOutcome {
    pub tx_signature: SolSignature,
    pub signature: FullSignature<Secp256k1>,
    pub recovery_id: u8,
    pub signer_account: String,
    pub request_id: [u8; 32],
    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub algo: String,
    pub dest: String,
    pub params: String,
}

impl fmt::Debug for SolSignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolSignOutcome")
            .field("tx_signature", &self.tx_signature)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .field("recovery_id", &self.recovery_id)
            .field("signer_account", &self.signer_account)
            .field("request_id", &hex::encode(self.request_id))
            .field("payload", &hex::encode(self.payload))
            .field("payload_hash", &hex::encode(self.payload_hash))
            .field("path", &self.path)
            .field("key_version", &self.key_version)
            .field("algo", &self.algo)
            .field("dest", &self.dest)
            .field("params", &self.params)
            .finish()
    }
}

struct SolSignatureResponse {
    request_id: [u8; 32],
    signature: FullSignature<Secp256k1>,
    recovery_id: u8,
}

pub struct SolRespondBidirectionalOutcome {
    pub request_id: [u8; 32],
    pub responder: String,
    pub serialized_output: Vec<u8>,
    pub signature: FullSignature<Secp256k1>,
    pub recovery_id: u8,
}

impl<'a> SolSignAction<'a> {
    async fn execute(mut self) -> anyhow::Result<SolSignOutcome> {
        let payload = self.inner.payload_or_random();
        let payload_hash = self.inner.compute_payload_hash();
        let path = self.inner.path.clone();
        let key_version = self.inner.key_version;
        let algo = self.inner.algo.clone();
        let dest = self.inner.dest.clone();
        let params = self.inner.params.clone();
        let operation = self.call.as_str();

        let solana = self
            .inner
            .nodes
            .solana
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("solana instance not available in cluster"))?;

        tracing::info!(
            payload = %hex::encode(payload_hash),
            path,
            key_version,
            algo,
            dest,
            params,
            operation,
            "calling solana {operation} request",
        );

        let (tx_signature, response) = self
            .submit_contract_call(payload_hash, &path, key_version, &algo, &dest, &params)
            .await?;

        let signer_account = solana.payer_keypair.pubkey().to_string();

        Ok(SolSignOutcome {
            tx_signature,
            signature: response.signature,
            recovery_id: response.recovery_id,
            signer_account,
            request_id: response.request_id,
            payload,
            payload_hash,
            path,
            key_version,
            algo,
            dest,
            params,
        })
    }

    async fn submit_contract_call(
        &self,
        payload_hash: [u8; 32],
        path: &str,
        key_version: u32,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> anyhow::Result<(SolSignature, SolSignatureResponse)> {
        let solana = self
            .inner
            .nodes
            .solana
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("solana instance not available in cluster"))?;
        let operation = self.call.as_str();

        tracing::info!(
            payload = %hex::encode(payload_hash),
            path,
            key_version,
            algo,
            dest,
            params,
            operation,
            "initiating solana {operation} request",
        );

        let program_id = solana.program_keypair.pubkey();
        let response_listener = tokio::spawn(wait_for_signature_responded_event(
            solana.rpc_address.clone(),
            solana.ws_address.clone(),
            program_id,
            Duration::from_secs(90),
        ));

        let tx_signature = match self.call {
            SignCall::Sign => match solana
                .sign(payload_hash, path, key_version, algo, dest, params)
                .await
            {
                Ok(sig) => sig,
                Err(err) => {
                    response_listener.abort();
                    return Err(err);
                }
            },
            SignCall::Bidirectional => {
                let config = self.args.clone();
                let transaction_data = match config.transaction_data.clone() {
                    Some(data) => data,
                    None => {
                        response_listener.abort();
                        anyhow::bail!(
                            "transaction data must be provided for solana sign_bidirectional requests"
                        );
                    }
                };

                if config.caip2_id.is_empty() {
                    response_listener.abort();
                    anyhow::bail!(
                        "caip2_id must be provided for solana sign_bidirectional requests"
                    );
                }

                let default_program_id = solana.program_keypair.pubkey();
                let program_id = config.program_id.unwrap_or(default_program_id);

                match solana
                    .sign_bidirectional(
                        &transaction_data,
                        &config.caip2_id,
                        key_version,
                        path,
                        algo,
                        dest,
                        params,
                        program_id,
                        &config.output_deserialization_schema,
                        &config.respond_serialization_schema,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(err) => {
                        response_listener.abort();
                        return Err(err);
                    }
                }
            }
        };

        tracing::info!("waiting for MPC response event...");
        let response = match response_listener.await {
            Ok(result) => result?,
            Err(join_err) => {
                anyhow::bail!("signature response listener task failed: {join_err}")
            }
        };
        Ok((tx_signature, response))
    }
}

const RESPOND_EVENT_HINT: &str = "Program log: Instruction: Respond";

async fn wait_for_signature_responded_event(
    rpc_http_url: String,
    rpc_ws_url: String,
    program_id: Pubkey,
    timeout: Duration,
) -> anyhow::Result<SolSignatureResponse> {
    let rpc_client = RpcClient::new(rpc_http_url);
    let pubsub_client = PubsubClient::new(rpc_ws_url.as_str()).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };
    let (mut stream, _unsubscribe) = pubsub_client.logs_subscribe(filter, config).await?;

    let mut seen = HashSet::new();
    let program_invoke_prefix = format!("Program {} invoke [", program_id);

    let deadline = sleep(timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                anyhow::bail!("timeout waiting for respond on sol");
            }
            maybe = stream.next() => {
                let Some(response) = maybe else {
                    anyhow::bail!("sol signature respond log stream closed unexpectedly");
                };

                if response.value.err.is_some() {
                    continue;
                }

                let logs = &response.value.logs;
                if !logs.iter().any(|log| log.contains(RESPOND_EVENT_HINT)) {
                    continue;
                }
                if !logs.iter().any(|log| log.starts_with(&program_invoke_prefix)) {
                    continue;
                }

                let sig_text = &response.value.signature;
                let Ok(tx_signature) = solana_sdk::signature::Signature::from_str(sig_text) else {
                    tracing::warn!(tx_signature = sig_text, "invalid solana signature string in respond logs");
                    continue;
                };

                if !seen.insert(tx_signature) {
                    continue;
                }

                match parse_signature_responded_events(&rpc_client, &tx_signature, &program_id).await {
                    Ok(events) => {
                        for event in events {
                            tracing::info!(
                                request_id = %hex::encode(event.request_id),
                                tx_signature = %tx_signature,
                                "received SignatureRespondedEvent via CPI logs",
                            );

                            match parse_sol_signature(&event.signature) {
                                Ok((signature, recovery_id)) => {
                                    return Ok(SolSignatureResponse {
                                        request_id: event.request_id,
                                        signature,
                                        recovery_id,
                                    });
                                }
                                Err(err) => {
                                    tracing::warn!(?err, "failed to parse sol signature from SignatureRespondedEvent");
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            tx_signature = %tx_signature,
                            "failed to parse SignatureRespondedEvent from respond transaction",
                        );
                    }
                }
            }
        }
    }
}

async fn parse_signature_responded_events(
    rpc_client: &RpcClient,
    signature: &solana_sdk::signature::Signature,
    program_id: &Pubkey,
) -> anyhow::Result<Vec<SignatureRespondedEvent>> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let tx = rpc_client
        .get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(solana_transaction_status::UiTransactionEncoding::JsonParsed),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await?;

    let Some(meta) = tx.transaction.meta else {
        return Ok(Vec::new());
    };

    let inner_sets = match meta.inner_instructions {
        solana_transaction_status::option_serializer::OptionSerializer::Some(inner) => inner,
        _ => return Ok(Vec::new()),
    };

    let target_program = program_id.to_string();
    let mut events = Vec::new();

    for (set_idx, inner_set) in inner_sets.iter().enumerate() {
        for (ix_idx, instruction) in inner_set.instructions.iter().enumerate() {
            let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(parsed)) = instruction
            else {
                continue;
            };

            if parsed.program_id != target_program {
                continue;
            }

            let Ok(ix_data) = solana_sdk::bs58::decode(&parsed.data).into_vec() else {
                tracing::warn!(
                    "failed to decode inner instruction data for SignatureRespondedEvent"
                );
                continue;
            };

            if ix_data.len() < anchor_client::anchor_lang::event::EVENT_IX_TAG_LE.len() + 8
                || !ix_data.starts_with(anchor_client::anchor_lang::event::EVENT_IX_TAG_LE)
            {
                continue;
            }

            let discriminator = &ix_data[8..16];
            if discriminator != SignatureRespondedEvent::DISCRIMINATOR {
                continue;
            }

            let event_data = &ix_data[16..];
            match SignatureRespondedEvent::deserialize(&mut &event_data[..]) {
                Ok(event) => {
                    tracing::info!(
                        request_id = %hex::encode(event.request_id),
                        inner_index = %format!("{}.{}", set_idx, ix_idx),
                        "parsed SignatureRespondedEvent from respond transaction",
                    );
                    events.push(event);
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "failed to deserialize SignatureRespondedEvent from respond transaction"
                    );
                }
            }
        }
    }

    Ok(events)
}

impl SignCall {
    const fn as_str(self) -> &'static str {
        match self {
            SignCall::Bidirectional => "sign_bidirectional",
            SignCall::Sign => "sign",
        }
    }
}

pub async fn wait_for_respond_bidirectional(
    solana: &containers::Solana,
    expected_request_id: [u8; 32],
    timeout: Duration,
) -> anyhow::Result<SolRespondBidirectionalOutcome> {
    let program_id = solana.program_keypair.pubkey();

    let cluster = AnchorCluster::Custom(solana.rpc_address.clone(), solana.ws_address.clone());
    let client = Client::new_with_options(
        cluster,
        Arc::new(solana.payer_keypair.insecure_clone()),
        CommitmentConfig::confirmed(),
    );
    let program = client.program(program_id)?;
    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    let event_unsub = program
        .on(move |_ctx, event: RespondBidirectionalEvent| {
            tracing::info!(
                request_id = %hex::encode(event.request_id),
                responder = ?event.responder,
                serialized_output_len = event.serialized_output.len(),
                "received RespondBidirectionalEvent",
            );

            if event.request_id != expected_request_id {
                return;
            }

            let signature_result = parse_sol_signature(&event.signature);
            if let Ok(mut sender) = tx.lock() {
                if let Some(sender) = sender.take() {
                    let outcome = signature_result.map(|(signature, recovery_id)| {
                        SolRespondBidirectionalOutcome {
                            request_id: event.request_id,
                            responder: event.responder.to_string(),
                            serialized_output: event.serialized_output.clone(),
                            signature,
                            recovery_id,
                        }
                    });
                    if sender.send(outcome).is_err() {
                        tracing::error!("failed to send RespondBidirectionalEvent outcome");
                    }
                }
            }
        })
        .await?;

    tracing::info!(
        request_id = %hex::encode(expected_request_id),
        "subscribed to RespondBidirectionalEvent, waiting for MPC response...",
    );
    let result = tokio::time::timeout(timeout, rx).await;
    event_unsub.unsubscribe().await;

    match result {
        Ok(Ok(Ok(outcome))) => Ok(outcome),
        Ok(Ok(Err(e))) => anyhow::bail!("failed to parse sol respond bidirectional signature: {e}"),
        Ok(Err(_)) => anyhow::bail!("sol respond bidirectional event channel closed unexpectedly"),
        Err(_) => anyhow::bail!("timeout waiting for respond bidirectional on sol"),
    }
}

impl<'a> IntoFuture for SignAction<'a> {
    type Output = anyhow::Result<SignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

// Helper methods for the SignAction
impl SignAction<'_> {
    async fn execute(mut self) -> anyhow::Result<SignOutcome> {
        let state = self.nodes.expect_running().await?;
        let account = self.account_or_new().await;
        let payload = self.payload_or_random();
        let payload_hash = self.compute_payload_hash();
        let status = self.transact_sign(&account, payload_hash).await?;

        let signature = wait_for::signature_responded(status).await?;
        let mut mpc_pk_bytes = vec![0x04];
        mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);

        // Useful for populating the "signatures_havent_changed" test's hardcoded values
        // tracing::warn!(
        //     "ref_string: big_r={}, s={}, mpc_pk_bytes={}, payload_hash={}, account_id={}",
        //     hex::encode(signature.big_r.to_encoded_point(true).to_bytes()),
        //     hex::encode(signature.s.to_bytes()),
        //     hex::encode(&mpc_pk_bytes),
        //     hex::encode(payload_hash),
        //     account.id(),
        // );
        actions::validate_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await?;

        Ok(SignOutcome {
            account,
            signature,
            payload,
            payload_hash,
        })
    }

    pub async fn account_or_new(&self) -> Account {
        if let Some(account) = &self.account {
            account.clone()
        } else {
            self.nodes.worker().dev_create_account().await.unwrap()
        }
    }

    pub fn payload_or_random(&mut self) -> [u8; 32] {
        let payload = self.payload.unwrap_or_else(|| rand::thread_rng().gen());
        self.payload = Some(payload);
        payload
    }

    pub fn compute_payload_hash(&mut self) -> [u8; 32] {
        if let Some(override_hash) = self.payload_hash_override {
            // Ensure payload is initialised so callers can still inspect it.
            let _ = self.payload_or_random();
            override_hash
        } else {
            *alloy::primitives::keccak256(self.payload_or_random())
        }
    }

    pub async fn transact_sign(
        &self,
        account: &Account,
        payload_hashed: [u8; 32],
    ) -> anyhow::Result<AsyncTransactionStatus> {
        let signer = InMemorySigner {
            account_id: account.id().clone(),
            public_key: account.secret_key().public_key().to_string().parse()?,
            secret_key: account.secret_key().to_string().parse()?,
        };
        let request = SignRequest {
            payload: payload_hashed,
            path: self.path.clone(),
            key_version: self.key_version,
        };
        let status = self
            .nodes
            .rpc_client
            .call(&signer, self.nodes.contract().id(), "sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(self.gas)
            .deposit(self.deposit)
            .transact_async()
            .await?;
        Ok(status)
    }
}

/// Convert a Solana contract signature to FullSignature<Secp256k1>
fn parse_sol_signature(
    solana_sig: &signet_program::Signature,
) -> anyhow::Result<(FullSignature<Secp256k1>, u8)> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, Scalar};

    // Convert the AffinePoint from Solana contract format
    // Create a 65-byte uncompressed point (0x04 || x_bytes || y_bytes)
    let mut point_bytes = Vec::with_capacity(65);
    point_bytes.push(0x04); // Uncompressed point prefix
    point_bytes.extend_from_slice(&solana_sig.big_r.x);
    point_bytes.extend_from_slice(&solana_sig.big_r.y);

    // Parse the point from the encoded format
    let encoded_point = k256::EncodedPoint::from_bytes(&point_bytes)?;
    let big_r = AffinePoint::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Invalid point coordinates"))?;

    // Convert s from bytes to Scalar using the ScalarExt trait
    let s =
        Scalar::from_bytes(solana_sig.s).ok_or_else(|| anyhow::anyhow!("Invalid scalar bytes"))?;

    // Create the FullSignature (note: FullSignature doesn't store recovery_id)
    Ok((FullSignature { big_r, s }, solana_sig.recovery_id))
}

/// Ethereum contract signature request outcome
pub struct EthSignOutcome {
    pub signer_address: Address,
    pub contract_address: String,
    pub eth_tx_hash: Option<String>,
    pub deposit_amount: u64,
    pub signature: FullSignature<Secp256k1>,
    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub algo: String,
    pub dest: String,
    pub params: String,
}

impl fmt::Debug for EthSignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthSignOutcome")
            .field("contract_address", &self.contract_address)
            .field("eth_tx_hash", &self.eth_tx_hash)
            .field("deposit_amount", &self.deposit_amount)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .field("payload", &self.payload)
            .field("payload_hash", &self.payload_hash)
            .field("algo", &self.algo)
            .field("dest", &self.dest)
            .field("params", &self.params)
            .finish()
    }
}

/// ETH contract signature request builder
pub struct EthSignAction<'a> {
    sign_action: SignAction<'a>,
    contract_addr: String,
    signer: PrivateKeySigner,
    deposit_amount: U256,
    algo: String,
    dest: String,
    params: String,
}

impl<'a> EthSignAction<'a> {
    pub fn new(sign_action: SignAction<'a>) -> Self {
        let eth = sign_action.nodes.cfg.eth.as_ref().unwrap().clone();
        let signer = PrivateKeySigner::from_str(eth.account_sk.as_ref())
            .with_context(|| "invalid private key")
            .unwrap();
        Self {
            sign_action,
            contract_addr: eth.contract_address.clone(),
            signer,
            deposit_amount: U256::from(1), // 1 wei
            algo: "ECDSA".to_string(),
            dest: "ethereum".to_string(),
            params: "{}".to_string(),
        }
    }

    /// Set the ETH contract address to interact with
    pub fn contract_address(mut self, address: &str) -> Self {
        self.contract_addr = address.to_string();
        self
    }

    /// Set the ETH deposit amount in wei
    pub fn deposit(mut self, amount: u64) -> Self {
        self.deposit_amount = U256::from(amount);
        self
    }

    /// Set the signing algorithm
    pub fn algorithm(mut self, algo: &str) -> Self {
        self.algo = algo.to_string();
        self
    }

    /// Set the destination
    pub fn destination(mut self, dest: &str) -> Self {
        self.dest = dest.to_string();
        self
    }

    /// Set additional parameters
    pub fn parameters(mut self, params: &str) -> Self {
        self.params = params.to_string();
        self
    }

    /// Set the account to sign with (delegates to underlying SignAction)
    pub fn account(mut self, account: Account) -> Self {
        self.sign_action = self.sign_action.account(account);
        self
    }

    /// Set the payload to sign (delegates to underlying SignAction)
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.sign_action = self.sign_action.payload(payload);
        self
    }

    /// Set the derivation path (delegates to underlying SignAction)
    pub fn path(mut self, path: &str) -> Self {
        self.sign_action = self.sign_action.path(path);
        self
    }

    /// Set the key version (delegates to underlying SignAction)
    pub fn key_version(mut self, key_version: u32) -> Self {
        self.sign_action = self.sign_action.key_version(key_version);
        self
    }
}

impl<'a> IntoFuture for EthSignAction<'a> {
    type Output = anyhow::Result<EthSignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

impl EthSignAction<'_> {
    async fn execute(self) -> anyhow::Result<EthSignOutcome> {
        // Store values we need
        let path = self.sign_action.path.clone();
        let payload = self
            .sign_action
            .payload
            .unwrap_or_else(|| rand::thread_rng().gen());
        let payload_hash = *alloy::primitives::keccak256(payload);
        let rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";
        let contract_addr: Address = self
            .contract_addr
            .parse()
            .with_context(|| format!("invalid contract address {}", self.contract_addr))?;

        tracing::info!(
            "calling ETH ChainSignatures contract: contract=0x{}, payload={:?}, path={}, algo={}, dest={}, params={}, deposit={}",
            self.contract_addr,
            payload,
            path,
            self.algo,
            self.dest,
            self.params,
            self.deposit_amount
        );

        // Prepare the signer and contract for signing and listening for events.
        let signer_address = self.signer.address();
        let provider = ProviderBuilder::new()
            .wallet(self.signer)
            .connect_http(rpc_url.parse()?);
        let contract = ChainSignatures::new(contract_addr, provider.clone());

        // Prepare the sign request
        let sign_request = ChainSignatures::SignRequest {
            payload: FixedBytes::<32>::from_slice(&payload_hash),
            path: path.clone(),
            keyVersion: self.sign_action.key_version,
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };

        tracing::info!(
            contract = format!("0x{}", self.contract_addr),
            from = format!("0x{:x}", signer_address),
            payload = format!("0x{}", hex::encode(payload_hash)),
            path,
            key_version = self.sign_action.key_version,
            algorithm = self.algo,
            destination = self.dest,
            parameters = self.params,
            deposit = ?self.deposit_amount,
            rpc = rpc_url,
            "calling ChainSignatures.sign() on Sepolia network"
        );

        // Call the contract
        let pending_tx = match contract
            .sign(sign_request)
            .value(U256::from(self.deposit_amount))
            .send()
            .await
        {
            Ok(pending_tx) => pending_tx,
            Err(err) => {
                tracing::error!("failed to send transaction: {}", err);
                anyhow::bail!("Failed to send transaction: {}", err);
            }
        };
        tracing::info!("eth transaction sent successfully!");

        // Wait for transaction to be mined
        let tx_hash = *pending_tx.tx_hash();
        if let Err(err) = pending_tx.watch().await {
            anyhow::bail!("Transaction failed to mine: {err}");
        }

        // Calculate the request ID using the same ABI encoding as the indexer
        let signature_requested_encoding = SignatureRequestedEncoding {
            sender: signer_address,
            payload: payload_hash.into(),
            path: path.clone(),
            keyVersion: self.sign_action.key_version,
            chainId: U256::from(11155111u64), // Sepolia chain ID
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };
        let request_id = alloy::primitives::keccak256(signature_requested_encoding.encode_data());
        tracing::info!(
            request_id = hex::encode(request_id),
            "transaction mined: 0x{tx_hash:x}; waiting for SignatureResponded event..."
        );

        // Poll for events
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 60; // 1 minute max wait
        let mut interval = tokio::time::interval(Duration::from_millis(1000));

        // Now wait for the SignatureResponded event
        loop {
            interval.tick().await;
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                anyhow::bail!(
                    "timeout waiting for SignatureResponded after {MAX_ATTEMPTS} attempts"
                );
            }

            let current_block = match provider.get_block_number().await {
                Ok(block) => block,
                Err(e) => {
                    tracing::debug!("error getting block number (attempt {}): {}", attempts, e);
                    continue;
                }
            };

            // filter for SignatureResponded events
            let filter = alloy::rpc::types::Filter::new()
                .address(contract_addr)
                .from_block(current_block.saturating_sub(10)) // Look back 10 blocks
                .to_block(current_block)
                .event_signature(alloy::primitives::keccak256(
                    "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
                ));

            // Query for logs
            let logs = match provider.get_logs(&filter).await {
                Ok(logs) => logs,
                Err(err) => {
                    tracing::debug!("Error querying logs (attempt {}): {}", attempts, err);
                    continue;
                }
            };
            for log in logs.iter().filter(|log| log.topics().len() >= 2) {
                // topics[0] is the event signature
                // topics[1] is the indexed requestId
                let event_request_id =
                    alloy::primitives::FixedBytes::<32>::from_slice(&log.topics()[1].0);
                if event_request_id != request_id {
                    continue;
                }
                tracing::info!(
                    request_id = hex::encode(event_request_id),
                    "SignatureResponded event found!"
                );

                // Parse the event data. Event data format: responder (address, 32 bytes) + signature struct
                if log.data().data.len() < 32 + 32 * 4 {
                    tracing::warn!("event data too short: {} bytes", log.data().data.len());
                    continue;
                }
                // responder + bigR.x + bigR.y + s + recoveryId
                // Skip responder address (32 bytes)
                let sig_data = &log.data().data[32..];
                let big_r_x = U256::from_be_slice(&sig_data[0..32]);
                let big_r_y = U256::from_be_slice(&sig_data[32..64]);
                let s = U256::from_be_slice(&sig_data[64..96]);
                tracing::info!(
                    big_r_x = hex::encode(big_r_x.to_be_bytes::<32>()),
                    big_r_y = hex::encode(big_r_y.to_be_bytes::<32>()),
                    s = hex::encode(s.to_be_bytes::<32>()),
                    "parsing signature from SignatureResponded event..."
                );

                // Convert to k256 types
                let x_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&big_r_x.to_be_bytes::<32>());
                let y_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&big_r_y.to_be_bytes::<32>());

                let encoded_point =
                    k256::EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);
                let big_r = k256::AffinePoint::from_encoded_point(&encoded_point).unwrap();

                let s_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&s.to_be_bytes::<32>());
                let s = k256::Scalar::from_bytes(s_bytes.into())
                    .ok_or_else(|| anyhow::anyhow!("invalid scalar value in event {s_bytes:?}"))?;

                let signature = FullSignature::<Secp256k1> { big_r, s };

                tracing::info!("successfully parsed signature from SignatureResponded event");
                return Ok(EthSignOutcome {
                    signer_address,
                    contract_address: self.contract_addr,
                    eth_tx_hash: Some(format!("0x{:x}", tx_hash)),
                    deposit_amount: self.deposit_amount.try_into().unwrap(),
                    signature,
                    payload,
                    payload_hash,
                    algo: self.algo,
                    dest: self.dest,
                    params: self.params,
                });
            }
        }
    }
}
