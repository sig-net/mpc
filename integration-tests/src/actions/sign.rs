use std::fmt;
use std::future::IntoFuture;
use std::time::Duration;

use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_contract::errors;
use mpc_contract::primitives::SignRequest;
use mpc_primitives::{SignId, Signature};
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use rand::Rng;
use solana_sdk::signer::Signer as _;

use crate::actions::{self, wait_for};
use crate::cluster::Cluster;
use crate::containers;

// Use the SignatureRespondedEvent from the contract crate
use signet_program::SignatureRespondedEvent;

/// Convert a Solana contract signature to FullSignature<Secp256k1>
fn convert_solana_signature_to_full_signature(
    solana_sig: &signet_program::Signature,
) -> anyhow::Result<FullSignature<Secp256k1>> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, Scalar};
    use mpc_crypto::ScalarExt;

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
    let full_signature = FullSignature { big_r, s };

    Ok(full_signature)
}

// Removed Solana-specific imports since we're now using the cluster's Solana instance directly

// Solana contract types (matching the contract definitions)
#[derive(Clone, Debug)]
pub struct AffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct EcdsaSignature {
    pub big_r: AffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

pub const SIGN_GAS: Gas = Gas::from_tgas(50);
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

pub struct SignOutcome {
    /// The account that signed the payload.
    pub account: Account,

    /// Underlying rogue account that responded to the signature request if we wanted
    /// to test the rogue behavior.
    pub rogue: Option<Account>,

    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub signature: FullSignature<Secp256k1>,
}

impl fmt::Debug for SignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignOutcome")
            .field("account", &self.account)
            .field("rogue", &self.rogue)
            .field("payload", &self.payload)
            .field("payload_hash", &self.payload_hash)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .finish()
    }
}

pub struct SignAction<'a> {
    nodes: &'a Cluster,
    count: usize,
    account: Option<Account>,
    payload: Option<[u8; 32]>,
    path: String,
    key_version: u32,
    gas: Gas,
    deposit: NearToken,
    execute_rogue: bool,
}

impl<'a> SignAction<'a> {
    pub fn new(nodes: &'a Cluster) -> Self {
        Self {
            nodes,
            count: 1,
            account: None,
            payload: None,
            path: "test".into(),
            key_version: 0,
            gas: SIGN_GAS,
            deposit: SIGN_DEPOSIT,
            execute_rogue: false,
        }
    }
}

impl SignAction<'_> {
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

    pub fn rogue_responder(mut self) -> Self {
        self.execute_rogue = true;
        self
    }

    /// Create a Solana-specific sign action that calls the Solana contract's sign function
    pub fn sol<'a>(self) -> SolanaSignAction<'a>
    where
        Self: 'a,
    {
        SolanaSignAction::new(self)
    }
}

/// Solana-specific sign action that calls the Solana contract's respond function
pub struct SolanaSignAction<'a> {
    inner: SignAction<'a>,
}

impl<'a> SolanaSignAction<'a> {
    fn new(inner: SignAction<'a>) -> Self {
        Self { inner }
    }

    /// Set the payload of this sign call.
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.inner = self.inner.payload(payload);
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
}

impl<'a> IntoFuture for SolanaSignAction<'a> {
    type Output = anyhow::Result<SolanaSignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute_solana())
    }
}

/// Result of a Solana contract sign call
pub struct SolanaSignOutcome {
    pub transaction_signature: String,
    pub request_id: [u8; 32],
    pub signature: FullSignature<Secp256k1>,
}

impl<'a> SolanaSignAction<'a> {
    async fn execute_solana(self) -> anyhow::Result<SolanaSignOutcome> {
        // Get Solana configuration from cluster
        let sol_config = self
            .inner
            .nodes
            .cfg
            .sol
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Solana configuration not available"))?;

        let payload = self
            .inner
            .payload
            .unwrap_or_else(|| rand::thread_rng().gen());
        let payload_hash = *alloy::primitives::keccak256(payload);

        // Call Solana contract's sign function (not respond!)
        let (transaction_signature, signature) = self
            .call_solana_sign(
                sol_config,
                payload_hash,
                &self.inner.path,
                self.inner.key_version,
            )
            .await?;

        Ok(SolanaSignOutcome {
            transaction_signature,
            request_id: payload_hash,
            signature,
        })
    }

    async fn call_solana_sign(
        &self,
        _sol_config: &mpc_node::indexer_sol::SolConfig,
        payload_hash: [u8; 32],
        path: &str,
        key_version: u32,
    ) -> anyhow::Result<(String, FullSignature<Secp256k1>)> {
        // Get the Solana instance from the cluster
        let solana = self
            .inner
            .nodes
            .solana
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Solana instance not available in cluster"))?;

        tracing::info!(
            "Calling Solana sign function with payload: {}, path: {}, key_version: {}",
            hex::encode(payload_hash),
            path,
            key_version
        );

        // Add a small delay to ensure the program is fully loaded
        tokio::time::sleep(Duration::from_millis(500)).await;

        // First, let's verify the program exists by checking its account
        let program_id = solana.program_keypair.pubkey();
        tracing::info!("Verifying program exists: {}", program_id);

        let account_info = solana.rpc_client.get_account(&program_id).await;
        match account_info {
            Ok(account) => {
                tracing::info!(
                    "Program account found, executable: {}, owner: {}",
                    account.executable,
                    account.owner
                );
            }
            Err(e) => {
                tracing::error!("Program account not found: {}", e);
                return Err(anyhow::anyhow!(
                    "Program account verification failed: {}",
                    e
                ));
            }
        }

        // Step 1: Initiate the sign request transaction
        tracing::info!("Initiating Solana sign request...");
        let sign_tx_signature = solana
            .sign_with_params(payload_hash, path, key_version)
            .await?;
        let sign_tx_hash = sign_tx_signature.to_string();
        tracing::info!("Sign request transaction sent: {}", sign_tx_hash);

        // Step 2: Wait for the response event from MPC nodes
        tracing::info!("Waiting for MPC signature response event...");
        let signature = self.wait_for_signature_response(solana).await?;
        Ok((sign_tx_hash, signature))
    }

    async fn wait_for_signature_response(
        &self,
        solana: &containers::Solana,
    ) -> anyhow::Result<FullSignature<Secp256k1>> {
        use anchor_client::{Client, Cluster};
        use solana_sdk::commitment_config::CommitmentConfig;
        use std::sync::Arc;
        use tokio::sync::oneshot;

        // Listen for the actual SignatureRespondedEvent from the external Solana contract
        // The MPC network will call the 'respond' function which emits this event
        let program_id = solana.program_keypair.pubkey();
        let timeout_duration = Duration::from_secs(90);

        tracing::info!("Setting up anchor client to subscribe to SignatureRespondedEvent");

        // Create anchor client using the same configuration as the MPC nodes
        let cluster = Cluster::Custom(
            format!("http://127.0.0.1:8899"), // RPC URL
            format!("ws://127.0.0.1:8900"),   // WebSocket URL
        );

        let client = Client::new_with_options(
            cluster,
            Arc::new(solana.payer_keypair.insecure_clone()),
            CommitmentConfig::confirmed(),
        );

        let program = client.program(program_id)?;

        // Create a channel to receive the event
        let (tx, rx) = oneshot::channel();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

        tracing::info!("Subscribing to SignatureRespondedEvent...");

        // Subscribe to SignatureRespondedEvent
        let event_unsubscriber = program
            .on(move |ctx, event: SignatureRespondedEvent| {
                tracing::info!(
                    "✅ Received SignatureRespondedEvent: request_id={}, responder={}, signature_tx={}",
                    hex::encode(event.request_id),
                    event.responder,
                    ctx.signature
                );

                // Convert the Solana contract signature to FullSignature<Secp256k1>
                let signature_result = convert_solana_signature_to_full_signature(&event.signature);

                // Send the signature through the channel
                if let Ok(mut sender) = tx.lock() {
                    if let Some(sender) = sender.take() {
                        if sender.send(signature_result).is_err() {
                            tracing::error!("Failed to send SignatureRespondedEvent result");
                        }
                    }
                }
            })
            .await?;

        tracing::info!(
            "Successfully subscribed to SignatureRespondedEvent, waiting for MPC response..."
        );

        // Wait for the event with timeout
        let result = tokio::time::timeout(timeout_duration, rx).await;

        // Clean up subscription
        event_unsubscriber.unsubscribe().await;

        match result {
            Ok(Ok(Ok(full_signature))) => {
                tracing::info!("✅ Successfully received and converted SignatureRespondedEvent");
                Ok(full_signature)
            }
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!("Failed to convert signature: {}", e)),
            Ok(Err(_)) => Err(anyhow::anyhow!("Channel closed unexpectedly")),
            Err(_) => Err(anyhow::anyhow!(
                "Timeout waiting for SignatureRespondedEvent after {} seconds - MPC network may not have responded",
                timeout_duration.as_secs()
            )),
        }
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
        let payload_hash = self.payload_hash();
        let status = self.transact_sign(&account, payload_hash).await?;

        // We have to use seperate transactions because one could fail.
        // This leads to a potential race condition where this transaction could get sent after the signature completes, but I think that's unlikely
        let rogue = if self.execute_rogue {
            let (rogue, rogue_status) = self
                .transact_rogue_respond(payload_hash, account.id())
                .await?;
            let err = wait_for::rogue_message_responded(rogue_status).await?;

            assert!(err.contains(&errors::RespondError::InvalidSignature.to_string()));
            Some(rogue)
        } else {
            None
        };

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
            rogue,
            signature,
            payload,
            payload_hash,
        })
    }

    async fn account_or_new(&self) -> Account {
        if let Some(account) = &self.account {
            account.clone()
        } else {
            self.nodes.worker().dev_create_account().await.unwrap()
        }
    }

    fn payload_or_random(&mut self) -> [u8; 32] {
        let payload = self.payload.unwrap_or_else(|| rand::thread_rng().gen());
        self.payload = Some(payload);
        payload
    }

    fn payload_hash(&mut self) -> [u8; 32] {
        *alloy::primitives::keccak256(self.payload_or_random())
    }

    async fn transact_sign(
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

    async fn transact_rogue_respond(
        &self,
        payload_hash: [u8; 32],
        predecessor: &AccountId,
    ) -> anyhow::Result<(Account, AsyncTransactionStatus)> {
        let rogue = self.nodes.worker().dev_create_account().await?;
        let signer = InMemorySigner {
            account_id: rogue.id().clone(),
            public_key: rogue.secret_key().public_key().to_string().parse()?,
            secret_key: rogue.secret_key().to_string().parse()?,
        };

        let big_r = serde_json::from_value(
            "02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C".into(),
        )?; // Fake BigR
        let s = serde_json::from_value(
            "20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6".into(),
        )?; // Fake S

        let signature = Signature {
            big_r,
            s,
            recovery_id: 0,
        };

        let sign_id = SignId::from_parts(predecessor, &payload_hash, &self.path, self.key_version);
        let status = self
            .nodes
            .rpc_client
            .call(&signer, self.nodes.contract().id(), "respond")
            .args_json(serde_json::json!({
                "sign_id": sign_id,
                "signature": signature,
            }))
            .max_gas()
            .transact_async()
            .await?;

        Ok((rogue, status))
    }
}
